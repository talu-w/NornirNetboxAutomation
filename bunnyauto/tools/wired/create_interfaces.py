"""``wired create-interfaces`` — create the interfaces NetBox is missing, and correct their types.

Ported from ``create_interfaces_netbox.py``. Plans by default; ``--apply`` writes.
It creates interfaces NetBox is missing and corrects the **type** of ones it has;
it never changes anything else on an interface, and never deletes one. Name
matching and interface types both come from :mod:`bunnyauto.netbox.interfaces`,
shared with every other tool.

**Types come from the device.** ``show interfaces`` (already run to list the
ports) reports each port's media type: ``10/100/1000BaseTX``, ``SFP-10GBase-SR``,
``Not Present``. That decides the NetBox type of a new interface, and an existing
interface whose type disagrees is corrected (``1000base-t`` -> ``1000base-tx``).
See :func:`~bunnyauto.netbox.interfaces.port_media` for the mapping. Only types
the NetBox accepts are used (it's asked once per run). A port with no usable media
type (Port-Channels, VLANs, ``unknown``) keeps its NetBox type, and a new one
gets the old guess from its name. A media type bunnyauto can't map is noted,
with its ports, and nothing is changed for it.

**Stacks.** SSH to a stack lists every member's ports, but NetBox keeps each
member as its own device (:mod:`bunnyauto.netbox.stacks`). A port is checked
and created on the member whose number it carries (``Gi2/0/1`` -> ``SwitchA-2``).
Ports without a member number (Port-Channels, VLANs, mgmt) go to the connected
device, or a Virtual Chassis's master. Every member of the switch's Virtual
Chassis counts, even one without the env tag (NetBox doesn't copy tags to a
chassis member); a member found only by name must be in scope. A member with no
usable NetBox device gets nothing. Its ports are reported, never parked on
another member. A copy already on the connected device counts as present only
when NetBox has no device of that member's own
(:meth:`~bunnyauto.netbox.stacks.Stack.stand_in`, the rule ``sync-interfaces``
uses too). When the member's device exists but is out of scope, the copy is a
leftover and the ports are reported.

**Already in NetBox** means present on the port's own device under the same
name or spelling (``Gi1/0/1`` is ``GigabitEthernet1/0/1``). On a stack member it
also covers the device-type template's member-1 name (``GigabitEthernet1/0/1``
on ``SwitchA-2`` is its ``Gi2/0/1``), and a Port-Channel or VLAN on any member
of the stack counts too. These are skipped with a note, never re-created. A
member's port found on the wrong member (left by runs before stacks were
handled) is reported for removal by hand, since this tool never deletes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

from bunnyauto.common import first_error
from bunnyauto.errors import ToolError
from bunnyauto.netbox.devices import (
    get_netbox_device,
    inventory_device_id,
    select_tagged_inventory,
)
from bunnyauto.netbox.interfaces import (
    PortMedia,
    canonical_name,
    interface_type,
    media_is_blank,
    member_local_names,
    port_media,
    stack_member,
    supported_type,
    type_fits,
)
from bunnyauto.netbox.records import choice_value
from bunnyauto.netbox.stacks import Stack, is_stack_wide, own_interfaces, resolve_stack
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context

_DISABLED_STATES = {"administratively down", "admin down", "disabled"}


@dataclass(frozen=True)
class DiscoveredInterface:
    name: str
    description: str = ""
    enabled: bool = True
    #: ``show interfaces``' "media type is ..." (``10/100/1000BaseTX``), ``""`` if none.
    media_type: str = ""


@dataclass(frozen=True, slots=True)
class _Existing:
    """A NetBox interface: as much of it as this tool compares."""

    id: int
    name: str
    type: str


@dataclass(frozen=True, slots=True)
class _Retype:
    """A NetBox interface whose type disagrees with the device's media report."""

    id: int
    name: str
    current: str
    wanted: str
    media: str


@dataclass(slots=True)
class _DevicePlan:
    """One NetBox device's share of the run, whichever host its ports were seen on."""

    device: Any
    #: The host the ports were discovered on, when that's another stack member.
    via: str = ""
    member: int | None = None
    discovered: int = 0
    existing: int = 0
    missing: list[DiscoveredInterface] = field(default_factory=list)
    #: Missing port -> the NetBox type it's created as.
    types: dict[str, str] = field(default_factory=dict)
    #: Interfaces here whose NetBox type the device's media report says is wrong.
    retype: list[_Retype] = field(default_factory=list)
    #: A media type bunnyauto can't map -> the ports that reported it.
    unmapped: dict[str, list[str]] = field(default_factory=dict)
    #: Reported port -> the device-type template's member-1 name for it here.
    template_named: dict[str, str] = field(default_factory=dict)
    #: Reported Port-Channel/VLAN -> the other stack members that already have it.
    elsewhere: dict[str, list[str]] = field(default_factory=dict)
    #: NetBox interface on this device -> the stack member it belongs on.
    misplaced: dict[str, str] = field(default_factory=dict)
    created: int = 0
    retyped: int = 0
    error: str = ""


@dataclass(slots=True)
class _Blocked:
    """Ports of a stack member that has no in-scope NetBox device."""

    via: str
    member: int
    reason: str
    ports: list[str] = field(default_factory=list)


def parse_interfaces(rows: Any, include_virtual: bool) -> list[DiscoveredInterface]:
    if not isinstance(rows, list):
        raise ToolError(
            "'show interfaces' did not return structured data — check that "
            "ntc-templates supports this platform's TextFSM template"
        )

    discovered: dict[str, DiscoveredInterface] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("interface") or row.get("port") or "").strip()
        if not name:
            continue
        if interface_type(name) == "virtual" and not include_virtual:
            continue
        status = str(row.get("link_status") or row.get("status") or "").casefold()
        discovered.setdefault(
            canonical_name(name),
            DiscoveredInterface(
                name=name,
                description=str(row.get("description") or "").strip(),
                enabled=status not in _DISABLED_STATES,
                media_type=str(row.get("media_type") or "").strip(),
            ),
        )
    return sorted(discovered.values(), key=lambda item: canonical_name(item.name))


def _collect(task: Task, include_virtual: bool) -> Result:
    collected = task.run(
        task=netmiko_send_command,
        name="show interfaces",
        command_string="show interfaces",
        use_textfsm=True,
        read_timeout=120,
    )
    return Result(
        host=task.host,
        changed=False,
        result=parse_interfaces(collected.result, include_virtual),
    )


@dataclass(slots=True)
class CreateInterfaces:
    name: str = "create-interfaces"
    summary: str = "Create the interfaces NetBox is missing and correct wrong interface types"
    writes: bool = True
    category: str = "wired"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "--device",
            default=None,
            help=(
                "limit to one device by name (must still be in scope); "
                "a stack's other members are checked along with it"
            ),
        )
        parser.add_argument(
            "--include-virtual",
            action="store_true",
            dest="include_virtual",
            help="also create loopbacks, VLANs, and tunnels (Port-Channels are always included)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        nb = ctx.netbox()
        in_scope = ctx.target_devices()
        tagged = in_scope
        if args.device:
            wanted = args.device.casefold()
            tagged = [d for d in in_scope if str(d.name).casefold() == wanted]
            if not tagged:
                raise ToolError(
                    f"device {args.device!r} was not found in scope ({ctx.scope().describe()})"
                )
        if not tagged:
            return ToolResult(
                status=Status.OK,
                summary=f"no NetBox devices in scope ({ctx.scope().describe()})",
            )

        selected = select_tagged_inventory(ctx.nornir(), tagged)
        if not selected.inventory.hosts:
            raise ToolError("no tagged NetBox devices matched the Nornir inventory")

        ctx.reporter.step(f"discovering interfaces on {len(selected.inventory.hosts)} device(s)")
        with ctx.reporter.track(selected, description="create-interfaces: discover") as tracked:
            run_result = tracked.run(
                task=_collect,
                name="create-interfaces: discover",
                include_virtual=args.include_virtual,
            )

        plans: dict[int, _DevicePlan] = {}
        blocked: dict[tuple[str, int], _Blocked] = {}
        failures: dict[str, str] = {}
        unreachable: dict[str, str] = {}
        checked_via: dict[int, str] = {}  # NetBox device id -> host its ports were seen on
        stacks_seen: dict[tuple[str, Any], str] = {}
        scope_label = ctx.scope().describe()
        media_seen = any(
            i.media_type for multi in run_result.values() for i in (_discovered(multi) or [])
        )
        supported = _supported_types(ctx, nb) if media_seen else None

        for host_name, multi in run_result.items():
            discovered = _discovered(multi)
            if multi.failed or discovered is None:
                unreachable[host_name] = first_error(multi, "interface discovery failed")
                continue

            try:
                device = get_netbox_device(nb, selected.inventory.hosts[host_name])
                members = (stack_member(i.name) for i in discovered)
                reported = {m for m in members if m is not None}
                stack = resolve_stack(nb, device, reported, in_scope, scope_label=scope_label)
                if stack.key in stacks_seen:
                    ctx.reporter.info(
                        f"{host_name}: same stack as {stacks_seen[stack.key]} — already checked"
                    )
                    continue
                index = _interface_index(nb, stack.devices())
            except Exception as exc:  # pynetbox RequestError etc.
                failures[host_name] = str(exc)
                ctx.reporter.error(f"{host_name}: NetBox lookup failed: {exc}")
                continue

            stacks_seen[stack.key] = host_name
            if stack.inherited:
                ctx.reporter.info(
                    f"{host_name}: including {_names(stack.inherited)} as part of its "
                    f"Virtual Chassis, though outside this run's scope ({scope_label})"
                )
            for device_id in _classify(stack, discovered, index, plans, blocked, supported):
                checked_via.setdefault(device_id, host_name)

        for host_name, message in unreachable.items():
            via = checked_via.get(inventory_device_id(selected.inventory.hosts[host_name]))
            if via is not None and via != host_name:
                # A stack member without its own management IP: expected, and covered.
                ctx.reporter.info(
                    f"{host_name}: not reachable on its own ({message}) — "
                    f"its interfaces were checked through {via}, the same stack"
                )
                continue
            failures[host_name] = message
            ctx.reporter.error(f"{host_name}: {message}")

        ordered = sorted(plans.values(), key=lambda plan: str(plan.device.name).casefold())
        changes = _report(ctx, ordered, list(blocked.values()))

        if ctx.settings.apply:
            for plan in ordered:
                _apply(ctx, nb, plan, failures)

        return _result(
            apply=ctx.settings.apply,
            changes=changes,
            plans=ordered,
            blocked=list(blocked.values()),
            failures=failures,
            progressed=bool(stacks_seen) and (not ordered or any(not p.error for p in ordered)),
        )


def _apply(ctx: Context, nb: Any, plan: _DevicePlan, failures: dict[str, str]) -> None:
    """Create ``plan``'s missing interfaces and correct its wrong types."""
    name = str(plan.device.name)
    errors: list[str] = []
    if plan.missing:
        try:
            plan.created = _create(nb, int(plan.device.id), plan.missing, plan.types)
            ctx.reporter.success(f"{name}: created {plan.created} interface(s)")
        except Exception as exc:  # pynetbox RequestError etc.
            errors.append(f"create failed: {exc}")
    if plan.retype:
        try:
            plan.retyped = _retype(nb, plan.retype)
            ctx.reporter.success(f"{name}: corrected the type of {plan.retyped} interface(s)")
        except Exception as exc:  # pynetbox RequestError etc.
            errors.append(f"type update failed: {exc}")
    for error in errors:
        ctx.reporter.error(f"{name}: {error}")
    if errors:
        plan.error = "; ".join(errors)
        failures[name] = plan.error


def _names(devices: list[Any]) -> str:
    return ", ".join(sorted(str(device.name) for device in devices))


def _supported_types(ctx: Context, nb: Any) -> frozenset[str] | None:
    """The interface type values this NetBox accepts, or ``None`` if it won't say."""
    try:
        choices = nb.dcim.interfaces.choices()["type"]
        return frozenset(str(c["value"]) for c in choices if isinstance(c, dict) and "value" in c)
    except Exception as exc:  # pynetbox RequestError, an unexpected OPTIONS shape, ...
        ctx.reporter.warn(
            f"could not read the interface types NetBox accepts ({exc}) — using only "
            "long-standing ones, so a BaseTX port stays 1000base-t"
        )
        return None


def _interface_index(nb: Any, devices: list[Any]) -> dict[int, dict[str, _Existing]]:
    """Each device's NetBox interfaces as ``{canonical name: interface}``, by device id."""
    index: dict[int, dict[str, _Existing]] = {}
    for device in devices:
        names = index[int(device.id)] = {}
        for record in own_interfaces(nb, device):
            names.setdefault(
                canonical_name(str(record.name)),
                _Existing(
                    id=int(record.id),
                    name=str(record.name),
                    type=choice_value(getattr(record, "type", None)) or "",
                ),
            )
    return index


def _classify(
    stack: Stack,
    discovered: list[DiscoveredInterface],
    index: dict[int, dict[str, _Existing]],
    plans: dict[int, _DevicePlan],
    blocked: dict[tuple[str, int], _Blocked],
    supported: frozenset[str] | None,
) -> set[int]:
    """File each discovered port under its device: present, missing, or ownerless.

    Returns the ids of the devices whose ports were checked.
    """
    checked: set[int] = {int(stack.connected.id)}
    for iface in discovered:
        member = stack_member(iface.name) if stack.is_stack else None
        owner = stack.owner(iface.name)
        if owner is None:  # only a stack port (member is set) can lack an owner
            _ownerless(stack, iface, int(member or 0), index, plans, blocked, supported)
            continue

        owner_id = int(owner.id)
        checked.add(owner_id)
        plan = _plan(plans, owner, stack)
        plan.discovered += 1
        names = index.get(owner_id, {})
        wanted = canonical_name(iface.name)
        if (found := names.get(wanted)) is not None:
            plan.existing += 1
            _check_type(plan, found, iface, supported)
        elif member is not None and (template := _template_interface(iface.name, names)):
            plan.template_named[iface.name] = template.name
            _check_type(plan, template, iface, supported)
        elif holders := _stack_wide_holders(iface.name, stack, index, owner_id):
            plan.elsewhere[iface.name] = holders
        elif all(canonical_name(i.name) != wanted for i in plan.missing):
            plan.missing.append(iface)
            reported = _reported_type(plan, iface, supported)
            plan.types[iface.name] = reported[1] if reported else interface_type(iface.name)

        # Every member device carries the template's member-1 names, so only a copy
        # of a member-2+ port is unambiguously on the wrong device.
        if member is not None and member != 1:
            for other in stack.devices():
                copy = index.get(int(other.id), {}).get(wanted)
                if copy is not None and int(other.id) != owner_id:
                    _plan(plans, other, stack).misplaced[copy.name] = str(owner.name)
    return checked


def _ownerless(
    stack: Stack,
    iface: DiscoveredInterface,
    member: int,
    index: dict[int, dict[str, _Existing]],
    plans: dict[int, _DevicePlan],
    blocked: dict[tuple[str, int], _Blocked],
    supported: frozenset[str] | None,
) -> None:
    """A port whose stack member has no in-scope device: present, or blocked."""
    # Already on the connected device means it's in NetBox where that device stands
    # in for the member (a modular chassis's line-card ports look like stack members).
    stand_in = stack.stand_in(iface.name)
    if stand_in is not None:
        found = index.get(int(stand_in.id), {}).get(canonical_name(iface.name))
        if found is not None:
            plan = _plan(plans, stand_in, stack)
            plan.discovered += 1
            plan.existing += 1
            _check_type(plan, found, iface, supported)
            return

    key = (str(stack.connected.name), member)
    item = blocked.get(key)
    if item is None:
        reason = stack.unresolved.get(member, "no NetBox device for this stack member")
        item = blocked[key] = _Blocked(via=str(stack.connected.name), member=member, reason=reason)
    item.ports.append(iface.name)


def _plan(plans: dict[int, _DevicePlan], device: Any, stack: Stack) -> _DevicePlan:
    device_id = int(device.id)
    plan = plans.get(device_id)
    if plan is None:
        via = "" if device_id == int(stack.connected.id) else str(stack.connected.name)
        plan = plans[device_id] = _DevicePlan(
            device=device, via=via, member=stack.member_number(device)
        )
    return plan


def _template_interface(name: str, names: dict[str, _Existing]) -> _Existing | None:
    """The interface under the device-type template's member-1 name for stack port ``name``."""
    for alias in member_local_names(name):
        found = names.get(canonical_name(alias))
        if found is not None:
            return found
    return None


def _reported_type(
    plan: _DevicePlan, iface: DiscoveredInterface, supported: frozenset[str] | None
) -> tuple[PortMedia, str] | None:
    """The device's media report for ``iface`` and the NetBox type it gives, if any.

    A media type that isn't blank but can't be mapped is recorded on ``plan``.
    """
    port = port_media(iface.name, iface.media_type)
    wanted = supported_type(port.types, supported) if port else None
    if port is None or wanted is None:
        if not media_is_blank(iface.media_type):
            plan.unmapped.setdefault(iface.media_type, []).append(iface.name)
        return None
    return port, wanted


def _check_type(
    plan: _DevicePlan,
    existing: _Existing,
    iface: DiscoveredInterface,
    supported: frozenset[str] | None,
) -> None:
    """Plan a type correction if ``existing`` disagrees with what the device reports."""
    reported = _reported_type(plan, iface, supported)
    if reported is None:
        return
    port, wanted = reported
    if type_fits(port, existing.type, wanted) or any(r.id == existing.id for r in plan.retype):
        return
    plan.retype.append(_Retype(existing.id, existing.name, existing.type, wanted, port.media))


def _stack_wide_holders(
    name: str, stack: Stack, index: dict[int, dict[str, _Existing]], owner_id: int
) -> list[str]:
    """Other stack members that already have Port-Channel/VLAN ``name``."""
    if not stack.is_stack or not is_stack_wide(name):
        return []
    wanted = canonical_name(name)
    return [
        str(device.name)
        for device in stack.devices()
        if int(device.id) != owner_id and wanted in index.get(int(device.id), {})
    ]


def _report(ctx: Context, plans: list[_DevicePlan], blocked: list[_Blocked]) -> list[str]:
    """Emit each device's notes; return the planned-change lines."""
    create, change = (
        ("create", "change") if ctx.settings.apply else ("would create", "would change")
    )
    changes: list[str] = []
    for plan in plans:
        name = str(plan.device.name)
        where = f" [stack member {plan.member}, seen on {plan.via}]" if plan.via else ""
        for iface in plan.missing:
            changes.append(f"{name}: {create} {iface.name} ({plan.types[iface.name]}){where}")
        for item in plan.retype:
            changes.append(
                f"{name}: {change} {item.name} from {item.current or 'no type'} to {item.wanted} "
                f"(device reports {item.media!r}){where}"
            )
        for media, ports in plan.unmapped.items():
            ctx.reporter.info(
                f"{name}: media type {media!r} on {len(ports)} port(s) (e.g. {ports[0]}) "
                "isn't mapped to a NetBox type — not used to set their type"
            )
        if plan.template_named:
            reported, template = next(iter(plan.template_named.items()))
            ctx.reporter.info(
                f"{name}: {len(plan.template_named)} interface(s) already in NetBox under the "
                f"device type's member-1 names (e.g. {reported} is {template}) — not created"
            )
        for port, holders in plan.elsewhere.items():
            ctx.reporter.info(
                f"{name}: {port} already exists on {', '.join(holders)} (same stack) — not created"
            )
        if plan.misplaced:
            found, owner = next(iter(plan.misplaced.items()))
            ctx.reporter.warn(
                f"{name}: {len(plan.misplaced)} interface(s) here belong to another stack "
                f"member (e.g. {found} belongs on {owner}), likely left by a run before "
                "stacks were handled — nothing is deleted; remove them in NetBox once any "
                "cables or IPs are moved"
            )
        if plan.discovered and not plan.missing:
            ctx.reporter.info(f"{name}: NetBox already has every interface")
    for item in blocked:
        ctx.reporter.warn(
            f"{item.via}: {len(item.ports)} port(s) of stack member {item.member} not created "
            f"(e.g. {item.ports[0]}) — {item.reason}"
        )
    return changes


def _result(
    *,
    apply: bool,
    changes: list[str],
    plans: list[_DevicePlan],
    blocked: list[_Blocked],
    failures: dict[str, str],
    progressed: bool,
) -> ToolResult:
    data: dict[str, Any] = {}
    for plan in plans:
        entry: dict[str, Any] = {
            "ok": not plan.error,
            "discovered": plan.discovered,
            "existing": plan.existing,
            "missing": [i.name for i in plan.missing],
            "created": plan.created,
            "retyped": plan.retyped,
        }
        if plan.retype:
            entry["retype"] = [
                {"name": r.name, "from": r.current, "to": r.wanted, "media": r.media}
                for r in plan.retype
            ]
        if plan.unmapped:
            entry["unmapped_media"] = {k: list(v) for k, v in plan.unmapped.items()}
        if plan.via:
            entry["via"] = plan.via
        if plan.member is not None:
            entry["stack_member"] = plan.member
        if plan.template_named:
            entry["template_named"] = dict(plan.template_named)
        if plan.elsewhere:
            entry["on_other_member"] = {k: list(v) for k, v in plan.elsewhere.items()}
        if plan.misplaced:
            entry["misplaced"] = dict(plan.misplaced)
        data[str(plan.device.name)] = entry
    for item in blocked:
        data.setdefault(item.via, {"ok": True}).setdefault("blocked", []).append(
            {"member": item.member, "reason": item.reason, "ports": list(item.ports)}
        )
    for name, message in failures.items():
        data.setdefault(name, {}).update({"ok": False, "error": message})

    blocked_ports = sum(len(item.ports) for item in blocked)
    missing = sum(len(plan.missing) for plan in plans)
    retypes = sum(len(plan.retype) for plan in plans)
    created = sum(plan.created for plan in plans)
    retyped = sum(plan.retyped for plan in plans)
    if failures or blocked_ports:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and (created or retyped):
        status = Status.CHANGED
    elif changes:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"created {created} interface(s)"
        if retypes:
            summary += f", corrected the type of {retyped}"
    elif changes:
        found = [f"{missing} interface(s) missing from NetBox"] if missing else []
        if retypes:
            found.append(
                f"{retypes} with the wrong type"
                if missing
                else f"{retypes} interface(s) with the wrong type in NetBox"
            )
        verb = "create" if not retypes else "correct" if not missing else "create and correct"
        summary = f"{', '.join(found)} — run with --apply to {verb}"
    elif blocked_ports:
        summary = "no interfaces to create or correct"
    else:
        summary = "NetBox is in sync — no interfaces to create or correct"
    if blocked_ports:
        summary += (
            f"; {blocked_ports} stack port(s) skipped — their member has no NetBox device in scope"
        )
    if failures:
        summary += f" ({len(failures)} device(s) failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


def _create(
    nb: Any, device_id: int, interfaces: list[DiscoveredInterface], types: dict[str, str]
) -> int:
    payload = [
        {
            "device": device_id,
            "name": iface.name,
            "type": types.get(iface.name) or interface_type(iface.name),
            "enabled": iface.enabled,
            "description": iface.description,
        }
        for iface in interfaces
    ]
    created = nb.dcim.interfaces.create(payload)
    return len(created) if isinstance(created, list) else 1


def _retype(nb: Any, retypes: list[_Retype]) -> int:
    """Set each interface's type; nothing else on it is touched."""
    updated = nb.dcim.interfaces.update([{"id": r.id, "type": r.wanted} for r in retypes])
    return len(updated) if isinstance(updated, list) else len(retypes)


def _discovered(multi) -> list[DiscoveredInterface] | None:
    for item in multi:
        if isinstance(item.result, list) and all(
            isinstance(v, DiscoveredInterface) for v in item.result
        ):
            return item.result
    return None


TOOL = CreateInterfaces()
