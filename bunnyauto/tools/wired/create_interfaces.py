"""``wired create-interfaces`` — discover device interfaces and create the missing ones in NetBox.

Ported from ``create_interfaces_netbox.py``. Plans by default; ``--apply`` writes.
It never updates or deletes an interface — only creates ones NetBox is missing.
Name matching and the NetBox type a new interface gets both come from
:mod:`bunnyauto.netbox.interfaces`, shared with every other tool.

**Stacks.** SSH to a stack lists every member's ports, but NetBox keeps each
member as its own device (:mod:`bunnyauto.netbox.stacks`). A port is checked
and created on the member whose number it carries (``Gi2/0/1`` -> ``SwitchA-2``).
Ports without a member number (Port-Channels, VLANs, mgmt) go to the connected
device, or a Virtual Chassis's master. A member with no in-scope NetBox device
gets nothing. Its ports are reported, never parked on another member.

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
    canonical_name,
    interface_type,
    member_local_names,
    stack_member,
)
from bunnyauto.netbox.records import related_id
from bunnyauto.netbox.stacks import Stack, resolve_stack
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context

_DISABLED_STATES = {"administratively down", "admin down", "disabled"}
#: Stack-wide logical interfaces: one on any member of the stack means it's in NetBox.
_STACK_WIDE_TYPES = frozenset({"lag", "virtual"})


@dataclass(frozen=True)
class DiscoveredInterface:
    name: str
    description: str = ""
    enabled: bool = True


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
    #: Reported port -> the device-type template's member-1 name for it here.
    template_named: dict[str, str] = field(default_factory=dict)
    #: Reported Port-Channel/VLAN -> the other stack members that already have it.
    elsewhere: dict[str, list[str]] = field(default_factory=dict)
    #: NetBox interface on this device -> the stack member it belongs on.
    misplaced: dict[str, str] = field(default_factory=dict)
    created: int = 0
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
    summary: str = "Create NetBox interfaces that a device has but NetBox is missing"
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
            for device_id in _classify(stack, discovered, index, plans, blocked):
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

        created_total = 0
        if ctx.settings.apply:
            for plan in ordered:
                if not plan.missing:
                    continue
                try:
                    plan.created = _create(nb, int(plan.device.id), plan.missing)
                except Exception as exc:  # pynetbox RequestError etc.
                    plan.error = f"create failed: {exc}"
                    failures[str(plan.device.name)] = plan.error
                    ctx.reporter.error(f"{plan.device.name}: {plan.error}")
                    continue
                created_total += plan.created
                ctx.reporter.success(f"{plan.device.name}: created {plan.created} interface(s)")

        return _result(
            apply=ctx.settings.apply,
            changes=changes,
            plans=ordered,
            blocked=list(blocked.values()),
            failures=failures,
            progressed=bool(stacks_seen) and (not ordered or any(not p.error for p in ordered)),
            created_total=created_total,
        )


def _interface_index(nb: Any, devices: list[Any]) -> dict[int, dict[str, str]]:
    """Each device's NetBox interfaces as ``{canonical name: NetBox name}``, by device id."""
    index: dict[int, dict[str, str]] = {}
    for device in devices:
        device_id = int(device.id)
        names = index[device_id] = {}
        for record in nb.dcim.interfaces.filter(device_id=device_id):
            # Only this device's own: older NetBox expanded a VC master's filter to its members.
            if related_id(getattr(record, "device", None)) not in (None, device_id):
                continue
            names.setdefault(canonical_name(str(record.name)), str(record.name))
    return index


def _classify(
    stack: Stack,
    discovered: list[DiscoveredInterface],
    index: dict[int, dict[str, str]],
    plans: dict[int, _DevicePlan],
    blocked: dict[tuple[str, int], _Blocked],
) -> set[int]:
    """File each discovered port under its device: present, missing, or ownerless.

    Returns the ids of the devices whose ports were checked.
    """
    checked: set[int] = {int(stack.connected.id)}
    for iface in discovered:
        member = stack_member(iface.name) if stack.is_stack else None
        owner = stack.owner(iface.name)
        if owner is None:  # only a stack port (member is set) can lack an owner
            _ownerless(stack, iface, int(member or 0), index, plans, blocked)
            continue

        owner_id = int(owner.id)
        checked.add(owner_id)
        plan = _plan(plans, owner, stack)
        plan.discovered += 1
        names = index.get(owner_id, {})
        wanted = canonical_name(iface.name)
        if wanted in names:
            plan.existing += 1
        elif member is not None and (template := _template_name(iface.name, names)):
            plan.template_named[iface.name] = template
        elif holders := _stack_wide_holders(iface.name, stack, index, owner_id):
            plan.elsewhere[iface.name] = holders
        elif all(canonical_name(i.name) != wanted for i in plan.missing):
            plan.missing.append(iface)

        # Every member device carries the template's member-1 names, so only a copy
        # of a member-2+ port is unambiguously on the wrong device.
        if member is not None and member != 1:
            for other in stack.devices():
                found = index.get(int(other.id), {}).get(wanted)
                if found is not None and int(other.id) != owner_id:
                    _plan(plans, other, stack).misplaced[found] = str(owner.name)
    return checked


def _ownerless(
    stack: Stack,
    iface: DiscoveredInterface,
    member: int,
    index: dict[int, dict[str, str]],
    plans: dict[int, _DevicePlan],
    blocked: dict[tuple[str, int], _Blocked],
) -> None:
    """A port whose stack member has no in-scope device: present, or blocked."""
    connected = stack.connected
    # Already on the connected device means it's in NetBox (a modular chassis's
    # line-card ports look like stack members). A connected member other than 1
    # has member-1 names from its own template, which are its ports, not member 1's.
    template_clash = member == 1 and stack.own_member not in (None, 1)
    if not template_clash and canonical_name(iface.name) in index.get(int(connected.id), {}):
        plan = _plan(plans, connected, stack)
        plan.discovered += 1
        plan.existing += 1
        return

    key = (str(connected.name), member)
    item = blocked.get(key)
    if item is None:
        reason = stack.unresolved.get(member, "no NetBox device for this stack member")
        item = blocked[key] = _Blocked(via=str(connected.name), member=member, reason=reason)
    item.ports.append(iface.name)


def _plan(plans: dict[int, _DevicePlan], device: Any, stack: Stack) -> _DevicePlan:
    device_id = int(device.id)
    plan = plans.get(device_id)
    if plan is None:
        member = next((m for m, d in stack.members.items() if int(d.id) == device_id), None)
        via = "" if device_id == int(stack.connected.id) else str(stack.connected.name)
        plan = plans[device_id] = _DevicePlan(device=device, via=via, member=member)
    return plan


def _template_name(name: str, names: dict[str, str]) -> str | None:
    """The device-type template's member-1 name for stack port ``name``, if present."""
    for alias in member_local_names(name):
        found = names.get(canonical_name(alias))
        if found is not None:
            return found
    return None


def _stack_wide_holders(
    name: str, stack: Stack, index: dict[int, dict[str, str]], owner_id: int
) -> list[str]:
    """Other stack members that already have Port-Channel/VLAN ``name``."""
    if not stack.is_stack or interface_type(name) not in _STACK_WIDE_TYPES:
        return []
    wanted = canonical_name(name)
    return [
        str(device.name)
        for device in stack.devices()
        if int(device.id) != owner_id and wanted in index.get(int(device.id), {})
    ]


def _report(ctx: Context, plans: list[_DevicePlan], blocked: list[_Blocked]) -> list[str]:
    """Emit each device's notes; return the planned-change lines."""
    verb = "create" if ctx.settings.apply else "would create"
    changes: list[str] = []
    for plan in plans:
        name = str(plan.device.name)
        where = f" [stack member {plan.member}, seen on {plan.via}]" if plan.via else ""
        for iface in plan.missing:
            changes.append(f"{name}: {verb} {iface.name} ({interface_type(iface.name)}){where}")
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
    created_total: int,
) -> ToolResult:
    data: dict[str, Any] = {}
    for plan in plans:
        entry: dict[str, Any] = {
            "ok": not plan.error,
            "discovered": plan.discovered,
            "existing": plan.existing,
            "missing": [i.name for i in plan.missing],
            "created": plan.created,
        }
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
    if failures or blocked_ports:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and created_total:
        status = Status.CHANGED
    elif changes:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"created {created_total} interface(s)"
    elif changes:
        summary = f"{len(changes)} interface(s) missing from NetBox — run with --apply to create"
    elif blocked_ports:
        summary = "no interfaces to create"
    else:
        summary = "NetBox is in sync — no interfaces to create"
    if blocked_ports:
        summary += (
            f"; {blocked_ports} stack port(s) skipped — their member has no NetBox device in scope"
        )
    if failures:
        summary += f" ({len(failures)} device(s) failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


def _create(nb: Any, device_id: int, interfaces: list[DiscoveredInterface]) -> int:
    payload = [
        {
            "device": device_id,
            "name": iface.name,
            "type": interface_type(iface.name),
            "enabled": iface.enabled,
            "description": iface.description,
        }
        for iface in interfaces
    ]
    created = nb.dcim.interfaces.create(payload)
    return len(created) if isinstance(created, list) else 1


def _discovered(multi) -> list[DiscoveredInterface] | None:
    for item in multi:
        if isinstance(item.result, list) and all(
            isinstance(v, DiscoveredInterface) for v in item.result
        ):
            return item.result
    return None


TOOL = CreateInterfaces()
