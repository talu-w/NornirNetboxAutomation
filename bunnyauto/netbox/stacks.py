"""Switch stacks: which NetBox device owns each of a stack's member-numbered ports.

A switch stack (Cisco StackWise, StackWise Virtual, ...) has one management
plane. SSH to it and ``show interfaces`` lists every member's ports
(``Gi1/0/1``, ``Gi2/0/1``, ...), but NetBox keeps each physical member as its
own device. A port belongs to the member whose number it carries
(:func:`bunnyauto.netbox.interfaces.stack_member`). :func:`resolve_stack` finds
the member devices for the device a tool connected to, trying in order:

1. **its NetBox Virtual Chassis**: a member's ``vc_position`` is its member
   number. That is explicit modeling, so it is trusted as-is.
2. **the owner's naming convention**, ``<host>-<member>[.<domain>]``
   (``SwitchA-2.example.com`` is member 2 of ``SwitchA``, see
   :func:`bunnyauto.netbox.hostnames.split_stack_suffix`). A name alone doesn't
   prove a stack (``dist-1``/``dist-2`` may be a redundant pair), so this
   applies only when the connected device's ports span more than one member
   number, its own included, and none is 0. Cisco numbers stack members from
   1, so a leading 0 means slot numbering (an ISR's ``Gi0/0/0``). A sibling
   with its own, different management IP is a separately managed switch,
   never a member.

Anything else is a standalone switch, or one NetBox device for a whole stack or
modular chassis, and every port stays on the connected device.

Member devices must be in the run's scope (env tag + role branch), the rule
every tool follows. A member number with no in-scope device is *unresolved*:
its ports get no owner, and the reason is kept for the report. They are never
handed to the connected device instead, which is a different physical switch.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from bunnyauto.netbox.hostnames import normalize_hostname, split_stack_suffix, with_stack_suffix
from bunnyauto.netbox.interfaces import stack_member
from bunnyauto.netbox.records import related_id


@dataclass(slots=True)
class Stack:
    """One physical switch or stack, as the NetBox devices that model it."""

    connected: Any
    #: Where ports without a member number go (VLANs, Port-Channels, mgmt):
    #: the Virtual Chassis master, otherwise the connected device.
    anchor: Any
    #: ``"virtual-chassis"`` or ``"name"``; ``""`` for a standalone device.
    source: str = ""
    #: The connected device's own member number (``None`` when standalone).
    own_member: int | None = None
    #: Member number -> that member's in-scope NetBox device.
    members: dict[int, Any] = field(default_factory=dict)
    #: Member number -> why no in-scope device owns that member's ports.
    unresolved: dict[int, str] = field(default_factory=dict)
    #: The same for every route into one physical stack, so it's checked once.
    key: tuple[str, Any] = ("device", 0)

    @property
    def is_stack(self) -> bool:
        return bool(self.source)

    def devices(self) -> list[Any]:
        """Every NetBox device in this stack, the connected one first, no repeats."""
        seen: dict[int, Any] = {}
        for device in (self.connected, self.anchor, *self.members.values()):
            seen.setdefault(int(device.id), device)
        return list(seen.values())

    def owner(self, interface_name: str) -> Any | None:
        """The device a port belongs to, or ``None`` if its member is unresolved."""
        if not self.source:
            return self.connected
        member = stack_member(interface_name)
        if member is None:
            return self.anchor
        return self.members.get(member)


def resolve_stack(
    nb: Any,
    device: Any,
    reported_members: Iterable[int],
    in_scope: Iterable[Any],
    *,
    scope_label: str = "",
) -> Stack:
    """Map each member number ``device``'s ports carry to the in-scope device owning it.

    ``reported_members`` are the member numbers seen in the connected device's
    own port names. ``in_scope`` are the devices this run may touch.
    ``scope_label`` (e.g. :meth:`bunnyauto.scope.Scope.describe`) names the
    scope in the reason for a member that exists in NetBox but falls outside it.
    """
    reported = set(reported_members)
    scoped = {int(d.id): d for d in in_scope}
    chassis_id = related_id(getattr(device, "virtual_chassis", None))
    if chassis_id is not None:
        return _from_virtual_chassis(nb, device, chassis_id, reported, scoped, scope_label)

    parsed = split_stack_suffix(str(device.name))
    if parsed is not None and len(reported) > 1 and parsed[1] in reported and min(reported) > 0:
        return _from_names(nb, device, parsed, reported, scoped, scope_label)
    return Stack(connected=device, anchor=device, key=("device", int(device.id)))


def management_ip(device: Any) -> str | None:
    """The device's primary IP without its mask (``"10.0.0.5"``), else ``None``."""
    for field_name in ("primary_ip", "primary_ip4", "primary_ip6"):
        value = getattr(device, field_name, None)
        if isinstance(value, dict):
            value = value.get("address")
        elif value is not None and not isinstance(value, str):
            value = getattr(value, "address", None)
        if value:
            return str(value).split("/")[0]
    return None


def _from_virtual_chassis(
    nb: Any,
    device: Any,
    chassis_id: int,
    reported: set[int],
    scoped: dict[int, Any],
    scope_label: str,
) -> Stack:
    chassis = nb.dcim.virtual_chassis.get(chassis_id)
    label = str(getattr(chassis, "name", "") or chassis_id)
    members: dict[int, Any] = {}
    unresolved: dict[int, str] = {}
    for member in nb.dcim.devices.filter(virtual_chassis_id=chassis_id):
        position = _position(member)
        if position is None:
            continue
        if int(member.id) in scoped:
            members[position] = scoped[int(member.id)]
        else:
            unresolved[position] = (
                f"{member.name} (member {position} of Virtual Chassis {label!r}) "
                f"is outside this run's scope{_scope_suffix(scope_label)}"
            )
    for position in reported - members.keys() - unresolved.keys():
        unresolved[position] = f"Virtual Chassis {label!r} has no member at position {position}"

    master_id = related_id(getattr(chassis, "master", None))
    return Stack(
        connected=device,
        anchor=scoped.get(master_id, device) if master_id is not None else device,
        source="virtual-chassis",
        own_member=_position(device),
        members=members,
        unresolved={m: why for m, why in unresolved.items() if m in reported},
        key=("virtual-chassis", chassis_id),
    )


def _from_names(
    nb: Any,
    device: Any,
    parsed: tuple[str, int],
    reported: set[int],
    scoped: dict[int, Any],
    scope_label: str,
) -> Stack:
    base, own = parsed
    stack_name = normalize_hostname(base)
    siblings: dict[int, list[Any]] = defaultdict(list)
    for candidate in scoped.values():
        split = split_stack_suffix(str(candidate.name))
        if not split or int(candidate.id) == int(device.id):
            continue
        if normalize_hostname(split[0]) == stack_name:
            siblings[split[1]].append(candidate)

    members: dict[int, Any] = {own: device}
    unresolved: dict[int, str] = {}
    own_ip = management_ip(device)
    everywhere: list[Any] | None = None  # every NetBox device named like this stack, fetched once
    for member in sorted(reported - {own}):
        found = siblings.get(member, [])
        if len(found) > 1:
            names = ", ".join(sorted(str(d.name) for d in found))
            unresolved[member] = f"more than one NetBox device could be member {member}: {names}"
            continue
        if not found:
            if everywhere is None:
                everywhere = _named_like(nb, stack_name)
            unresolved[member] = _missing_member(everywhere, base, member, scoped, scope_label)
            continue
        other_ip = management_ip(found[0])
        if own_ip and other_ip and other_ip != own_ip:
            unresolved[member] = (
                f"{found[0].name} has its own management IP ({other_ip}), "
                "so it is a separate switch, not a member of this stack"
            )
            continue
        members[member] = found[0]

    return Stack(
        connected=device,
        anchor=device,
        source="name",
        own_member=own,
        members=members,
        unresolved=unresolved,
        key=("name", stack_name),
    )


def _named_like(nb: Any, stack_name: str) -> list[Any]:
    """Every NetBox device, in scope or not, whose name starts ``<stack_name>-``."""
    try:
        return list(nb.dcim.devices.filter(name__isw=f"{stack_name}-"))
    except Exception:  # pynetbox RequestError etc. This lookup only sharpens a reason.
        return []


def _missing_member(
    candidates: list[Any],
    base: str,
    member: int,
    scoped: dict[int, Any],
    scope_label: str,
) -> str:
    """Why member ``member`` has no in-scope device: out of scope, or absent from NetBox."""
    stack_name = normalize_hostname(base)
    for candidate in candidates:
        split = split_stack_suffix(str(candidate.name))
        if (
            split
            and normalize_hostname(split[0]) == stack_name
            and split[1] == member
            and int(candidate.id) not in scoped
        ):
            return f"{candidate.name} is outside this run's scope{_scope_suffix(scope_label)}"
    return f"NetBox has no device named {with_stack_suffix([base], member)[0]}"


def _position(device: Any) -> int | None:
    value = getattr(device, "vc_position", None) if device is not None else None
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _scope_suffix(scope_label: str) -> str:
    return f" ({scope_label})" if scope_label else ""
