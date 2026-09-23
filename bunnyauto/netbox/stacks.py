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
   never a member, whether it's in the run's scope or not.

Anything else is a standalone switch, or one NetBox device for a whole stack or
modular chassis, and every port stays on the connected device.

Member devices must be in the run's scope (env tag + role branch), the rule
every tool follows. A member number with no in-scope device is *unresolved*:
its ports get no owner, and the reason is kept for the report. They are never
handed to the connected device instead, which is a different physical switch.
The one case where the connected device's copy of such a port *is* the port is
when NetBox has no device of that member's own (:meth:`Stack.stand_in`). If the
member's device exists but can't be used (out of scope, or ambiguous: it's
:attr:`Stack.claimed`), a copy on the connected device is a leftover.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from bunnyauto.netbox.hostnames import normalize_hostname, split_stack_suffix, with_stack_suffix
from bunnyauto.netbox.interfaces import interface_type, stack_member
from bunnyauto.netbox.records import related_id

#: Stack-wide logical interfaces (Port-Channels; VLANs, loopbacks, tunnels):
#: one per stack, not per member.
_STACK_WIDE_TYPES = frozenset({"lag", "virtual"})


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
    #: The unresolved members whose own NetBox device exists but can't be used
    #: (outside the scope, or more than one candidate). Their ports live on that
    #: device, so the connected device never stands in for them.
    claimed: set[int] = field(default_factory=set)
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

    def member_number(self, device: Any) -> int | None:
        """The member number ``device`` holds in this stack, if it's one of :attr:`members`."""
        device_id = int(device.id)
        return next((m for m, d in self.members.items() if int(d.id) == device_id), None)

    def stand_in(self, interface_name: str) -> Any | None:
        """The connected device, if its interface of this name *is* this ownerless port.

        For a port whose member is unresolved (:meth:`owner` is ``None``). If
        NetBox has no device of that member's own, it models the stack or
        chassis as the connected device alone: a modular chassis's line cards
        read like members, and a same-named sibling with its own management IP
        is a separate switch. Then NetBox's interface of that name on the
        connected device is the port. ``None`` when it would be a different
        port: the member's own device exists (:attr:`claimed`), so a copy on the
        connected device is a leftover; or it's member 1's port seen through
        member 2 or later, whose device-type template gives it member-1 names
        for its *own* ports.
        """
        member = stack_member(interface_name) if self.source else None
        if member is None or member in self.members or member in self.claimed:
            return None
        if member == 1 and self.own_member not in (None, 1):
            return None
        return self.connected


def is_stack_wide(interface_name: str) -> bool:
    """True for a Port-Channel, VLAN, loopback or tunnel: one per stack, not per member.

    NetBox may keep it on any member's device, so finding it on one is finding it.
    """
    return interface_type(interface_name) in _STACK_WIDE_TYPES


def own_interfaces(nb: Any, device: Any) -> list[Any]:
    """``device``'s own NetBox interfaces.

    Older NetBox answered a Virtual Chassis master's ``device_id`` filter with
    every member's interfaces. Those are the members' ports, so they're dropped.
    """
    device_id = int(device.id)
    return [
        record
        for record in nb.dcim.interfaces.filter(device_id=device_id)
        if related_id(getattr(record, "device", None)) in (None, device_id)
    ]


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
    claimed: set[int] = set()
    for member in nb.dcim.devices.filter(virtual_chassis_id=chassis_id):
        position = _position(member)
        if position is None:
            continue
        if int(member.id) in scoped:
            members[position] = scoped[int(member.id)]
        else:
            claimed.add(position)
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
        claimed=claimed & reported,
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
        number = _member_of(candidate, stack_name)
        if number is not None and int(candidate.id) != int(device.id):
            siblings[number].append(candidate)

    members: dict[int, Any] = {own: device}
    unresolved: dict[int, str] = {}
    claimed: set[int] = set()
    own_ip = management_ip(device)
    everywhere: list[Any] | None = None  # every NetBox device named like this stack, fetched once
    for member in sorted(reported - {own}):
        found = siblings.get(member, [])
        if len(found) > 1:
            names = ", ".join(sorted(str(d.name) for d in found))
            unresolved[member] = f"more than one NetBox device could be member {member}: {names}"
            claimed.add(member)
            continue
        if found:
            separate = _separate_switch(found[0], own_ip)
            if separate:
                unresolved[member] = separate
            else:
                members[member] = found[0]
            continue

        if everywhere is None:
            everywhere = _named_like(nb, stack_name)
        outside = [
            candidate
            for candidate in everywhere
            if _member_of(candidate, stack_name) == member and int(candidate.id) not in scoped
        ]
        if not outside:
            name = with_stack_suffix([base], member)[0]
            unresolved[member] = f"NetBox has no device named {name}"
            continue
        # Out of scope, but still a separate switch if it has its own management IP.
        separate = [_separate_switch(candidate, own_ip) for candidate in outside]
        stack_like = [c for c, why in zip(outside, separate, strict=True) if why is None]
        if not stack_like:
            unresolved[member] = separate[0] or ""
            continue
        unresolved[member] = (
            f"{stack_like[0].name} is outside this run's scope{_scope_suffix(scope_label)}"
        )
        claimed.add(member)

    return Stack(
        connected=device,
        anchor=device,
        source="name",
        own_member=own,
        members=members,
        unresolved=unresolved,
        claimed=claimed,
        key=("name", stack_name),
    )


def _named_like(nb: Any, stack_name: str) -> list[Any]:
    """Every NetBox device, in scope or not, whose name starts ``<stack_name>-``."""
    try:
        return list(nb.dcim.devices.filter(name__isw=f"{stack_name}-"))
    except Exception:  # pynetbox RequestError etc. This lookup only sharpens a reason.
        return []


def _member_of(device: Any, stack_name: str) -> int | None:
    """The member number in ``device``'s name if it's ``<stack_name>-<member>``, else ``None``."""
    split = split_stack_suffix(str(device.name))
    if split is None or normalize_hostname(split[0]) != stack_name:
        return None
    return split[1]


def _separate_switch(candidate: Any, own_ip: str | None) -> str | None:
    """Why ``candidate`` is a separately managed switch, not a member; ``None`` if it isn't."""
    other_ip = management_ip(candidate)
    if own_ip and other_ip and other_ip != own_ip:
        return (
            f"{candidate.name} has its own management IP ({other_ip}), "
            "so it is a separate switch, not a member of this stack"
        )
    return None


def _position(device: Any) -> int | None:
    value = getattr(device, "vc_position", None) if device is not None else None
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _scope_suffix(scope_label: str) -> str:
    return f" ({scope_label})" if scope_label else ""
