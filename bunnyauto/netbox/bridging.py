"""A Linux-style device's uplinks in NetBox: ports → (bond) → bridge, where its IP lives.

An Aruba AP runs Linux and doesn't hold its IP on a physical port. Its ports
feed a software bridge, ``br0``, and the management IP lives on the bridge.
With both uplinks cabled, the AP first bonds them into ``bond0`` (active/standby,
or LACP when the switch speaks it), and ``bond0`` feeds ``br0``. NetBox models
exactly that:

* ``br0``: an interface of type ``bridge``. It holds the IP.
* ``bond0``: an interface of type ``lag``. The cabled ports are its members
  (their ``lag`` field), and its own ``bridge`` field points at ``br0``.
* With one port cabled there's no bond: that port's ``bridge`` field points at
  ``br0``.

NetBox won't cable a virtual interface, so cables stay on the physical ports
(:mod:`bunnyauto.netbox.cabling`).

Which ports are uplinks comes from the device itself (an AP's ``show ap lldp
neighbors`` ``Interface`` column): two or more ports with a neighbor means
``bond0``. :func:`plan_uplink_bridge` is pure and returns the writes in order;
:func:`apply_bridge_step` makes one. Nothing is ever removed or unlinked. A port
that stops reporting a neighbor keeps its link, and ``bond0`` stays once it
exists (a later run that sees one uplink keeps using it and says so).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from bunnyauto.netbox.interfaces import is_wired_type, match_interface
from bunnyauto.netbox.records import choice_value, related_id

BRIDGE_NAME = "br0"
BOND_NAME = "bond0"


@dataclass(frozen=True, slots=True)
class BridgeStep:
    """One write. ``text`` starts with a verb: ``"create interface 'br0' (bridge)"``."""

    text: str
    interface: str  # the interface created or changed
    create_type: str = ""  # set for a create: the new interface's type
    lag: str = ""  # set the interface's LAG to the interface with this name
    bridge: str = ""  # set the interface's bridge to the interface with this name
    clear_bridge: bool = False  # it joins a LAG, which is bridged instead


@dataclass(slots=True)
class BridgePlan:
    """What :func:`plan_uplink_bridge` decided for one device."""

    bridge: str  # the bridge's name: the IP goes here
    bond: str = ""  # the LAG the uplinks are in, if there is one
    uplinks: list[str] = field(default_factory=list)  # the reported uplinks' NetBox names
    steps: list[BridgeStep] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def plan_uplink_bridge(interfaces: list[Any], reported_ports: list[str]) -> BridgePlan:
    """The writes that give a device its bridge, and bond when needed. No I/O.

    ``interfaces`` are the device's NetBox interfaces. For a device that doesn't
    exist yet, pass a preview of its device type's template with ``id`` 0.
    ``reported_ports`` are the ports the device says have a neighbor (``eth0``,
    ``eth1``), matched to wired interfaces by :func:`match_interface`. One that
    matches nothing is skipped; the cable for it reports the mismatch. A device
    with no wired interface at all (a device type without an interface template)
    gets the reported ports created, so its cables have somewhere to land.
    """
    by_name = {str(i.name).casefold(): i for i in interfaces}
    bridge = by_name.get(BRIDGE_NAME)
    bond = by_name.get(BOND_NAME)
    plan = BridgePlan(bridge=str(bridge.name) if bridge is not None else BRIDGE_NAME)
    if bridge is None:
        plan.steps.append(
            BridgeStep(f"create interface {BRIDGE_NAME!r} (bridge)", BRIDGE_NAME, "bridge")
        )

    wired = [i for i in interfaces if is_wired_type(choice_value(getattr(i, "type", None)) or "")]
    if not wired:
        for reported in dict.fromkeys(p.strip() for p in reported_ports if p.strip()):
            plan.steps.append(BridgeStep(f"create interface {reported!r}", reported, "other"))
            wired.append(SimpleNamespace(id=0, name=reported, type="other", lag=None, bridge=None))
    wired_names = [str(i.name) for i in wired]
    uplinks: dict[str, Any] = {}
    for reported in reported_ports:
        name = match_interface(reported, wired_names)
        if name is not None:
            uplinks[name] = next(i for i in wired if str(i.name) == name)
    ports = [uplinks[name] for name in sorted(uplinks)]
    plan.uplinks = [str(p.name) for p in ports]
    if not ports:
        return plan

    bridge_id = _id(bridge)
    if len(ports) == 1 and bond is None:
        port = ports[0]
        if bridge_id is None or related_id(getattr(port, "bridge", None)) != bridge_id:
            plan.steps.append(
                BridgeStep(
                    f"link {port.name!r} to bridge {plan.bridge!r}",
                    str(port.name),
                    bridge=plan.bridge,
                )
            )
        return plan

    plan.bond = str(bond.name) if bond is not None else BOND_NAME
    if bond is None:
        plan.steps.append(
            BridgeStep(
                f"create interface {BOND_NAME!r} (LAG) in bridge {plan.bridge!r}",
                BOND_NAME,
                "lag",
                bridge=plan.bridge,
            )
        )
    elif bridge_id is None or related_id(getattr(bond, "bridge", None)) != bridge_id:
        plan.steps.append(
            BridgeStep(
                f"link {plan.bond!r} to bridge {plan.bridge!r}", plan.bond, bridge=plan.bridge
            )
        )
    bond_id = _id(bond)
    for port in ports:
        bridged = related_id(getattr(port, "bridge", None)) is not None
        if bond_id is None or related_id(getattr(port, "lag", None)) != bond_id or bridged:
            text = f"add {port.name!r} to LAG {plan.bond!r}"
            if bridged:
                text += " and clear its own bridge link"
            plan.steps.append(BridgeStep(text, str(port.name), lag=plan.bond, clear_bridge=bridged))
    if len(ports) == 1:
        plan.notes.append(
            f"only {ports[0].name!r} reported an LLDP neighbor; {plan.bond!r} is kept "
            "(nothing is removed)"
        )
    return plan


def apply_bridge_step(nb: Any, device: Any, step: BridgeStep, records: dict[str, Any]) -> None:
    """Make one :class:`BridgeStep` write. Raises on a NetBox error.

    ``records`` maps the device's interface names to their records. An interface
    this creates is added to it, so later steps can point at it.
    """
    body: dict[str, Any] = {}
    for field_name, target in (("lag", step.lag), ("bridge", step.bridge)):
        if target:
            if target not in records:
                raise LookupError(f"{target!r} doesn't exist on {device.name}")
            body[field_name] = int(records[target].id)
    if step.clear_bridge:
        body["bridge"] = None
    if step.create_type:
        records[step.interface] = nb.dcim.interfaces.create(
            {"device": int(device.id), "name": step.interface, "type": step.create_type, **body}
        )
    else:
        records[step.interface].update(body)


def _id(record: Any) -> int | None:
    """A record's id, or ``None`` for a missing record or a plan-mode preview (id 0)."""
    value = related_id(record)
    return value or None
