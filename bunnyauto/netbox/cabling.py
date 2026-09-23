"""Plan and create a NetBox cable from what a device reports about its neighbor.

A neighbor protocol (LLDP, CDP) reports, for one local port, the neighbor's
identity and the neighbor's own port. Either can appear under several fields,
depending on how *that* neighbor advertises itself. :func:`plan_neighbor_cable`
turns that into a cable plan without writing anything:

1. **The neighbor device.** Its reported names are tried in turn against NetBox
   (:mod:`bunnyauto.netbox.hostnames`). If the port id carries a stack-member
   number, the ``<hostname>-<member>`` name is tried first: a virtual stack
   shares one chassis identity, but each member is its own NetBox device.
2. **The neighbor's port.** Its reported port names are tried against that
   device's actual interfaces (:mod:`bunnyauto.netbox.interfaces`).
3. **The local port.** The named port if the caller knows it, otherwise the
   local device's first wired interface.
4. **Existing cables.** An interface that already has a cable is **never
   touched**. It's reported as a conflict, because silently mis-correcting
   physical wiring is worse than a note.

This came out of ``wireless enrich`` (AP to switch, from
``show ap lldp neighbors``). A wired CDP/LLDP cable sync would call the same two
functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bunnyauto.netbox.hostnames import match_hostname_candidates, with_stack_suffix
from bunnyauto.netbox.interfaces import (
    match_interface,
    match_interface_candidates,
    pick_wired_record,
    stack_member,
)


@dataclass(slots=True)
class CablePlan:
    """What :func:`plan_neighbor_cable` decided. ``a`` = the local end, ``b`` = the neighbor."""

    action: str  # "create" | "conflict" | "blocked"
    a_interface_id: int = 0
    a_interface_name: str = ""
    b_device_name: str = ""
    b_interface_id: int = 0
    b_interface_name: str = ""
    note: str = ""


def plan_neighbor_cable(
    nb: Any,
    *,
    local_device: Any,
    neighbor_names: list[str],
    neighbor_ports: list[str],
    devices: list[Any],
    local_port: str | None = None,
    interface_cache: dict[int, list[Any]] | None = None,
) -> CablePlan:
    """Resolve one reported neighbor to a cable between two NetBox interfaces.

    ``devices`` is every NetBox device the neighbor could be; ``interface_cache``
    (device id -> interfaces) lets a caller reuse one lookup per neighbor
    across many local devices that land on the same switch.
    """
    cache = interface_cache if interface_cache is not None else {}

    member = next(
        (m for m in (stack_member(port) for port in neighbor_ports) if m is not None), None
    )
    names = with_stack_suffix(neighbor_names, member)

    neighbor = match_hostname_candidates(names, devices)
    if neighbor is None:
        return CablePlan(action="blocked", note=f"neighbor {names!r} matched no NetBox device")

    neighbor_interfaces = _interfaces(nb, cache, int(neighbor.id))
    b_name = match_interface_candidates(neighbor_ports, [str(i.name) for i in neighbor_interfaces])
    if b_name is None:
        return CablePlan(
            action="blocked",
            b_device_name=str(neighbor.name),
            note=f"neighbor port {neighbor_ports!r} matched no interface on NetBox device "
            f"{neighbor.name!r}",
        )
    b_iface = next(i for i in neighbor_interfaces if str(i.name) == b_name)

    local_interfaces = _interfaces(nb, cache, int(local_device.id))
    if local_port:
        a_name = match_interface(local_port, [str(i.name) for i in local_interfaces])
        a_iface = next((i for i in local_interfaces if str(i.name) == a_name), None)
        missing = f"{local_device.name!r} has no interface matching {local_port!r}"
    else:
        a_iface = pick_wired_record(local_interfaces)
        missing = f"{local_device.name!r} has no wired interface to cable"
    if a_iface is None:
        return CablePlan(
            action="blocked",
            b_device_name=str(neighbor.name),
            b_interface_id=int(b_iface.id),
            b_interface_name=str(b_iface.name),
            note=missing,
        )

    plan = CablePlan(
        action="create",
        a_interface_id=int(a_iface.id),
        a_interface_name=str(a_iface.name),
        b_device_name=str(neighbor.name),
        b_interface_id=int(b_iface.id),
        b_interface_name=str(b_iface.name),
    )
    if getattr(a_iface, "cable", None) or getattr(b_iface, "cable", None):
        plan.action = "conflict"
        plan.note = (
            f"{local_device.name}:{a_iface.name} or {neighbor.name}:{b_iface.name} "
            "already has a cable — left untouched"
        )
    return plan


def create_cable(nb: Any, plan: CablePlan) -> None:
    """Create the cable a ``"create"`` plan describes. Raises on a NetBox error."""
    nb.dcim.cables.create(
        {
            "a_terminations": [{"object_type": "dcim.interface", "object_id": plan.a_interface_id}],
            "b_terminations": [{"object_type": "dcim.interface", "object_id": plan.b_interface_id}],
            "status": "connected",
        }
    )


def _interfaces(nb: Any, cache: dict[int, list[Any]], device_id: int) -> list[Any]:
    if device_id not in cache:
        cache[device_id] = list(nb.dcim.interfaces.filter(device_id=device_id))
    return cache[device_id]
