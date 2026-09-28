"""Plan and write a NetBox cable from what a device reports about its neighbor.

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
3. **The local port.** The named port if the caller knows it (an AP's LLDP
   ``Interface``), otherwise the local device's first wired interface.
4. **What NetBox has now** (owner decision 2026-09-28: the reported data is
   trusted, so NetBox is corrected to match it; this replaced the 2026-09-22
   "never touch an existing cable" rule):

   * ``"in-sync"``: one cable already joins the two ports, directly or through
     patch panels (the local port's traced path ends at the neighbor's port).
   * ``"create"``: neither port has a cable.
   * ``"update"``: exactly one of them has a cable, straight to some other
     interface. That cable is **re-pointed**: its stale end is swapped for the
     free port, so the cable keeps its id, label and history. Nothing is ever
     deleted.
   * ``"conflict"``: both ports have *different* direct cables. Joining them
     would mean deleting one, so it's left for a person.
   * ``"untouched"``: a cable runs into a patch panel (front/rear port), a
     circuit or anything else that isn't an interface, or it has several
     terminations per end. NetBox's path there can't be corrected from one
     neighbor report, so it's only noted.

:func:`create_cable` / :func:`update_cable` write a plan; :func:`record_cable`
mirrors the result on in-memory interface records so later plans in the same
run see it.

This came out of the old ``wireless enrich`` (AP to switch, from
``show ap lldp neighbors``), now part of ``wireless sync``. A wired CDP/LLDP
cable sync would call the same functions.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from bunnyauto.netbox.hostnames import match_hostname_candidates, with_stack_suffix
from bunnyauto.netbox.interfaces import (
    match_interface,
    match_interface_candidates,
    pick_wired_record,
    stack_member,
)
from bunnyauto.netbox.records import related_id

_INTERFACE = "dcim.interface"


@dataclass(slots=True)
class CablePlan:
    """What :func:`plan_neighbor_cable` decided. ``a`` = the local end, ``b`` = the neighbor."""

    action: str  # "create" | "update" | "in-sync" | "conflict" | "untouched" | "blocked"
    a_interface_id: int = 0
    a_interface_name: str = ""
    b_device_name: str = ""
    b_interface_id: int = 0
    b_interface_name: str = ""
    note: str = ""
    #: ``"update"`` only: the cable being re-pointed, its end that's being
    #: replaced (``device:port``) and the replacement, and the new terminations.
    cable_id: int = 0
    replaced: str = ""
    replaced_id: int = 0
    replacement: str = ""
    terminations: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def plan_neighbor_cable(
    nb: Any,
    *,
    local_device: Any,
    neighbor_names: list[str],
    neighbor_ports: list[str],
    devices: list[Any],
    local_port: str | None = None,
    local_interfaces: list[Any] | None = None,
    interface_cache: dict[int, list[Any]] | None = None,
) -> CablePlan:
    """Resolve one reported neighbor to a cable between two NetBox interfaces.

    ``devices`` is every NetBox device the neighbor could be; ``interface_cache``
    (device id -> interfaces) lets a caller reuse one lookup per neighbor
    across many local devices that land on the same switch. ``local_interfaces``
    are the local device's interfaces when the caller already has them — or a
    preview of them, for a device that doesn't exist in NetBox yet (the plan is
    then for display only); otherwise they're fetched. An ``"update"`` plan
    reads the stale cable from NetBox.
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

    if local_interfaces is None:
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
    a_end = f"{local_device.name}:{a_iface.name}"
    b_end = f"{neighbor.name}:{b_iface.name}"
    a_cable = getattr(a_iface, "cable", None)
    b_cable = getattr(b_iface, "cable", None)

    if _same_cable(a_cable, b_cable) or _path_reaches(a_iface, b_iface):
        plan.action = "in-sync"
    elif not a_cable and not b_cable:
        pass  # "create"
    elif a_cable and b_cable:
        if _direct(a_iface) and _direct(b_iface):
            plan.action = "conflict"
            plan.note = (
                f"{a_end} and {b_end} are each cabled to something else in NetBox, but "
                f"{local_device.name} reports them connected to each other; joining them "
                "would delete a cable, so fix it in NetBox"
            )
        else:
            plan.action = "untouched"
            plan.note = (
                f"{a_end} and {b_end} are cabled through a patch panel or other object in "
                "NetBox whose path doesn't join them — left alone; check that path in NetBox"
            )
    else:
        holder, newcomer, newcomer_end = (
            (a_iface, b_iface, b_end) if a_cable else (b_iface, a_iface, a_end)
        )
        _plan_repoint(nb, plan, holder, newcomer, newcomer_end, a_cable or b_cable)
    return plan


def _plan_repoint(
    nb: Any, plan: CablePlan, holder: Any, newcomer: Any, newcomer_end: str, cable_ref: Any
) -> None:
    """Make ``plan`` re-point the cable on ``holder`` so its other end is ``newcomer``."""
    cable_id = related_id(cable_ref)
    cable = nb.dcim.cables.get(cable_id) if cable_id else None
    if cable is None:
        plan.action = "untouched"
        plan.note = f"cable #{cable_id} on {holder.name} couldn't be read from NetBox — left alone"
        return
    sides = {side: list(_field(cable, f"{side}_terminations") or []) for side in ("a", "b")}
    holder_side = next(
        (
            side
            for side, terms in sides.items()
            if len(terms) == 1 and _termination(terms[0]) == (_INTERFACE, int(holder.id))
        ),
        None,
    )
    other_side = {"a": "b", "b": "a"}.get(holder_side or "")
    stale = sides[other_side] if other_side else []
    if other_side is None or len(stale) != 1 or _termination(stale[0])[0] != _INTERFACE:
        plan.action = "untouched"
        plan.note = (
            f"cable #{cable_id} on {holder.name} runs into a patch panel or other object in "
            f"NetBox, not straight to an interface — left alone; check that path in NetBox"
        )
        return
    plan.action = "update"
    plan.cable_id = int(cable_id)
    plan.replaced = _termination_name(stale[0])
    plan.replaced_id = int(_termination(stale[0])[1])
    plan.replacement = newcomer_end
    plan.terminations = {
        f"{holder_side}_terminations": [{"object_type": _INTERFACE, "object_id": int(holder.id)}],
        f"{other_side}_terminations": [{"object_type": _INTERFACE, "object_id": int(newcomer.id)}],
    }


def create_cable(nb: Any, plan: CablePlan) -> Any:
    """Create the cable a ``"create"`` plan describes and return it. Raises on a NetBox error."""
    return nb.dcim.cables.create(
        {
            "a_terminations": [{"object_type": _INTERFACE, "object_id": plan.a_interface_id}],
            "b_terminations": [{"object_type": _INTERFACE, "object_id": plan.b_interface_id}],
            "status": "connected",
        }
    )


def update_cable(nb: Any, plan: CablePlan) -> None:
    """Re-point the cable an ``"update"`` plan describes. Raises on a NetBox error.

    Sent as a plain PATCH body (pynetbox's bulk ``update``), so both termination
    lists go to NetBox exactly as planned.
    """
    nb.dcim.cables.update([{"id": plan.cable_id, **plan.terminations}])


def record_cable(plan: CablePlan, cable_id: int, interface_lists: Iterable[list[Any]]) -> None:
    """Mirror a cable just written to NetBox on the in-memory interface records.

    Both ends of ``plan`` get the cable, and an ``"update"``'s replaced end loses
    it, so a later plan in the same run (another AP on a freed switch port)
    sees NetBox as it now is. Call it only after a real write, never in plan
    mode. Preview records (id 0) are never touched.
    """
    ref = SimpleNamespace(id=cable_id)
    ends = {plan.a_interface_id, plan.b_interface_id} - {0}
    for records in interface_lists:
        for iface in records:
            iface_id = related_id(iface)
            if not iface_id:
                continue
            if iface_id in ends:
                iface.cable, iface.link_peers_type = ref, _INTERFACE
            elif plan.replaced_id and iface_id == plan.replaced_id:
                iface.cable, iface.link_peers_type = None, None


def _same_cable(a_cable: Any, b_cable: Any) -> bool:
    a_id = related_id(a_cable)
    return bool(a_cable and b_cable) and a_id is not None and a_id == related_id(b_cable)


def _path_reaches(a_iface: Any, b_iface: Any) -> bool:
    """True if ``a_iface``'s traced cable path (through patch panels) ends at ``b_iface``."""
    if getattr(a_iface, "connected_endpoints_type", None) not in (None, _INTERFACE):
        return False
    endpoints = getattr(a_iface, "connected_endpoints", None) or []
    return any(related_id(e) == int(b_iface.id) for e in endpoints)


def _direct(iface: Any) -> bool:
    """True if the interface's cable runs straight to another interface."""
    return getattr(iface, "link_peers_type", None) in (None, _INTERFACE)


def _field(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _termination(term: Any) -> tuple[str, int]:
    """``(object_type, object_id)`` of a cable termination (a pynetbox object or a dict)."""
    return str(_field(term, "object_type") or ""), int(_field(term, "object_id") or 0)


def _termination_name(term: Any) -> str:
    obj = _field(term, "object")
    name, device = _field(obj, "name"), _field(_field(obj, "device"), "name")
    if name and device:
        return f"{device}:{name}"
    object_type, object_id = _termination(term)
    return f"{object_type} #{object_id}"


def _interfaces(nb: Any, cache: dict[int, list[Any]], device_id: int) -> list[Any]:
    if device_id not in cache:
        cache[device_id] = list(nb.dcim.interfaces.filter(device_id=device_id))
    return cache[device_id]
