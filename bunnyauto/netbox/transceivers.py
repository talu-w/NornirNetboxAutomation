"""Transceivers as NetBox inventory items, attached to the interface they sit in.

A device's ``show inventory`` names each optic after its port and gives its
description, part number and serial. Here that becomes one NetBox inventory item
per optic: named after the interface, assigned to it (``component``), with
``part_id``/``serial``/``description`` from the device and ``discovered`` set.

:func:`plan_inventory_item` decides, without I/O, whether one optic needs an
item: already there, to be created, or skipped with a reason. It only ever
*creates*. An optic NetBox already records elsewhere (same serial, on another
port or device), or a port NetBox already holds a different optic in, is
reported for a person to sort out, never moved or overwritten.
:func:`load_inventory_items` and :func:`inventory_item_payload` are the reads
and the write body.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from bunnyauto.netbox.records import related_id, related_name

#: ``component_type`` of an inventory item assigned to an interface.
INTERFACE_COMPONENT = "dcim.interface"


@dataclass(frozen=True, slots=True)
class Transceiver:
    """One optic from ``show inventory``: the port it's in and what it is."""

    port: str
    description: str = ""
    part_id: str = ""
    #: Cisco's VID, the part's hardware revision. Not stored in NetBox.
    version: str = ""
    serial: str = ""

    def label(self) -> str:
        """``"SFP-10G-SR (SFP-10GBase-SR, serial AVD1234ABCD)"``, for messages."""
        details = [d for d in (self.description, f"serial {self.serial or 'not reported'}") if d]
        return f"{self.part_id or 'transceiver'} ({', '.join(details)})"


@dataclass(frozen=True, slots=True)
class ItemPlan:
    """What to do about one optic's inventory item."""

    action: Literal["create", "present", "skip"]
    reason: str = ""


def load_inventory_items(nb: Any, device_ids: Iterable[int], serials: Iterable[str]) -> list[Any]:
    """Inventory items on ``device_ids``, plus any anywhere carrying one of ``serials``.

    Two queries, deduplicated by id: what's already on these devices (a port's
    current item, a taken name), and whether an optic is recorded somewhere else.
    """
    items: dict[int, Any] = {}
    ids = sorted(set(device_ids))
    wanted = sorted({s for s in serials if s})
    if ids:
        for item in nb.dcim.inventory_items.filter(device_id=ids):
            items[int(item.id)] = item
    if wanted:
        for item in nb.dcim.inventory_items.filter(serial=wanted):
            items[int(item.id)] = item
    return list(items.values())


def plan_inventory_item(
    optic: Transceiver,
    *,
    device_id: int,
    interface_id: int | None,
    name: str,
    items: Iterable[Any],
) -> ItemPlan:
    """Whether ``optic``, in interface ``interface_id`` of device ``device_id``, needs an item.

    ``interface_id`` is ``None`` for an interface this run is about to create.
    ``name`` is the item's name (the interface's). ``items`` comes from
    :func:`load_inventory_items`.

    * Its serial is already on an item attached to this interface: ``present``.
    * Its serial is on any other item, anywhere: ``skip`` (the optic moved, or
      NetBox has it wrong; never duplicated, never moved).
    * This interface already has an item with another optic: ``skip``. The optic
      was likely swapped. Without a serial, the same part number counts as ``present``.
    * The name is taken on the device by an item not on this port: ``skip``.
    * Otherwise ``create``.
    """
    records = list(items)
    serial = optic.serial.strip().casefold()
    for item in records:
        if serial and str(getattr(item, "serial", "") or "").strip().casefold() == serial:
            if related_id(item.device) == device_id and _attached_to(item, interface_id):
                return ItemPlan("present")
            return ItemPlan(
                "skip",
                f"serial {optic.serial} is already in NetBox as {str(item.name)!r} on "
                f"{related_name(item.device) or 'another device'} — move it in NetBox "
                "if the optic moved",
            )

    here = [i for i in records if related_id(i.device) == device_id]
    for item in here:
        if not _attached_to(item, interface_id):
            continue
        same_part = str(getattr(item, "part_id", "") or "").casefold() == optic.part_id.casefold()
        if not serial and same_part:
            return ItemPlan("present")
        return ItemPlan(
            "skip",
            f"NetBox already has {_describe(item)} on this port (inventory item "
            f"{str(item.name)!r}) — not replaced; was the optic swapped?",
        )

    for item in here:
        if related_id(getattr(item, "parent", None)) is None and str(item.name) == name:
            return ItemPlan(
                "skip", f"the device already has an inventory item named {name!r} on another port"
            )
    return ItemPlan("create")


def inventory_item_payload(
    optic: Transceiver, *, device_id: int, interface_id: int, name: str
) -> dict[str, Any]:
    """The NetBox create body for ``optic``'s inventory item, attached to its interface."""
    return {
        "device": device_id,
        "name": name,
        "component_type": INTERFACE_COMPONENT,
        "component_id": interface_id,
        "part_id": optic.part_id,
        "serial": optic.serial,
        "description": optic.description,
        "discovered": True,
    }


def _attached_to(item: Any, interface_id: int | None) -> bool:
    if interface_id is None:
        return False
    component_type = str(getattr(item, "component_type", "") or "")
    return component_type == INTERFACE_COMPONENT and related_id(
        getattr(item, "component_id", None)
    ) == int(interface_id)


def _describe(item: Any) -> str:
    part = str(getattr(item, "part_id", "") or "") or "an optic"
    serial = str(getattr(item, "serial", "") or "")
    return f"{part} (serial {serial})" if serial else part
