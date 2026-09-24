"""Tests for planning transceiver inventory items (pure — no NetBox, no HTTP)."""

from __future__ import annotations

from types import SimpleNamespace

from bunnyauto.netbox.transceivers import (
    Transceiver,
    inventory_item_payload,
    load_inventory_items,
    plan_inventory_item,
)

OPTIC = Transceiver("TenGigabitEthernet1/1/1", "SFP-10GBase-SR", "SFP-10G-SR", "V03", "AVD123")


def _item(id_=5, name="TenGigabitEthernet1/1/1", device_id=1, *, interface_id=None, **fields):
    return SimpleNamespace(
        id=id_,
        name=name,
        device={"id": device_id, "name": f"sw{device_id}"},
        parent=fields.pop("parent", None),
        component_type="dcim.interface" if interface_id else None,
        component_id=interface_id,
        serial=fields.pop("serial", ""),
        part_id=fields.pop("part_id", ""),
    )


def _plan(items, *, interface_id=100, name="TenGigabitEthernet1/1/1", optic=OPTIC):
    return plan_inventory_item(
        optic, device_id=1, interface_id=interface_id, name=name, items=items
    )


def test_nothing_in_netbox_is_a_create():
    assert _plan([]).action == "create"


def test_same_serial_on_this_interface_is_present():
    assert _plan([_item(interface_id=100, serial="avd123")]).action == "present"


def test_same_serial_anywhere_else_is_skipped():
    elsewhere = [
        _item(device_id=2, interface_id=200, serial="AVD123"),  # another device
        _item(name="Te1/1/2", interface_id=101, serial="AVD123"),  # another port
        _item(name="spare", serial="AVD123"),  # not on any port
    ]
    for item in elsewhere:
        plan = _plan([item])
        assert plan.action == "skip"
        assert "serial AVD123 is already in NetBox" in plan.reason


def test_a_different_optic_on_this_port_is_skipped():
    plan = _plan([_item(interface_id=100, serial="OTHER", part_id="SFP-10G-LR")])
    assert plan.action == "skip"
    assert "SFP-10G-LR (serial OTHER)" in plan.reason


def test_without_a_serial_the_same_part_on_this_port_is_present():
    optic = Transceiver("Te1/1/1", "SFP-10GBase-SR", "SFP-10G-SR")
    assert _plan([_item(interface_id=100, part_id="SFP-10G-SR")], optic=optic).action == "present"
    other = _item(interface_id=100, part_id="SFP-10G-LR")
    assert _plan([other], optic=optic).action == "skip"


def test_a_taken_name_is_skipped_but_a_child_item_of_that_name_is_not():
    assert _plan([_item(interface_id=999)]).action == "skip"
    assert _plan([_item(parent={"id": 3})]).action == "create"


def test_interface_created_this_run_checks_serial_and_name_only():
    assert _plan([], interface_id=None).action == "create"
    assert _plan([_item(serial="AVD123")], interface_id=None).action == "skip"


def test_payload_attaches_the_item_to_the_interface():
    assert inventory_item_payload(OPTIC, device_id=1, interface_id=100, name="Te1/1/1") == {
        "device": 1,
        "name": "Te1/1/1",
        "component_type": "dcim.interface",
        "component_id": 100,
        "part_id": "SFP-10G-SR",
        "serial": "AVD123",
        "description": "SFP-10GBase-SR",
        "discovered": True,
    }


def test_label():
    assert OPTIC.label() == "SFP-10G-SR (SFP-10GBase-SR, serial AVD123)"
    assert Transceiver("Gi1/1/1").label() == "transceiver (serial not reported)"


def test_load_inventory_items_queries_devices_and_serials_once_each():
    calls = []
    a, b = _item(id_=1), _item(id_=2, device_id=9, serial="X")

    def filter_(**kwargs):
        calls.append(kwargs)
        return [a] if "device_id" in kwargs else [a, b]

    nb = SimpleNamespace(dcim=SimpleNamespace(inventory_items=SimpleNamespace(filter=filter_)))

    items = load_inventory_items(nb, [2, 1, 1], ["X", "", "X"])

    assert calls == [{"device_id": [1, 2]}, {"serial": ["X"]}]
    assert [i.id for i in items] == [1, 2]  # deduplicated
