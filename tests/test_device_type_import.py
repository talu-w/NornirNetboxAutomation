"""Tests for the import-device-type tool (fake pynetbox, no real NetBox/HTTP)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools.device_type_import import TOOL, load_device_type_yaml, slugify

# --- fake pynetbox ---------------------------------------------------


class _Rec(SimpleNamespace):
    def update(self, body):
        self.updated = body
        for key, value in body.items():
            setattr(self, key, value)
        return True


class _Endpoint:
    def __init__(self, items=()):
        self._items = list(items)
        self.created: list[dict] = []
        self._next_id = 1000

    def all(self):
        return list(self._items)

    def get(self, **kw):
        for item in self._items:
            if all(getattr(item, k, None) == v for k, v in kw.items()):
                return item
        return None

    def filter(self, **kw):
        return [
            item for item in self._items if all(getattr(item, k, None) == v for k, v in kw.items())
        ]

    def create(self, body):
        self.created.append(body)
        rec = _Rec(id=self._next_id, **body)
        self._next_id += 1
        self._items.append(rec)
        return rec


class _NB:
    def __init__(self, *, manufacturers=(), device_types=(), templates=None):
        self.dcim = SimpleNamespace(
            manufacturers=_Endpoint(manufacturers),
            device_types=_Endpoint(device_types),
        )
        templates = templates or {}
        for attr in (
            "console_port_templates",
            "console_server_port_templates",
            "power_port_templates",
            "power_outlet_templates",
            "rear_port_templates",
            "front_port_templates",
            "device_bay_templates",
            "module_bay_templates",
            "interface_templates",
        ):
            setattr(self.dcim, attr, _Endpoint(templates.get(attr, ())))


class _Ctx:
    def __init__(self, nb, *, apply=False):
        self.settings = SimpleNamespace(apply=apply)
        self.reporter = Reporter(json_mode=True)
        self._nb = nb

    def netbox(self):
        return self._nb


def _args(file: Path) -> argparse.Namespace:
    return argparse.Namespace(file=file)


AP_YAML = """\
manufacturer: HPE
model: Aruba AP-655
slug: hpe-aruba-ap-655
part_number: AP-655
u_height: 0
is_full_depth: false
weight: 1.8
weight_unit: kg
airflow: passive
comments: 'Aruba 650 Series'
interfaces:
- name: E0
  type: 5gbase-t
  poe_mode: pd
  poe_type: type4-ieee802.3bt
- name: E1
  type: 5gbase-t
console-ports:
- name: Serial Console
  type: usb-micro-b
power-ports:
- name: 12 Vdc
  type: dc-terminal
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "device-type.yaml"
    path.write_text(text)
    return path


# --- slugify / load ---------------------------------------------------


def test_slugify():
    assert slugify("HPE") == "hpe"
    assert slugify("Cisco Systems, Inc.") == "cisco-systems-inc"


def test_slugify_rejects_empty():
    with pytest.raises(ToolError):
        slugify("###")


def test_load_requires_top_level_mapping(tmp_path):
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ToolError, match="top-level mapping"):
        load_device_type_yaml(path)


def test_load_requires_manufacturer_model_slug(tmp_path):
    path = _write(tmp_path, "model: Foo\nslug: foo\n")
    with pytest.raises(ToolError, match="manufacturer"):
        load_device_type_yaml(path)


def test_load_rejects_non_list_category(tmp_path):
    path = _write(tmp_path, "manufacturer: HPE\nmodel: M\nslug: m\ninterfaces: not-a-list\n")
    with pytest.raises(ToolError, match="'interfaces' should be a list"):
        load_device_type_yaml(path)


def test_load_rejects_item_without_name(tmp_path):
    path = _write(
        tmp_path,
        "manufacturer: HPE\nmodel: M\nslug: m\ninterfaces:\n- type: other\n",
    )
    with pytest.raises(ToolError, match="missing a 'name'"):
        load_device_type_yaml(path)


def test_missing_file_is_friendly_error(tmp_path):
    with pytest.raises(ToolError, match="could not read"):
        load_device_type_yaml(tmp_path / "nope.yaml")


# --- planning ----------------------------------------------------------


def test_plan_new_device_type(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB()
    result = TOOL.run(_Ctx(nb), _args(path))
    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert any("would create manufacturer 'HPE'" in c for c in result.changes)
    assert any("would create device type 'Aruba AP-655'" in c for c in result.changes)
    assert any("interfaces: would create 'E0'" in c for c in result.changes)
    assert any("console-ports: would create 'Serial Console'" in c for c in result.changes)
    assert any("power-ports: would create '12 Vdc'" in c for c in result.changes)
    assert nb.dcim.device_types.created == []


def test_plan_existing_device_type_missing_templates_only(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB(
        manufacturers=[_Rec(id=1, name="HPE", slug="hpe")],
        device_types=[_Rec(id=50, model="Aruba AP-655", slug="hpe-aruba-ap-655")],
        templates={"interface_templates": [_Rec(id=1, name="E0", device_type_id=50)]},
    )
    result = TOOL.run(_Ctx(nb), _args(path))
    assert result.status is Status.DRIFT
    assert not any("manufacturer" in c for c in result.changes)
    assert not any("device type" in c for c in result.changes)
    assert not any("'E0'" in c for c in result.changes)  # already present
    assert any("interfaces: would create 'E1'" in c for c in result.changes)


def test_fully_in_sync_is_ok(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB(
        manufacturers=[_Rec(id=1, name="HPE", slug="hpe")],
        device_types=[_Rec(id=50, model="Aruba AP-655", slug="hpe-aruba-ap-655")],
        templates={
            "interface_templates": [
                _Rec(id=1, name="E0", device_type_id=50),
                _Rec(id=2, name="E1", device_type_id=50),
            ],
            "console_port_templates": [_Rec(id=3, name="Serial Console", device_type_id=50)],
            "power_port_templates": [_Rec(id=4, name="12 Vdc", device_type_id=50)],
        },
    )
    result = TOOL.run(_Ctx(nb), _args(path))
    assert result.status is Status.OK
    assert result.changes == []


# --- applying ------------------------------------------------------


def test_apply_creates_everything(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB()
    result = TOOL.run(_Ctx(nb, apply=True), _args(path))
    assert result.status is Status.CHANGED
    assert result.exit_code == 20

    (mfr_body,) = nb.dcim.manufacturers.created
    assert mfr_body == {"name": "HPE", "slug": "hpe"}

    (dt_body,) = nb.dcim.device_types.created
    assert dt_body["manufacturer"] == nb.dcim.manufacturers._items[0].id
    assert dt_body["model"] == "Aruba AP-655"
    assert dt_body["slug"] == "hpe-aruba-ap-655"
    assert dt_body["part_number"] == "AP-655"
    assert dt_body["u_height"] == 0
    assert dt_body["is_full_depth"] is False
    assert dt_body["weight"] == 1.8
    assert dt_body["weight_unit"] == "kg"
    assert dt_body["airflow"] == "passive"

    device_type_id = nb.dcim.device_types._items[0].id
    iface_names = {b["name"] for b in nb.dcim.interface_templates.created}
    assert iface_names == {"E0", "E1"}
    for body in nb.dcim.interface_templates.created:
        assert body["device_type"] == device_type_id

    (console,) = nb.dcim.console_port_templates.created
    assert console["name"] == "Serial Console"
    assert console["type"] == "usb-micro-b"

    (power,) = nb.dcim.power_port_templates.created
    assert power["name"] == "12 Vdc"


def test_apply_only_creates_missing_templates_on_existing_device_type(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB(
        manufacturers=[_Rec(id=1, name="HPE", slug="hpe")],
        device_types=[_Rec(id=50, model="Aruba AP-655", slug="hpe-aruba-ap-655")],
        templates={"interface_templates": [_Rec(id=1, name="E0", device_type_id=50)]},
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args(path))
    assert result.status is Status.CHANGED
    assert nb.dcim.manufacturers.created == []
    assert nb.dcim.device_types.created == []
    iface_names = {b["name"] for b in nb.dcim.interface_templates.created}
    assert iface_names == {"E1"}  # E0 already existed


# --- cross-referencing templates ------------------------------------


CROSSREF_YAML = """\
manufacturer: Acme
model: PDU
slug: acme-pdu
power-ports:
- name: PSU1
  type: iec-60320-c14
power-outlets:
- name: Outlet1
  type: iec-60320-c13
  power_port: PSU1
- name: Outlet2
  type: iec-60320-c13
  power_port: Nonexistent
rear-ports:
- name: Rear1
  type: 8p8c
front-ports:
- name: Front1
  type: 8p8c
  rear_port: Rear1
"""


def test_crossref_resolved_and_unknown_ref_blocked(tmp_path):
    path = _write(tmp_path, CROSSREF_YAML)
    nb = _NB()
    result = TOOL.run(_Ctx(nb, apply=True), _args(path))
    assert result.status is Status.PARTIAL

    (outlet,) = nb.dcim.power_outlet_templates.created
    assert outlet["name"] == "Outlet1"
    power_port_id = nb.dcim.power_port_templates._items[0].id
    assert outlet["power_port"] == power_port_id

    (front,) = nb.dcim.front_port_templates.created
    rear_port_id = nb.dcim.rear_port_templates._items[0].id
    assert front["rear_port"] == rear_port_id

    assert any("Outlet2" in b and "Nonexistent" in b for b in result.data["blocked"])


def test_crossref_blocked_in_plan_mode_too(tmp_path):
    path = _write(tmp_path, CROSSREF_YAML)
    nb = _NB()
    result = TOOL.run(_Ctx(nb), _args(path))
    assert result.status is Status.PARTIAL
    assert any("Outlet2" in b for b in result.data["blocked"])
    assert any("power-outlets: would create 'Outlet1'" in c for c in result.changes)


# --- failure handling -------------------------------------------------


def test_create_failure_is_partial(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB()

    def boom(body):
        raise RuntimeError("duplicate name")

    nb.dcim.console_port_templates.create = boom
    result = TOOL.run(_Ctx(nb, apply=True), _args(path))
    assert result.status is Status.PARTIAL
    assert nb.dcim.device_types.created  # device type still created
    assert any("console-ports:Serial Console" in f for f in result.data["failures"])


def test_manufacturer_create_failure_raises(tmp_path):
    path = _write(tmp_path, AP_YAML)
    nb = _NB()

    def boom(body):
        raise RuntimeError("nope")

    nb.dcim.manufacturers.create = boom
    with pytest.raises(ToolError, match="could not create manufacturer"):
        TOOL.run(_Ctx(nb, apply=True), _args(path))


# --- images note --------------------------------------------------------


def test_image_fields_produce_a_note_not_a_change(tmp_path):
    path = _write(tmp_path, AP_YAML + "front_image: true\n")
    nb = _NB()
    result = TOOL.run(_Ctx(nb), _args(path))
    assert not any("image" in c for c in result.changes)


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["import-device-type"] is TOOL
    assert TOOL.writes is True
    assert TOOL.needs_devices is False
