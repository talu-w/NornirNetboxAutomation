"""Tests for the import-device-type tool (fake pynetbox, no real NetBox/HTTP)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools.netbox.import_device_type import (
    TOOL,
    load_device_type_yaml,
    slugify,
    yaml_files,
)

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


def _args(path: Path) -> argparse.Namespace:
    return argparse.Namespace(path=path)


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


# --- a folder of files --------------------------------------------------

SWITCH_YAML = """\
manufacturer: HPE
model: Aruba 6300M
slug: hpe-aruba-6300m
interfaces:
- name: 1/1/1
  type: 1000base-t
"""

PDU_YAML = """\
manufacturer: Acme
model: PDU
slug: acme-pdu
power-ports:
- name: PSU1
  type: iec-60320-c14
"""


def _folder(tmp_path: Path, files: dict[str, str]) -> Path:
    folder = tmp_path / "types"
    folder.mkdir()
    for name, text in files.items():
        (folder / name).write_text(text)
    return folder


def _pdu_in_netbox() -> dict:
    return {
        "manufacturers": [_Rec(id=7, name="Acme", slug="acme")],
        "device_types": [_Rec(id=70, model="PDU", slug="acme-pdu")],
        "templates": {"power_port_templates": [_Rec(id=71, name="PSU1", device_type_id=70)]},
    }


def test_yaml_files_only_top_level_yaml_and_yml_by_name(tmp_path):
    folder = _folder(
        tmp_path,
        {
            "b.yml": PDU_YAML,
            "A.yaml": AP_YAML,
            "notes.txt": "x",
            "._A.yaml": "macOS junk",
        },
    )
    (folder / "sub").mkdir()
    (folder / "sub" / "c.yaml").write_text(SWITCH_YAML)
    assert [p.name for p in yaml_files(folder)] == ["A.yaml", "b.yml"]


def test_empty_folder_is_friendly_error(tmp_path):
    folder = _folder(tmp_path, {"readme.txt": "nothing here"})
    with pytest.raises(ToolError, match="has no .yaml or .yml files"):
        TOOL.run(_Ctx(_NB()), _args(folder))


def test_folder_plan_checks_each_file(tmp_path):
    folder = _folder(
        tmp_path,
        {"ap-655.yaml": AP_YAML, "6300m.yaml": SWITCH_YAML, "pdu.yaml": PDU_YAML},
    )
    nb = _NB(**_pdu_in_netbox())
    result = TOOL.run(_Ctx(nb), _args(folder))

    assert result.status is Status.DRIFT
    files = result.data["files"]
    assert files["pdu.yaml"]["status"] == "ok"
    assert files["ap-655.yaml"]["status"] == "drift"
    assert files["6300m.yaml"]["status"] == "drift"
    assert "1 already in NetBox" in result.summary
    assert "2 to create" in result.summary
    assert "run with --apply" in result.summary
    # Both HPE files need the manufacturer; the plan lists it once.
    assert sum("would create manufacturer 'HPE'" in c for c in result.changes) == 1
    assert "ap-655.yaml: interfaces: would create 'E0'" in result.changes
    assert "6300m.yaml: interfaces: would create '1/1/1'" in result.changes
    assert nb.dcim.manufacturers.created == []
    assert nb.dcim.device_types.created == []


def test_folder_all_in_netbox_is_ok(tmp_path):
    folder = _folder(tmp_path, {"pdu.yaml": PDU_YAML})
    result = TOOL.run(_Ctx(_NB(**_pdu_in_netbox())), _args(folder))
    assert result.status is Status.OK
    assert result.changes == []
    assert "1 already in NetBox" in result.summary


def test_folder_apply_creates_each_file_and_the_manufacturer_once(tmp_path):
    folder = _folder(tmp_path, {"ap-655.yaml": AP_YAML, "6300m.yaml": SWITCH_YAML})
    nb = _NB()
    result = TOOL.run(_Ctx(nb, apply=True), _args(folder))

    assert result.status is Status.CHANGED
    assert nb.dcim.manufacturers.created == [{"name": "HPE", "slug": "hpe"}]
    assert {b["slug"] for b in nb.dcim.device_types.created} == {
        "hpe-aruba-ap-655",
        "hpe-aruba-6300m",
    }
    assert "2 created" in result.summary


def test_folder_bad_file_is_reported_and_the_rest_still_run(tmp_path):
    folder = _folder(tmp_path, {"ap-655.yaml": AP_YAML, "broken.yaml": "model: Foo\nslug: foo\n"})
    nb = _NB()
    result = TOOL.run(_Ctx(nb, apply=True), _args(folder))

    assert result.status is Status.PARTIAL
    assert result.exit_code == 2
    assert result.data["files"]["broken.yaml"]["status"] == "error"
    assert result.data["files"]["broken.yaml"]["reason"] == (
        "broken.yaml is missing required field 'manufacturer'"
    )
    assert result.data["files"]["ap-655.yaml"]["status"] == "changed"
    assert "1 failed" in result.summary


def test_folder_every_file_failing_is_error(tmp_path):
    folder = _folder(tmp_path, {"a.yaml": "- a list\n", "b.yaml": "model: Foo\n"})
    result = TOOL.run(_Ctx(_NB()), _args(folder))
    assert result.status is Status.ERROR
    assert "2 failed" in result.summary


def test_folder_create_failure_fails_that_file_only(tmp_path):
    folder = _folder(tmp_path, {"ap-655.yaml": AP_YAML, "pdu.yaml": PDU_YAML})
    nb = _NB()
    real_create = nb.dcim.manufacturers.create

    def refuse_hpe(body):
        if body["slug"] == "hpe":
            raise RuntimeError("nope")
        return real_create(body)

    nb.dcim.manufacturers.create = refuse_hpe
    result = TOOL.run(_Ctx(nb, apply=True), _args(folder))

    assert result.status is Status.PARTIAL
    assert result.data["files"]["ap-655.yaml"]["reason"].startswith(
        "ap-655.yaml: could not create manufacturer 'HPE'"
    )
    assert result.data["files"]["pdu.yaml"]["status"] == "changed"
    assert [b["slug"] for b in nb.dcim.device_types.created] == ["acme-pdu"]


def test_folder_duplicate_slug_is_skipped_not_merged(tmp_path):
    folder = _folder(
        tmp_path,
        {"ap-655 (1).yaml": AP_YAML.replace("E1", "E9"), "ap-655.yaml": AP_YAML},
    )
    nb = _NB()
    result = TOOL.run(_Ctx(nb, apply=True), _args(folder))

    assert result.status is Status.CHANGED  # a duplicate is a warning, not a failure
    skipped = result.data["files"]["ap-655.yaml"]
    assert skipped["status"] == "skipped"
    assert "ap-655 (1).yaml" in skipped["reason"]
    assert len(nb.dcim.device_types.created) == 1
    assert {b["name"] for b in nb.dcim.interface_templates.created} == {"E0", "E9"}
    assert "1 skipped (duplicate slug)" in result.summary


def test_path_argument_expands_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    parser = argparse.ArgumentParser()
    TOOL.add_arguments(parser)
    assert parser.parse_args(["~/ndx"]).path == tmp_path / "ndx"


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["netbox"]["import-device-type"] is TOOL
    assert TOOL.writes is True
    assert TOOL.needs_devices is False
