"""Tests for the create-interfaces tool (no real Nornir or NetBox)."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools import create_interfaces as ci
from bunnyauto.tools.create_interfaces import (
    TOOL,
    DiscoveredInterface,
    interface_type,
    normalize_name,
    parse_interfaces,
)

# ---------------------------------------------------------------------------
# naming / typing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("GigabitEthernet1/0/1", "gi1/0/1"),
        ("Gi1/0/1", "gi1/0/1"),
        ("Port-Channel10", "po10"),
        ("Loopback0", "lo0"),
    ],
)
def test_normalize_name(name, expected):
    assert normalize_name(name) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Port-channel1", "lag"),
        ("Po1", "lag"),
        ("Loopback0", "virtual"),
        ("Vlan10", "virtual"),
        ("Tunnel0", "virtual"),
        ("GigabitEthernet1/0/1", "1000base-t"),
        ("TenGigE1/1/1", "10gbase-x-sfpp"),
        ("Weird0", "other"),
    ],
)
def test_interface_type(name, expected):
    assert interface_type(name) == expected


# ---------------------------------------------------------------------------
# parse_interfaces
# ---------------------------------------------------------------------------


def test_parse_interfaces_basic():
    rows = [
        {"interface": "GigabitEthernet1/0/1", "description": "uplink", "link_status": "up"},
        {"interface": "GigabitEthernet1/0/2", "link_status": "administratively down"},
        {"interface": "Vlan10", "link_status": "up"},
        {"interface": "Port-channel1", "link_status": "up"},
    ]
    result = parse_interfaces(rows, include_virtual=False)
    names = [i.name for i in result]
    assert "Vlan10" not in names  # virtual excluded
    assert "Port-channel1" in names  # aggregates always kept
    by_name = {i.name: i for i in result}
    assert by_name["GigabitEthernet1/0/1"].description == "uplink"
    assert by_name["GigabitEthernet1/0/2"].enabled is False


def test_parse_interfaces_include_virtual():
    rows = [{"interface": "Vlan10", "link_status": "up"}]
    assert [i.name for i in parse_interfaces(rows, include_virtual=True)] == ["Vlan10"]


def test_parse_interfaces_rejects_unstructured():
    with pytest.raises(ToolError):
        parse_interfaces("not a list", include_virtual=False)


# ---------------------------------------------------------------------------
# the tool
# ---------------------------------------------------------------------------


class _Device:
    def __init__(self, id_: int, name: str):
        self.id = id_
        self.name = name


class _Iface:
    def __init__(self, name: str):
        self.name = name


class _Interfaces:
    def __init__(self, existing: dict[int, list[str]]):
        self._existing = existing
        self.created: list[dict] = []

    def filter(self, device_id=None):
        return [_Iface(n) for n in self._existing.get(device_id, [])]

    def create(self, payload):
        self.created.extend(payload)
        return payload


class _Devices:
    def __init__(self, devices):
        self._devices = devices

    def filter(self, tag=None):
        return list(self._devices)


class _NB:
    def __init__(self, devices, existing):
        self.dcim = argparse.Namespace(devices=_Devices(devices), interfaces=_Interfaces(existing))


class _Multi(list):
    def __init__(self, items, *, failed=False):
        super().__init__(items)
        self.failed = failed


class _Item:
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception


class _Selected:
    def __init__(self, hosts, run_result):
        self.inventory = argparse.Namespace(hosts=hosts)
        self._run_result = run_result

    def run(self, **kwargs):
        return self._run_result


@dataclass
class _Ctx:
    settings: Settings
    reporter: Reporter
    _nb: object = None

    def netbox(self):
        return self._nb

    def nornir(self):
        return object()


def _ctx(*, apply: bool = False) -> _Ctx:
    return _Ctx(
        settings=Settings(
            environment="test",
            nb_url="https://nb",
            config_file="config.yaml",
            target_tag="nornirtest",
            apply=apply,
        ),
        reporter=Reporter(json_mode=True),
    )


def _args(*, device=None, include_virtual=False) -> argparse.Namespace:
    return argparse.Namespace(device=device, include_virtual=include_virtual)


@pytest.fixture
def wired(monkeypatch):
    """Return a helper that wires up fake NetBox + inventory for the tool."""

    def _wire(*, existing, discovered, failed_hosts=()):
        device = _Device(1, "sw1")
        nb = _NB([device], existing)

        run_result = {}
        for name, ifaces in discovered.items():
            run_result[name] = _Multi(
                [_Item(result=[DiscoveredInterface(n) for n in ifaces])],
                failed=name in failed_hosts,
            )

        selected = _Selected({"sw1": object()}, run_result)
        monkeypatch.setattr(ci, "select_tagged_inventory", lambda nr, tagged: selected)
        monkeypatch.setattr(ci, "get_netbox_device", lambda nb_, host: device)
        return nb

    return _wire


def test_plan_reports_drift(wired):
    nb = wired(existing={1: ["Gi1/0/1"]}, discovered={"sw1": ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3"]})
    ctx = _ctx(apply=False)
    ctx._nb = nb

    result = TOOL.run(ctx, _args())

    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert any("would create" in c and "Gi1/0/2" in c for c in result.changes)
    assert nb.dcim.interfaces.created == []


def test_apply_creates(wired):
    nb = wired(existing={1: ["Gi1/0/1"]}, discovered={"sw1": ["Gi1/0/1", "Gi1/0/2"]})
    ctx = _ctx(apply=True)
    ctx._nb = nb

    result = TOOL.run(ctx, _args())

    assert result.status is Status.CHANGED
    assert result.exit_code == 20
    assert [c["name"] for c in nb.dcim.interfaces.created] == ["Gi1/0/2"]
    assert nb.dcim.interfaces.created[0]["type"] == "1000base-t"


def test_in_sync_is_ok(wired):
    nb = wired(existing={1: ["Gi1/0/1"]}, discovered={"sw1": ["Gi1/0/1"]})
    ctx = _ctx()
    ctx._nb = nb
    result = TOOL.run(ctx, _args())
    assert result.status is Status.OK
    assert result.changes == []


def test_collection_failure_is_error(wired):
    nb = wired(existing={1: []}, discovered={"sw1": []}, failed_hosts={"sw1"})
    ctx = _ctx()
    ctx._nb = nb
    result = TOOL.run(ctx, _args())
    assert result.status is Status.ERROR


def test_unknown_device_raises(monkeypatch):
    device = _Device(1, "sw1")
    nb = _NB([device], {})
    ctx = _ctx()
    ctx._nb = nb
    with pytest.raises(ToolError, match="was not found"):
        TOOL.run(ctx, _args(device="sw99"))
