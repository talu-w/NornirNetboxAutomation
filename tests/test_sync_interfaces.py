"""Tests for sync-interfaces: engine parsers + tool status wiring."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.sync import engine
from bunnyauto.tools import sync_interfaces
from bunnyauto.tools.sync_interfaces import TOOL

# ---------------------------------------------------------------------------
# engine parsers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("1,10,20-22", [1, 10, 20, 21, 22]),
        ("none", []),
        ("", []),
        ("30-28", [28, 29, 30]),
    ],
)
def test_expand_vlan_list(expr, expected):
    assert engine.expand_vlan_list(expr) == expected


def test_interface_signature_normalizes_long_and_short():
    assert engine.interface_signature("GigabitEthernet1/0/1") == engine.interface_signature(
        "Gi1/0/1"
    )


def test_parse_vlan_brief():
    output = (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "10   users                            active    Gi1/0/1, Gi1/0/2\n"
        "20   voice                            active    Gi1/0/3\n"
    )
    access = engine.parse_vlan_brief(output)
    assert access["Gi1/0/1"] == 10
    assert access["Gi1/0/3"] == 20


def test_parse_switchports_access_and_voice():
    output = (
        "Name: Gi1/0/1\n"
        "Administrative Mode: static access\n"
        "Operational Mode: static access\n"
        "Access Mode VLAN: 10 (users)\n"
        "Voice VLAN: 20\n"
    )
    ports = engine.parse_switchports(output)
    sp = ports["gi1/0/1"]
    assert sp.access_vlan == 10
    assert sp.voice_vlan == 20


def test_parse_svi_addresses():
    output = "Vlan20 is up, line protocol is up\n  Internet address is 10.20.0.1/24\n"
    assert engine.parse_svi_addresses(output) == ("10.20.0.1/24",)


# ---------------------------------------------------------------------------
# the tool
# ---------------------------------------------------------------------------


@dataclass
class _Summary:
    device: str
    dry_run: bool
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    changes: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


@dataclass
class _Collected:
    inventory_name: str
    vlan_svi_addresses: dict = field(default_factory=dict)


class _Selected:
    def __init__(self, hosts, collected):
        self.inventory = argparse.Namespace(hosts=hosts)
        self._collected = collected

    def run(self, **kwargs):
        return {name: _Multi([_Item(result=c)]) for name, c in self._collected.items()}


class _Item:
    def __init__(self, result):
        self.result = result


class _Multi(list):
    failed = False


class _Devices:
    def __init__(self, devices):
        self._devices = devices

    def filter(self, tag=None):
        return list(self._devices)


class _NB:
    def __init__(self, devices):
        self.dcim = argparse.Namespace(devices=_Devices(devices))


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


def _args() -> argparse.Namespace:
    return argparse.Namespace(voice_vlan_model="tagged", access_vlan_placement="clear")


@pytest.fixture
def wired(monkeypatch):
    def _wire(summaries):
        collected = {name: _Collected(name) for name in summaries}
        selected = _Selected({name: object() for name in summaries}, collected)
        monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", lambda nr, d: selected)
        monkeypatch.setattr(engine, "build_vlan_cache", lambda nb: argparse.Namespace(by_vid={}))
        monkeypatch.setattr(engine, "load_vlan_prefixes", lambda nb, cache, ids: None)
        monkeypatch.setattr(engine, "find_collected_result", lambda multi: multi[0].result)
        monkeypatch.setattr(
            engine,
            "sync_device",
            lambda *, nb, collected, vlan_cache, dry_run: summaries[collected.inventory_name],
        )
        return _NB([object()])

    return _wire


def test_no_devices(monkeypatch):
    monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", lambda nr, d: None)
    ctx = _ctx()
    ctx._nb = _NB([])
    result = TOOL.run(ctx, _args())
    assert result.status is Status.OK
    assert "nornirtest" in result.summary


def test_plan_reports_drift(wired):
    nb = wired(
        {
            "sw1": _Summary(
                "sw1", dry_run=True, updated=2, changes=["Gi1/0/1: vlan 10->20", "Gi1/0/2: enabled"]
            ),
            "sw2": _Summary("sw2", dry_run=True, updated=0, unchanged=48),
        }
    )
    ctx = _ctx(apply=False)
    ctx._nb = nb
    result = TOOL.run(ctx, _args())

    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert any("sw1: Gi1/0/1" in c for c in result.changes)


def test_apply_reports_changed(wired):
    nb = wired({"sw1": _Summary("sw1", dry_run=False, updated=3, changes=["a", "b", "c"])})
    ctx = _ctx(apply=True)
    ctx._nb = nb
    result = TOOL.run(ctx, _args())
    assert result.status is Status.CHANGED
    assert result.exit_code == 20


def test_in_sync_is_ok(wired):
    nb = wired({"sw1": _Summary("sw1", dry_run=True, updated=0, unchanged=50)})
    ctx = _ctx()
    ctx._nb = nb
    result = TOOL.run(ctx, _args())
    assert result.status is Status.OK


def test_device_error_is_partial(wired):
    nb = wired(
        {
            "sw1": _Summary("sw1", dry_run=True, updated=1, changes=["x"]),
            "sw2": _Summary("sw2", dry_run=True, errors=["VLAN 99 not in NetBox"]),
        }
    )
    ctx = _ctx()
    ctx._nb = nb
    result = TOOL.run(ctx, _args())
    assert result.status is Status.PARTIAL


def test_unmatched_inventory_raises(monkeypatch):
    selected = _Selected({}, {})
    monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", lambda nr, d: selected)
    ctx = _ctx()
    ctx._nb = _NB([object()])
    with pytest.raises(ToolError, match="matched the Nornir inventory"):
        TOOL.run(ctx, _args())
