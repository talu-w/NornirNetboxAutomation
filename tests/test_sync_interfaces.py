"""Tests for sync-interfaces: engine parsers, tool status wiring, stack routing."""

from __future__ import annotations

import argparse
import io
import re
from dataclasses import dataclass

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.netbox.stacks import Stack
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.scope import Scope
from bunnyauto.sync import engine
from bunnyauto.tools.wired import sync_interfaces
from bunnyauto.tools.wired.sync_interfaces import TOOL

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


_Summary = engine.SyncSummary


def _collected(name: str, device_id: int, *, ports=(), vlan_ports=()) -> engine.CollectedDevice:
    """What one host reports: ``ports`` as link state/description, ``vlan_ports`` as access."""
    return engine.CollectedDevice(
        inventory_name=name,
        netbox_device_id=device_id,
        interfaces=[engine.InterfaceVlanState(name=port, mode="access") for port in vlan_ports],
        interface_metadata=[
            engine.InterfaceMetadataState(
                name=port, enabled=True, description=f"seen {port}", device_status="connected"
            )
            for port in ports
        ],
    )


class _Host:
    def __init__(self, name: str, device_id: int):
        self.name = name
        self.data = {"netbox_device_id": device_id}

    def get(self, key, default=None):
        return self.data.get(key, default)


class _Selected:
    def __init__(self, hosts, results):
        self.inventory = argparse.Namespace(hosts=hosts)
        self._results = results

    def run(self, **kwargs):
        return self._results


class _Item:
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception


class _Multi(list):
    def __init__(self, items, *, failed=False):
        super().__init__(items)
        self.failed = failed


class _Device:
    def __init__(self, id_: int, name: str, *, ip=None, chassis=None, position=None):
        self.id = id_
        self.name = name
        self.primary_ip = {"address": ip} if ip else None
        self.virtual_chassis = {"id": chassis} if chassis else None
        self.vc_position = position


class _Iface:
    """A NetBox interface record: remembers every update it receives."""

    def __init__(self, id_: int, name: str, device_id: int):
        self.id = id_
        self.name = name
        self.device = {"id": device_id}
        self.enabled = False
        self.description = ""
        self.mode = None
        self.untagged_vlan = None
        self.tagged_vlans = []
        self.updates: list[dict] = []

    def update(self, payload):
        self.updates.append(payload)
        for key, value in payload.items():
            setattr(self, key, value)
        return True


class _Interfaces:
    def __init__(self, existing: dict[int, list[str]]):
        self.records = [
            _Iface(index, name, device_id)
            for index, (device_id, name) in enumerate(
                ((device_id, name) for device_id, names in existing.items() for name in names),
                start=1,
            )
        ]

    def filter(self, device_id=None):
        return [record for record in self.records if record.device["id"] == device_id]

    def get(self, id_):
        return next((record for record in self.records if record.id == id_), None)

    def on(self, device_id: int, name: str) -> _Iface:
        return next(r for r in self.records if r.device["id"] == device_id and r.name == name)


class _Devices:
    """``filter()`` with the scope's filters returns ``devices``; lookups search ``everywhere``."""

    def __init__(self, devices, everywhere=None):
        self._devices = devices
        self._everywhere = everywhere if everywhere is not None else devices

    def filter(self, **filters):
        self.last_filters = filters
        if "virtual_chassis_id" in filters:
            wanted = filters["virtual_chassis_id"]
            return [d for d in self._everywhere if (d.virtual_chassis or {}).get("id") == wanted]
        if "name__isw" in filters:
            prefix = filters["name__isw"].casefold()
            return [d for d in self._everywhere if d.name.casefold().startswith(prefix)]
        return list(self._devices)

    def get(self, id_):
        return next((d for d in self._everywhere if d.id == id_), None)


class _NB:
    def __init__(self, devices, existing=None, *, everywhere=None, chassis=None):
        self.dcim = argparse.Namespace(
            devices=_Devices(devices, everywhere),
            interfaces=_Interfaces(existing or {}),
            virtual_chassis=argparse.Namespace(get=lambda id_: (chassis or {}).get(id_)),
            locations=None,  # VLAN scope lookups: the fake devices have no site/location/rack
        )


@dataclass
class _Ctx:
    settings: Settings
    reporter: Reporter
    _nb: object = None

    def netbox(self):
        return self._nb

    def nornir(self):
        return object()

    def scope(self):
        return Scope(tag=self.settings.target_tag, role="wired-network", branch="wired-network")

    def target_devices(self):
        return list(self._nb.dcim.devices.filter(**self.scope().device_filters()))


def _ctx(*, apply: bool = False, stream: io.StringIO | None = None, nb=None) -> _Ctx:
    """A context; pass ``stream`` to capture the reporter's notes as plain text."""
    return _Ctx(
        settings=Settings(
            environment="test",
            nb_url="https://nb",
            config_file="config.yaml",
            target_tag="nornirtest",
            apply=apply,
        ),
        reporter=(
            Reporter(json_mode=True) if stream is None else Reporter(use_rich=False, stream=stream)
        ),
        _nb=nb,
    )


def _args() -> argparse.Namespace:
    return argparse.Namespace(voice_vlan_model="tagged", access_vlan_placement="clear")


@pytest.fixture
def wired(monkeypatch):
    """The tool with the engine's sync stubbed: each host returns the given summary."""

    def _wire(summaries):
        devices = {name: _Device(index, name) for index, name in enumerate(summaries, start=1)}
        results = {
            name: _Multi([_Item(result=_collected(name, devices[name].id))]) for name in summaries
        }
        hosts = {name: _Host(name, devices[name].id) for name in summaries}
        selected = _Selected(hosts, results)
        monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", lambda nr, d: selected)
        monkeypatch.setattr(engine, "build_vlan_cache", lambda nb: argparse.Namespace(by_vid={}))
        monkeypatch.setattr(engine, "load_vlan_prefixes", lambda nb, cache, ids: None)
        monkeypatch.setattr(
            engine,
            "build_interface_search_scope",
            lambda nb, collected, in_scope, *, scope_label="": argparse.Namespace(
                stack=Stack(
                    connected=devices[collected.inventory_name],
                    anchor=devices[collected.inventory_name],
                    key=("device", devices[collected.inventory_name].id),
                )
            ),
        )
        monkeypatch.setattr(
            engine,
            "sync_device",
            lambda *, nb, collected, scope, vlan_cache, dry_run: summaries[
                collected.inventory_name
            ],
        )
        return _NB(list(devices.values()))

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


# ---------------------------------------------------------------------------
# stacks: each member is its own NetBox device (<host>-<member>, or a Virtual Chassis)
# ---------------------------------------------------------------------------

A1 = "SwitchA-1.corp.example.com"
A2 = "SwitchA-2.corp.example.com"
A3 = "SwitchA-3.corp.example.com"
STACK_PORTS = ["Gi1/0/1", "Gi2/0/1", "Gi3/0/1", "Po1"]


def _stack(*, members=3):
    """SwitchA's members: only member 1 holds the stack's management IP."""
    devices = [_Device(1, A1, ip="10.0.0.11/24"), _Device(2, A2), _Device(3, A3)]
    return devices[:members]


def _targets(result) -> list[str]:
    """Each change line's ``<device>/<interface>`` plus any routing note, in order."""
    pattern = re.compile(r"(?:DRY-RUN|VERIFIED) (.+?)(?: metadata \(|: \{)")
    return [pattern.search(line).group(1) for line in result.changes]


@pytest.fixture
def stack_run(monkeypatch):
    """Run the tool with the real engine against a fake NetBox.

    ``devices`` are the in-scope NetBox devices; ``everywhere`` adds ones the
    scope excludes. ``existing`` maps a device id to its NetBox interface names.
    ``reported`` maps a host (the device of that name) to the ports it reports
    (link state + description); ``vlan_ports`` adds VLAN state for some of them.
    """

    def _run(
        *,
        devices,
        existing,
        reported,
        everywhere=None,
        chassis=None,
        failed_hosts=(),
        vlan_ports=None,
        apply=False,
        stream=None,
    ):
        nb = _NB(devices, existing, everywhere=everywhere, chassis=chassis)
        by_name = {d.name: d for d in [*devices, *(everywhere or [])]}
        results = {
            host: _Multi(
                [
                    _Item(
                        result=_collected(
                            host,
                            by_name[host].id,
                            ports=ports,
                            vlan_ports=(vlan_ports or {}).get(host, ()),
                        )
                    )
                ],
                failed=host in failed_hosts,
            )
            for host, ports in reported.items()
        }
        selected = _Selected({host: _Host(host, by_name[host].id) for host in reported}, results)
        monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", lambda nr, d: selected)
        monkeypatch.setattr(
            engine,
            "build_vlan_cache",
            lambda nb_: engine.VlanCache(by_vid={}, by_id={}, groups_by_id={}),
        )
        return TOOL.run(_ctx(apply=apply, stream=stream, nb=nb), _args()), nb

    return _run


def test_member_ports_are_synced_on_their_own_member(stack_run):
    result, _nb = stack_run(
        devices=_stack(),
        existing={1: ["Gi1/0/1", "Po1"], 2: ["Gi2/0/1"], 3: ["Gi3/0/1"]},
        reported={A1: STACK_PORTS},
        vlan_ports={A1: ["Gi2/0/1"]},
    )

    assert result.status is Status.DRIFT
    assert sorted(_targets(result)) == sorted(
        [
            f"{A1}/Gi1/0/1",
            f"{A1}/Po1",
            f"{A2}/Gi2/0/1 [stack member 2]",  # VLAN state
            f"{A2}/Gi2/0/1 [stack member 2]",  # link state + description
            f"{A3}/Gi3/0/1 [stack member 3]",
        ]
    )
    assert result.data[A1]["stack"] == {
        "source": "name",
        "members": {1: A1, 2: A2, 3: A3},
        "unresolved": {},
    }
    assert result.data[A1]["routed"] == 3
    assert "3 of them on another stack member's NetBox device" in result.summary


def test_member_port_is_updated_on_its_member_never_through_a_copy_on_the_connected_switch(
    stack_run,
):
    # An older create-interfaces run left member 2's port on SwitchA-1 as well.
    notes = io.StringIO()
    result, nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["Gi1/0/1", "GigabitEthernet2/0/1"], 2: ["GigabitEthernet2/0/1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1"]},
        apply=True,
        stream=notes,
    )

    member_port = nb.dcim.interfaces.on(2, "GigabitEthernet2/0/1")
    copy = nb.dcim.interfaces.on(1, "GigabitEthernet2/0/1")
    assert member_port.updates == [{"enabled": True, "description": "seen Gi2/0/1"}]
    assert copy.updates == []
    assert result.status is Status.CHANGED  # the copy is a note, not a failure
    assert result.data[A1]["misplaced"] == {f"{A1}/GigabitEthernet2/0/1": A2}
    assert "1 interface(s) sitting on the wrong stack member left as-is" in result.summary
    assert f"GigabitEthernet2/0/1 belongs on {A2}" in notes.getvalue()


def test_template_named_member_port_is_updated_under_its_template_name(stack_run):
    # SwitchA-2 came from the device type: its Gi2/0/1 is named GigabitEthernet1/0/1.
    result, _nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["GigabitEthernet1/0/1", "Gi2/0/1"], 2: ["GigabitEthernet1/0/1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1"]},
    )

    assert _targets(result) == [
        f"{A1}/GigabitEthernet1/0/1",
        f"{A2}/GigabitEthernet1/0/1 [stack member 2, reported as Gi2/0/1]",
    ]
    assert result.data[A1]["misplaced"] == {f"{A1}/Gi2/0/1": A2}


def test_member_port_missing_from_its_member_is_an_error_not_a_write_to_the_copy(stack_run):
    result, nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["Gi1/0/1", "Gi2/0/1"], 2: []},
        reported={A1: ["Gi1/0/1", "Gi2/0/1"]},
        apply=True,
    )

    assert nb.dcim.interfaces.on(1, "Gi2/0/1").updates == []
    assert "(1 device(s) failed)" in result.summary
    (error,) = result.data[A1]["errors"]
    assert error.startswith(f"Gi2/0/1: interface does not exist on NetBox device '{A2}'")
    assert "wired create-interfaces creates it" in error


def test_member_outside_the_scope_is_blocked_and_its_copy_is_never_written(stack_run):
    a2_untagged = _Device(2, A2)
    result, nb = stack_run(
        devices=_stack(members=1),
        everywhere=[*_stack(members=1), a2_untagged],
        existing={1: ["Gi1/0/1", "GigabitEthernet2/0/1"], 2: ["GigabitEthernet2/0/1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1"]},
        vlan_ports={A1: ["Gi2/0/1"]},
        apply=True,
    )

    assert nb.dcim.interfaces.on(1, "GigabitEthernet2/0/1").updates == []
    assert nb.dcim.interfaces.on(2, "GigabitEthernet2/0/1").updates == []
    assert result.status is Status.PARTIAL
    assert result.exit_code == 2
    (blocked,) = result.data[A1]["blocked"]
    assert blocked["member"] == 2
    assert blocked["ports"] == ["Gi2/0/1"]  # listed once, though both passes saw it
    assert blocked["reason"].startswith(f"{A2} is outside this run's scope (tag 'nornirtest'")
    assert "1 stack port(s) skipped" in result.summary


def test_stack_modeled_as_one_device_keeps_every_port(stack_run):
    # No core-2 anywhere: NetBox models the chassis (or stack) as core-1 alone.
    result, _nb = stack_run(
        devices=[_Device(1, "core-1", ip="10.0.0.1/24")],
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        reported={"core-1": ["Gi1/0/1", "Gi2/0/1"]},
    )

    assert result.status is Status.DRIFT
    assert _targets(result) == ["core-1/GigabitEthernet1/0/1", "core-1/GigabitEthernet2/0/1"]


@pytest.mark.parametrize("core2_in_scope", [True, False])
def test_separately_managed_chassis_never_takes_the_line_card_ports(stack_run, core2_in_scope):
    # core-1/core-2 are a redundant pair: slot 2 reads like stack member 2.
    core1 = _Device(1, "core-1", ip="10.0.0.1/24")
    core2 = _Device(2, "core-2", ip="10.0.0.2/24")
    result, nb = stack_run(
        devices=[core1, core2] if core2_in_scope else [core1],
        everywhere=[core1, core2],
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"], 2: ["GigabitEthernet2/0/1"]},
        reported={"core-1": ["Gi1/0/1", "Gi2/0/1"]},
        apply=True,
    )

    assert result.status is Status.CHANGED
    assert nb.dcim.interfaces.on(1, "GigabitEthernet2/0/1").updates
    assert nb.dcim.interfaces.on(2, "GigabitEthernet2/0/1").updates == []


def test_virtual_chassis_member_wins_over_a_copy_and_the_master_keeps_stack_wide_ports(
    stack_run,
):
    top = _Device(10, "bldg-a-top", ip="10.0.0.5/24", chassis=7, position=1)
    bottom = _Device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: argparse.Namespace(name="bldg-a", master={"id": 10})}
    result, _nb = stack_run(
        devices=[top, bottom],
        chassis=chassis,
        existing={10: ["Gi1/0/1", "Gi2/0/1", "Po1"], 11: ["Gi2/0/1"]},
        reported={"bldg-a-top": ["Gi1/0/1", "Gi2/0/1", "Po1"]},
    )

    assert _targets(result) == [
        "bldg-a-top/Gi1/0/1",
        "bldg-a-bottom/Gi2/0/1 [stack member 2]",
        "bldg-a-top/Po1",
    ]
    assert result.data["bldg-a-top"]["stack"]["source"] == "virtual-chassis"
    assert result.data["bldg-a-top"]["misplaced"] == {"bldg-a-top/Gi2/0/1": "bldg-a-bottom"}


def test_virtual_chassis_member_outside_the_scope_is_never_touched(stack_run):
    top = _Device(10, "bldg-a-top", ip="10.0.0.5/24", chassis=7, position=1)
    bottom = _Device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: argparse.Namespace(name="bldg-a", master={"id": 10})}
    result, nb = stack_run(
        devices=[top],
        everywhere=[top, bottom],
        chassis=chassis,
        existing={10: ["Gi1/0/1", "Gi2/0/1"], 11: ["Gi2/0/1"]},
        reported={"bldg-a-top": ["Gi1/0/1", "Gi2/0/1"]},
        apply=True,
    )

    assert nb.dcim.interfaces.on(11, "Gi2/0/1").updates == []
    assert nb.dcim.interfaces.on(10, "Gi2/0/1").updates == []
    (blocked,) = result.data["bldg-a-top"]["blocked"]
    assert blocked["reason"].startswith(
        "bldg-a-bottom (member 2 of Virtual Chassis 'bldg-a') is outside this run's scope"
    )


def test_port_channel_kept_on_another_member_is_synced_there(stack_run):
    result, _nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["Gi1/0/1"], 2: ["Gi2/0/1", "Port-channel1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1", "Po1"]},
    )

    assert f"{A2}/Port-channel1 [stack member 2]" in _targets(result)


def test_connected_member_two_never_writes_member_one_ports_onto_its_template_names(stack_run):
    # Reached through SwitchA-2, whose template calls its own Gi2/0/1 GigabitEthernet1/0/1.
    # Member 1's device is out of scope, so member 1's Gi1/0/1 must go nowhere.
    a2 = _Device(2, A2, ip="10.0.0.11/24")
    result, nb = stack_run(
        devices=[a2],
        everywhere=[a2, _Device(1, A1)],
        existing={2: ["GigabitEthernet1/0/1"]},
        reported={A2: ["Gi1/0/1", "Gi2/0/1"]},
        apply=True,
    )

    assert nb.dcim.interfaces.on(2, "GigabitEthernet1/0/1").updates == [
        {"enabled": True, "description": "seen Gi2/0/1"}
    ]
    assert _targets(result) == [f"{A2}/GigabitEthernet1/0/1 [reported as Gi2/0/1]"]
    (blocked,) = result.data[A2]["blocked"]
    assert (blocked["member"], blocked["ports"]) == (1, ["Gi1/0/1"])


def test_unreachable_member_is_covered_by_its_stack(stack_run):
    # SwitchA-2 has no management IP of its own, so SSH to it fails; SwitchA-1 covers it.
    notes = io.StringIO()
    result, _nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["Gi1/0/1"], 2: ["Gi2/0/1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1"], A2: []},
        failed_hosts={A2},
        stream=notes,
    )

    assert result.status is Status.DRIFT
    assert result.data[A2] == {"synced_through": A1}
    assert f"synced through {A1}" in notes.getvalue()


def test_unreachable_member_of_an_unsynced_stack_still_fails(stack_run):
    result, _nb = stack_run(
        devices=_stack(members=2),
        existing={2: ["Gi2/0/1"]},
        reported={A2: []},
        failed_hosts={A2},
    )

    assert result.status is Status.ERROR
    assert "error" in result.data[A2]


def test_stack_reached_through_two_members_is_synced_once(stack_run):
    ports = ["Gi1/0/1", "Gi2/0/1"]
    result, _nb = stack_run(
        devices=_stack(members=2),
        existing={1: ["Gi1/0/1"], 2: ["Gi2/0/1"]},
        reported={A1: ports, A2: ports},
    )

    assert len(result.changes) == 2
    assert result.data[A2] == {"same_stack_as": A1}
    assert "across 1 device(s)" in result.summary


def test_port_channel_on_two_other_members_is_an_error_not_a_guess(stack_run):
    result, nb = stack_run(
        devices=_stack(),
        existing={1: ["Gi1/0/1"], 2: ["Gi2/0/1", "Po1"], 3: ["Gi3/0/1", "Po1"]},
        reported={A1: ["Gi1/0/1", "Gi2/0/1", "Gi3/0/1", "Po1"]},
        apply=True,
    )

    assert nb.dcim.interfaces.on(2, "Po1").updates == []
    assert nb.dcim.interfaces.on(3, "Po1").updates == []
    (error,) = result.data[A1]["errors"]
    assert error == f"Po1: more than one stack member has this interface: {A2}/Po1, {A3}/Po1"
