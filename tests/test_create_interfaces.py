"""Tests for the create-interfaces tool (no real Nornir or NetBox)."""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.scope import Scope
from bunnyauto.tools.wired import create_interfaces as ci
from bunnyauto.tools.wired.create_interfaces import (
    TOOL,
    DiscoveredInterface,
    parse_interfaces,
)

# Interface naming and typing are shared now — see tests/test_netbox_interfaces.py.

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
    def __init__(self, id_: int, name: str, *, ip=None, chassis=None, position=None):
        self.id = id_
        self.name = name
        self.primary_ip = {"address": ip} if ip else None
        self.virtual_chassis = {"id": chassis} if chassis else None
        self.vc_position = position


class _Iface:
    def __init__(self, name: str, device_id: int | None = None):
        self.name = name
        self.device = {"id": device_id} if device_id is not None else None


class _Interfaces:
    def __init__(self, existing: dict[int, list[str]]):
        self._existing = existing
        self.created: list[dict] = []

    def filter(self, device_id=None):
        return [_Iface(n, device_id) for n in self._existing.get(device_id, [])]

    def create(self, payload):
        self.created.extend(payload)
        return payload


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


class _NB:
    def __init__(self, devices, existing, *, everywhere=None, chassis=None):
        self.dcim = argparse.Namespace(
            devices=_Devices(devices, everywhere),
            interfaces=_Interfaces(existing),
            virtual_chassis=argparse.Namespace(get=lambda id_: (chassis or {}).get(id_)),
        )


class _Host:
    def __init__(self, name: str, device_id: int):
        self.name = name
        self.data = {"netbox_device_id": device_id}

    def get(self, key, default=None):
        return self.data.get(key, default)


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


def _args(*, device=None, include_virtual=False) -> argparse.Namespace:
    return argparse.Namespace(device=device, include_virtual=include_virtual)


@pytest.fixture
def wired(monkeypatch):
    """Return a helper that wires up fake NetBox + inventory for the tool.

    ``devices`` are the in-scope NetBox devices (default: one ``sw1``);
    ``everywhere`` adds devices NetBox has but the scope excludes. Each name in
    ``discovered`` is a Nornir host for the device of that name.
    """

    def _wire(
        *,
        existing,
        discovered,
        failed_hosts=(),
        devices=None,
        everywhere=None,
        chassis=None,
    ):
        devices = devices if devices is not None else [_Device(1, "sw1")]
        by_name = {d.name: d for d in [*devices, *(everywhere or [])]}
        nb = _NB(devices, existing, everywhere=everywhere, chassis=chassis)

        run_result = {}
        for name, ifaces in discovered.items():
            run_result[name] = _Multi(
                [_Item(result=[DiscoveredInterface(n) for n in ifaces])],
                failed=name in failed_hosts,
            )

        hosts = {name: _Host(name, by_name[name].id) for name in discovered}
        selected = _Selected(hosts, run_result)
        monkeypatch.setattr(ci, "select_tagged_inventory", lambda nr, tagged: selected)
        monkeypatch.setattr(ci, "get_netbox_device", lambda nb_, host: by_name[host.name])
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


# ---------------------------------------------------------------------------
# stacks: each member is its own NetBox device (<host>-<member>, or a Virtual Chassis)
# ---------------------------------------------------------------------------

A1 = "SwitchA-1.corp.example.com"
A2 = "SwitchA-2.corp.example.com"
A3 = "SwitchA-3.corp.example.com"
STACK_PORTS = [
    "GigabitEthernet1/0/1",
    "GigabitEthernet2/0/1",
    "GigabitEthernet3/0/1",
    "Port-channel1",
]


def _stack(*, members=3):
    """SwitchA's members: only member 1 holds the stack's management IP."""
    devices = [_Device(1, A1, ip="10.0.0.11/24"), _Device(2, A2), _Device(3, A3)]
    return devices[:members]


def _created(nb) -> set[tuple[int, str]]:
    return {(c["device"], c["name"]) for c in nb.dcim.interfaces.created}


def test_stack_member_ports_are_created_on_their_own_member(wired):
    nb = wired(existing={}, discovered={A1: STACK_PORTS}, devices=_stack())

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert result.status is Status.CHANGED
    assert _created(nb) == {
        (1, "GigabitEthernet1/0/1"),
        (1, "Port-channel1"),
        (2, "GigabitEthernet2/0/1"),
        (3, "GigabitEthernet3/0/1"),
    }


def test_plan_names_the_member_and_where_its_ports_were_seen(wired):
    nb = wired(existing={}, discovered={A1: STACK_PORTS}, devices=_stack())

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.DRIFT
    assert (
        f"{A2}: would create GigabitEthernet2/0/1 (1000base-t) [stack member 2, seen on {A1}]"
        in result.changes
    )
    assert f"{A1}: would create GigabitEthernet1/0/1 (1000base-t)" in result.changes
    assert result.data[A2]["via"] == A1
    assert result.data[A2]["stack_member"] == 2


def test_member_port_already_on_its_member_is_not_recreated(wired):
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1", "Port-channel1"], 2: ["Gi2/0/1"]},
        discovered={A1: STACK_PORTS},
        devices=_stack(),
    )

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert _created(nb) == {(3, "GigabitEthernet3/0/1")}
    assert result.data[A2]["existing"] == 1
    assert result.data[A2]["missing"] == []


def test_template_numbered_member_port_is_skipped_with_a_note(wired):
    # NetBox built SwitchA-2 from the device type's template: member-1 numbering.
    nb = wired(
        existing={2: ["GigabitEthernet1/0/1"]},
        discovered={A1: STACK_PORTS},
        devices=_stack(),
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert (2, "GigabitEthernet2/0/1") not in _created(nb)
    assert result.data[A2]["template_named"] == {"GigabitEthernet2/0/1": "GigabitEthernet1/0/1"}
    assert "GigabitEthernet2/0/1 is GigabitEthernet1/0/1" in notes.getvalue()


def test_copy_on_the_wrong_member_is_reported_and_never_deleted(wired):
    # An earlier run put member 2's port on member 1.
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        discovered={A1: STACK_PORTS},
        devices=_stack(),
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert (2, "GigabitEthernet2/0/1") in _created(nb)
    assert result.data[A1]["misplaced"] == {"GigabitEthernet2/0/1": A2}
    assert "nothing is deleted" in notes.getvalue()
    assert result.status is Status.CHANGED  # a note, not a failure


def test_template_names_on_other_members_are_not_misplaced_member_one_ports(wired):
    # Every member device carries the template's GigabitEthernet1/0/1.
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1"], 2: ["GigabitEthernet1/0/1"]},
        discovered={A1: STACK_PORTS},
        devices=_stack(),
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert all("misplaced" not in entry for entry in result.data.values())


def test_member_missing_from_netbox_is_skipped_not_put_on_the_connected_device(wired):
    nb = wired(existing={}, discovered={A1: STACK_PORTS}, devices=_stack(members=2))

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert not any(name == "GigabitEthernet3/0/1" for _, name in _created(nb))
    assert result.status is Status.PARTIAL
    assert result.exit_code == 2
    assert result.data[A1]["blocked"] == [
        {
            "member": 3,
            "reason": "NetBox has no device named SwitchA-3.corp.example.com",
            "ports": ["GigabitEthernet3/0/1"],
        }
    ]
    assert "1 stack port(s) skipped" in result.summary


def test_member_outside_the_scope_is_named_in_the_reason(wired):
    untagged = _Device(3, A3)
    nb = wired(
        existing={},
        discovered={A1: STACK_PORTS},
        devices=_stack(members=2),
        everywhere=[*_stack(members=2), untagged],
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    (blocked,) = result.data[A1]["blocked"]
    assert blocked["reason"].startswith(f"{A3} is outside this run's scope (tag 'nornirtest'")


def test_member_already_on_the_connected_device_is_not_blocked(wired):
    # Modular chassis: slot 2's ports read like member 2, and NetBox has them on core-1.
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        discovered={"core-1": ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        devices=[_Device(1, "core-1", ip="10.0.0.1/24")],
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.OK
    assert "blocked" not in result.data["core-1"]


def test_copy_on_the_connected_device_never_stands_in_for_an_out_of_scope_member(wired):
    # SwitchA-2 exists but is outside the scope, so SwitchA-1's GigabitEthernet2/0/1 is a
    # leftover copy, not member 2's port: the port is reported, not counted as present.
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        discovered={A1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        devices=_stack(members=1),
        everywhere=[*_stack(members=1), _Device(2, A2)],
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.PARTIAL
    (blocked,) = result.data[A1]["blocked"]
    assert (blocked["member"], blocked["ports"]) == (2, ["GigabitEthernet2/0/1"])
    assert blocked["reason"].startswith(f"{A2} is outside this run's scope")


def test_line_card_ports_stay_present_when_the_other_chassis_is_out_of_scope(wired):
    # core-2 is a separately managed chassis (its own IP), merely left out of the scope.
    core1 = _Device(1, "core-1", ip="10.0.0.1/24")
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        discovered={"core-1": ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        devices=[core1],
        everywhere=[core1, _Device(2, "core-2", ip="10.0.0.2/24")],
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.OK
    assert "blocked" not in result.data["core-1"]


def test_switch_with_its_own_management_ip_is_never_a_stack_member(wired):
    # core-1 and core-2 are a redundant pair of chassis, not one stack.
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1"]},
        discovered={"core-1": ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        devices=[_Device(1, "core-1", ip="10.0.0.1/24"), _Device(2, "core-2", ip="10.0.0.2/24")],
    )

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert nb.dcim.interfaces.created == []
    (blocked,) = result.data["core-1"]["blocked"]
    assert "core-2 has its own management IP (10.0.0.2)" in blocked["reason"]


def test_redundant_pair_named_like_a_stack_keeps_its_own_ports(wired):
    # dist-2 reports only member-1 ports: a standalone switch, whatever its name says.
    nb = wired(
        existing={},
        discovered={"dist-2": ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"]},
        devices=[_Device(1, "dist-1", ip="10.0.0.1/24"), _Device(2, "dist-2", ip="10.0.0.2/24")],
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert _created(nb) == {(2, "GigabitEthernet1/0/1"), (2, "GigabitEthernet1/0/2")}


def test_router_slot_numbering_is_not_read_as_a_stack(wired):
    # ISR slot 0 and slot 1: a Cisco stack never has a member 0.
    nb = wired(
        existing={},
        discovered={"rtr-1": ["GigabitEthernet0/0/0", "GigabitEthernet1/0/0"]},
        devices=[_Device(1, "rtr-1", ip="10.0.0.1/24"), _Device(2, "rtr-0")],
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert _created(nb) == {(1, "GigabitEthernet0/0/0"), (1, "GigabitEthernet1/0/0")}


def test_virtual_chassis_routes_ports_by_position(wired):
    top = _Device(10, "bldg-a-top", ip="10.0.0.5/24", chassis=7, position=1)
    bottom = _Device(11, "bldg-a-bottom", chassis=7, position=2)
    chassis = {7: argparse.Namespace(name="bldg-a", master={"id": 10})}
    nb = wired(
        existing={},
        discovered={"bldg-a-top": ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1", "Po1"]},
        devices=[top, bottom],
        chassis=chassis,
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert _created(nb) == {(10, "GigabitEthernet1/0/1"), (10, "Po1"), (11, "GigabitEthernet2/0/1")}


def test_port_channel_on_another_member_is_not_recreated(wired):
    nb = wired(
        existing={1: ["GigabitEthernet1/0/1"], 2: ["Port-channel1", "GigabitEthernet2/0/1"]},
        discovered={A1: STACK_PORTS[:2] + ["Port-channel1"]},
        devices=_stack(members=2),
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.OK
    assert result.data[A1]["on_other_member"] == {"Port-channel1": [A2]}


def test_unreachable_member_is_covered_by_its_stack(wired):
    # SwitchA-2 has no management IP of its own, so SSH to it fails; SwitchA-1 covers it.
    nb = wired(
        existing={},
        discovered={A1: STACK_PORTS, A2: []},
        failed_hosts={A2},
        devices=_stack(),
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(stream=notes, nb=nb), _args())

    assert result.status is Status.DRIFT
    assert "error" not in result.data[A2]
    assert f"checked through {A1}" in notes.getvalue()


def test_unreachable_member_of_an_unchecked_stack_still_fails(wired):
    nb = wired(existing={}, discovered={A2: []}, failed_hosts={A2}, devices=_stack())

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.ERROR
    assert result.data[A2]["ok"] is False


def test_stack_reached_through_two_members_is_checked_once(wired):
    nb = wired(existing={}, discovered={A1: STACK_PORTS, A2: STACK_PORTS}, devices=_stack())

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    names = [(c["device"], c["name"]) for c in nb.dcim.interfaces.created]
    assert len(names) == len(set(names)) == 4


def test_connected_member_two_does_not_lend_its_template_names_to_member_one(wired):
    # Reached through SwitchA-2 (its template gave it GigabitEthernet1/0/1 for its own
    # Gi2/0/1); member 1's device is out of scope, so member 1's port stays unplaced.
    a2 = _Device(2, A2, ip="10.0.0.11/24")
    nb = wired(
        existing={2: ["GigabitEthernet1/0/1"]},
        discovered={A2: ["GigabitEthernet1/0/1", "GigabitEthernet2/0/1"]},
        devices=[a2],
        everywhere=[a2, _Device(1, A1)],
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.data[A2]["template_named"] == {"GigabitEthernet2/0/1": "GigabitEthernet1/0/1"}
    (blocked,) = result.data[A2]["blocked"]
    assert blocked["member"] == 1
    assert blocked["ports"] == ["GigabitEthernet1/0/1"]
