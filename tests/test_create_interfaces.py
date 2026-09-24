"""Tests for the create-interfaces tool (no real Nornir or NetBox)."""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.netbox.transceivers import Transceiver
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.scope import Scope
from bunnyauto.tools.wired import create_interfaces as ci
from bunnyauto.tools.wired.create_interfaces import (
    TOOL,
    DiscoveredInterface,
    Discovery,
    parse_interfaces,
    parse_inventory,
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


def test_parse_interfaces_keeps_the_media_type():
    rows = [
        {"interface": "GigabitEthernet1/0/1", "media_type": "10/100/1000BaseTX"},
        {"interface": "Port-channel1", "media_type": ""},
    ]
    by_name = {i.name: i for i in parse_interfaces(rows, include_virtual=False)}
    assert by_name["GigabitEthernet1/0/1"].media_type == "10/100/1000BaseTX"
    assert by_name["Port-channel1"].media_type == ""


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
    def __init__(self, id_: int, name: str, device_id: int | None = None, type_=None):
        self.id = id_
        self.name = name
        self.device = {"id": device_id} if device_id is not None else None
        self.type = {"value": type_, "label": type_} if type_ else None


#: A slice of NetBox's interface type choices (OPTIONS /api/dcim/interfaces/).
NETBOX_TYPES = [
    "virtual",
    "lag",
    "100base-tx",
    "1000base-t",
    "1000base-tx",
    "2.5gbase-t",
    "5gbase-t",
    "10gbase-t",
    "1000base-x-sfp",
    "10gbase-x-sfpp",
    "10gbase-x-x2",
    "10gbase-sr",
    "25gbase-x-sfp28",
    "40gbase-x-qsfpp",
    "100gbase-x-qsfp28",
    "other",
]


class _Interfaces:
    """``existing`` maps a device id to its interfaces: a name, or ``(name, type)``."""

    def __init__(self, existing: dict[int, list], types=NETBOX_TYPES):
        self._existing = existing
        self._types = types
        self.created: list[dict] = []
        self.updated: list[dict] = []

    def filter(self, device_id=None):
        records = []
        for n, entry in enumerate(self._existing.get(device_id, [])):
            name, type_ = entry if isinstance(entry, tuple) else (entry, None)
            records.append(_Iface(device_id * 1000 + n, name, device_id, type_))
        return records

    def choices(self):
        if self._types is None:
            raise ValueError("Unexpected format in the OPTIONS response")
        return {"type": [{"value": t, "display_name": t.upper()} for t in self._types]}

    def create(self, payload):
        self.created.extend(payload)
        return [SimpleNamespace(id=9000 + n, **item) for n, item in enumerate(payload)]

    def update(self, payload):
        self.updated.extend(payload)
        return payload


class _InventoryItems:
    """``items``: inventory items as ``SimpleNamespace`` records (see :func:`_item`)."""

    def __init__(self, items=()):
        self.items = list(items)
        self.created: list[dict] = []
        self.queries: list[dict] = []

    def filter(self, device_id=None, serial=None):
        self.queries.append({"device_id": device_id, "serial": serial})
        if device_id is not None:
            return [i for i in self.items if i.device["id"] in device_id]
        wanted = {s.casefold() for s in serial}
        return [i for i in self.items if (i.serial or "").casefold() in wanted]

    def create(self, payload):
        self.created.extend(payload)
        return payload


def _item(id_, name, device_id, *, interface_id=None, serial="", part_id="", device_name="sw1"):
    return SimpleNamespace(
        id=id_,
        name=name,
        device={"id": device_id, "name": device_name},
        parent=None,
        component_type="dcim.interface" if interface_id else None,
        component_id=interface_id,
        serial=serial,
        part_id=part_id,
    )


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
    def __init__(
        self, devices, existing, *, everywhere=None, chassis=None, types=NETBOX_TYPES, items=()
    ):
        self.dcim = argparse.Namespace(
            devices=_Devices(devices, everywhere),
            interfaces=_Interfaces(existing, types),
            inventory_items=_InventoryItems(items),
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
    ``discovered`` is a Nornir host for the device of that name; its ports are
    names, or ``(name, media type)`` as ``show interfaces`` reports them.
    ``types`` is what NetBox's OPTIONS answer lists (``None``: it fails).
    ``optics`` maps a host to the transceivers its ``show inventory`` reports;
    ``items`` are NetBox's existing inventory items; ``inventory_errors`` maps a
    host to why its ``show inventory`` couldn't be read.
    """

    def _wire(
        *,
        existing,
        discovered,
        failed_hosts=(),
        devices=None,
        everywhere=None,
        chassis=None,
        types=NETBOX_TYPES,
        optics=None,
        items=(),
        inventory_errors=None,
    ):
        devices = devices if devices is not None else [_Device(1, "sw1")]
        by_name = {d.name: d for d in [*devices, *(everywhere or [])]}
        nb = _NB(
            devices, existing, everywhere=everywhere, chassis=chassis, types=types, items=items
        )

        run_result = {}
        for name, ifaces in discovered.items():
            ports = [
                DiscoveredInterface(i[0], media_type=i[1])
                if isinstance(i, tuple)
                else DiscoveredInterface(i)
                for i in ifaces
            ]
            found = Discovery(
                ports,
                list((optics or {}).get(name, [])),
                inventory_error=(inventory_errors or {}).get(name, ""),
            )
            run_result[name] = _Multi([_Item(result=found)], failed=name in failed_hosts)

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


def test_untagged_virtual_chassis_members_get_their_own_ports(wired):
    # Owner-reported: VC 'SwitchA-1' with only its master tagged nornirtest. Members
    # 2 and 3 were found, then refused as "outside this run's scope".
    chassis = {7: argparse.Namespace(name="SwitchA-1", master={"id": 1})}
    a1 = _Device(1, A1, ip="10.0.0.11/24", chassis=7, position=1)
    a2 = _Device(2, A2, chassis=7, position=2)
    a3 = _Device(3, A3, chassis=7, position=3)
    nb = wired(
        existing={2: ["GigabitEthernet1/0/2"]},  # member 2's template name for its Gi2/0/2
        discovered={A1: [*STACK_PORTS, "GigabitEthernet2/0/2"]},
        devices=[a1],
        everywhere=[a1, a2, a3],
        chassis=chassis,
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert result.status is Status.CHANGED
    assert _created(nb) == {
        (1, "GigabitEthernet1/0/1"),
        (1, "Port-channel1"),
        (2, "GigabitEthernet2/0/1"),
        (3, "GigabitEthernet3/0/1"),
    }
    assert result.data[A2]["template_named"] == {"GigabitEthernet2/0/2": "GigabitEthernet1/0/2"}
    assert f"including {A2}, {A3} as part of its Virtual Chassis" in notes.getvalue()


# ---------------------------------------------------------------------------
# interface types from the device's own media report
# ---------------------------------------------------------------------------

TX = "10/100/1000BaseTX"


def test_new_interface_gets_the_type_the_device_reports(wired):
    nb = wired(existing={1: []}, discovered={"sw1": [("Gi1/0/1", TX), ("Gi1/1/1", "Not Present")]})

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert result.status is Status.CHANGED
    types = {c["name"]: c["type"] for c in nb.dcim.interfaces.created}
    # the old name-only guess made both 1000base-t, though Gi1/1/1 is an SFP cage
    assert types == {"Gi1/0/1": "1000base-tx", "Gi1/1/1": "1000base-x-sfp"}


def test_existing_interface_with_the_wrong_type_is_corrected(wired):
    # Owner-reported: NetBox said 1000BASE-T (1GE), the switch says 10/100/1000BaseTX.
    nb = wired(
        existing={1: [("GigabitEthernet1/0/1", "1000base-t")]},
        discovered={"sw1": [("GigabitEthernet1/0/1", TX)]},
    )

    plan = TOOL.run(_ctx(nb=nb), _args())

    assert plan.status is Status.DRIFT
    assert plan.changes == [
        "sw1: would change GigabitEthernet1/0/1 from 1000base-t to 1000base-tx "
        "(device reports '10/100/1000BaseTX')"
    ]
    assert plan.data["sw1"]["retype"] == [
        {"name": "GigabitEthernet1/0/1", "from": "1000base-t", "to": "1000base-tx", "media": TX}
    ]
    assert "wrong type" in plan.summary
    assert nb.dcim.interfaces.updated == []

    applied = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert applied.status is Status.CHANGED
    assert nb.dcim.interfaces.updated == [{"id": 1000, "type": "1000base-tx"}]
    assert nb.dcim.interfaces.created == []
    assert applied.data["sw1"]["retyped"] == 1


def test_matching_type_is_left_alone(wired):
    nb = wired(
        existing={1: [("Gi1/0/1", "1000base-tx"), ("Te1/1/1", "10gbase-x-sfpp")]},
        discovered={"sw1": [("Gi1/0/1", TX), ("Te1/1/1", "SFP-10GBase-SR")]},
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.status is Status.OK
    assert result.changes == []


def test_cage_modelled_as_its_optic_or_x2_is_left_alone(wired):
    nb = wired(
        existing={1: [("Te1/1/1", "10gbase-sr"), ("Te1/1/2", "10gbase-x-x2")]},
        discovered={"sw1": [("Te1/1/1", "SFP-10GBase-SR"), ("Te1/1/2", "SFP-10GBase-LR")]},
    )

    assert TOOL.run(_ctx(nb=nb), _args()).status is Status.OK


def test_copper_type_on_a_transceiver_cage_is_corrected(wired):
    nb = wired(
        existing={1: [("Gi1/1/1", "1000base-t"), ("Te1/0/1", "10gbase-x-sfpp")]},
        discovered={
            "sw1": [
                ("Gi1/1/1", "1000BaseSX SFP"),
                ("Te1/0/1", "100/1000/2.5G/5G/10GBaseTX"),  # mGig copper, not SFP+
            ]
        },
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert nb.dcim.interfaces.updated == [
        {"id": 1000, "type": "1000base-x-sfp"},
        {"id": 1001, "type": "10gbase-t"},
    ]


def test_no_usable_media_type_never_changes_a_type(wired):
    nb = wired(
        existing={1: [("Gi1/0/1", "other"), ("Port-channel1", "lag")]},
        discovered={"sw1": [("Gi1/0/1", "unknown"), ("Port-channel1", "")]},
    )

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert result.status is Status.OK
    assert nb.dcim.interfaces.updated == []


def test_unmapped_media_type_is_noted_and_changes_nothing(wired):
    nb = wired(
        existing={1: [("Gi0/0/0", "1000base-t")]},
        discovered={"sw1": [("Gi0/0/0", "Auto Select"), ("Gi0/0/1", "Auto Select")]},
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert nb.dcim.interfaces.updated == []
    # the new port falls back to the name-only guess
    assert nb.dcim.interfaces.created[0]["type"] == "1000base-t"
    assert result.data["sw1"]["unmapped_media"] == {"Auto Select": ["Gi0/0/0", "Gi0/0/1"]}
    assert "media type 'Auto Select' on 2 port(s)" in notes.getvalue()


def test_type_this_netbox_lacks_falls_back_to_the_older_one(wired):
    nb = wired(
        existing={1: [("Gi1/0/1", "1000base-t")]},
        discovered={"sw1": [("Gi1/0/1", TX), ("Gi1/0/2", TX)]},
        types=[t for t in NETBOX_TYPES if t != "1000base-tx"],
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert nb.dcim.interfaces.updated == []
    assert nb.dcim.interfaces.created[0]["type"] == "1000base-t"


def test_unreadable_type_choices_warn_and_use_long_standing_types(wired):
    nb = wired(
        existing={1: [("Gi1/0/1", "1000base-t")]},
        discovered={"sw1": [("Gi1/0/1", TX), ("Gi1/1/1", "1000BaseSX SFP")]},
        types=None,
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert result.status is Status.CHANGED
    assert nb.dcim.interfaces.updated == []  # 1000base-t stays
    assert nb.dcim.interfaces.created[0]["type"] == "1000base-x-sfp"
    assert "could not read the interface types NetBox accepts" in notes.getvalue()


def test_type_update_failure_is_reported(wired):
    nb = wired(existing={1: [("Gi1/0/1", "1000base-t")]}, discovered={"sw1": [("Gi1/0/1", TX)]})

    def refuse(payload):
        raise RuntimeError("400 Bad Request")

    nb.dcim.interfaces.update = refuse

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert result.status is Status.ERROR
    assert result.data["sw1"]["error"] == "type update failed: 400 Bad Request"


def test_stack_members_template_named_port_gets_its_type_corrected(wired):
    # SwitchA-2's GigabitEthernet1/0/1 (template name) is the switch's Gi2/0/1.
    nb = wired(
        existing={
            1: [("GigabitEthernet1/0/1", "1000base-tx")],
            2: [("GigabitEthernet1/0/1", "1000base-t")],
        },
        discovered={A1: [("GigabitEthernet1/0/1", TX), ("GigabitEthernet2/0/1", TX)]},
        devices=_stack(members=2),
    )

    result = TOOL.run(_ctx(nb=nb), _args())

    assert result.changes == [
        f"{A2}: would change GigabitEthernet1/0/1 from 1000base-t to 1000base-tx "
        f"(device reports '10/100/1000BaseTX') [stack member 2, seen on {A1}]"
    ]


# ---------------------------------------------------------------------------
# transceivers: show inventory -> NetBox inventory items on their interfaces
# ---------------------------------------------------------------------------

SHOW_INVENTORY = """\
NAME: "c93xx Stack", DESCR: "c93xx Stack"
PID: C9300-48P         , VID: V02  , SN: FOC1234X0AB

NAME: "Switch 1", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FOC1234X0AB

NAME: "Switch 1 - FRU Uplink Module 1", DESCR: "8x10G Uplink Module"
PID: C9300-NM-8X       , VID: V01  , SN: FOC2222Y1CD

NAME: "TenGigabitEthernet1/1/1", DESCR: "SFP-10GBase-SR"
PID: SFP-10G-SR          , VID: V03  , SN: AVD1234ABCD

NAME: "GigabitEthernet1/1/2", DESCR: "1000BaseSX SFP"
PID: GLC-SX-MMD          , VID: V01  , SN: FNS1111AAAA

NAME: "subslot 0/0 transceiver 0", DESCR: "GE SX"
PID: GLC-SX-MMD          , VID: V01  , SN: FNS2222BBBB
"""


def test_parse_inventory_keeps_only_entries_named_after_a_port():
    from ntc_templates.parse import parse_output

    rows = parse_output(platform="cisco_ios", command="show inventory", data=SHOW_INVENTORY)
    ports = ["Te1/1/1", "GigabitEthernet1/1/2", "GigabitEthernet1/0/1"]

    optics, unplaced = parse_inventory(rows, ports)

    assert optics == [
        Transceiver(
            "TenGigabitEthernet1/1/1", "SFP-10GBase-SR", "SFP-10G-SR", "V03", "AVD1234ABCD"
        ),
        Transceiver("GigabitEthernet1/1/2", "1000BaseSX SFP", "GLC-SX-MMD", "V01", "FNS1111AAAA"),
    ]
    # chassis, switch and uplink module aren't ports; the ISR-style name is flagged
    assert unplaced == ["subslot 0/0 transceiver 0"]


def test_parse_inventory_of_unstructured_output_is_empty():
    assert parse_inventory("% Invalid input", ["Gi1/0/1"]) == ([], [])


SR = Transceiver("TenGigabitEthernet1/1/1", "SFP-10GBase-SR", "SFP-10G-SR", "V03", "AVD1234ABCD")


def test_optic_gets_an_inventory_item_on_its_interface(wired):
    nb = wired(
        existing={1: [("TenGigabitEthernet1/1/1", "10gbase-x-sfpp")]},
        discovered={"sw1": ["TenGigabitEthernet1/1/1"]},
        optics={"sw1": [SR]},
    )

    plan = TOOL.run(_ctx(nb=nb), _args())

    assert plan.status is Status.DRIFT
    assert plan.changes == [
        "sw1: would create inventory item for TenGigabitEthernet1/1/1: "
        "SFP-10G-SR (SFP-10GBase-SR, serial AVD1234ABCD)"
    ]
    assert "1 transceiver(s) not yet in NetBox" in plan.summary
    assert nb.dcim.inventory_items.created == []

    applied = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert applied.status is Status.CHANGED
    assert nb.dcim.inventory_items.created == [
        {
            "device": 1,
            "name": "TenGigabitEthernet1/1/1",
            "component_type": "dcim.interface",
            "component_id": 1000,
            "part_id": "SFP-10G-SR",
            "serial": "AVD1234ABCD",
            "description": "SFP-10GBase-SR",
            "discovered": True,
        }
    ]
    assert applied.data["sw1"]["transceivers_created"] == 1


def test_optic_already_recorded_on_its_interface_is_in_sync(wired):
    nb = wired(
        existing={1: [("TenGigabitEthernet1/1/1", "10gbase-x-sfpp")]},
        discovered={"sw1": ["TenGigabitEthernet1/1/1"]},
        optics={"sw1": [SR]},
        items=[_item(5, "Te1/1/1 optic", 1, interface_id=1000, serial="avd1234abcd")],
    )

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert result.status is Status.OK
    assert nb.dcim.inventory_items.created == []
    assert result.data["sw1"]["transceivers"][0]["action"] == "present"


def test_optic_recorded_on_another_device_is_reported_not_duplicated(wired):
    nb = wired(
        existing={1: ["TenGigabitEthernet1/1/1"]},
        discovered={"sw1": ["TenGigabitEthernet1/1/1"]},
        optics={"sw1": [SR]},
        items=[_item(5, "Te1/1/4", 7, interface_id=7004, serial="AVD1234ABCD", device_name="sw7")],
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert nb.dcim.inventory_items.created == []
    assert result.status is Status.OK  # a note for a person, not a failure
    assert "serial AVD1234ABCD is already in NetBox as 'Te1/1/4' on sw7" in notes.getvalue()
    assert result.data["sw1"]["transceivers"][0]["action"] == "skip"


def test_port_holding_a_different_optic_is_reported_not_replaced(wired):
    nb = wired(
        existing={1: ["TenGigabitEthernet1/1/1"]},
        discovered={"sw1": ["TenGigabitEthernet1/1/1"]},
        optics={"sw1": [SR]},
        items=[_item(5, "TenGigabitEthernet1/1/1", 1, interface_id=1000, serial="OLD999")],
    )
    notes = io.StringIO()

    TOOL.run(_ctx(apply=True, stream=notes, nb=nb), _args())

    assert nb.dcim.inventory_items.created == []
    assert "NetBox already has an optic (serial OLD999) on this port" in notes.getvalue()


def test_optic_in_a_port_created_this_run_is_attached_to_the_new_interface(wired):
    nb = wired(
        existing={1: []}, discovered={"sw1": ["TenGigabitEthernet1/1/1"]}, optics={"sw1": [SR]}
    )

    plan = TOOL.run(_ctx(nb=nb), _args())
    assert any("(with the new interface)" in c for c in plan.changes)

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    (item,) = nb.dcim.inventory_items.created
    assert item["component_id"] == 9000  # the id NetBox gave the interface just created


def test_optic_is_not_recorded_when_its_interface_could_not_be_created(wired):
    nb = wired(
        existing={1: []}, discovered={"sw1": ["TenGigabitEthernet1/1/1"]}, optics={"sw1": [SR]}
    )

    def refuse(payload):
        raise RuntimeError("400 Bad Request")

    nb.dcim.interfaces.create = refuse

    result = TOOL.run(_ctx(apply=True, nb=nb), _args())

    assert nb.dcim.inventory_items.created == []
    assert result.data["sw1"]["error"] == "create failed: 400 Bad Request"


def test_stack_members_optic_goes_on_the_member_device(wired):
    # SwitchA-2's template-named TenGigabitEthernet1/1/1 is the stack's Te2/1/1.
    optic = Transceiver("TenGigabitEthernet2/1/1", "SFP-10GBase-LR", "SFP-10G-LR", "V01", "LR1")
    nb = wired(
        existing={1: ["TenGigabitEthernet1/1/1"], 2: ["TenGigabitEthernet1/1/1"]},
        discovered={A1: ["TenGigabitEthernet1/1/1", "TenGigabitEthernet2/1/1"]},
        devices=_stack(members=2),
        optics={A1: [optic]},
    )

    TOOL.run(_ctx(apply=True, nb=nb), _args())

    (item,) = nb.dcim.inventory_items.created
    assert (item["device"], item["component_id"], item["name"]) == (
        2,
        2000,
        "TenGigabitEthernet1/1/1",
    )


def test_unreadable_inventory_still_checks_interfaces(wired):
    nb = wired(
        existing={1: []},
        discovered={"sw1": ["Gi1/0/1"]},
        inventory_errors={"sw1": "show inventory failed: timed out"},
    )
    notes = io.StringIO()

    result = TOOL.run(_ctx(stream=notes, nb=nb), _args())

    assert result.status is Status.DRIFT
    assert "transceivers not checked — show inventory failed: timed out" in notes.getvalue()


def test_no_optics_means_no_inventory_lookups(wired):
    nb = wired(existing={1: ["Gi1/0/1"]}, discovered={"sw1": ["Gi1/0/1"]})

    TOOL.run(_ctx(nb=nb), _args())

    assert nb.dcim.inventory_items.queries == []
