"""Tests for the shared bridge/bond planner: ports -> (bond0) -> br0 (no NetBox, no HTTP)."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

import pytest

from bunnyauto.netbox.bridging import BridgeStep, apply_bridge_step, plan_uplink_bridge


def _iface(id_, name, type_="1000base-t", *, lag=None, bridge=None):
    return SimpleNamespace(id=id_, name=name, type=type_, lag=lag, bridge=bridge)


def _ap(*, br0=False, bond0=False, bond_bridged=True, e0=None, e1=None):
    """An AP-515-style device: E0/E1 plus a radio, and optionally br0/bond0 already."""
    interfaces = [
        e0 or _iface(1, "E0", "2.5gbase-t"),
        e1 or _iface(2, "E1"),
        _iface(3, "5GHz WiFi", "ieee802.11ax"),
    ]
    if br0:
        interfaces.append(_iface(10, "br0", "bridge"))
    if bond0:
        interfaces.append(
            _iface(11, "bond0", "lag", bridge=SimpleNamespace(id=10) if bond_bridged else None)
        )
    return interfaces


def _texts(plan):
    return [step.text for step in plan.steps]


# --- planning ------------------------------------------------------------


def test_every_device_gets_a_bridge_even_without_lldp():
    plan = plan_uplink_bridge(_ap(), [])
    assert _texts(plan) == ["create interface 'br0' (bridge)"]
    assert (plan.bridge, plan.bond, plan.uplinks) == ("br0", "", [])


def test_one_uplink_is_linked_straight_to_the_bridge():
    plan = plan_uplink_bridge(_ap(), ["eth1"])
    assert _texts(plan) == ["create interface 'br0' (bridge)", "link 'E1' to bridge 'br0'"]
    assert plan.steps[1] == BridgeStep("link 'E1' to bridge 'br0'", "E1", bridge="br0")
    assert plan.uplinks == ["E1"]


def test_one_uplink_already_linked_is_in_sync():
    e1 = _iface(2, "E1", bridge=SimpleNamespace(id=10))
    assert plan_uplink_bridge(_ap(br0=True, e1=e1), ["eth1"]).steps == []


def test_two_uplinks_are_bonded_and_the_bond_is_bridged():
    plan = plan_uplink_bridge(_ap(), ["eth1", "eth0"])
    assert _texts(plan) == [
        "create interface 'br0' (bridge)",
        "create interface 'bond0' (LAG) in bridge 'br0'",
        "add 'E0' to LAG 'bond0'",
        "add 'E1' to LAG 'bond0'",
    ]
    assert plan.steps[1] == BridgeStep(
        "create interface 'bond0' (LAG) in bridge 'br0'", "bond0", "lag", bridge="br0"
    )
    assert (plan.bond, plan.uplinks) == ("bond0", ["E0", "E1"])


def test_a_fully_bonded_ap_is_in_sync():
    bond = SimpleNamespace(id=11)
    interfaces = _ap(
        br0=True, bond0=True, e0=_iface(1, "E0", lag=bond), e1=_iface(2, "E1", lag=bond)
    )
    assert plan_uplink_bridge(interfaces, ["eth0", "eth1"]).steps == []


def test_a_single_uplink_ap_gaining_a_second_moves_its_port_into_the_bond():
    """E0 was linked to br0 directly; now both ports are cabled, so E0 joins bond0
    and drops its own bridge link (bond0 carries it into br0)."""
    e0 = _iface(1, "E0", bridge=SimpleNamespace(id=10))
    plan = plan_uplink_bridge(_ap(br0=True, e0=e0), ["eth0", "eth1"])
    assert _texts(plan) == [
        "create interface 'bond0' (LAG) in bridge 'br0'",
        "add 'E0' to LAG 'bond0' and clear its own bridge link",
        "add 'E1' to LAG 'bond0'",
    ]
    assert plan.steps[1].clear_bridge is True


def test_an_existing_bond_is_kept_when_only_one_uplink_reports():
    bond = SimpleNamespace(id=11)
    interfaces = _ap(
        br0=True, bond0=True, e0=_iface(1, "E0", lag=bond), e1=_iface(2, "E1", lag=bond)
    )
    plan = plan_uplink_bridge(interfaces, ["eth0"])
    assert plan.steps == []
    assert plan.bond == "bond0"
    assert plan.notes == [
        "only 'E0' reported an LLDP neighbor; 'bond0' is kept (nothing is removed)"
    ]


def test_an_unbridged_existing_bond_is_linked():
    bond = SimpleNamespace(id=11)
    interfaces = _ap(
        br0=True,
        bond0=True,
        bond_bridged=False,
        e0=_iface(1, "E0", lag=bond),
        e1=_iface(2, "E1", lag=bond),
    )
    assert _texts(plan_uplink_bridge(interfaces, ["eth0", "eth1"])) == [
        "link 'bond0' to bridge 'br0'"
    ]


def test_a_reported_port_the_device_lacks_is_skipped():
    plan = plan_uplink_bridge(_ap(), ["eth7"])
    assert _texts(plan) == ["create interface 'br0' (bridge)"]
    assert plan.uplinks == []


def test_a_device_without_wired_ports_gets_the_reported_ports_created():
    """An un-templated device type: the AP's own port names are better than nowhere
    for its cables to land."""
    plan = plan_uplink_bridge([_iface(3, "5GHz WiFi", "ieee802.11ax")], ["eth1"])
    assert _texts(plan) == [
        "create interface 'br0' (bridge)",
        "create interface 'eth1'",
        "link 'eth1' to bridge 'br0'",
    ]
    assert plan.steps[1].create_type == "other"


def test_a_radio_is_never_an_uplink():
    plan = plan_uplink_bridge(_ap(), ["5GHz WiFi"])
    assert plan.uplinks == []


def test_an_existing_bridge_keeps_its_netbox_spelling():
    interfaces = [_iface(1, "E0"), _iface(10, "BR0", "bridge")]
    plan = plan_uplink_bridge(interfaces, ["eth0"])
    assert plan.bridge == "BR0"
    assert _texts(plan) == ["link 'E0' to bridge 'BR0'"]


def test_a_preview_bridge_still_needs_its_links():
    """A device type whose template already has br0: plan mode previews it with id 0,
    and the ports still have to be linked once NetBox creates it."""
    preview = [_iface(0, "E0"), _iface(0, "br0", "bridge")]
    assert _texts(plan_uplink_bridge(preview, ["eth0"])) == ["link 'E0' to bridge 'br0'"]


# --- applying --------------------------------------------------------------


class _Rec(SimpleNamespace):
    def update(self, body):
        self.__dict__.setdefault("updates", []).append(dict(body))
        return True


class _Interfaces:
    def __init__(self):
        self.created: list[dict] = []
        self._ids = itertools.count(500)

    def create(self, body):
        self.created.append(body)
        return _Rec(id=next(self._ids), **body)


def _nb():
    return SimpleNamespace(dcim=SimpleNamespace(interfaces=_Interfaces()))


def test_applying_a_plan_creates_and_links_in_order():
    nb = _nb()
    device = SimpleNamespace(id=100, name="hq-ap01")
    e0 = _Rec(id=1, name="E0", type="2.5gbase-t", lag=None, bridge=SimpleNamespace(id=10))
    e1 = _Rec(id=2, name="E1", type="1000base-t", lag=None, bridge=None)
    records = {"E0": e0, "E1": e1}
    plan = plan_uplink_bridge(list(records.values()), ["eth0", "eth1"])
    for step in plan.steps:
        apply_bridge_step(nb, device, step, records)

    br0_body, bond0_body = nb.dcim.interfaces.created
    assert br0_body == {"device": 100, "name": "br0", "type": "bridge"}
    assert bond0_body == {"device": 100, "name": "bond0", "type": "lag", "bridge": 500}
    assert e0.updates == [{"lag": 501, "bridge": None}]
    assert e1.updates == [{"lag": 501}]
    assert set(records) == {"E0", "E1", "br0", "bond0"}


def test_a_step_pointing_at_a_missing_interface_raises():
    step = BridgeStep("link 'E0' to bridge 'br0'", "E0", bridge="br0")
    with pytest.raises(LookupError, match="'br0' doesn't exist on hq-ap01"):
        apply_bridge_step(_nb(), SimpleNamespace(id=100, name="hq-ap01"), step, {"E0": _Rec(id=1)})
