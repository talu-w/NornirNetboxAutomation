"""Tests for the pure IPAM helpers: prefix matching and IP planning (no NetBox, no HTTP)."""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

from bunnyauto.netbox.ipam import Prefix, find_prefix, plan_primary_ip


def _prefix(id_, cidr, vrf_id=None):
    return Prefix(id=id_, network=ipaddress.ip_network(cidr), vrf_id=vrf_id)


PREFIXES = [_prefix(1, "10.0.0.0/8"), _prefix(2, "10.1.1.0/24")]


def test_finds_containing_prefix():
    addr = ipaddress.ip_address("10.1.1.1")
    assert find_prefix(addr, PREFIXES).id == 2


def test_narrowest_prefix_wins_over_broader_containing_prefix():
    addr = ipaddress.ip_address("10.1.1.200")
    match = find_prefix(addr, PREFIXES)
    assert match.id == 2  # /24, not the /8


def test_falls_back_to_broader_prefix_outside_the_narrow_one():
    addr = ipaddress.ip_address("10.2.0.1")  # inside /8 but outside /24
    assert find_prefix(addr, PREFIXES).id == 1


def test_no_containing_prefix_returns_none():
    addr = ipaddress.ip_address("192.168.1.1")
    assert find_prefix(addr, PREFIXES) is None


def test_ambiguous_equal_length_prefixes_return_none():
    addr = ipaddress.ip_address("10.1.1.1")
    prefixes = [_prefix(1, "10.1.1.0/24"), _prefix(2, "10.1.1.0/24")]
    assert find_prefix(addr, prefixes) is None


def test_vrf_id_is_carried_through():
    addr = ipaddress.ip_address("10.1.1.1")
    prefixes = [_prefix(1, "10.1.1.0/24", vrf_id=9)]
    assert find_prefix(addr, prefixes).vrf_id == 9


def test_ipv6_containment():
    addr = ipaddress.ip_address("2001:db8:1::5")
    prefixes = [_prefix(1, "2001:db8::/32"), _prefix(2, "2001:db8:1::/48")]
    assert find_prefix(addr, prefixes).id == 2


# --- plan_primary_ip ------------------------------------------------------


def _iface(id_, name, type_="1000base-t"):
    return SimpleNamespace(id=id_, name=name, type=type_)


AP_PORTS = [_iface(1, "E0"), _iface(2, "E1"), _iface(3, "5GHz WiFi", "ieee802.11ax")]


def _ip(assigned_to=None, *, id_=99, vrf=None, kind="dcim.interface"):
    return SimpleNamespace(
        id=id_,
        vrf=vrf,
        assigned_object_id=assigned_to,
        assigned_object_type=kind if assigned_to is not None else None,
    )


def _plan(**kw):
    kw.setdefault("address", "10.1.1.5/24")
    kw.setdefault("vrf_id", None)
    kw.setdefault("interfaces", AP_PORTS)
    return plan_primary_ip(**kw)


def test_new_ip_goes_on_the_live_port():
    plan = _plan(live_ports=["eth1"])
    assert (plan.interface_name, plan.interface_id, plan.source) == ("E1", 2, "live")
    assert plan.ip is None and plan.set_primary


def test_existing_ip_on_another_port_moves_to_the_live_port():
    plan = _plan(live_ports=["eth1"], existing_ips=[_ip(1)], primary_ip_id=99)
    assert plan.moved_from == "E0" and plan.attach
    assert plan.interface_id == 2
    assert not plan.set_primary


def test_with_two_live_ports_the_ip_stays_on_the_one_it_is_on():
    plan = _plan(live_ports=["eth0", "eth1"], existing_ips=[_ip(2)], primary_ip_id=99)
    assert plan.in_sync and plan.interface_name == "E1"


def test_with_two_live_ports_a_new_ip_goes_on_the_first_by_name():
    assert _plan(live_ports=["eth1", "eth0"]).interface_name == "E0"


def test_without_live_ports_an_ip_is_never_moved():
    plan = _plan(existing_ips=[_ip(2)], primary_ip_id=99)
    assert plan.in_sync and plan.source == "netbox"


def test_without_live_ports_a_new_ip_goes_on_the_first_wired_port():
    plan = _plan()
    assert (plan.interface_name, plan.source) == ("E0", "first-wired")


def test_no_wired_port_falls_back_to_creating_ethernet0():
    plan = _plan(interfaces=[_iface(3, "5GHz WiFi", "ieee802.11ax")])
    assert (plan.interface_name, plan.interface_id, plan.source) == ("Ethernet0", None, "fallback")


def test_no_wired_port_but_a_live_one_creates_the_live_port():
    plan = _plan(interfaces=[], live_ports=["eth1"])
    assert (plan.interface_name, plan.interface_id) == ("eth1", None)


def test_live_port_missing_from_a_device_with_other_wired_ports_is_blocked():
    plan = _plan(interfaces=[_iface(1, "E0")], live_ports=["eth1"])
    assert plan.blocked and "eth1" in plan.note


def test_ip_on_another_devices_interface_is_blocked():
    plan = _plan(existing_ips=[_ip(7777)])
    assert plan.blocked and "another device" in plan.note


def test_ip_on_a_vm_interface_with_a_colliding_id_is_blocked():
    plan = _plan(existing_ips=[_ip(1, kind="virtualization.vminterface")])
    assert plan.blocked


def test_only_the_ip_in_the_prefixs_vrf_counts():
    other_vrf = _ip(7777, vrf=SimpleNamespace(id=4))
    plan = _plan(existing_ips=[other_vrf])
    assert not plan.blocked and plan.ip is None


def test_duplicate_ips_in_one_vrf_are_blocked():
    assert _plan(existing_ips=[_ip(id_=1), _ip(id_=2)]).blocked


def test_unassigned_existing_ip_is_attached():
    plan = _plan(existing_ips=[_ip()])
    assert plan.attach and not plan.moved_from and plan.interface_name == "E0"


def test_ipv6_sets_primary_ip6():
    assert _plan(address="2001:db8::5/64").primary_field == "primary_ip6"


def test_a_preview_of_a_device_not_created_yet_holds_no_ip():
    """A device not created yet is previewed from its template with id 0: an IP
    some real interface already holds is someone else's, never this device's."""
    preview = [_iface(0, "E0"), _iface(0, "E1")]
    assert _plan(interfaces=preview, existing_ips=[_ip(5)]).blocked
    plan = _plan(interfaces=preview, live_ports=["eth1"])
    assert (plan.interface_name, plan.interface_id, plan.ip) == ("E1", 0, None)
