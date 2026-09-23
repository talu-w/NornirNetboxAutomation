"""Tests for the pure IP-to-prefix matching helper (no NetBox, no HTTP)."""

from __future__ import annotations

import ipaddress

from bunnyauto.netbox.ipam import Prefix, find_prefix


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
