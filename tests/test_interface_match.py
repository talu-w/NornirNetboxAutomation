"""Tests for the pure wired/wireless interface-type classifier (no NetBox, no HTTP)."""

from __future__ import annotations

from bunnyauto.interface_match import is_wired_type, pick_wired_interface

# Real interface set for the Aruba AP-655 device type (NetBox Data Exchange).
AP_655_INTERFACES = [
    ("E0", "5gbase-t"),
    ("E1", "5gbase-t"),
    ("6GHz WiFi", "ieee802.11ax"),
    ("5GHz WiFi", "ieee802.11ax"),
    ("2.4GHz WiFi", "ieee802.11ax"),
    ("Bluetooth", "ieee802.15.1"),
    ("Zigbee", "other-wireless"),
]


def test_wired_ethernet_types_are_wired():
    assert is_wired_type("5gbase-t")
    assert is_wired_type("1000base-t")
    assert is_wired_type("10gbase-x-sfpp")
    assert is_wired_type("other")


def test_radio_and_virtual_types_are_not_wired():
    assert not is_wired_type("ieee802.11ax")
    assert not is_wired_type("ieee802.15.1")
    assert not is_wired_type("other-wireless")
    assert not is_wired_type("virtual")
    assert not is_wired_type("lag")
    assert not is_wired_type("bridge")
    assert not is_wired_type("")
    assert not is_wired_type(None)


def test_case_insensitive():
    assert is_wired_type("5GBASE-T")
    assert not is_wired_type("IEEE802.11AX")


def test_pick_wired_interface_prefers_first_wired_port_by_name():
    assert pick_wired_interface(AP_655_INTERFACES) == "E0"


def test_pick_wired_interface_ignores_radios_entirely():
    radios_only = [(n, t) for n, t in AP_655_INTERFACES if not is_wired_type(t)]
    assert pick_wired_interface(radios_only) is None


def test_pick_wired_interface_empty():
    assert pick_wired_interface([]) is None
