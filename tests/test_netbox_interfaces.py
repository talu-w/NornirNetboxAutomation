"""Tests for the shared interface name/type module (pure — no NetBox, no HTTP).

One alias table now serves create-interfaces, the sync-interfaces engine, and
the LLDP/cable matcher; these pin down that every spelling each of the old
three tables knew still resolves, and that they now agree with each other.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bunnyauto.netbox.interfaces import (
    canonical_name,
    interface_signature,
    interface_type,
    is_wired_type,
    match_interface,
    match_interface_candidates,
    member_local_names,
    pick_wired_interface,
    pick_wired_record,
    stack_member,
)

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

# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("long", "short"),
    [
        ("GigabitEthernet1/0/24", "Gi1/0/24"),
        ("GigabitEthernet 1/0/24", "gi 1/0/24"),
        ("TenGigabitEthernet1/1/1", "Te1/1/1"),
        ("TenGigE1/1/1", "Te1/1/1"),
        ("FastEthernet0/1", "Fa0/1"),
        ("FiveGigabitEthernet1/0/49", "Fi1/0/49"),
        ("TwoGigabitEthernet1/0/1", "Tw1/0/1"),
        ("TwentyFiveGigE1/1/1", "Twe1/1/1"),
        ("FortyGigabitEthernet1/1/1", "Fo1/1/1"),
        ("HundredGigE1/0/49", "Hu1/0/49"),
        ("FourHundredGigE1/0/1", "Fou1/0/1"),
        ("Port-channel10", "Po10"),
        ("Port-Channel10", "po10"),
        ("Loopback0", "Lo0"),
        ("Ethernet1/1", "Et1/1"),
        ("AppGigabitEthernet1/0/1", "Ap1/0/1"),
    ],
)
def test_long_and_short_spellings_are_one_interface(long, short):
    assert canonical_name(long) == canonical_name(short)


def test_canonical_form_is_the_short_family():
    assert canonical_name("GigabitEthernet1/0/1") == "gi1/0/1"
    assert canonical_name("Port-Channel10") == "po10"
    assert canonical_name("Loopback0") == "lo0"


def test_two_gig_and_twenty_five_gig_stay_distinct():
    """Cisco 'Tw' is TwoGigabitEthernet (2.5G); 25G abbreviates to 'Twe'."""
    assert canonical_name("Tw1/0/1") != canonical_name("Twe1/0/1")
    assert canonical_name("Fo1/1/1") != canonical_name("Fou1/1/1")


def test_unknown_family_is_kept_so_an_exact_spelling_still_matches():
    assert interface_signature("Weird0/1") == ("weird", "0/1")
    assert canonical_name("6GHz WiFi") == "6ghzwifi"


def test_match_interface_exact():
    names = ["GigabitEthernet1/0/24", "GigabitEthernet1/0/25"]
    assert match_interface("GigabitEthernet1/0/24", names) == "GigabitEthernet1/0/24"


def test_match_interface_abbreviated_form():
    names = ["GigabitEthernet1/0/24", "GigabitEthernet1/0/25"]
    assert match_interface("Gi1/0/24", names) == "GigabitEthernet1/0/24"


def test_match_interface_five_gig_abbreviated_form():
    """Owner-confirmed abbreviation: 'Fi' for FiveGigabitEthernet."""
    names = ["FiveGigabitEthernet1/0/49"]
    assert match_interface("Fi1/0/49", names) == "FiveGigabitEthernet1/0/49"


def test_match_interface_two_gig_abbreviated_form():
    names = ["TwoGigabitEthernet1/0/3", "TwentyFiveGigE1/1/1"]
    assert match_interface("Tw1/0/3", names) == "TwoGigabitEthernet1/0/3"


def test_match_interface_no_match_returns_none():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface("Gi1/0/99", names) is None


def test_match_interface_empty_returns_none():
    assert match_interface("", ["GigabitEthernet1/0/24"]) is None


def test_match_interface_ambiguous_returns_none():
    assert match_interface("Gi1/0/1", ["GigabitEthernet1/0/1", "Gig1/0/1"]) is None


def test_match_interface_candidates_falls_through_to_the_next_one():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface_candidates(["not-a-port", "Gi1/0/24"], names) == names[0]


def test_match_interface_candidates_none_resolve():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface_candidates(["nope", "still-nope"], names) is None


# ---------------------------------------------------------------------------
# stack members
# ---------------------------------------------------------------------------


def test_stack_member_three_segment_port():
    assert stack_member("Gi1/0/24") == 1
    assert stack_member("GigabitEthernet1/0/24") == 1
    assert stack_member("Te2/1/1") == 2


def test_stack_member_two_segment_port_returns_none():
    """A non-stacked switch's <module>/<port> name must never be mistaken
    for a member number — only a full 3-segment shape counts."""
    assert stack_member("Gi0/24") is None
    assert stack_member("GigabitEthernet0/24") is None


def test_stack_member_no_slash_returns_none():
    assert stack_member("Vlan10") is None
    assert stack_member("Loopback0") is None


def test_stack_member_bare_numeric_port_and_subinterface():
    assert stack_member("1/0/24") == 1
    assert stack_member("Gi3/0/1.100") == 3


# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Port-channel1", "lag"),
        ("Po1", "lag"),
        ("Loopback0", "virtual"),
        ("Vlan10", "virtual"),
        ("Tunnel0", "virtual"),
        ("FastEthernet0/1", "100base-tx"),
        ("GigabitEthernet1/0/1", "1000base-t"),
        ("FiveGigabitEthernet1/0/1", "5gbase-t"),
        ("TenGigE1/1/1", "10gbase-x-sfpp"),
        ("TwentyFiveGigE1/1/1", "25gbase-x-sfp28"),
        ("FortyGigabitEthernet1/1/1", "40gbase-x-qsfpp"),
        ("HundredGigE1/0/49", "100gbase-x-qsfp28"),
        ("Weird0", "other"),
    ],
)
def test_interface_type(name, expected):
    assert interface_type(name) == expected


def test_two_gig_ports_are_typed_two_point_five_gig_not_twenty_five():
    """Regression: create-interfaces' old regex table matched any 'Tw' prefix
    as 25G SFP28, so a Catalyst mGig port (TwoGigabitEthernet) got the wrong type."""
    assert interface_type("TwoGigabitEthernet1/0/1") == "2.5gbase-t"
    assert interface_type("Tw1/0/1") == "2.5gbase-t"


def test_four_hundred_gig_is_not_typed_forty_gig():
    assert interface_type("FourHundredGigE1/0/1") == "400gbase-x-qsfpdd"


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


def test_pick_wired_record_reads_nested_choice_types():
    records = [
        SimpleNamespace(id=1, name="6GHz WiFi", type=SimpleNamespace(value="ieee802.11ax")),
        SimpleNamespace(id=2, name="E1", type={"value": "5gbase-t"}),
        SimpleNamespace(id=3, name="E0", type="5gbase-t"),
    ]
    assert pick_wired_record(records).id == 3


def test_pick_wired_record_none_when_only_radios():
    records = [SimpleNamespace(id=1, name="Bluetooth", type="ieee802.15.1")]
    assert pick_wired_record(records) is None


def test_member_local_names_are_the_templates_member_one_forms():
    assert member_local_names("Gi2/0/3") == ["Gi1/0/3", "Gi0/3"]
    assert member_local_names("GigabitEthernet 3/1/4") == [
        "GigabitEthernet1/1/4",
        "GigabitEthernet1/4",
    ]


def test_member_local_names_keep_a_subinterface():
    assert member_local_names("Te2/0/1.100") == ["Te1/0/1.100", "Te0/1.100"]


def test_member_local_names_need_the_three_segment_stack_shape():
    assert member_local_names("Gi0/1") == []
    assert member_local_names("Port-channel1") == []
