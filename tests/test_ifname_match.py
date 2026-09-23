"""Tests for the pure LLDP-remote-port-to-NetBox-interface matcher."""

from __future__ import annotations

from bunnyauto.ifname_match import (
    match_interface,
    match_interface_candidates,
    normalize_port_name,
    stack_member_hint,
)


def test_normalize_expands_known_abbreviations():
    assert normalize_port_name("Gi1/0/24") == "gigabitethernet1/0/24"
    assert normalize_port_name("GigabitEthernet1/0/24") == "gigabitethernet1/0/24"
    assert normalize_port_name("Te1/1/1") == "tengigabitethernet1/1/1"
    assert normalize_port_name("Fa0/1") == "fastethernet0/1"


def test_normalize_handles_a_space_between_prefix_and_number():
    assert normalize_port_name("GigabitEthernet 1/0/24") == "gigabitethernet1/0/24"


def test_normalize_keeps_unknown_prefix_as_is():
    assert normalize_port_name("Weird0/1") == "weird0/1"


def test_match_interface_exact():
    names = ["GigabitEthernet1/0/24", "GigabitEthernet1/0/25"]
    assert match_interface("GigabitEthernet1/0/24", names) == "GigabitEthernet1/0/24"


def test_match_interface_abbreviated_form():
    names = ["GigabitEthernet1/0/24", "GigabitEthernet1/0/25"]
    assert match_interface("Gi1/0/24", names) == "GigabitEthernet1/0/24"


def test_match_interface_no_match_returns_none():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface("Gi1/0/99", names) is None


def test_match_interface_empty_returns_none():
    assert match_interface("", ["GigabitEthernet1/0/24"]) is None


def test_match_interface_candidates_falls_through_to_the_next_one():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface_candidates(["not-a-port", "Gi1/0/24"], names) == names[0]


def test_match_interface_candidates_none_resolve():
    names = ["GigabitEthernet1/0/24"]
    assert match_interface_candidates(["nope", "still-nope"], names) is None


def test_stack_member_hint_three_segment_port():
    assert stack_member_hint("Gi1/0/24") == "1"
    assert stack_member_hint("GigabitEthernet1/0/24") == "1"
    assert stack_member_hint("Te2/1/1") == "2"


def test_stack_member_hint_two_segment_port_returns_none():
    """A non-stacked switch's <module>/<port> name must never be mistaken
    for a member number — only a full 3-segment shape counts."""
    assert stack_member_hint("Gi0/24") is None
    assert stack_member_hint("GigabitEthernet0/24") is None


def test_stack_member_hint_no_slash_returns_none():
    assert stack_member_hint("Vlan10") is None
    assert stack_member_hint("Loopback0") is None


def test_stack_member_hint_bare_numeric_port():
    assert stack_member_hint("1/0/24") == "1"
