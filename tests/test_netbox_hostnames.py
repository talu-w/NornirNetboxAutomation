"""Tests for the pure LLDP-neighbor-hostname-to-NetBox-device matcher."""

from __future__ import annotations

from types import SimpleNamespace

from bunnyauto.netbox.hostnames import (
    match_hostname,
    match_hostname_candidates,
    normalize_hostname,
    with_stack_suffix,
)


def test_normalize_hostname_strips_domain_and_casefolds():
    assert normalize_hostname("HQ-IDF1-SW01.corp.example.com") == "hq-idf1-sw01"
    assert normalize_hostname("hq-idf1-sw01") == "hq-idf1-sw01"


def test_match_hostname_exact():
    devices = [SimpleNamespace(name="hq-idf1-sw01"), SimpleNamespace(name="hq-idf1-sw02")]
    match = match_hostname("hq-idf1-sw01", devices)
    assert match is devices[0]


def test_match_hostname_fqdn_vs_short_name():
    devices = [SimpleNamespace(name="hq-idf1-sw01")]
    assert match_hostname("HQ-IDF1-SW01.corp.example.com", devices) is devices[0]


def test_match_hostname_no_match_returns_none():
    devices = [SimpleNamespace(name="hq-idf1-sw01")]
    assert match_hostname("unknown-switch", devices) is None


def test_match_hostname_empty_returns_none():
    devices = [SimpleNamespace(name="hq-idf1-sw01")]
    assert match_hostname("", devices) is None


def test_match_hostname_ambiguous_returns_none():
    devices = [SimpleNamespace(name="sw01.site-a.example.com"), SimpleNamespace(name="sw01")]
    assert match_hostname("sw01", devices) is None


def test_match_hostname_candidates_falls_through_to_the_next_one():
    """E.g. Chassis Name fails to match (MAC-like), Chassis ID candidate does."""
    devices = [SimpleNamespace(name="hq-idf1-sw01")]
    match = match_hostname_candidates(["aa:bb:cc:dd:ee:ff", "hq-idf1-sw01"], devices)
    assert match is devices[0]


def test_match_hostname_candidates_first_match_wins():
    devices = [SimpleNamespace(name="hq-idf1-sw01"), SimpleNamespace(name="other")]
    match = match_hostname_candidates(["hq-idf1-sw01", "other"], devices)
    assert match is devices[0]


def test_match_hostname_candidates_none_resolve():
    devices = [SimpleNamespace(name="hq-idf1-sw01")]
    assert match_hostname_candidates(["nope", "still-nope"], devices) is None


def test_with_stack_suffix_prepends_suffixed_form():
    assert with_stack_suffix(["hq-idf1-sw01"], "1") == ["hq-idf1-sw01-1", "hq-idf1-sw01"]


def test_with_stack_suffix_inserts_before_the_domain_not_after_it():
    """Regression: NetBox names a stacked member 'host-1.example.com', not
    'host.example.com-1' — a naive f'{candidate}-{member}' concatenation
    got this wrong for any candidate that was already a FQDN, which every
    real LLDP chassis name in the owner's deployment is."""
    assert with_stack_suffix(["hq-idf1-sw01.ect.net"], "1") == [
        "hq-idf1-sw01-1.ect.net",
        "hq-idf1-sw01.ect.net",
    ]


def test_with_stack_suffix_no_member_leaves_candidates_unchanged():
    assert with_stack_suffix(["hq-idf1-sw01"], None) == ["hq-idf1-sw01"]
    assert with_stack_suffix(["hq-idf1-sw01"], "") == ["hq-idf1-sw01"]


def test_with_stack_suffix_end_to_end_resolves_the_correct_member():
    """The stack's chassis reports one bare name; each member is its own
    NetBox device — the suffixed form must resolve, and must resolve to the
    *correct* member, not just any device on the stack."""
    devices = [
        SimpleNamespace(name="hq-idf1-sw01-1"),
        SimpleNamespace(name="hq-idf1-sw01-2"),
    ]
    candidates = with_stack_suffix(["hq-idf1-sw01"], "2")
    match = match_hostname_candidates(candidates, devices)
    assert match is devices[1]


def test_with_stack_suffix_end_to_end_with_fqdn_naming():
    """Same as above, but with the owner's real naming shape end to end:
    LLDP reports the bare stack chassis as an FQDN, NetBox names each
    member '<host>-<member>.<domain>'."""
    devices = [
        SimpleNamespace(name="hq-idf1-sw01-1.ect.net"),
        SimpleNamespace(name="hq-idf1-sw01-2.ect.net"),
    ]
    candidates = with_stack_suffix(["hq-idf1-sw01.ect.net"], "2")
    match = match_hostname_candidates(candidates, devices)
    assert match is devices[1]
