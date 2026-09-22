"""Tests for the pure LLDP-neighbor-hostname-to-NetBox-device matcher."""

from __future__ import annotations

from types import SimpleNamespace

from bunnyauto.hostname_match import match_hostname, normalize_hostname


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
