"""Tests for the pure Aruba parsing + site-matching helpers (no HTTP)."""

from __future__ import annotations

from bunnyauto.aruba.inventory import parse_ap_database, parse_switches
from bunnyauto.aruba.sitematch import Site, match_site, normalize

# ---------------------------------------------------------------------------
# parse_ap_database / parse_switches
# ---------------------------------------------------------------------------

AP_PAYLOAD = {
    "_meta": ["Name", "AP Type", "IP Address", "Status", "Serial #", "Wired MAC Address"],
    "AP Database": [
        {
            "Name": "hq-idf1-ap01",
            "AP Type": "515",
            "IP Address": "10.1.10.11",
            "Status": "Up 5d:1h:2m",
            "Serial #": "CN0011AB",
            "Wired MAC Address": "00:11:22:33:44:55",
        },
        {
            "Name": "hq-idf1-ap02",
            "AP Type": "AP-535",
            "IP Address": "10.1.10.12",
            "Status": "Down",
            "Serial #": "CN0022CD",
        },
    ],
}

SWITCH_PAYLOAD = {
    "All Switches": [
        {
            "Name": "hq-wlc01",
            "IP Address": "10.1.0.5",
            "Model": "A7210",
            "Serial Number": "CX0099ZZ",
            "Status": "up",
        }
    ],
}


def test_parse_ap_database():
    aps = parse_ap_database(AP_PAYLOAD)
    assert [a.name for a in aps] == ["hq-idf1-ap01", "hq-idf1-ap02"]
    assert aps[0].serial == "CN0011AB"
    assert aps[0].model == "515"
    assert aps[0].mac == "00:11:22:33:44:55"
    assert aps[0].kind == "ap"
    assert aps[1].mac == ""  # missing key tolerated


def test_parse_switches():
    wlcs = parse_switches(SWITCH_PAYLOAD)
    assert len(wlcs) == 1
    assert wlcs[0].name == "hq-wlc01"
    assert wlcs[0].serial == "CX0099ZZ"
    assert wlcs[0].kind == "wlc"


def test_parse_tolerates_list_and_empty():
    assert parse_ap_database([{"Name": "x", "AP Type": "515"}])[0].name == "x"
    assert parse_ap_database({}) == []
    assert parse_switches({"_meta": ["a"], "count": 0}) == []


def test_model_candidates():
    aps = parse_ap_database(AP_PAYLOAD)
    assert aps[0].model_candidates == ["515", "AP-515"]
    assert aps[1].model_candidates == ["AP-535", "535"]


# ---------------------------------------------------------------------------
# match_site
# ---------------------------------------------------------------------------

SITES = [
    Site(slug="hq", id=1, name="Headquarters"),
    Site(slug="hq-annex", id=2, name="HQ Annex"),
    Site(slug="branch-north", id=3, name="Branch North"),
]


def test_normalize():
    assert normalize("HQ-IDF1_AP01") == "hq-idf1-ap01"
    assert normalize("  Branch North  ") == "branch-north"


def test_match_site_longest_prefix_wins():
    assert match_site("hq-annex-idf2-ap9", SITES).id == 2
    assert match_site("hq-idf1-ap01", SITES).id == 1
    assert match_site("branch-north-ap1", SITES).id == 3


def test_match_site_exact_and_no_match():
    assert match_site("HQ", SITES).id == 1
    assert match_site("datacenter-ap1", SITES) is None
    assert match_site("hquarters-ap1", SITES) is None  # not on a '-' boundary


def test_match_site_ambiguous_returns_none():
    sites = [Site(slug="ab", id=1, name="A"), Site(slug="ab", id=2, name="B")]
    assert match_site("ab-ap1", sites) is None
