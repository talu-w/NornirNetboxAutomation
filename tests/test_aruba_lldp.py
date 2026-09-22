"""Tests for the pure ``show ap lldp neighbors`` parser (no HTTP)."""

from __future__ import annotations

from bunnyauto.aruba.lldp import parse_lldp_neighbors

PAYLOAD = {
    "_meta": ["AP Name", "Neighbor System Name", "Neighbor Port"],
    "AP LLDP Neighbors": [
        {
            "AP Name": "hq-idf1-ap01",
            "Neighbor System Name": "hq-idf1-sw01",
            "Neighbor Port": "GigabitEthernet1/0/24",
        },
        {
            "AP Name": "hq-idf1-ap02",
            "Neighbor System Name": "",  # no neighbor reported
            "Neighbor Port": "",
        },
    ],
}


def test_parse_lldp_neighbors():
    rows = parse_lldp_neighbors(PAYLOAD)
    assert len(rows) == 1
    assert rows[0].ap_name == "hq-idf1-ap01"
    assert rows[0].remote_system_name == "hq-idf1-sw01"
    assert rows[0].remote_port == "GigabitEthernet1/0/24"


def test_row_missing_any_required_field_is_skipped():
    assert parse_lldp_neighbors([{"AP Name": "ap1"}]) == []
    assert parse_lldp_neighbors([{"AP Name": "ap1", "Neighbor System Name": "sw1"}]) == []


def test_alternate_field_spellings_are_tolerated():
    row = {
        "Name": "ap1",  # alternate spelling for AP Name
        "System Name": "sw1",
        "Port ID": "Gi1/0/24",
    }
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.ap_name == "ap1"
    assert neighbor.remote_system_name == "sw1"
    assert neighbor.remote_port == "Gi1/0/24"


def test_tolerates_list_and_empty_payload():
    assert parse_lldp_neighbors([]) == []
    assert parse_lldp_neighbors({}) == []
    assert parse_lldp_neighbors({"_meta": ["a"], "count": 0}) == []
