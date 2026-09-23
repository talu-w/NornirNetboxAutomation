"""Tests for the pure ``show ap lldp neighbors`` parser (no HTTP)."""

from __future__ import annotations

from bunnyauto.aruba.lldp import parse_lldp_neighbors

PAYLOAD = {
    "_meta": ["AP Name", "Chassis Name", "Port ID"],
    "AP LLDP Neighbors": [
        {
            "AP Name": "hq-idf1-ap01",
            "Chassis Name": "hq-idf1-sw01",
            "Port ID": "GigabitEthernet1/0/24",
        },
        {
            "AP Name": "hq-idf1-ap02",
            "Chassis Name": "",  # no neighbor reported
            "Port ID": "",
        },
    ],
}


def test_parse_lldp_neighbors():
    rows = parse_lldp_neighbors(PAYLOAD)
    assert len(rows) == 1
    assert rows[0].ap_name == "hq-idf1-ap01"
    assert rows[0].remote_system_candidates == ["hq-idf1-sw01"]
    assert rows[0].remote_port_candidates == ["GigabitEthernet1/0/24"]


def test_row_missing_any_required_field_is_skipped():
    assert parse_lldp_neighbors([{"AP Name": "ap1"}]) == []
    assert parse_lldp_neighbors([{"AP Name": "ap1", "Chassis Name": "sw1"}]) == []


def test_both_chassis_name_and_chassis_id_are_kept_as_candidates():
    """Real hardware: which field holds a usable hostname (vs. a MAC) depends
    on how the neighboring switch is configured — keep both, let the caller
    try each against NetBox."""
    row = {
        "AP Name": "ap1",
        "Chassis Name": "sw1",
        "Chassis ID": "aa:bb:cc:dd:ee:ff",
        "Port ID": "Gi1/0/24",
    }
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.remote_system_candidates == ["sw1", "aa:bb:cc:dd:ee:ff"]


def test_both_port_id_and_port_desc_are_kept_as_candidates():
    row = {
        "AP Name": "ap1",
        "Chassis Name": "sw1",
        "Port ID": "Gi1/0/24",
        "Port Desc": "GigabitEthernet1/0/24",
    }
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.remote_port_candidates == ["Gi1/0/24", "GigabitEthernet1/0/24"]


def test_alternate_field_spellings_are_tolerated():
    row = {
        "Name": "ap1",  # alternate spelling for AP Name
        "System Name": "sw1",  # alternate spelling for Chassis Name
        "Neighbor Port": "Gi1/0/24",  # alternate spelling for Port ID
    }
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.ap_name == "ap1"
    assert neighbor.remote_system_candidates == ["sw1"]
    assert neighbor.remote_port_candidates == ["Gi1/0/24"]


def test_tolerates_list_and_empty_payload():
    assert parse_lldp_neighbors([]) == []
    assert parse_lldp_neighbors({}) == []
    assert parse_lldp_neighbors({"_meta": ["a"], "count": 0}) == []
