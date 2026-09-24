"""Tests for the pure ``show ap lldp neighbors`` parser (no HTTP)."""

from __future__ import annotations

from bunnyauto.aruba.lldp import parse_lldp_neighbors

PAYLOAD = {
    "_meta": [
        "AP",
        "Capabilities",
        "Chassis Name/ID",
        "Interface",
        "Mgmt. Address",
        "Neighbor",
        "Port Desc",
        "Port ID",
    ],
    "AP LLDP Neighbors": [
        {
            "AP": "hq-idf1-ap01",
            "Capabilities": "B",
            "Chassis Name/ID": "hq-idf1-sw01",
            "Interface": "eth0",
            "Mgmt. Address": "10.1.0.10",
            "Neighbor": "1",
            "Port Desc": "GigabitEthernet1/0/24",
            "Port ID": "GigabitEthernet1/0/24",
        },
        {
            "AP": "hq-idf1-ap02",
            "Capabilities": "",
            "Chassis Name/ID": "",  # no neighbor reported
            "Interface": "eth0",
            "Mgmt. Address": "",
            "Neighbor": "",
            "Port Desc": "",
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
    assert rows[0].local_port == "eth0"


def test_interface_column_is_the_aps_own_port():
    row = {"AP": "ap1", "Interface": "eth1", "Chassis Name/ID": "sw1", "Port ID": "Gi1/0/24"}
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.local_port == "eth1"


def test_missing_interface_column_leaves_local_port_empty():
    row = {"AP": "ap1", "Chassis Name/ID": "sw1", "Port ID": "Gi1/0/24"}
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.local_port == ""


def test_row_missing_any_required_field_is_skipped():
    assert parse_lldp_neighbors([{"AP": "ap1"}]) == []
    assert parse_lldp_neighbors([{"AP": "ap1", "Chassis Name/ID": "sw1"}]) == []


def test_ap_column_is_recognized():
    """Regression: real hardware's AP-identity column is literally 'AP', not
    'AP Name' — every row was being skipped entirely before this was added,
    since ap_name is required before anything else is even attempted."""
    row = {"AP": "hq-idf1-ap01", "Chassis Name/ID": "sw1", "Port ID": "Gi1/0/24"}
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.ap_name == "hq-idf1-ap01"


def test_combined_chassis_name_id_column_is_recognized():
    """Regression: real hardware combines this into one 'Chassis Name/ID'
    column, not the separate 'Chassis Name' / 'Chassis ID' columns first
    guessed — every row was still being skipped even after the 'AP' fix,
    since remote_system_candidates came back empty."""
    row = {"AP": "ap1", "Chassis Name/ID": "hq-idf1-sw01", "Port ID": "Gi1/0/24"}
    (neighbor,) = parse_lldp_neighbors([row])
    assert neighbor.remote_system_candidates == ["hq-idf1-sw01"]


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
