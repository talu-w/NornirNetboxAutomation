"""Tests for the pure ``show ap bss-table`` parser (no HTTP)."""

from __future__ import annotations

from bunnyauto.aruba.radios import Bss, parse_bss_table

#: The owner's payload shape (2026-09-28; the values are mock data).
PAYLOAD = {
    "Aruba AP BSS Table": [
        {
            "acl": "108",
            "acl-state": "-",
            "ap name": "acess-point-hello-world",
            "band/ht-mode/bandwidth": "2.4GHz/HE/20MHz",
            "bss": "11:22:33:44:ba:aa:55",
            "ch/EIRP/max-EIRP": "1/10.0/23.0",
            "cluster": "Z",
            "cur-cl": "0",
            "datazone": "no",
            "ess": "DavesAuto-Wireless-Guest",
            "flags": "KrT",
            "fm": "T",
            "in-t(s)": "0",
            "ip": "192.168.222.55",
            "mtu": "1500",
            "port": "N/A",
            "tot-t": "9h:30m:18s",
            "type": "ap",
        }
    ]
}


def _row(**over):
    base = {
        "ap name": "ap1",
        "band/ht-mode/bandwidth": "5GHz/VHT/80MHz",
        "ch/EIRP/max-EIRP": "52E/18.0/23.0",
        "ess": "Corp",
        "type": "ap",
    }
    return {**base, **over}


def test_the_owners_payload_shape():
    (bss,) = parse_bss_table(PAYLOAD)
    assert bss == Bss(
        ap_name="acess-point-hello-world",
        ssid="DavesAuto-Wireless-Guest",
        band="2.4",
        width=20,
        channel=1,
        direction="",
        channel_label="1",
        eirp=10.0,
        kind="ap",
    )


def test_wide_channels_keep_their_primary_channel_and_width():
    rows = [
        _row(),
        _row(**{"band/ht-mode/bandwidth": "6GHz/HE/160MHz", "ch/EIRP/max-EIRP": "37S/15.0/21.8"}),
        _row(**{"band/ht-mode/bandwidth": "5GHz/HT/40MHz", "ch/EIRP/max-EIRP": "36+/12.0/20.0"}),
    ]
    got = [
        (b.band, b.channel, b.width, b.direction, b.channel_label) for b in parse_bss_table(rows)
    ]
    assert got == [
        ("5", 52, 80, "", "52E"),
        ("6", 37, 160, "", "37S"),
        ("5", 36, 40, "+", "36+"),
    ]


def test_a_channel_aruba_substituted_drops_its_star():
    (bss,) = parse_bss_table([_row(**{"ch/EIRP/max-EIRP": "149E*/18.0/23.0"})])
    assert (bss.channel, bss.channel_label) == (149, "149E")


def test_80_plus_80_is_an_unknown_width_not_a_guess():
    (bss,) = parse_bss_table([_row(**{"band/ht-mode/bandwidth": "5GHz/VHT/80+80MHz"})])
    assert bss.width == 0


def test_without_a_bandwidth_column_the_channel_marker_gives_the_width():
    rows = [
        {"ap name": "ap1", "ch/EIRP/max-EIRP": "36E/18/23", "ess": "Corp"},
        {"ap name": "ap1", "ch/EIRP/max-EIRP": "36/18/23", "ess": "Corp"},
    ]
    assert [(b.band, b.width) for b in parse_bss_table(rows)] == [("", 80), ("", 20)]


def test_unreadable_values_are_empty_not_guessed():
    (bss,) = parse_bss_table([_row(**{"ch/EIRP/max-EIRP": "N/A", "band/ht-mode/bandwidth": ""})])
    assert (bss.band, bss.channel, bss.width, bss.eirp) == ("", 0, 0, None)


def test_air_monitors_are_marked_and_rows_without_an_ap_are_skipped():
    rows = [_row(type="am", ess=""), {"ess": "Corp"}]
    (bss,) = parse_bss_table(rows)
    assert bss.kind == "am"


def test_tolerates_list_and_empty_payload():
    assert parse_bss_table([]) == []
    assert parse_bss_table({"_meta": ["bss"], "Num APs": "0"}) == []
