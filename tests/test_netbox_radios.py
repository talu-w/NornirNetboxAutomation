"""Tests for the shared radio module: channels, radio interfaces, updates (no NetBox, no HTTP)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bunnyauto.netbox.radios import RfChannel, plan_radio, radio_interface, rf_channel

#: A slice of NetBox's WirelessChannelChoices values.
VALUES = frozenset(
    {
        "2.4g-1-2412-22",
        "2.4g-6-2437-22",
        "5g-36-5180-20",
        "5g-38-5190-40",
        "5g-42-5210-80",
        "5g-58-5290-80",
        "5g-114-5570-160",
        "5g-155-5775-80",
        "6g-7-5985-80",
        "6g-47-6185-160",
    }
)


# --- channels -------------------------------------------------------------


@pytest.mark.parametrize(
    ("band", "channel", "width", "direction", "value"),
    [
        ("2.4", 1, 20, "", "2.4g-1-2412-22"),  # NetBox models 2.4 GHz as 22 MHz
        ("5", 36, 20, "", "5g-36-5180-20"),
        ("5", 36, 40, "+", "5g-38-5190-40"),
        ("5", 40, 40, "-", "5g-38-5190-40"),
        ("5", 40, 40, "", "5g-38-5190-40"),  # no marker: the standard block
        ("5", 36, 80, "", "5g-42-5210-80"),
        ("5", 52, 80, "", "5g-58-5290-80"),  # Aruba 52E
        ("5", 149, 80, "", "5g-155-5775-80"),
        ("5", 100, 160, "", "5g-114-5570-160"),
        ("6", 5, 80, "", "6g-7-5985-80"),
        ("6", 37, 160, "", "6g-47-6185-160"),  # Aruba 37S
    ],
)
def test_aruba_primary_channels_become_netbox_centre_channels(
    band, channel, width, direction, value
):
    result = rf_channel(band, channel, width, direction, values=VALUES)
    assert result is not None and result.value == value


def test_frequency_and_width_come_with_the_channel():
    assert rf_channel("5", 52, 80, values=VALUES) == RfChannel("5g-58-5290-80", 5290.0, 80.0)


def test_2_4ghz_40mhz_has_no_netbox_channel_but_keeps_frequency_and_width():
    assert rf_channel("2.4", 6, 40, "-", values=VALUES) == RfChannel(None, 2427.0, 40.0)


def test_a_value_this_netbox_lacks_is_dropped():
    assert rf_channel("5", 165, 20, values=VALUES) == RfChannel(None, 5825.0, 20.0)


def test_without_netbox_values_the_computed_value_is_trusted():
    assert rf_channel("5", 165, 20).value == "5g-165-5825-20"


@pytest.mark.parametrize(
    ("band", "channel", "width", "direction"),
    [
        ("5", 36, 0, ""),  # 80+80: unknown width
        ("5", 0, 20, ""),  # unreadable channel
        ("", 36, 20, ""),  # no band
        ("2.4", 6, 40, ""),  # 2.4 GHz 40 MHz without a marker
        ("5", 36, 320, ""),
    ],
)
def test_channels_that_cannot_be_placed(band, channel, width, direction):
    assert rf_channel(band, channel, width, direction) is None


# --- radio interfaces -----------------------------------------------------


def _iface(name, type_="ieee802.11ax", **fields):
    return SimpleNamespace(id=fields.pop("id", 1), name=name, type=type_, **fields)


AP_655 = [
    _iface("E0", "5gbase-t"),
    _iface("6GHz WiFi"),
    _iface("5GHz WiFi"),
    _iface("2.4GHz WiFi"),
    _iface("Bluetooth", "ieee802.15.1"),
]


@pytest.mark.parametrize(
    ("band", "name"), [("2.4", "2.4GHz WiFi"), ("5", "5GHz WiFi"), ("6", "6GHz WiFi")]
)
def test_each_band_finds_its_ndx_radio(band, name):
    radio, why = radio_interface(AP_655, band)
    assert (radio.name, why) == (name, "")


def test_a_missing_radio_says_so():
    radio, why = radio_interface([_iface("5GHz WiFi")], "6")
    assert radio is None and "no 6 GHz radio interface" in why


def test_two_radios_for_one_band_are_ambiguous():
    radio, why = radio_interface([_iface("5GHz WiFi"), _iface("5 GHz Radio 2")], "5")
    assert radio is None and "more than one 5 GHz" in why


def test_a_wired_port_named_like_a_band_is_never_a_radio():
    assert radio_interface([_iface("5G uplink", "5gbase-t")], "5")[0] is None


# --- planning an update ------------------------------------------------------

CH_52E = RfChannel("5g-58-5290-80", 5290.0, 80.0)


def test_an_empty_radio_gets_everything():
    body = plan_radio(_iface("5GHz WiFi"), channel=CH_52E, tx_power=18, wireless_lan_ids=[7, 3])
    assert body == {
        "rf_role": "ap",
        "rf_channel": "5g-58-5290-80",
        "rf_channel_frequency": 5290.0,
        "rf_channel_width": 80.0,
        "tx_power": 18,
        "wireless_lans": [3, 7],
    }


def test_a_radio_that_already_matches_needs_nothing():
    radio = _iface(
        "5GHz WiFi",
        rf_role={"value": "ap"},
        rf_channel={"value": "5g-58-5290-80"},
        rf_channel_frequency=5290,
        rf_channel_width="80.000",
        tx_power=18,
        wireless_lans=[SimpleNamespace(id=3), {"id": 7}],
    )
    assert plan_radio(radio, channel=CH_52E, tx_power=18, wireless_lan_ids=[7, 3]) == {}


def test_a_channel_change_sends_frequency_and_width_with_it():
    """NetBox refuses a stored frequency/width that disagrees with a new channel."""
    radio = _iface(
        "5GHz WiFi",
        rf_role="ap",
        rf_channel="5g-42-5210-80",
        rf_channel_frequency=5210.0,
        rf_channel_width=80.0,
        tx_power=18,
    )
    assert plan_radio(radio, channel=CH_52E, tx_power=18, wireless_lan_ids=None) == {
        "rf_channel": "5g-58-5290-80",
        "rf_channel_frequency": 5290.0,
        "rf_channel_width": 80.0,
    }


def test_none_leaves_a_field_alone():
    radio = _iface("5GHz WiFi", rf_role="ap", tx_power=5, wireless_lans=[{"id": 9}])
    assert plan_radio(radio, channel=None, tx_power=None, wireless_lan_ids=None) == {}


def test_a_wireless_lan_plan_mode_would_create_is_always_a_change():
    radio = _iface("5GHz WiFi", rf_role="ap", wireless_lans=[{"id": 3}])
    body = plan_radio(radio, channel=None, tx_power=None, wireless_lan_ids=[3, 0])
    assert body == {"wireless_lans": [3]}
