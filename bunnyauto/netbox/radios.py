"""A radio interface's RF settings in NetBox: channel, frequency, width, power, SSIDs.

Pure — no I/O, except :func:`load_channel_values` and :func:`load_wireless_lans`.

**Channels.** NetBox names a wide channel by its *centre* 20 MHz channel and
stores it as ``<band>-<channel>-<centre MHz>-<width MHz>`` (``5g-58-5290-80``). A
vendor names it by its primary channel plus a width (Aruba's ``52E``: channel 52,
80 MHz). :func:`rf_channel` converts with the standard 802.11 channel blocks: a
40/80/160 MHz block in 5 GHz starts at channel 36 (or 149), in 6 GHz at channel
1, and a 40 MHz channel with its secondary marked above or below (``36+``,
``40-``) is centred two channels that way. NetBox models 2.4 GHz channels as
22 MHz wide and has no 2.4 GHz 40 MHz channels. A channel NetBox has no value
for is returned as a frequency and width only, which NetBox accepts without a
channel.

**Radios.** :func:`radio_interface` finds a device's Wi-Fi radio interface for a
band by name (``5GHz WiFi``, as NetBox Data Exchange device types call them).
:func:`plan_radio` returns the fields of one radio interface that differ from
what the device reports. NetBox refuses a stored frequency or width that
disagrees with a channel, so a channel change always sends all three together.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from bunnyauto.netbox.records import choice_value, related_id

#: Channel-number span of a 40/80/160 MHz block (4 channel numbers per 20 MHz).
_BLOCK = {40: 8, 80: 16, 160: 32}
_BAND_NAMES = {
    "2.4": re.compile(r"2\.4\s*g"),
    "5": re.compile(r"(?<![\d.])5\s*g"),
    "6": re.compile(r"(?<![\d.])6\s*g"),
}


@dataclass(frozen=True, slots=True)
class RfChannel:
    """One radio channel as NetBox stores it."""

    value: str | None  # NetBox's rf_channel value; None if NetBox has none for it
    frequency: float  # centre frequency, MHz
    width: float  # MHz, as NetBox stores it (a 2.4 GHz channel is 22)


def rf_channel(
    band: str,
    channel: int,
    width: int,
    direction: str = "",
    *,
    values: Collection[str] | None = None,
) -> RfChannel | None:
    """NetBox's channel for a primary ``channel`` of ``width`` MHz in ``band`` GHz.

    ``direction`` is a 40 MHz channel's ``"+"`` / ``"-"`` marker. ``values`` is
    NetBox's own list of ``rf_channel`` values, when it could be read: a value
    not in it is dropped (the frequency and width are still set). ``None`` for a
    band, width or channel this can't place.
    """
    centre = _centre(band, channel, width, direction)
    if centre is None:
        return None
    frequency = _frequency(band, centre)
    netbox_width = 22 if band == "2.4" and width == 20 else width
    value: str | None = f"{band}g-{centre}-{frequency}-{netbox_width}"
    if (band == "2.4" and width != 20) or (values is not None and value not in values):
        value = None
    return RfChannel(value=value, frequency=float(frequency), width=float(netbox_width))


def radio_interface(interfaces: list[Any], band: str) -> tuple[Any | None, str]:
    """The device's one Wi-Fi radio interface for ``band``, or ``(None, why not)``."""
    pattern = _BAND_NAMES.get(band)
    radios = [
        i
        for i in interfaces
        if (choice_value(getattr(i, "type", None)) or "").startswith("ieee802.11")
        and pattern is not None
        and pattern.search(re.sub(r"\s+", "", str(i.name)).casefold())
    ]
    if len(radios) == 1:
        return radios[0], ""
    if not radios:
        return None, f"NetBox has no {band} GHz radio interface on it (named like '{band}GHz WiFi')"
    names = ", ".join(repr(str(i.name)) for i in radios)
    return None, f"NetBox has more than one {band} GHz radio interface on it ({names})"


def plan_radio(
    interface: Any,
    *,
    channel: RfChannel | None,
    tx_power: int | None,
    wireless_lan_ids: list[int] | None,
) -> dict[str, Any]:
    """The update that makes ``interface`` match the reported radio; ``{}`` if it does.

    ``None`` for any of ``channel`` / ``tx_power`` / ``wireless_lan_ids`` leaves
    that field alone. An id of 0 in ``wireless_lan_ids`` is a wireless LAN plan
    mode would create, so it always counts as a change.
    """
    body: dict[str, Any] = {}
    if choice_value(getattr(interface, "rf_role", None)) != "ap":
        body["rf_role"] = "ap"
    if channel is not None:
        current = (
            choice_value(getattr(interface, "rf_channel", None)) or None,
            _float(getattr(interface, "rf_channel_frequency", None)),
            _float(getattr(interface, "rf_channel_width", None)),
        )
        if current != (channel.value, channel.frequency, channel.width):
            body.update(
                rf_channel=channel.value,
                rf_channel_frequency=channel.frequency,
                rf_channel_width=channel.width,
            )
    if tx_power is not None and getattr(interface, "tx_power", None) != tx_power:
        body["tx_power"] = tx_power
    if wireless_lan_ids is not None:
        linked = getattr(interface, "wireless_lans", None) or []
        current_ids = sorted(related_id(w) or 0 for w in linked)
        if 0 in wireless_lan_ids or current_ids != sorted(wireless_lan_ids):
            body["wireless_lans"] = sorted(i for i in wireless_lan_ids if i)
    return body


def load_channel_values(nb: Any) -> frozenset[str] | None:
    """The ``rf_channel`` values this NetBox accepts, or ``None`` if it won't say."""
    try:
        choices = nb.dcim.interfaces.choices()["rf_channel"]
    except Exception:  # pynetbox RequestError, an unexpected OPTIONS shape, ...
        return None
    return frozenset(str(c["value"]) for c in choices if isinstance(c, dict) and "value" in c)


def load_wireless_lans(nb: Any) -> dict[str, list[Any]]:
    """Every NetBox wireless LAN, by SSID (SSIDs are case-sensitive)."""
    by_ssid: dict[str, list[Any]] = {}
    for wlan in nb.wireless.wireless_lans.all():
        by_ssid.setdefault(str(wlan.ssid), []).append(wlan)
    return by_ssid


def _centre(band: str, channel: int, width: int, direction: str) -> int | None:
    if channel <= 0 or band not in ("2.4", "5", "6"):
        return None
    if width == 20:
        return channel
    if width == 40 and direction:
        return channel + 2 if direction == "+" else channel - 2
    if band == "2.4" or width not in _BLOCK:
        return None  # 2.4 GHz 40 MHz without a marker, or 80+80 / 320 MHz
    first = 1 if band == "6" else (36 if channel <= 144 else 149)
    if channel < first:
        return None
    size = _BLOCK[width]
    return first + size * ((channel - first) // size) + size // 2 - 2


def _frequency(band: str, channel: int) -> int:
    if band == "2.4":
        return 2484 if channel == 14 else 2407 + 5 * channel
    return (5950 if band == "6" else 5000) + 5 * channel


def _float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
