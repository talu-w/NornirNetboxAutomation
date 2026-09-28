"""Parse Aruba's ``show ap bss-table`` into one record per SSID per radio.

Pure — no I/O. One row is one BSS: an SSID broadcast by one radio of one AP.
Field names confirmed against the payload shape the owner supplied (2026-09-28):
``ap name``, ``ess`` (the SSID), ``band/ht-mode/bandwidth`` (``"2.4GHz/HE/20MHz"``),
``ch/EIRP/max-EIRP`` (``"1/10.0/23.0"``: channel, current EIRP, maximum EIRP)
and ``type`` (``ap``, or ``am`` for an air monitor). The other columns (``bss``,
``cluster``, ``flags``, ``fm``, ...) aren't used.

A channel carries Aruba's width marker: ``36`` (20 MHz), ``36+`` / ``36-``
(40 MHz, secondary channel above/below), ``36E`` (80 MHz), ``36S`` (160 MHz).
A trailing ``*`` (a channel picked because the configured one isn't supported)
is dropped. The bandwidth column wins over the marker; the marker is only used
when the column says nothing. ``80+80MHz`` is two separate channels, so it's
reported as width 0 (unknown), never guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from bunnyauto.aruba.inventory import _get, _rows

_BAND = re.compile(r"^\s*(2\.4|5|6)\s*ghz", re.I)
_WIDTH = re.compile(r"^(\d+)\s*mhz$", re.I)
_CHANNEL = re.compile(r"^(\d+)([+\-es]?)\**$", re.I)
_WIDTH_BY_MARK = {"+": 40, "-": 40, "e": 80, "s": 160}


@dataclass(frozen=True)
class Bss:
    """One SSID on one radio of one AP, as a WLC reports it."""

    ap_name: str
    ssid: str
    band: str  # "2.4" | "5" | "6" (GHz); "" if not reported
    width: int  # channel width in MHz; 0 if unknown
    channel: int  # the primary 20 MHz channel; 0 if unreadable
    direction: str  # "+" | "-" for a 40 MHz channel's secondary; "" otherwise
    channel_label: str  # the channel as reported, e.g. "52E"
    eirp: float | None  # current EIRP, dBm
    kind: str  # "ap", or "am" for an air monitor


def parse_bss_table(payload: dict[str, Any] | list[dict[str, Any]]) -> list[Bss]:
    """Records from ``show ap bss-table``. A row without an AP name is skipped."""
    records: list[Bss] = []
    for row in _rows(payload):
        ap_name = _get(row, "ap name")
        if not ap_name:
            continue
        band, width = _band_and_width(_get(row, "band/ht-mode/bandwidth"))
        label, _, rest = _get(row, "ch/EIRP/max-EIRP").partition("/")
        label = label.strip().rstrip("*")
        channel, mark = _channel(label)
        if width is None:  # no bandwidth column: the channel's marker says it
            width = _WIDTH_BY_MARK.get(mark.casefold(), 20 if channel else 0)
        records.append(
            Bss(
                ap_name=ap_name,
                ssid=_get(row, "ess"),
                band=band,
                width=width,
                channel=channel,
                direction=mark if mark in "+-" else "",
                channel_label=label,
                eirp=_number(rest.partition("/")[0]),
                kind=(_get(row, "type") or "ap").casefold(),
            )
        )
    return records


def _band_and_width(value: str) -> tuple[str, int | None]:
    """``"5GHz/VHT/80MHz"`` -> ``("5", 80)``.

    The width is ``None`` when there's no bandwidth part at all, and 0 when
    there is one but it isn't a single channel (``80+80MHz``).
    """
    parts = [p.strip() for p in value.split("/")]
    match = _BAND.match(parts[0])
    band = match.group(1) if match else ""
    if len(parts) < 3:
        return band, None
    width_match = _WIDTH.match(parts[-1])
    return band, int(width_match.group(1)) if width_match else 0


def _channel(label: str) -> tuple[int, str]:
    """``"52E"`` -> ``(52, "E")``; ``"36+"`` -> ``(36, "+")``; unreadable -> ``(0, "")``."""
    match = _CHANNEL.match(label)
    if not match:
        return 0, ""
    return int(match.group(1)), match.group(2)


def _number(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None
