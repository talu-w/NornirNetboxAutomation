"""Turn Aruba ``show`` output into flat device records.

Pure — no I/O. AOS field names drift between versions, so every lookup tries a
list of spellings and tolerates missing keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_AP_PREFIX = re.compile(r"^ap[-_]?", re.I)


@dataclass(frozen=True)
class WirelessDevice:
    """One WLC or AP as the Conductor reports it."""

    name: str
    serial: str
    model: str
    mac: str
    ip: str
    kind: str  # "ap" | "wlc"
    status: str

    @property
    def model_candidates(self) -> list[str]:
        """Model strings to try against NetBox device types, best guess first."""
        raw = self.model.strip()
        out: list[str] = []
        for candidate in (raw, _AP_PREFIX.sub("", raw), f"AP-{_AP_PREFIX.sub('', raw)}"):
            candidate = candidate.strip()
            if candidate and candidate not in out:
                out.append(candidate)
        return out


def _get(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        for actual, value in row.items():
            if actual.strip().casefold() == key.casefold() and value not in (None, ""):
                return str(value).strip()
    return ""


def parse_ap_database(payload: dict[str, Any] | list[dict[str, Any]]) -> list[WirelessDevice]:
    """Records from ``show ap database`` / ``show ap database long``."""
    devices: list[WirelessDevice] = []
    for row in _rows(payload):
        name = _get(row, "Name", "AP Name")
        if not name:
            continue
        devices.append(
            WirelessDevice(
                name=name,
                serial=_get(row, "Serial #", "Serial Number", "serial"),
                model=_get(row, "AP Type", "Model", "AP Model"),
                mac=_get(row, "Wired MAC Address", "Wired MAC", "mac", "MAC Address"),
                ip=_get(row, "IP Address", "IP", "Switch IP"),
                kind="ap",
                status=_get(row, "Status", "State"),
            )
        )
    return devices


def parse_switches(payload: dict[str, Any] | list[dict[str, Any]]) -> list[WirelessDevice]:
    """Records from ``show switches`` (the controllers the Conductor manages)."""
    devices: list[WirelessDevice] = []
    for row in _rows(payload):
        name = _get(row, "Name", "Switch Name")
        ip = _get(row, "IP Address", "IP")
        if not name and not ip:
            continue
        devices.append(
            WirelessDevice(
                name=name or ip,
                serial=_get(row, "Serial #", "Serial Number", "serial"),
                model=_get(row, "Model", "Switch Model", "Type"),
                mac=_get(row, "MAC Address", "mac"),
                ip=ip,
                kind="wlc",
                status=_get(row, "Status", "State", "Config State"),
            )
        )
    return devices


def _rows(payload: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key, value in payload.items():
        if key == "_meta":
            continue
        if isinstance(value, list) and value and all(isinstance(row, dict) for row in value):
            return value
    return []
