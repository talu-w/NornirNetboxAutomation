"""Parse Aruba's ``show ap lldp neighbors`` output into flat rows.

Pure — no I/O. Command name confirmed against real AOS 8 hardware (all WLC
models) 2026-09-22 — unlike most Aruba field names in this package, this one
is not a guess. The *field* names inside each row are still tried across a few
candidate spellings, same tolerant style as :mod:`bunnyauto.aruba.inventory`,
since AOS field spellings are known to drift between versions.

A row missing any of the three fields ``wireless-enrich`` needs (which AP,
which remote system, which remote port) is skipped rather than guessed —
same "never substitute a wrong value" rule as the rest of this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LldpNeighbor:
    """One AP's reported wired LLDP neighbor, as a WLC reports it."""

    ap_name: str
    remote_system_name: str
    remote_port: str


def _get(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        for actual, value in row.items():
            if actual.strip().casefold() == key.casefold() and value not in (None, ""):
                return str(value).strip()
    return ""


def parse_lldp_neighbors(payload: dict[str, Any] | list[dict[str, Any]]) -> list[LldpNeighbor]:
    """Records from ``show ap lldp neighbors``."""
    neighbors: list[LldpNeighbor] = []
    for row in _rows(payload):
        ap_name = _get(row, "AP Name", "Name")
        remote_system_name = _get(
            row, "Neighbor System Name", "System Name", "Neighbor Name", "Chassis Name"
        )
        remote_port = _get(
            row,
            "Neighbor Port",
            "Neighbor Port Description",
            "Port Description",
            "Port ID",
            "Remote Port",
        )
        if not ap_name or not remote_system_name or not remote_port:
            continue
        neighbors.append(
            LldpNeighbor(
                ap_name=ap_name,
                remote_system_name=remote_system_name,
                remote_port=remote_port,
            )
        )
    return neighbors


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
