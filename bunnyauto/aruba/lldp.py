"""Parse Aruba's ``show ap lldp neighbors`` output into flat rows.

Pure — no I/O. Command name confirmed against real AOS 8 hardware (all WLC
models) 2026-09-22 — unlike most Aruba field names in this package, this one
is not a guess. Field names inside each row are likewise now confirmed
against a real payload the owner supplied directly (2026-09-23): the row
identifies the local AP under the column ``AP`` (not ``"AP Name"``), and the
neighbor's identity under the single combined column ``Chassis Name/ID``
(*not* two separate ``"Chassis Name"``/``"Chassis ID"`` columns — an earlier,
wrong guess). The row also carries ``Capabilities``, ``Interface`` (the AP's
own local port), ``Mgmt. Address`` (the neighboring switch's management IP —
a possible future fallback match if hostname matching ever proves
unreliable, not wired in yet) and ``Neighbor`` (meaning unconfirmed), none of
which this parser currently uses. The neighbor's port is under ``Port ID`` or
``Port Desc`` (both are the *neighbor's own* port, per live testing — not the
AP's local port). Every candidate for a field is kept, not just the first
non-empty one, so the caller can try each against NetBox and use whichever
one actually resolves — same "try progressively more candidates" pattern as
:func:`bunnyauto.netbox.tokens.match_record`'s ``model_candidates``,
since which field holds the useful value isn't knowable in advance.

A row missing any of the three fields ``wireless enrich`` needs (which AP, at
least one remote-system candidate, at least one remote-port candidate) is
skipped rather than guessed — same "never substitute a wrong value" rule as
the rest of this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LldpNeighbor:
    """One AP's reported wired LLDP neighbor, as a WLC reports it.

    ``remote_system_candidates`` / ``remote_port_candidates`` hold every
    non-empty value found for that field, in the order confirmed against real
    hardware then older best-guess spellings — try each against NetBox in
    order and use whichever one resolves.
    """

    ap_name: str
    remote_system_candidates: list[str]
    remote_port_candidates: list[str]


def _get(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        for actual, value in row.items():
            if actual.strip().casefold() == key.casefold() and value not in (None, ""):
                return str(value).strip()
    return ""


def _get_all(row: dict[str, Any], *keys: str) -> list[str]:
    """Every non-empty value among these field-name candidates, in order, de-duplicated."""
    out: list[str] = []
    for key in keys:
        for actual, value in row.items():
            if actual.strip().casefold() == key.casefold() and value not in (None, ""):
                text = str(value).strip()
                if text and text not in out:
                    out.append(text)
    return out


def parse_lldp_neighbors(payload: dict[str, Any] | list[dict[str, Any]]) -> list[LldpNeighbor]:
    """Records from ``show ap lldp neighbors``."""
    neighbors: list[LldpNeighbor] = []
    for row in _rows(payload):
        ap_name = _get(row, "AP", "AP Name", "Name")
        remote_system_candidates = _get_all(
            row,
            "Chassis Name/ID",
            "Chassis Name",
            "Chassis ID",
            "Neighbor System Name",
            "System Name",
            "Neighbor Name",
        )
        remote_port_candidates = _get_all(
            row,
            "Port ID",
            "Port Desc",
            "Port Description",
            "Neighbor Port",
            "Neighbor Port Description",
            "Remote Port",
        )
        if not ap_name or not remote_system_candidates or not remote_port_candidates:
            continue
        neighbors.append(
            LldpNeighbor(
                ap_name=ap_name,
                remote_system_candidates=remote_system_candidates,
                remote_port_candidates=remote_port_candidates,
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
