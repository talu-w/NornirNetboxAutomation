"""Match an LLDP neighbor's reported system name to an existing NetBox device.

Pure — no I/O. The only signal is the name string an LLDP neighbor reports,
which may be a bare hostname or a fully-qualified one depending on the
switch's own configuration; NetBox device names in this project are short
hostnames. Both sides are normalized to their short form (casefold, domain
suffix dropped) before comparing. More than one device normalizing to the
same name is ambiguous and returns ``None`` — same "never guess" rule as
:func:`bunnyauto.aruba.sitematch.match_site`.
"""

from __future__ import annotations

from typing import Any


def normalize_hostname(value: str) -> str:
    """Casefold and drop everything from the first '.' onward (FQDN -> short name)."""
    return str(value).strip().casefold().split(".")[0]


def match_hostname(remote_system_name: str, devices: list[Any]) -> Any | None:
    """Return the one NetBox device whose name matches, or ``None``."""
    target = normalize_hostname(remote_system_name)
    if not target:
        return None
    matches = [d for d in devices if normalize_hostname(getattr(d, "name", "")) == target]
    return matches[0] if len(matches) == 1 else None


def match_hostname_candidates(candidates: list[str], devices: list[Any]) -> Any | None:
    """Try each candidate name in order; return the first that resolves.

    An LLDP neighbor can report its identity under more than one field (e.g.
    Chassis Name vs. Chassis ID) and which one holds a usable hostname isn't
    knowable in advance — one may be a MAC address, or use a different naming
    convention NetBox doesn't match. The first candidate that resolves to
    exactly one NetBox device wins; an ambiguous or unmatched candidate is
    skipped in favor of the next one.
    """
    for candidate in candidates:
        match = match_hostname(candidate, devices)
        if match is not None:
            return match
    return None
