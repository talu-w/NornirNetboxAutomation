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


def with_stack_suffix(candidates: list[str], member: str | None) -> list[str]:
    """Expand each candidate with a ``<host>-<member>[.<domain>]`` form tried first.

    A virtually-stacked switch's chassis reports one shared LLDP identity for
    the whole stack (its base hostname, no per-member suffix) — but each
    stack member is deliberately kept as its own separate NetBox device
    named ``<hostname>-<member>``, never collapsed to one shared name, since
    different neighbors can be homed to different physical members of the
    same stack (confirmed 2026-09-23: renaming NetBox devices to drop the
    suffix is not the fix). The member-suffixed form is tried *first* when a
    member hint is available (see
    :func:`bunnyauto.ifname_match.stack_member_hint`) so a coincidentally
    bare-named device elsewhere in NetBox never wins over the actual stack
    member; the raw candidate is kept as a fallback for a switch that isn't
    stacked at all. A ``None``/falsy ``member`` returns the candidates
    unchanged.

    The suffix goes **before** the domain, not appended to the end of the
    whole string: NetBox names a stacked member ``host-1.example.com``, not
    ``host.example.com-1`` (confirmed 2026-09-23 — the naive
    ``f"{candidate}-{member}"`` concatenation got this wrong for any
    candidate that was already a FQDN, which every real LLDP chassis name in
    this deployment is). Only the first ``.`` matters — everything from
    there onward is carried through unchanged, same "ignore the domain"
    convention :func:`normalize_hostname` already uses for comparison.
    """
    if not member:
        return list(candidates)
    expanded: list[str] = []
    for candidate in candidates:
        text = str(candidate)
        host, dot, domain = text.partition(".")
        suffixed = f"{host}-{member}{dot}{domain}"
        if suffixed not in expanded:
            expanded.append(suffixed)
    for candidate in candidates:
        if candidate not in expanded:
            expanded.append(candidate)
    return expanded
