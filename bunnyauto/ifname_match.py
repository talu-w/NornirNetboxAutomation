"""Match an LLDP-reported remote port name to a switch's actual NetBox interface.

Pure — no I/O. An LLDP neighbor's port field can be the exact interface name
(``GigabitEthernet1/0/24``) or a switch-vendor abbreviation of it
(``Gi1/0/24``, ``gi 1/0/24``) — which one depends on the neighboring switch's
own LLDP configuration, not on anything Aruba controls. An exact
(case-insensitive) match is tried first; failing that, both sides are
normalized by expanding known family abbreviations before comparing. No match,
or more than one NetBox interface normalizing the same way, returns ``None`` —
same "never guess" rule as the rest of this project's matching helpers.

Also home to :func:`stack_member_hint`, which reads the stack-member number
back out of a ``<member>/<module>/<port>``-shaped port id (confirmed
2026-09-23 against real stacked switches) — used by ``wireless-enrich`` /
:mod:`bunnyauto.hostname_match` to find the correct *member's* NetBox device
in a virtual stack, since a stack's whole chassis shares one LLDP identity
but each member is its own NetBox device.
"""

from __future__ import annotations

import re

_LEADING_ALPHA = re.compile(r"^([a-z]+)\s*(.*)$")
#: <member>/<module>/<port> — exactly three numeric segments, the Cisco/Aruba
#: stacking convention (e.g. "1/0/24" -> stack member "1"). Deliberately
#: requires all three segments so a plain <module>/<port> name on a
#: non-stacked switch (e.g. "0/24") is never mistaken for a member number.
_STACK_MEMBER_PORT = re.compile(r"^[a-z]*(\d+)/\d+/\d+$")

#: Cisco-style port-family abbreviations, longest/most-specific first so e.g.
#: "te" is not swallowed by a shorter alias that doesn't apply to it.
_FAMILY_ALIASES: tuple[tuple[str, str], ...] = (
    ("hundredgigabitethernet", "hundredgigabitethernet"),
    ("twentyfivegigabitethernet", "twentyfivegigabitethernet"),
    ("tengigabitethernet", "tengigabitethernet"),
    ("gigabitethernet", "gigabitethernet"),
    ("fastethernet", "fastethernet"),
    ("hu", "hundredgigabitethernet"),
    ("twe", "twentyfivegigabitethernet"),
    ("te", "tengigabitethernet"),
    ("gi", "gigabitethernet"),
    ("ge", "gigabitethernet"),
    ("fa", "fastethernet"),
    ("fe", "fastethernet"),
    ("eth", "ethernet"),
    ("et", "ethernet"),
)


def normalize_port_name(value: str) -> str:
    """Lowercase, strip whitespace/separators, expand a known family alias.

    ``"Gi1/0/24"`` and ``"GigabitEthernet 1/0/24"`` both normalize to
    ``"gigabitethernet1/0/24"``. A prefix that matches no known alias is kept
    as-is (lowercased), so an exact match still works for anything this
    module doesn't know about.
    """
    text = str(value).strip().casefold()
    match = _LEADING_ALPHA.match(text)
    if not match:
        return text
    prefix, rest = match.group(1), match.group(2).strip()
    for alias, expansion in _FAMILY_ALIASES:
        if prefix == alias:
            return f"{expansion}{rest}"
    return f"{prefix}{rest}"


def match_interface(remote_port: str, interface_names: list[str]) -> str | None:
    """Return the one interface name matching ``remote_port``, or ``None``."""
    target = str(remote_port).strip().casefold()
    if not target:
        return None

    exact = [name for name in interface_names if name.strip().casefold() == target]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None

    normalized_target = normalize_port_name(remote_port)
    normalized_matches = [
        name for name in interface_names if normalize_port_name(name) == normalized_target
    ]
    return normalized_matches[0] if len(normalized_matches) == 1 else None


def stack_member_hint(port_name: str) -> str | None:
    """The stack-member number embedded in a <member>/<module>/<port> port id.

    A virtually-stacked switch's chassis reports one shared LLDP identity for
    the whole stack, but the *port* naming convention still encodes which
    physical member owns that port — e.g. ``"Gi1/0/24"`` /
    ``"GigabitEthernet1/0/24"`` is stack member ``"1"``, module ``0``, port
    ``24``. Runs on the family-normalized name so any recognized (or
    unrecognized-but-still-3-segment) prefix works the same way. Requires the
    *full* three-segment shape — a two-segment ``<module>/<port>`` name (a
    non-stacked switch) never yields a hint, since there is no way to tell a
    bare module number from a stack-member number by shape alone. ``None``
    means "no hint available", never a wrong guess.
    """
    normalized = normalize_port_name(port_name)
    match = _STACK_MEMBER_PORT.match(normalized)
    return match.group(1) if match else None


def match_interface_candidates(candidates: list[str], interface_names: list[str]) -> str | None:
    """Try each candidate port name in order; return the first that resolves.

    An LLDP neighbor can report its port under more than one field (e.g. Port
    ID vs. Port Desc) — try each against the switch's actual interfaces and
    use whichever one resolves, same reasoning as
    :func:`bunnyauto.hostname_match.match_hostname_candidates`.
    """
    for candidate in candidates:
        match = match_interface(candidate, interface_names)
        if match is not None:
            return match
    return None
