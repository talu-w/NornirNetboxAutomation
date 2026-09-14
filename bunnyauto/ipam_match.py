"""Find the NetBox prefix that contains a given IP address.

Pure — no I/O. NetBox prefixes can nest (``10.0.0.0/8`` and ``10.1.1.0/24`` both
contain ``10.1.1.5``); the **narrowest** (largest prefix length) containing
prefix wins. A tie between two equally-specific prefixes is ambiguous and
returns ``None`` so the caller reports it rather than guessing — same rule as
:func:`bunnyauto.aruba.sitematch.match_site`.
"""

from __future__ import annotations

import ipaddress
from typing import NamedTuple

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class Prefix(NamedTuple):
    id: int
    network: IPNetwork
    vrf_id: int | None


def find_prefix(addr: IPAddress, prefixes: list[Prefix]) -> Prefix | None:
    """Return the most specific ``Prefix`` containing ``addr``, or ``None``."""
    candidates = [p for p in prefixes if addr in p.network]
    if not candidates:
        return None
    best_len = max(p.network.prefixlen for p in candidates)
    best = [p for p in candidates if p.network.prefixlen == best_len]
    return best[0] if len(best) == 1 else None
