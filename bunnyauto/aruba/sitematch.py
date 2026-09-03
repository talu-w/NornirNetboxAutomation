"""Map an Aruba device hostname to an existing NetBox site.

The only signal is the hostname, which by local convention starts with the site
name (``<site-name>-...``), but the exact form varies by location. The rule
here: normalize both sides, then pick the NetBox site whose slug is the
**longest prefix** of the hostname that ends on a separator boundary (or matches
in full). A length tie between two candidate sites is treated as ambiguous and
returns ``None`` so the caller reports it rather than guessing.

Pure — no I/O. The caller passes the NetBox sites in as ``Site`` tuples.
"""

from __future__ import annotations

import re
from typing import NamedTuple

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


class Site(NamedTuple):
    slug: str
    id: int
    name: str


def normalize(value: str) -> str:
    """Lowercase and collapse every run of non-alphanumeric chars to a single '-'."""
    return _NON_ALNUM.sub("-", str(value).casefold()).strip("-")


def match_site(hostname: str, sites: list[Site]) -> Site | None:
    """Return the site whose normalized slug best-prefixes ``hostname``.

    ``None`` if nothing matches, or if two sites tie for the longest match.
    """
    host = normalize(hostname)
    if not host:
        return None

    best: list[Site] = []
    best_len = 0
    for site in sites:
        slug = normalize(site.slug)
        if not slug:
            continue
        if host == slug or host.startswith(f"{slug}-"):
            if len(slug) > best_len:
                best, best_len = [site], len(slug)
            elif len(slug) == best_len:
                best.append(site)

    if len(best) == 1:
        return best[0]
    return None
