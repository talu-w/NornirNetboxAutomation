"""Read-only Aruba OS 8 Mobility Conductor access.

``conductor.py`` is a minimal REST client (login -> showcommand -> logout);
``inventory.py`` and ``sitematch.py`` are pure functions that turn the
conductor's ``show`` output into device records and map a hostname to a NetBox
site. Nothing in this package connects to anything on import — same rule as
:mod:`bunnyauto.firewall`.
"""

from __future__ import annotations

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.aruba.inventory import WirelessDevice, parse_ap_database, parse_switches
from bunnyauto.aruba.sitematch import match_site, normalize

__all__ = [
    "ArubaConductorClient",
    "WirelessDevice",
    "parse_ap_database",
    "parse_switches",
    "match_site",
    "normalize",
]
