"""Firewall API support for bunnyauto tools.

Nothing here connects on import. :class:`~bunnyauto.firewall.fortigate.FortiGateClient`
is a thin read-only wrapper over the FortiGate REST API; :mod:`bunnyauto.firewall.usage`
is the pure subnet-usage analysis the ``fw-subnet-check`` tool runs on what the
client returns.
"""

from __future__ import annotations

from bunnyauto.firewall.fortigate import FortiGateClient
from bunnyauto.firewall.usage import (
    AddressMatch,
    PolicyRef,
    UsageReport,
    analyze,
)

__all__ = [
    "FortiGateClient",
    "AddressMatch",
    "PolicyRef",
    "UsageReport",
    "analyze",
]
