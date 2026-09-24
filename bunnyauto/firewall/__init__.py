"""Firewall API support for bunnyauto tools.

Nothing here connects on import. :class:`~bunnyauto.firewall.fortigate.FortiGateClient`
is a thin wrapper over the FortiGate REST API — reads, plus creating one subnet address
object (:class:`~bunnyauto.firewall.fortigate.NewAddress`); :mod:`bunnyauto.firewall.usage`
is the pure subnet-usage analysis the ``security subnet-check`` tool runs on what the
client returns.
"""

from __future__ import annotations

from bunnyauto.firewall.fortigate import FortiGateClient, NewAddress
from bunnyauto.firewall.usage import (
    AddressMatch,
    InterfaceMatch,
    PolicyRef,
    UsageReport,
    analyze,
)

__all__ = [
    "FortiGateClient",
    "NewAddress",
    "AddressMatch",
    "InterfaceMatch",
    "PolicyRef",
    "UsageReport",
    "analyze",
]
