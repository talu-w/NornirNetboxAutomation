"""Classify NetBox interface types as wired-Ethernet vs. everything else.

Pure — no I/O. ``wireless-sync`` uses this to pick which of a device's
interfaces an IP belongs on, without ever guessing a literal name: real
Aruba device types (imported from NetBox Data Exchange, for example) carry
an interface template with wired ports (``E0``, ``E1``, ...) alongside
Wi-Fi/Bluetooth/Zigbee radios (``6GHz WiFi``, ``Bluetooth``, ...) — the first
wired-Ethernet interface, by name, wins. Radio and non-physical interface
types are never candidates, so an IP is never proposed for a radio interface.
"""

from __future__ import annotations

#: Interface types that exist but aren't a physical wired port an IP belongs on.
_NON_WIRED_TYPES = frozenset({"other-wireless", "virtual", "lag", "bridge"})
#: NetBox's wireless-radio type families (802.11 Wi-Fi, 802.15 Bluetooth/Zigbee-ish).
_WIRELESS_PREFIXES = ("ieee802.11", "ieee802.15")


def is_wired_type(interface_type: str) -> bool:
    """True if a NetBox interface type slug is a physical wired port."""
    value = (interface_type or "").strip().casefold()
    if not value or value in _NON_WIRED_TYPES:
        return False
    return not value.startswith(_WIRELESS_PREFIXES)


def pick_wired_interface(interfaces: list[tuple[str, str]]) -> str | None:
    """Given ``[(name, type), ...]``, return the alphabetically-first wired name.

    ``None`` if the device (or its device type's interface template) carries
    no wired interface at all.
    """
    wired = sorted(name for name, itype in interfaces if is_wired_type(itype))
    return wired[0] if wired else None
