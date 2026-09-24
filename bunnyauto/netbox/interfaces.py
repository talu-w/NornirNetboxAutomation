"""Interface names and types: the one place bunnyauto knows how ports are spelled.

Pure, no I/O. Every tool that compares an interface name from a device (CLI
output, an LLDP neighbor's Port ID) with one in NetBox goes through here, so
``Gi1/0/24``, ``gi 1/0/24`` and ``GigabitEthernet1/0/24`` are the same port
everywhere. (Until 2026-09-23 there were three separate alias tables: one in
``create-interfaces``, one in the ``sync-interfaces`` engine, and one in the
wireless LLDP matcher. Each was missing families the others knew.)

**Names.** :func:`interface_signature` splits a name into ``(family, rest)``
with the family reduced to one canonical short form (``"gi"``);
:func:`canonical_name` joins them back (``"gi1/0/24"``). :func:`match_interface`
and :func:`match_interface_candidates` resolve a reported name against a
device's actual NetBox interface names, trying an exact match first, then a
canonical one, and returning nothing if the match is ambiguous.
:func:`stack_member` reads the member number out of a
``<member>/<module>/<port>`` name. A stack's members share one chassis identity
but each is its own NetBox device. :func:`member_local_names` gives the
member-1 names a device-type template puts on every member device.

**Types.** :func:`interface_type` maps a name to the NetBox interface type a
newly created interface gets. :func:`is_wired_type` and
:func:`pick_wired_interface` classify NetBox type slugs, so an IP or a cable
lands on a wired port and never on a Wi-Fi, Bluetooth or Zigbee radio.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from bunnyauto.netbox.records import choice_value

#: Every known spelling of a port family, mapped to its one canonical short form.
#: New abbreviation seen in the fleet? Add it here. Every matcher, the type
#: mapping, and the stack-member reader all pick it up.
FAMILY_ALIASES: dict[str, str] = {
    # 100M
    "fa": "fa",
    "fe": "fa",
    "fastethernet": "fa",
    # 1G
    "gi": "gi",
    "gig": "gi",
    "ge": "gi",
    "gige": "gi",
    "gigabitethernet": "gi",
    # 2.5G. Cisco's "Tw" is TwoGigabitEthernet; 25G abbreviates to "Twe".
    "tw": "tw",
    "two": "tw",
    "twogige": "tw",
    "twogigabitethernet": "tw",
    # 5G
    "fi": "fi",
    "fivegige": "fi",
    "fivegigabitethernet": "fi",
    # 10G
    "te": "te",
    "ten": "te",
    "tengige": "te",
    "tengigabitethernet": "te",
    # 25G
    "twe": "twe",
    "twentyfivegige": "twe",
    "twentyfivegigabitethernet": "twe",
    # 40G
    "fo": "fo",
    "fortygige": "fo",
    "fortygigabitethernet": "fo",
    # 100G
    "hu": "hu",
    "hundredgige": "hu",
    "hundredgigabitethernet": "hu",
    # 400G
    "fou": "fou",
    "fourhundredgige": "fou",
    "fourhundredgigabitethernet": "fou",
    # generic Ethernet (Arista/Nexus style). Aruba APs: NetBox Data Exchange
    # device types name the ports "E0"/"E1"; the AP's own LLDP table says "eth0"/"eth1".
    "e": "eth",
    "eth": "eth",
    "et": "eth",
    "ethernet": "eth",
    # logical / special
    "po": "po",
    "port-channel": "po",
    "portchannel": "po",
    "lo": "lo",
    "loopback": "lo",
    "ap": "ap",
    "appgigabitethernet": "ap",
}

#: Canonical family -> the NetBox interface type ``create-interfaces`` creates it as.
_FAMILY_TYPES: dict[str, str] = {
    "po": "lag",
    "lo": "virtual",
    "vlan": "virtual",
    "bdi": "virtual",
    "irb": "virtual",
    "tunnel": "virtual",
    "tun": "virtual",
    "fa": "100base-tx",
    "gi": "1000base-t",
    "tw": "2.5gbase-t",
    "fi": "5gbase-t",
    "te": "10gbase-x-sfpp",
    "twe": "25gbase-x-sfp28",
    "fo": "40gbase-x-qsfpp",
    "hu": "100gbase-x-qsfp28",
    "fou": "400gbase-x-qsfpdd",
}

#: Interface types that exist but aren't a physical wired port an IP belongs on.
_NON_WIRED_TYPES = frozenset({"other-wireless", "virtual", "lag", "bridge"})
#: NetBox's wireless-radio type families (802.11 Wi-Fi, 802.15 Bluetooth/Zigbee-ish).
_WIRELESS_PREFIXES = ("ieee802.11", "ieee802.15")

_SIGNATURE = re.compile(r"^(?P<family>[a-z-]+)(?P<rest>.+)$")
#: <member>/<module>/<port>, the Cisco/Aruba stacking convention (``"1/0/24"`` is
#: member 1). Deliberately requires all three segments, so a non-stacked
#: switch's plain ``<module>/<port>`` (``"0/24"``) is never read as a member.
_STACK_MEMBER = re.compile(r"^(?:[a-z][a-z-]*)?(\d+)/\d+/\d+(?:\.\d+)?$")
#: A stack port split for :func:`member_local_names` (case kept, spaces dropped).
_MEMBER_LOCAL = re.compile(
    r"^(?P<prefix>[A-Za-z-]+)(?P<member>\d+)/(?P<remainder>\d+/\d+(?:\.\d+)?)$"
)


def _compact(name: str) -> str:
    return re.sub(r"\s+", "", str(name)).casefold()


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


def interface_signature(name: str) -> tuple[str, str]:
    """Split a name into ``(canonical family, rest)``: ``"Gi1/0/1"`` -> ``("gi", "1/0/1")``.

    Whitespace is dropped and case folded. A family this module doesn't know is
    kept as-is (lowercased), so an exact spelling still matches itself.
    """
    compact = _compact(name)
    match = _SIGNATURE.match(compact)
    if not match:
        return "", compact
    family = match.group("family")
    return FAMILY_ALIASES.get(family, family), match.group("rest")


def canonical_name(name: str) -> str:
    """One comparable spelling: ``"GigabitEthernet 1/0/24"`` -> ``"gi1/0/24"``."""
    family, rest = interface_signature(name)
    return f"{family}{rest}"


def match_interface(reported: str, interface_names: list[str]) -> str | None:
    """The one interface name matching ``reported``, or ``None``.

    An exact (case-insensitive) match wins. Otherwise both sides are compared
    by :func:`canonical_name`. No match, or more than one, returns ``None``.
    Never a guess.
    """
    target = str(reported).strip().casefold()
    if not target:
        return None

    exact = [name for name in interface_names if name.strip().casefold() == target]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None

    wanted = canonical_name(reported)
    canonical = [name for name in interface_names if canonical_name(name) == wanted]
    return canonical[0] if len(canonical) == 1 else None


def match_interface_candidates(candidates: list[str], interface_names: list[str]) -> str | None:
    """Try each candidate port name in order; return the first that resolves.

    A neighbor can report its port under more than one field (LLDP ``Port ID``
    vs. ``Port Desc``). Each is tried against the device's actual interfaces,
    and the first one that resolves wins.
    """
    for candidate in candidates:
        match = match_interface(candidate, interface_names)
        if match is not None:
            return match
    return None


def stack_member(name: str) -> int | None:
    """The stack-member number in a ``<member>/<module>/<port>`` name, else ``None``.

    ``"Gi2/0/24"`` / ``"GigabitEthernet2/0/24"`` / ``"2/0/24"`` -> ``2``; a
    subinterface suffix (``.100``) is allowed. A two-segment ``<module>/<port>``
    name (a non-stacked switch) returns ``None``, since there's no way to tell a
    module number from a member number by shape alone.
    """
    match = _STACK_MEMBER.match(_compact(name))
    return int(match.group(1)) if match else None


def member_local_names(name: str) -> list[str]:
    """The names a device-type template gives a stack member's port: ``"Gi2/0/3"`` ->
    ``["Gi1/0/3", "Gi0/3"]``.

    A device type's interface template is fixed, so every member device NetBox
    creates from it gets member-1 numbering (``Gi1/0/3``), or no member segment
    at all (``Gi0/3``), even when IOS calls the port ``Gi2/0/3``. On a
    stack-member device, those are the same physical port under the template's
    name. Returns ``[]`` for a name without the ``<member>/<module>/<port>`` shape.
    """
    match = _MEMBER_LOCAL.match(str(name).strip().replace(" ", ""))
    if not match:
        return []
    prefix, remainder = match.group("prefix"), match.group("remainder")
    return [f"{prefix}1/{remainder}", f"{prefix}{remainder}"]


# ---------------------------------------------------------------------------
# types
# ---------------------------------------------------------------------------


def interface_type(name: str) -> str:
    """The NetBox interface type for a port named ``name`` (``"other"`` if unknown).

    Port-Channels are ``lag``; loopbacks, VLAN SVIs, BDIs, IRBs and tunnels are
    ``virtual``; physical families map to their speed's type.
    """
    family, _rest = interface_signature(name)
    return _FAMILY_TYPES.get(family, "other")


def is_wired_type(interface_type_slug: str) -> bool:
    """True if a NetBox interface type slug is a physical wired port."""
    value = (interface_type_slug or "").strip().casefold()
    if not value or value in _NON_WIRED_TYPES:
        return False
    return not value.startswith(_WIRELESS_PREFIXES)


def pick_wired_interface(interfaces: list[tuple[str, str]]) -> str | None:
    """Given ``[(name, type), ...]``, return the alphabetically-first wired name.

    Real device types (e.g. an AP imported from NetBox Data Exchange) carry wired
    ports (``E0``, ``E1``) alongside Wi-Fi/Bluetooth/Zigbee radios; radios and
    virtual/LAG/bridge interfaces are never candidates. ``None`` if the device
    (or its device type's interface template) has no wired interface at all.
    """
    wired = sorted(name for name, itype in interfaces if is_wired_type(itype))
    return wired[0] if wired else None


def pick_wired_record(interfaces: Iterable[Any]) -> Any | None:
    """:func:`pick_wired_interface` over NetBox interface (or interface-template) records.

    Returns the record itself, so the caller has its ``id``, or ``None``.
    """
    records = list(interfaces)
    picked = pick_wired_interface(
        [(str(i.name), choice_value(getattr(i, "type", None)) or "") for i in records]
    )
    if picked is None:
        return None
    return next((i for i in records if str(i.name) == picked), None)
