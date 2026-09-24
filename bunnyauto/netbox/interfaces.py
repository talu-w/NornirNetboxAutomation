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

**Types.** :func:`port_media` reads a port's NetBox type from what the device
itself reports (the ``media type is ...`` line of ``show interfaces``):
``10/100/1000BaseTX`` is ``1000base-tx``, ``SFP-10GBase-SR`` on ``Te1/1/1`` is an
SFP+ cage. :func:`type_fits` says whether a NetBox interface's type already
agrees with that. :func:`interface_type` is the fallback, a guess from the name
alone, used only when the device says nothing. :func:`is_wired_type` and
:func:`pick_wired_interface` classify NetBox type slugs, so an IP or a cable
lands on a wired port and never on a Wi-Fi, Bluetooth or Zigbee radio.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
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

#: Canonical family -> the port's line rate in Mb/s. Cisco names a transceiver
#: cage for the fastest optic it takes (``Te1/1/1`` stays ``Te`` with a 1G SFP in it).
_FAMILY_SPEEDS: dict[str, int] = {
    "fa": 100,
    "gi": 1_000,
    "tw": 2_500,
    "fi": 5_000,
    "te": 10_000,
    "twe": 25_000,
    "fo": 40_000,
    "hu": 100_000,
    "fou": 400_000,
}

#: A copper port's line rate -> its NetBox type.
_COPPER_TYPES: dict[int, str] = {
    100: "100base-tx",
    1_000: "1000base-t",
    2_500: "2.5gbase-t",
    5_000: "5gbase-t",
    10_000: "10gbase-t",
    25_000: "25gbase-t",
}
#: Cisco's ``10/100/1000BaseTX``, preferred first. ``1000base-tx`` is newer in
#: NetBox than ``1000base-t``, so an older NetBox falls back to the latter.
_GIGABIT_TX_TYPES = ("1000base-tx", "1000base-t")

#: A transceiver cage's line rate -> its NetBox type. The cage, not the optic in
#: it, so swapping an SR for an LR never changes NetBox.
_CAGE_TYPES: dict[int, str] = {
    100: "100base-x-sfp",
    1_000: "1000base-x-sfp",
    2_500: "2.5gbase-x-sfp",
    10_000: "10gbase-x-sfpp",
    25_000: "25gbase-x-sfp28",
    40_000: "40gbase-x-qsfpp",
    50_000: "50gbase-x-sfp56",
    100_000: "100gbase-x-qsfp28",
    200_000: "200gbase-x-qsfp56",
    400_000: "400gbase-x-qsfpdd",
}

#: Media types that say nothing about the port (Port-Channels, virtual ports).
#: Compared with whitespace and underscores removed.
_NO_MEDIA = frozenset({"", "unknown", "unknownmediatype", "n/a", "na", "none", "-", "--"})
#: An empty transceiver cage: it's a cage, but there's no optic to name.
_EMPTY_CAGE = frozenset({"notpresent", "notransceiver", "noxcvr", "nogbic", "nosfp"})
#: A pluggable form factor named in the media type (``SFP-10GBase-SR``, ``QSFP 40G SR4``).
_PLUGGABLE = re.compile(r"(?<![a-z])(?:q?sfp|osfp|cfp|gbic|xenpak|xfp|x2(?!\d))")
#: The PMD after ``Base``: ``tx``/``t`` is copper, anything else (``sr``, ``lx``) an optic.
_PMD = re.compile(r"base-?([a-z]+)")
_RJ45 = re.compile(r"rj-?45")
#: Each rate a media type lists: ``10/100/1000`` (Mb/s), ``2.5G/5G/10G``, ``40G``.
_MEDIA_SPEED = re.compile(r"(?<![a-z0-9.])(\d+(?:\.\d+)?)(g?)(?=base|/|-|\s|$)")
#: The line rate a NetBox Ethernet type slug starts with (``10gbase-``, ``1000base-``).
_TYPE_SPEED = re.compile(r"^(\d+(?:\.\d+)?)(g?)base-")
_TWISTED_PAIR = re.compile(r"^[\d.]+g?base-t(?:x|1)?$")

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
    ``virtual``; physical families map to their speed's type. A guess from the
    name alone (``Gi`` could be copper or an SFP cage), so it's only the
    fallback when the device reports no usable media type (:func:`port_media`).
    """
    family, _rest = interface_signature(name)
    return _FAMILY_TYPES.get(family, "other")


@dataclass(frozen=True, slots=True)
class PortMedia:
    """The NetBox type a device's own media report gives one port."""

    #: As the device reported it, for messages.
    media: str
    #: NetBox type slugs, preferred first (see :func:`supported_type`).
    types: tuple[str, ...]
    #: A transceiver cage, where any pluggable or optical type of ``speed`` fits.
    cage: bool
    #: Line rate in Mb/s.
    speed: int


def media_is_blank(media: str) -> bool:
    """True if a reported media type says nothing about the port (``""``, ``unknown``, ``N/A``)."""
    return _compact_media(media) in _NO_MEDIA


def port_media(name: str, media: str) -> PortMedia | None:
    """What the device's media type says port ``name``'s NetBox type is.

    ``media`` is the ``media type is ...`` value from ``show interfaces``.

    * **Copper** (``...BaseTX``, ``...BaseT``, ``RJ45``): the copper type of the
      fastest rate listed, T and TX as reported. ``10/100/1000BaseTX`` is
      ``1000base-tx``, ``100/1000/2.5G/5G/10GBaseTX`` is ``10gbase-t``.
    * **Transceiver cage** (an optic such as ``SFP-10GBase-SR`` or ``1000BaseSX
      SFP``, or ``Not Present``): the cage type for the port's own speed, read
      from its name (``Te`` is SFP+ even with a 1G optic in it), so swapping an
      optic never changes NetBox. The optic's rate is used only when the name
      carries none (``Ethernet1/1``).

    ``None`` when the report says nothing (:func:`media_is_blank`), isn't
    recognised, or is ambiguous (copper *and* a form factor, e.g. a
    dual-purpose ``10/100/1000BaseTX SFP`` port). Never a guess.
    """
    text = str(media or "").strip().casefold()
    compact = _compact_media(text)
    if compact in _NO_MEDIA:
        return None
    family, _rest = interface_signature(name)
    port_speed = _FAMILY_SPEEDS.get(family)
    if compact in _EMPTY_CAGE:
        return _cage(media, port_speed)

    pmd = _PMD.search(text)
    flavor = pmd.group(1) if pmd else ""
    copper = flavor in {"t", "tx"} or bool(_RJ45.search(text))
    pluggable = bool(_PLUGGABLE.search(text)) or (bool(flavor) and not copper)
    if copper == pluggable:  # ambiguous, or neither
        return None

    rates = [
        round(float(value) * (1_000 if giga else 1)) for value, giga in _MEDIA_SPEED.findall(text)
    ]
    reported = max(rates, default=None)
    if pluggable:
        return _cage(media, port_speed or reported)

    speed = reported or port_speed
    if speed == 1_000 and flavor == "tx":
        return PortMedia(str(media).strip(), _GIGABIT_TX_TYPES, cage=False, speed=speed)
    copper_type = _COPPER_TYPES.get(speed or 0)
    if copper_type is None:
        return None
    return PortMedia(str(media).strip(), (copper_type,), cage=False, speed=int(speed or 0))


def supported_type(types: Iterable[str], supported: Collection[str] | None) -> str | None:
    """The first of ``types`` this NetBox accepts, else ``None``.

    ``supported`` is NetBox's own list of interface type values. When it
    couldn't be read (``None``), the last, longest-standing type is used.
    """
    candidates = list(types)
    if supported is None:
        return candidates[-1] if candidates else None
    return next((t for t in candidates if t in supported), None)


def type_fits(port: PortMedia, current: str | None, wanted: str) -> bool:
    """Whether a NetBox interface's ``current`` type already agrees with ``port``.

    ``wanted`` is the type :func:`supported_type` picked for ``port``. A copper
    port must be exactly that: ``1000base-t`` is not ``BaseTX``. A transceiver
    cage accepts any non-copper type of its speed, so an SFP+ port someone
    modelled as ``10gbase-sr`` or X2 is left alone.
    """
    value = str(current or "").strip().casefold()
    if value == wanted:
        return True
    if not port.cage or _TWISTED_PAIR.match(value):
        return False
    return _type_speed(value) == port.speed


def _compact_media(media: str) -> str:
    return re.sub(r"[\s_]+", "", str(media or "")).casefold()


def _cage(media: str, speed: int | None) -> PortMedia | None:
    cage_type = _CAGE_TYPES.get(speed or 0)
    if cage_type is None:
        return None
    return PortMedia(str(media).strip(), (cage_type,), cage=True, speed=int(speed or 0))


def _type_speed(slug: str) -> int | None:
    """The line rate (Mb/s) a NetBox Ethernet type slug names, else ``None``."""
    match = _TYPE_SPEED.match(slug)
    if not match:
        return None
    value, giga = match.groups()
    return round(float(value) * (1_000 if giga else 1))


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
