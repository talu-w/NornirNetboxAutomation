"""NetBox IPAM: which prefix holds an address, and making an address a device's primary IP.

:func:`find_prefix` is pure. NetBox prefixes can nest (``10.0.0.0/8`` and
``10.1.1.0/24`` both contain ``10.1.1.5``), and the **narrowest** containing
prefix (largest prefix length) wins. A tie between two equally specific
prefixes is ambiguous and returns ``None``, so the caller reports it rather than
guessing, the same rule as :func:`bunnyauto.aruba.sitematch.match_site`.

:func:`assign_primary_ip` came out of ``wireless sync``. It is the one way a
tool creates or attaches an IP on a device's wired interface and sets it as the
device's primary IPv4, so any future onboarding tool (wired or otherwise) does
it the same way. It never creates a Prefix or an IP Range.
"""

from __future__ import annotations

import ipaddress
from typing import Any, NamedTuple

from bunnyauto.netbox.interfaces import pick_wired_record

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Created only when a device has no wired interface at all (no device-type
#: template) and no explicit interface was requested — a last resort.
FALLBACK_INTERFACE_NAME = "Ethernet0"


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


def load_prefixes(nb: Any) -> list[Prefix]:
    """Every NetBox Prefix, parsed to a CIDR network. Malformed ones are skipped."""
    prefixes: list[Prefix] = []
    for p in nb.ipam.prefixes.all():
        try:
            network = ipaddress.ip_network(str(p.prefix), strict=False)
        except ValueError:
            continue
        vrf = getattr(p, "vrf", None)
        vrf_id = int(vrf.id) if vrf is not None else None
        prefixes.append(Prefix(id=int(p.id), network=network, vrf_id=vrf_id))
    return prefixes


def assign_primary_ip(
    nb: Any,
    *,
    device: Any,
    address: str,
    vrf_id: int | None,
    interface_name: str | None = None,
) -> tuple[str, str]:
    """Create/attach ``address`` on ``device`` and make it the primary IPv4.

    ``interface_name``, if given, is used exactly (created if the device doesn't
    have it, since an explicit override is trusted as-is). Otherwise the device's
    own interfaces, normally already populated from its NetBox device type's
    interface template (wired ports alongside any radios), are searched for the
    first wired-Ethernet interface by name
    (:func:`bunnyauto.netbox.interfaces.pick_wired_record`). A device with no
    wired interface at all gets :data:`FALLBACK_INTERFACE_NAME` created as a last
    resort.

    Returns ``(status, detail)``. ``status`` is ``"created"``, ``"exists"``, or
    ``"error"``. ``detail`` is the interface name used on success, or the error
    text on failure.
    """
    try:
        interfaces = list(nb.dcim.interfaces.filter(device_id=int(device.id)))
        if interface_name:
            interface = next((i for i in interfaces if str(i.name) == interface_name), None)
            if interface is None:
                interface = nb.dcim.interfaces.create(
                    {"device": int(device.id), "name": interface_name, "type": "other"}
                )
        else:
            interface = pick_wired_record(interfaces)
            if interface is None:
                interface = nb.dcim.interfaces.create(
                    {
                        "device": int(device.id),
                        "name": FALLBACK_INTERFACE_NAME,
                        "type": "other",
                    }
                )

        existing = nb.ipam.ip_addresses.get(address=address)
        if existing is None:
            body: dict[str, Any] = {
                "address": address,
                "status": "active",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": int(interface.id),
            }
            if vrf_id is not None:
                body["vrf"] = vrf_id
            ip_obj = nb.ipam.ip_addresses.create(body)
            result = "created"
        else:
            if getattr(existing, "assigned_object_id", None) != int(interface.id):
                existing.update(
                    {
                        "assigned_object_type": "dcim.interface",
                        "assigned_object_id": int(interface.id),
                    }
                )
            ip_obj = existing
            result = "exists"

        device.update({"primary_ip4": int(ip_obj.id)})
    except Exception as exc:  # pynetbox RequestError etc.
        return "error", str(exc)
    return result, str(interface.name)
