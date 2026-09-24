"""NetBox IPAM: which prefix holds an address, and making an address a device's primary IP.

:func:`find_prefix` is pure. NetBox prefixes can nest (``10.0.0.0/8`` and
``10.1.1.0/24`` both contain ``10.1.1.5``), and the **narrowest** containing
prefix (largest prefix length) wins. A tie between two equally specific
prefixes is ambiguous and returns ``None``, so the caller reports it rather than
guessing, the same rule as :func:`bunnyauto.aruba.sitematch.match_site`.

:func:`plan_primary_ip` / :func:`apply_ip_plan` came out of ``wireless sync``.
They are the one way a tool puts an IP on a device's wired interface and makes
it the device's primary IP, so any future onboarding tool (wired or otherwise)
does it the same way. Planning is separate from writing, so plan mode shows the
exact interface before anything changes. When the device itself reports which
port it's connected on (an AP's LLDP ``Interface``), that port wins, and an IP
NetBox has on another of the device's interfaces is **moved** there. Without
that, an IP is never moved. Nothing here creates a Prefix or an IP Range, or
takes an IP another device's interface already holds.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, NamedTuple

from bunnyauto.netbox.interfaces import match_interface, pick_wired_record
from bunnyauto.netbox.records import related_id

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Created only when a device has no wired interface at all (no device-type
#: template) and didn't report the port it's connected on — a last resort.
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


@dataclass(slots=True)
class IpPlan:
    """How to make ``address`` a device's primary IP, as :func:`plan_primary_ip` decided.

    Nothing is written until :func:`apply_ip_plan`. A ``blocked`` plan carries the
    reason in ``note`` and is never applied.
    """

    address: str  # "10.1.1.5/24"
    vrf_id: int | None = None
    interface_name: str = ""
    #: The target interface's id; ``None`` when it has to be created first.
    interface_id: int | None = None
    #: Why that interface: ``"live"`` (the device reports it's connected there),
    #: ``"netbox"`` (the IP is already on it), ``"first-wired"`` or ``"fallback"``.
    source: str = ""
    #: The existing NetBox IP record; ``None`` means create one.
    ip: Any = None
    #: The existing IP isn't on the target interface yet (unassigned, or moving).
    attach: bool = False
    #: The interface on this device the IP sits on now, when it has to move.
    moved_from: str = ""
    set_primary: bool = False
    blocked: bool = False
    note: str = ""

    @property
    def primary_field(self) -> str:
        """``primary_ip4`` or ``primary_ip6``, by the address family."""
        return "primary_ip6" if ":" in self.address else "primary_ip4"

    @property
    def in_sync(self) -> bool:
        """Already exactly right in NetBox: nothing to write."""
        return not (
            self.blocked
            or self.interface_id is None
            or self.ip is None
            or self.attach
            or self.set_primary
        )


def plan_primary_ip(
    *,
    address: str,
    vrf_id: int | None,
    interfaces: list[Any],
    live_ports: list[str] | None = None,
    existing_ips: list[Any] | None = None,
    primary_ip_id: int | None = None,
) -> IpPlan:
    """Decide which interface ``address`` belongs on, and what has to change. No I/O.

    ``interfaces`` are the device's NetBox interfaces. For a device that doesn't
    exist yet, pass a preview built from its device type's interface template,
    with ``id`` 0 (NetBox creates the same interfaces with the device).
    ``existing_ips`` are the NetBox IP records with this address; the one in
    ``vrf_id`` is the one that counts. ``primary_ip_id`` is the device's current
    primary IP of the same family.

    The interface, in order:

    1. ``live_ports``, the ports the device itself reports it's connected on (an
       AP's LLDP ``Interface``, ``eth1`` ≡ ``E1``). With more than one, the one
       the IP is already on stays; otherwise the first by name. If none of them
       exists on the device: a device with no wired interface at all gets the
       reported port created, but one with other wired ports is **blocked**,
       since NetBox and the device disagree about its hardware.
    2. Without live ports, the interface of this device the IP is already on. It
       is never moved on a guess.
    3. The device's first wired interface by name, or, when it has none,
       :data:`FALLBACK_INTERFACE_NAME` (created).

    An IP already assigned to something that isn't one of this device's
    interfaces is **blocked**, never taken over.
    """
    plan = IpPlan(address=address, vrf_id=vrf_id)
    same_vrf = [ip for ip in existing_ips or [] if related_id(getattr(ip, "vrf", None)) == vrf_id]
    if len(same_vrf) > 1:
        plan.blocked = True
        plan.note = f"NetBox has {len(same_vrf)} copies of {address} in that VRF — left alone"
        return plan
    existing = same_vrf[0] if same_vrf else None

    ours = {int(i.id): i for i in interfaces if int(getattr(i, "id", 0) or 0)}
    current = None
    if existing is not None:
        assigned_id = related_id(getattr(existing, "assigned_object_id", None))
        if assigned_id is not None:
            assigned_type = str(getattr(existing, "assigned_object_type", None) or "")
            if assigned_type in ("", "dcim.interface"):
                current = ours.get(assigned_id)
            if current is None:
                plan.blocked = True
                plan.note = (
                    f"{address} is already assigned to another device's interface in "
                    "NetBox — left alone"
                )
                return plan

    names = [str(i.name) for i in interfaces]
    live: list[str] = []
    for port in live_ports or []:
        name = match_interface(port, names)
        if name is not None and name not in live:
            live.append(name)

    target = None
    if live_ports:
        plan.source = "live"
        if live:
            keep = current is not None and str(current.name) in live
            target = current if keep else next(i for i in interfaces if str(i.name) == min(live))
        elif pick_wired_record(interfaces) is None:
            plan.interface_name = live_ports[0]
        else:
            plan.blocked = True
            plan.note = (
                f"the device reports it's connected on {', '.join(live_ports)}, but its "
                "NetBox interfaces have no match — left alone"
            )
            return plan
    elif current is not None:
        target, plan.source = current, "netbox"
    else:
        target = pick_wired_record(interfaces)
        plan.source = "first-wired"
        if target is None:
            plan.interface_name, plan.source = FALLBACK_INTERFACE_NAME, "fallback"

    if target is not None:
        plan.interface_name, plan.interface_id = str(target.name), int(target.id)
    plan.ip = existing
    if existing is not None:
        on_target = current is not None and target is not None and int(current.id) == int(target.id)
        plan.attach = not on_target
        if current is not None and not on_target:
            plan.moved_from = str(current.name)
    plan.set_primary = existing is None or primary_ip_id != int(existing.id)
    return plan


def apply_ip_plan(nb: Any, device: Any, plan: IpPlan) -> str | None:
    """Write what :func:`plan_primary_ip` decided. ``None`` on success, else the error text."""
    if plan.blocked or plan.in_sync:
        return None
    try:
        interface_id = plan.interface_id
        if interface_id is None:
            interface = nb.dcim.interfaces.create(
                {"device": int(device.id), "name": plan.interface_name, "type": "other"}
            )
            interface_id = int(interface.id)
        link = {"assigned_object_type": "dcim.interface", "assigned_object_id": interface_id}
        if plan.ip is None:
            body: dict[str, Any] = {"address": plan.address, "status": "active", **link}
            if plan.vrf_id is not None:
                body["vrf"] = plan.vrf_id
            ip_id = int(nb.ipam.ip_addresses.create(body).id)
        else:
            ip_id = int(plan.ip.id)
            if plan.attach:
                plan.ip.update(link)
        if plan.set_primary:
            device.update({plan.primary_field: ip_id})
    except Exception as exc:  # pynetbox RequestError etc.
        return str(exc)
    return None
