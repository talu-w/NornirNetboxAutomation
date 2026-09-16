"""Is this subnet already on the firewall, and if so, where?

Pure functions over the raw dicts a :class:`FortiGateClient` returns — no I/O,
so this is the part with the heavy test coverage.

The question the ``fw-subnet-check`` tool answers has three outcomes:

* **not present** — no address object overlaps the queried subnet. Free to use.
* **present, unreferenced** — an object exists (exact, or a wider/narrower block
  that overlaps) but no policy points at it. A name/space collision, not a rule.
* **in use** — an overlapping object is referenced by one or more policies,
  directly or through an address group.

"Overlap" for two IP networks always means one contains the other (networks
never partially overlap); address *ranges* can partially overlap, and those are
reported with relation ``"overlap"``.

A FortiGate is in either *profile-based* NGFW mode (policies under
``firewall/policy``, GUI calls them "Policy") or *policy-based* NGFW mode
(``firewall/security-policy``, GUI calls them "Security Policy" — the factory
default on some higher-end models, e.g. the 900G/901G series). Only one is ever
populated on a given box, but ``FortiGateClient.policies()`` queries both and
tags each row with where it came from, so this module never has to care which
mode the box is in — ``PolicyRef.source`` just carries the tag through.

**Match-all objects** (``0.0.0.0/0`` / ``::/0``, or a range spanning the whole
family — FortiGate's built-in ``all``) contain *every* query, so counting them
as a "present" match would make everything look in use. They are pulled out into
``report.catch_alls`` instead: reported as informational notes, never as a real
match, and they never move the exit code.

**Interface addresses** are a separate signal again: the tool's job is "is there
an address object / policy for this subnet", not "is this IP alive on the box".
A subnet already configured on a live interface (primary, secondary, or IPv6)
goes into ``report.interfaces`` and is reported as a note — it never sets
``present``/``in_use`` and never changes the exit code, even when nothing else
matched.

**Broad supernets** (owner feedback, 2026-09-17): when an address object
*contains* the query (relation ``"supernet"``) and is wider than
``MIN_MATCH_PREFIXLEN`` for its family, it goes into ``report.broad_matches``
instead of a real match — informational, never moves the exit code. The
RFC1918 blocks (``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``) are the
classic case: routinely referenced by "deny to all private space"-style
policies, and they will always contain whatever small, manageable end-device
subnet is being checked, so counting that as a conflict would make every check
"fail". The filter is scoped to the "supernet" relation only — an *exact*
match on a broad object (you queried the ``/8`` itself) or a *subnet* relation
(a small object nested inside a broad query) are left as real matches; only
"this huge block happens to contain what I'm checking" is suppressed. The
owner only specified the IPv4 threshold (``/24`` — "usual smaller/manageable
subnets ... to support end-devices"); ``/64`` is used for IPv6 as the closest
equivalent (conventional LAN allocation size) but hasn't been confirmed —
revisit if wrong.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_POLICY_ADDR_FIELDS = ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6")

# Minimum specificity (smallest /prefix) an address object's own network must have
# to count as a real "present" match, keyed by IP version. Anything broader — a
# supernet like 10.0.0.0/8 — goes to UsageReport.broad_matches instead: a note, not
# a match. See the module docstring ("Broad supernets").
MIN_MATCH_PREFIXLEN = {4: 24, 6: 64}


@dataclass(slots=True)
class PolicyRef:
    """One firewall policy that points at a matched address (or its group)."""

    policyid: int
    name: str
    field: str  # srcaddr / dstaddr / srcaddr6 / dstaddr6
    via: str | None  # group name the reference goes through, or None if direct
    source: str = "policy"  # "policy" | "security-policy" — which CMDB endpoint

    def as_dict(self) -> dict[str, Any]:
        return {
            "policyid": self.policyid,
            "name": self.name,
            "field": self.field,
            "via": self.via,
            "source": self.source,
        }


@dataclass(slots=True)
class AddressMatch:
    """A firewall address object whose space overlaps the queried subnet."""

    name: str
    cidr: str  # normalised: "10.1.2.0/24", or "10.1.2.10-10.1.2.20" for a range
    kind: str  # "ipmask" | "ipprefix" | "iprange"
    relation: str  # "exact" | "supernet" | "subnet" | "overlap" | "catch-all"
    comment: str = ""
    groups: list[str] = field(default_factory=list)
    policies: list[PolicyRef] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "cidr": self.cidr,
            "kind": self.kind,
            "relation": self.relation,
            "comment": self.comment,
            "groups": list(self.groups),
            "policies": [ref.as_dict() for ref in self.policies],
        }


@dataclass(slots=True)
class InterfaceMatch:
    """A live FortiGate interface whose configured address overlaps the query.

    Informational only — this is not an address object or a policy, so it never
    contributes to ``UsageReport.present`` / ``attached``.
    """

    name: str  # interface name, e.g. "port10"
    vdom: str
    kind: str  # "primary" | "secondary" | "ipv6" | "ipv6-secondary"
    ip: str  # the interface's own address, e.g. "10.1.2.1/24"
    network: str  # that address's network, e.g. "10.1.2.0/24"
    relation: str  # "exact" | "supernet" | "subnet"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vdom": self.vdom,
            "kind": self.kind,
            "ip": self.ip,
            "network": self.network,
            "relation": self.relation,
        }


@dataclass(slots=True)
class UsageReport:
    query: str
    vdom: str
    family: int
    matches: list[AddressMatch] = field(default_factory=list)
    catch_alls: list[AddressMatch] = field(default_factory=list)
    broad_matches: list[AddressMatch] = field(default_factory=list)
    interfaces: list[InterfaceMatch] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.matches)

    @property
    def attached(self) -> bool:
        return any(match.policies for match in self.matches)

    @property
    def permitted_by_catch_all(self) -> bool:
        """A ``0.0.0.0/0`` / ``::/0`` object that a policy references covers this query."""
        return any(match.policies for match in self.catch_alls)

    @property
    def permitted_by_broad_match(self) -> bool:
        """A supernet wider than MIN_MATCH_PREFIXLEN that a policy references covers this query."""
        return any(match.policies for match in self.broad_matches)

    @property
    def on_interface(self) -> bool:
        """A live interface already has an address in (or containing) this range."""
        return bool(self.interfaces)

    @property
    def exact(self) -> AddressMatch | None:
        return next((m for m in self.matches if m.relation == "exact"), None)

    @property
    def policy_count(self) -> int:
        return len({ref.policyid for m in self.matches for ref in m.policies})

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "vdom": self.vdom,
            "family": self.family,
            "present": self.present,
            "in_use": self.attached,
            "permitted_by_catch_all": self.permitted_by_catch_all,
            "exact_match": self.exact.name if self.exact else None,
            "match_count": len(self.matches),
            "policy_count": self.policy_count,
            "matches": [m.as_dict() for m in self.matches],
            "catch_alls": [m.as_dict() for m in self.catch_alls],
            "permitted_by_broad_match": self.permitted_by_broad_match,
            "broad_matches": [m.as_dict() for m in self.broad_matches],
            "on_interface": self.on_interface,
            "interfaces": [m.as_dict() for m in self.interfaces],
        }


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------


def parse_query(value: str) -> IPNetwork:
    """A bare host is treated as a /32 (or /128); host bits are tolerated."""
    return ipaddress.ip_network(value.strip(), strict=False)


def _mask_to_network(raw: Any) -> IPNetwork | None:
    """FortiGate ``subnet`` is ``"10.1.2.0 255.255.255.0"`` (or a 2-item list)."""
    if isinstance(raw, (list, tuple)):
        raw = " ".join(str(part) for part in raw)
    text = str(raw or "").strip().replace(" ", "/")
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _prefix_to_network(raw: Any) -> IPNetwork | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _network_is_match_all(net: IPNetwork) -> bool:
    """``0.0.0.0/0`` or ``::/0`` — contains every address of its family."""
    return net.prefixlen == 0


def _range_is_match_all(lo: Any, hi: Any) -> bool:
    """A start/end pair that spans the entire address family."""
    return int(lo) == 0 and int(hi) == (1 << lo.max_prefixlen) - 1


def _is_broad(net: IPNetwork) -> bool:
    """Wider than MIN_MATCH_PREFIXLEN for its family — a supernet, not a real match."""
    threshold = MIN_MATCH_PREFIXLEN.get(net.version)
    return threshold is not None and net.prefixlen < threshold


def _range_is_broad(lo: Any, hi: Any) -> bool:
    """A range spanning more addresses than MIN_MATCH_PREFIXLEN allows for its family."""
    threshold = MIN_MATCH_PREFIXLEN.get(lo.version)
    if threshold is None:
        return False
    return (int(hi) - int(lo) + 1) > (1 << (lo.max_prefixlen - threshold))


def _interface_address(raw: Any, *, cidr: bool) -> tuple[Any, IPNetwork] | None:
    """One interface address -> ``(host, network)``, or ``None`` if unset.

    ``ip`` / ``secondaryip[].ip`` are FortiGate's ``"10.1.2.1 255.255.255.0"``
    mask form; ``ipv6.ip6-address`` / ``ip6-extra-addr[].prefix`` are already
    CIDR (``"2001:db8:1::1/64"``). Either way an all-zero host (``0.0.0.0`` /
    ``::``) means the interface has no address configured — not a match.
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if not cidr:
        text = text.replace(" ", "/")
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError:
        return None
    if int(iface.ip) == 0:
        return None
    return iface.ip, iface.network


def _range_bounds(obj: dict[str, Any]) -> tuple[Any, Any] | None:
    start, end = obj.get("start-ip"), obj.get("end-ip")
    if not start or not end:
        return None
    try:
        return ipaddress.ip_address(str(start)), ipaddress.ip_address(str(end))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# relation classification
# ---------------------------------------------------------------------------


def _network_relation(obj: IPNetwork, query: IPNetwork) -> str | None:
    if obj.version != query.version or not obj.overlaps(query):
        return None
    if obj == query:
        return "exact"
    if obj.supernet_of(query):
        return "supernet"
    if obj.subnet_of(query):
        return "subnet"
    return "overlap"  # unreachable for pure networks, kept for safety


def _range_relation(lo: Any, hi: Any, query: IPNetwork) -> str | None:
    if lo.version != query.version:
        return None
    q_lo = int(query.network_address)
    q_hi = int(query.broadcast_address)
    r_lo, r_hi = int(lo), int(hi)
    if r_hi < q_lo or r_lo > q_hi:
        return None
    if r_lo <= q_lo and r_hi >= q_hi:
        return "supernet"
    if r_lo >= q_lo and r_hi <= q_hi:
        return "subnet"
    return "overlap"


# ---------------------------------------------------------------------------
# group membership
# ---------------------------------------------------------------------------


def _member_names(members: Any) -> list[str]:
    names: list[str] = []
    for member in members or []:
        if isinstance(member, dict):
            name = member.get("name")
        else:
            name = member
        if name:
            names.append(str(name))
    return names


def _group_index(groups: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {
        str(group.get("name")): _member_names(group.get("member"))
        for group in groups
        if group.get("name")
    }


def _groups_containing(name: str, index: dict[str, list[str]]) -> set[str]:
    """Every group that holds ``name`` directly or through a nested group."""
    found: set[str] = set()
    stack = [name]
    while stack:
        current = stack.pop()
        for group, members in index.items():
            if current in members and group not in found:
                found.add(group)
                stack.append(group)
    return found


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def _analyze_interfaces(query: IPNetwork, interfaces: list[dict[str, Any]]) -> list[InterfaceMatch]:
    """Live interface addresses (primary, secondary, IPv6) that overlap ``query``.

    Field names beyond ``ip`` / ``secondaryip`` / ``ipv6.ip6-address`` (namely
    ``ipv6.ip6-extra-addr[].prefix`` for secondary IPv6) are a best guess at the
    FortiOS ``system/interface`` schema and should be eyeballed against a real
    FortiGate before this is relied on for IPv6 secondary addresses.
    """
    found: list[InterfaceMatch] = []
    for iface in interfaces:
        name = str(iface.get("name") or "")
        if not name:
            continue
        vdom = str(iface.get("vdom") or "")

        candidates: list[tuple[str, Any, bool]] = [("primary", iface.get("ip"), False)]
        for sec in iface.get("secondaryip") or []:
            if isinstance(sec, dict):
                candidates.append(("secondary", sec.get("ip"), False))

        ipv6 = iface.get("ipv6")
        if isinstance(ipv6, dict):
            candidates.append(("ipv6", ipv6.get("ip6-address"), True))
            for sec6 in ipv6.get("ip6-extra-addr") or []:
                if isinstance(sec6, dict):
                    raw6 = sec6.get("prefix") or sec6.get("ip6-address")
                    candidates.append(("ipv6-secondary", raw6, True))

        for kind, raw, cidr in candidates:
            parsed = _interface_address(raw, cidr=cidr)
            if parsed is None:
                continue
            host, net = parsed
            if net.version != query.version:
                continue
            relation = _network_relation(net, query)
            if relation is None:
                continue
            found.append(
                InterfaceMatch(
                    name=name,
                    vdom=vdom,
                    kind=kind,
                    ip=f"{host}/{net.prefixlen}",
                    network=str(net),
                    relation=relation,
                )
            )

    found.sort(key=lambda m: (_RELATION_ORDER.get(m.relation, 9), m.name, m.kind))
    return found


def analyze(
    query: IPNetwork,
    addresses: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    *,
    interfaces: list[dict[str, Any]] | None = None,
    vdom: str = "root",
) -> UsageReport:
    report = UsageReport(query=str(query), vdom=vdom, family=query.version)
    report.interfaces = _analyze_interfaces(query, interfaces or [])

    group_index = _group_index(groups)

    # name -> [(policyid, policy name, field, source), ...]
    references: dict[str, list[tuple[int, str, str, str]]] = {}
    for policy in policies:
        try:
            pid = int(policy.get("policyid", 0))
        except (TypeError, ValueError):
            pid = 0
        pname = str(policy.get("name", "") or "")
        source = str(policy.get("_bunnyauto_policy_source") or "policy")
        for pol_field in _POLICY_ADDR_FIELDS:
            for ref_name in _member_names(policy.get(pol_field)):
                references.setdefault(ref_name, []).append((pid, pname, pol_field, source))

    for obj in addresses:
        name = str(obj.get("name") or "")
        if not name:
            continue
        kind = str(obj.get("type") or "")

        net = _mask_to_network(obj.get("subnet"))
        if net is None and obj.get("ip6"):
            net = _prefix_to_network(obj.get("ip6"))
            if net is not None:
                kind = kind or "ipprefix"

        match_all = False
        broad = False
        if net is not None:
            cidr = str(net)
            kind = kind or "ipmask"
            if net.version == query.version and _network_is_match_all(net):
                match_all, relation = True, "catch-all"
            else:
                relation = _network_relation(net, query)
                if relation == "supernet" and _is_broad(net):
                    broad = True
        else:
            bounds = _range_bounds(obj)
            if bounds is None:
                continue  # fqdn / geography / dynamic / mac — no address space
            lo, hi = bounds
            cidr = f"{lo}-{hi}"
            kind = kind or "iprange"
            if lo.version == query.version and _range_is_match_all(lo, hi):
                match_all, relation = True, "catch-all"
            else:
                relation = _range_relation(lo, hi, query)
                if relation == "supernet" and _range_is_broad(lo, hi):
                    broad = True

        if relation is None:
            continue

        match = AddressMatch(
            name=name,
            cidr=cidr,
            kind=kind,
            relation=relation,
            comment=str(obj.get("comment", "") or ""),
        )

        containing = _groups_containing(name, group_index)
        match.groups = sorted(containing)

        seen: set[tuple[int, str, str, str | None]] = set()
        for pid, pname, pol_field, source in references.get(name, []):
            key = (pid, pname, pol_field, None)
            if key not in seen:
                seen.add(key)
                match.policies.append(PolicyRef(pid, pname, pol_field, None, source))
        for group in sorted(containing):
            for pid, pname, pol_field, source in references.get(group, []):
                key = (pid, pname, pol_field, group)
                if key not in seen:
                    seen.add(key)
                    match.policies.append(PolicyRef(pid, pname, pol_field, group, source))

        match.policies.sort(key=lambda ref: (ref.policyid, ref.field, ref.via or ""))
        if match_all:
            report.catch_alls.append(match)
        elif broad:
            report.broad_matches.append(match)
        else:
            report.matches.append(match)

    report.matches.sort(key=lambda m: (_RELATION_ORDER.get(m.relation, 9), m.cidr, m.name))
    report.catch_alls.sort(key=lambda m: (m.cidr, m.name))
    report.broad_matches.sort(key=lambda m: (_RELATION_ORDER.get(m.relation, 9), m.cidr, m.name))
    return report


_RELATION_ORDER = {"exact": 0, "supernet": 1, "subnet": 2, "overlap": 3}
