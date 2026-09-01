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
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_POLICY_ADDR_FIELDS = ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6")


@dataclass(slots=True)
class PolicyRef:
    """One firewall policy that points at a matched address (or its group)."""

    policyid: int
    name: str
    field: str  # srcaddr / dstaddr / srcaddr6 / dstaddr6
    via: str | None  # group name the reference goes through, or None if direct

    def as_dict(self) -> dict[str, Any]:
        return {
            "policyid": self.policyid,
            "name": self.name,
            "field": self.field,
            "via": self.via,
        }


@dataclass(slots=True)
class AddressMatch:
    """A firewall address object whose space overlaps the queried subnet."""

    name: str
    cidr: str  # normalised: "10.1.2.0/24", or "10.1.2.10-10.1.2.20" for a range
    kind: str  # "ipmask" | "ipprefix" | "iprange"
    relation: str  # "exact" | "supernet" | "subnet" | "overlap"
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
class UsageReport:
    query: str
    vdom: str
    family: int
    matches: list[AddressMatch] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.matches)

    @property
    def attached(self) -> bool:
        return any(match.policies for match in self.matches)

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
            "exact_match": self.exact.name if self.exact else None,
            "match_count": len(self.matches),
            "policy_count": self.policy_count,
            "matches": [m.as_dict() for m in self.matches],
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
    if not text or text in {"::/0"}:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


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


def analyze(
    query: IPNetwork,
    addresses: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    policies: list[dict[str, Any]],
    *,
    vdom: str = "root",
) -> UsageReport:
    report = UsageReport(query=str(query), vdom=vdom, family=query.version)

    group_index = _group_index(groups)

    # name -> [(policyid, policy name, field), ...]
    references: dict[str, list[tuple[int, str, str]]] = {}
    for policy in policies:
        try:
            pid = int(policy.get("policyid", 0))
        except (TypeError, ValueError):
            pid = 0
        pname = str(policy.get("name", "") or "")
        for pol_field in _POLICY_ADDR_FIELDS:
            for ref_name in _member_names(policy.get(pol_field)):
                references.setdefault(ref_name, []).append((pid, pname, pol_field))

    for obj in addresses:
        name = str(obj.get("name") or "")
        if not name:
            continue
        kind = str(obj.get("type") or "")

        net = _mask_to_network(obj.get("subnet"))
        if net is None and obj.get("ip6"):
            net = _prefix_to_network(obj.get("ip6"))
            kind = kind or "ipprefix"

        if net is not None:
            relation = _network_relation(net, query)
            cidr = str(net)
            kind = kind or "ipmask"
        else:
            bounds = _range_bounds(obj)
            if bounds is None:
                continue  # fqdn / geography / dynamic / mac — no address space
            relation = _range_relation(bounds[0], bounds[1], query)
            cidr = f"{bounds[0]}-{bounds[1]}"
            kind = kind or "iprange"

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
        for pid, pname, pol_field in references.get(name, []):
            key = (pid, pname, pol_field, None)
            if key not in seen:
                seen.add(key)
                match.policies.append(PolicyRef(pid, pname, pol_field, None))
        for group in sorted(containing):
            for pid, pname, pol_field in references.get(group, []):
                key = (pid, pname, pol_field, group)
                if key not in seen:
                    seen.add(key)
                    match.policies.append(PolicyRef(pid, pname, pol_field, group))

        match.policies.sort(key=lambda ref: (ref.policyid, ref.field, ref.via or ""))
        report.matches.append(match)

    report.matches.sort(key=lambda m: (_RELATION_ORDER.get(m.relation, 9), m.cidr, m.name))
    return report


_RELATION_ORDER = {"exact": 0, "supernet": 1, "subnet": 2, "overlap": 3}
