"""Tests for the pure subnet-usage analysis (no HTTP, no FortiGate)."""

from __future__ import annotations

import json

import pytest

from bunnyauto.firewall.usage import analyze, parse_query

# --- FortiGate-shaped fixtures -------------------------------------------

NET_HQ = {"name": "net_hq", "type": "ipmask", "subnet": "10.1.0.0 255.255.0.0", "comment": "HQ"}
NET_HQ_SLASH = {"name": "net_hq", "type": "ipmask", "subnet": "10.1.0.0/16"}
SUB_2 = {"name": "vlan2", "type": "ipmask", "subnet": "10.1.2.0 255.255.255.0"}
V6_LAB = {"name": "v6_lab", "type": "ipprefix", "ip6": "2001:db8:1::/64"}
DHCP_POOL = {"name": "dhcp_pool", "type": "iprange", "start-ip": "10.1.2.10", "end-ip": "10.1.2.50"}
FQDN = {"name": "ext_host", "type": "fqdn", "fqdn": "example.com"}


def _policy(pid, name, **fields):
    base = {"policyid": pid, "name": name}
    base.update({k: [{"name": n} for n in v] for k, v in fields.items()})
    return base


# --- presence -----------------------------------------------------------


def test_not_present_when_nothing_overlaps():
    report = analyze(parse_query("192.168.9.0/24"), [NET_HQ], [], [])
    assert report.present is False
    assert report.attached is False
    assert report.as_dict()["match_count"] == 0


def test_fqdn_and_wrong_family_are_ignored():
    report = analyze(parse_query("10.9.9.0/24"), [FQDN, V6_LAB], [], [])
    assert report.present is False


def test_exact_match_without_policy_is_present_but_unattached():
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], [], [])
    assert report.present is True
    assert report.attached is False
    assert report.exact is not None
    assert report.exact.name == "net_hq"
    assert report.matches[0].relation == "exact"


@pytest.mark.parametrize("obj", [NET_HQ, NET_HQ_SLASH])
def test_subnet_field_accepts_mask_or_slash(obj):
    report = analyze(parse_query("10.1.0.0/16"), [obj], [], [])
    assert report.matches[0].cidr == "10.1.0.0/16"


# --- relation classification ------------------------------------------


def test_supernet_relation_and_direct_policy():
    pol = _policy(12, "hq-out", dstaddr=["net_hq"])
    report = analyze(parse_query("10.1.2.0/24"), [NET_HQ], [], [pol])
    match = report.matches[0]
    assert match.relation == "supernet"
    assert match.policies[0].via is None
    assert match.policies[0].field == "dstaddr"
    assert match.policies[0].policyid == 12
    assert report.attached is True


def test_subnet_relation():
    report = analyze(parse_query("10.1.0.0/16"), [SUB_2], [], [])
    assert report.matches[0].relation == "subnet"


def test_iprange_inside_query_is_subnet():
    report = analyze(parse_query("10.1.2.0/24"), [DHCP_POOL], [], [])
    m = report.matches[0]
    assert m.kind == "iprange"
    assert m.relation == "subnet"
    assert m.cidr == "10.1.2.10-10.1.2.50"


def test_iprange_partial_overlap():
    report = analyze(parse_query("10.1.2.0/28"), [DHCP_POOL], [], [])
    assert report.matches[0].relation == "overlap"


# --- group resolution -------------------------------------------------


def test_policy_reference_through_a_group():
    groups = [{"name": "grp-internal", "member": [{"name": "net_hq"}, {"name": "other"}]}]
    pol = _policy(5, "internal", srcaddr=["grp-internal"])
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], groups, [pol])
    match = report.matches[0]
    assert match.groups == ["grp-internal"]
    assert match.policies[0].via == "grp-internal"
    assert match.policies[0].field == "srcaddr"


def test_nested_groups_are_followed():
    groups = [
        {"name": "grp-a", "member": [{"name": "net_hq"}]},
        {"name": "grp-b", "member": [{"name": "grp-a"}]},
    ]
    pol = _policy(7, "nested", dstaddr=["grp-b"])
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], groups, [pol])
    match = report.matches[0]
    assert set(match.groups) == {"grp-a", "grp-b"}
    assert match.policies[0].via == "grp-b"


def test_duplicate_policy_references_are_deduped():
    groups = [{"name": "g", "member": [{"name": "net_hq"}]}]
    # same policy references both the object directly and its group
    pol = _policy(9, "dup", srcaddr=["net_hq"], dstaddr=["g"])
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], groups, [pol])
    refs = report.matches[0].policies
    assert len(refs) == 2  # (9, srcaddr, direct) and (9, dstaddr, via g)
    assert {r.field for r in refs} == {"srcaddr", "dstaddr"}


# --- IPv6 -----------------------------------------------------------


def test_ipv6_exact_match():
    pol = _policy(20, "v6", srcaddr6=["v6_lab"])
    report = analyze(parse_query("2001:db8:1::/64"), [V6_LAB], [], [pol])
    assert report.family == 6
    assert report.matches[0].relation == "exact"
    assert report.matches[0].policies[0].field == "srcaddr6"


# --- output shape --------------------------------------------------


def test_report_as_dict_is_json_serialisable():
    groups = [{"name": "g", "member": [{"name": "net_hq"}]}]
    pol = _policy(1, "p", srcaddr=["g"])
    report = analyze(parse_query("10.1.2.0/24"), [NET_HQ, SUB_2], groups, [pol], vdom="root")
    payload = report.as_dict()
    json.dumps(payload)  # must not raise
    assert payload["query"] == "10.1.2.0/24"
    assert payload["in_use"] is True
    assert payload["policy_count"] == 1
    # exact match (vlan2) sorts before the supernet (net_hq)
    assert [m["relation"] for m in payload["matches"]] == ["exact", "supernet"]


def test_parse_query_bare_host_is_a_single_address():
    assert str(parse_query("10.1.2.5")) == "10.1.2.5/32"
    assert str(parse_query("10.1.2.5/24")) == "10.1.2.0/24"  # host bits tolerated
