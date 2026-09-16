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
ALL_V4 = {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"}
ALL_V6 = {"name": "all6", "type": "ipprefix", "ip6": "::/0"}
ALL_RANGE = {
    "name": "all_range",
    "type": "iprange",
    "start-ip": "0.0.0.0",
    "end-ip": "255.255.255.255",
}


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


def test_broad_supernet_is_not_a_match_but_is_noted():
    """Owner feedback 2026-09-17: a /16 swallowing a /24 query must not read as a fail."""
    pol = _policy(12, "hq-out", dstaddr=["net_hq"])
    report = analyze(parse_query("10.1.2.0/24"), [NET_HQ], [], [pol])
    assert report.present is False
    assert report.matches == []
    match = report.broad_matches[0]
    assert match.relation == "supernet"
    assert match.name == "net_hq"
    assert match.policies[0].via is None
    assert match.policies[0].field == "dstaddr"
    assert match.policies[0].policyid == 12
    assert report.attached is False  # attached only looks at real matches
    assert report.permitted_by_broad_match is True


def test_supernet_at_the_threshold_prefixlen_still_counts():
    """/24 is the floor, not excluded — only *wider* than /24 is treated as broad."""
    report = analyze(parse_query("10.1.2.8/30"), [SUB_2], [], [])
    assert report.present is True
    assert report.broad_matches == []
    assert report.matches[0].relation == "supernet"


def test_exact_match_on_a_broad_object_still_counts():
    """The broad-supernet filter only applies to the 'supernet' relation, not 'exact'."""
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], [], [])
    assert report.present is True
    assert report.broad_matches == []
    assert report.matches[0].relation == "exact"


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


# --- match-all / catch-all objects ----------------------------------


@pytest.mark.parametrize("obj", [ALL_V4, ALL_RANGE])
def test_match_all_v4_object_is_not_a_match(obj):
    pol = _policy(1, "allow-any", srcaddr=["all", "all_range"])
    report = analyze(parse_query("192.168.32.0/24"), [obj], [], [pol])
    assert report.present is False
    assert report.attached is False
    assert report.matches == []
    assert [m.name for m in report.catch_alls] == [obj["name"]]
    assert report.catch_alls[0].relation == "catch-all"
    assert report.permitted_by_catch_all is True


def test_match_all_v6_object_is_not_a_match():
    pol = _policy(2, "v6-any", srcaddr6=["all6"])
    report = analyze(parse_query("2001:db8:99::/64"), [ALL_V6], [], [pol])
    assert report.present is False
    assert report.catch_alls[0].name == "all6"
    assert report.permitted_by_catch_all is True


def test_match_all_wrong_family_is_dropped_entirely():
    report = analyze(parse_query("2001:db8::/64"), [ALL_V4], [], [])
    assert report.catch_alls == []
    assert report.present is False


def test_match_all_alongside_a_real_match_still_drifts():
    pol = _policy(3, "p", dstaddr=["vlan2"])
    report = analyze(parse_query("10.1.2.0/24"), [ALL_V4, SUB_2], [], [pol])
    assert report.present is True
    assert report.attached is True
    assert [m.name for m in report.matches] == ["vlan2"]
    assert [m.name for m in report.catch_alls] == ["all"]


def test_unreferenced_match_all_is_reported_but_not_permitting():
    report = analyze(parse_query("10.5.5.0/24"), [ALL_V4], [], [])
    assert report.catch_alls[0].name == "all"
    assert report.permitted_by_catch_all is False
    payload = report.as_dict()
    assert payload["permitted_by_catch_all"] is False
    assert payload["catch_alls"][0]["name"] == "all"


# --- interface addresses ----------------------------------------------

IFACE_PRIMARY = {"name": "port10", "vdom": "root", "ip": "10.1.2.1 255.255.255.0"}
IFACE_UNSET = {"name": "port11", "vdom": "root", "ip": "0.0.0.0 0.0.0.0"}
IFACE_SECONDARY = {
    "name": "port12",
    "vdom": "root",
    "ip": "0.0.0.0 0.0.0.0",
    "secondaryip": [{"id": 1, "ip": "10.1.2.5 255.255.255.0"}],
}
IFACE_V6 = {"name": "port13", "vdom": "root", "ipv6": {"ip6-address": "2001:db8:1::1/64"}}
IFACE_V6_UNSET = {"name": "port14", "vdom": "root", "ipv6": {"ip6-address": "::/0"}}


def test_interface_primary_address_overlapping_query_is_noted():
    report = analyze(
        parse_query("10.1.2.0/24"), [], [], [], interfaces=[IFACE_PRIMARY], vdom="root"
    )
    assert report.on_interface is True
    assert report.present is False  # never counts as a real match
    m = report.interfaces[0]
    assert m.name == "port10"
    assert m.kind == "primary"
    assert m.ip == "10.1.2.1/24"
    assert m.network == "10.1.2.0/24"
    assert m.relation == "exact"


def test_interface_with_no_address_is_ignored():
    report = analyze(parse_query("10.1.2.0/24"), [], [], [], interfaces=[IFACE_UNSET])
    assert report.interfaces == []
    assert report.on_interface is False


def test_interface_secondary_ip_is_matched():
    report = analyze(parse_query("10.1.2.0/28"), [], [], [], interfaces=[IFACE_SECONDARY])
    assert report.interfaces[0].kind == "secondary"
    assert report.interfaces[0].ip == "10.1.2.5/24"
    assert report.interfaces[0].relation == "supernet"


def test_interface_ipv6_address_is_matched():
    report = analyze(parse_query("2001:db8:1::/64"), [], [], [], interfaces=[IFACE_V6])
    assert report.interfaces[0].kind == "ipv6"
    assert report.interfaces[0].relation == "exact"


def test_interface_ipv6_unset_and_wrong_family_are_ignored():
    report = analyze(parse_query("10.1.2.0/24"), [], [], [], interfaces=[IFACE_V6, IFACE_V6_UNSET])
    assert report.interfaces == []


def test_interfaces_default_to_empty_when_omitted():
    report = analyze(parse_query("10.1.2.0/24"), [NET_HQ], [], [])
    assert report.interfaces == []
    assert report.as_dict()["on_interface"] is False


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


# --- policy-based NGFW mode ("Security Policy" on the box's GUI) ------


def test_security_policy_source_is_the_default_policy_when_untagged():
    """A dict with no source tag (e.g. hand-built in a test) is plain 'policy'."""
    pol = _policy(1, "p", dstaddr=["net_hq"])
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], [], [pol])
    assert report.matches[0].policies[0].source == "policy"


def test_security_policy_hit_is_tagged_and_still_counts_as_in_use():
    pol = _policy(12, "allow-out", dstaddr=["net_hq"])
    pol["_bunnyauto_policy_source"] = "security-policy"
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], [], [pol])
    assert report.attached is True
    assert report.matches[0].policies[0].source == "security-policy"


def test_mixed_policy_and_security_policy_hits_on_one_object():
    profile_pol = _policy(1, "profile", srcaddr=["net_hq"])
    ngfw_pol = _policy(2, "ngfw", dstaddr=["net_hq"])
    ngfw_pol["_bunnyauto_policy_source"] = "security-policy"
    report = analyze(parse_query("10.1.0.0/16"), [NET_HQ], [], [profile_pol, ngfw_pol])
    sources = {ref.policyid: ref.source for ref in report.matches[0].policies}
    assert sources == {1: "policy", 2: "security-policy"}


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
    # net_hq (/16) is a broad supernet -> not a real match, so its policy hit doesn't
    # count toward in_use/policy_count; sub_2 (/24, exact) is the only real match.
    assert payload["in_use"] is False
    assert payload["policy_count"] == 0
    assert [m["relation"] for m in payload["matches"]] == ["exact"]
    assert payload["permitted_by_broad_match"] is True
    assert [m["relation"] for m in payload["broad_matches"]] == ["supernet"]


def test_parse_query_bare_host_is_a_single_address():
    assert str(parse_query("10.1.2.5")) == "10.1.2.5/32"
    assert str(parse_query("10.1.2.5/24")) == "10.1.2.0/24"  # host bits tolerated
