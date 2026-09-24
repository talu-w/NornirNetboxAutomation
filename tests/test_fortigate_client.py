"""Tests for the FortiGate REST client (fake requests.Session, no network)."""

from __future__ import annotations

import ipaddress

import pytest
import requests

from bunnyauto.errors import FirewallError
from bunnyauto.firewall.fortigate import FortiGateClient, NewAddress


class _Resp:
    def __init__(self, status_code=200, payload=None, *, bad_json=False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("no json")
        return self._payload


class _FakeSession:
    """Minimal stand-in for requests.Session; routes GETs by URL suffix, answers POSTs."""

    routes: dict[str, object] = {}
    post_result: object = None
    posts: list[tuple[str, dict]] = []

    def __init__(self):
        self.verify = None
        self.headers: dict[str, str] = {}
        self.calls: list[str] = []
        self.closed = False

    def get(self, url, **kw):
        self.calls.append(url)
        for suffix, result in _FakeSession.routes.items():
            if url.endswith(suffix):
                if isinstance(result, Exception):
                    raise result
                return result
        return _Resp(404, {})

    def post(self, url, **kw):
        _FakeSession.posts.append((url, kw))
        if isinstance(_FakeSession.post_result, Exception):
            raise _FakeSession.post_result
        return _FakeSession.post_result

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_session(monkeypatch):
    _FakeSession.routes = {}
    _FakeSession.post_result = _Resp(200, {"status": "success", "http_status": 200})
    _FakeSession.posts = []
    monkeypatch.setattr(requests, "Session", _FakeSession)


def _client(**kw):
    return FortiGateClient("https://fw.example.com", "tok", **kw)


# --- policies: profile-based + policy-based (900/901G "Security Policy") ----


def test_policies_merges_both_endpoints_and_tags_source():
    _FakeSession.routes["firewall/policy"] = _Resp(
        200, {"results": [{"policyid": 1, "name": "p1"}]}
    )
    _FakeSession.routes["firewall/security-policy"] = _Resp(
        200, {"results": [{"policyid": 2, "name": "sp1"}]}
    )
    rows = _client().policies()
    tagged = {row["policyid"]: row["_bunnyauto_policy_source"] for row in rows}
    assert tagged == {1: "policy", 2: "security-policy"}


def test_policies_tolerates_missing_security_policy_endpoint():
    """Older firmware that predates policy-based NGFW mode 404s on the new endpoint."""
    _FakeSession.routes["firewall/policy"] = _Resp(
        200, {"results": [{"policyid": 1, "name": "p1"}]}
    )
    _FakeSession.routes["firewall/security-policy"] = _Resp(404)
    rows = _client().policies()
    assert [r["policyid"] for r in rows] == [1]
    assert rows[0]["_bunnyauto_policy_source"] == "policy"


def test_policies_still_errors_on_a_real_failure_of_the_profile_based_endpoint():
    _FakeSession.routes["firewall/policy"] = _Resp(500)
    with pytest.raises(FirewallError, match="HTTP 500"):
        _client().policies()


def test_policies_on_a_pure_policy_based_box():
    """The 900G/901G case: firewall/policy comes back empty, security-policy has the rules."""
    _FakeSession.routes["firewall/policy"] = _Resp(200, {"results": []})
    _FakeSession.routes["firewall/security-policy"] = _Resp(
        200, {"results": [{"policyid": 12, "name": "allow-out", "dstaddr": [{"name": "net_hq"}]}]}
    )
    rows = _client().policies()
    assert len(rows) == 1
    assert rows[0]["_bunnyauto_policy_source"] == "security-policy"


# --- interfaces --------------------------------------------------------


def test_interfaces_endpoint():
    _FakeSession.routes["system/interface"] = _Resp(
        200, {"results": [{"name": "port10", "ip": "10.1.2.1 255.255.255.0"}]}
    )
    rows = _client().interfaces()
    assert rows[0]["name"] == "port10"


# --- create_address: the one write -----------------------------------------


def _new(subnet="10.20.30.0/24", name="10.20.30.0/24", comment="made here"):
    return NewAddress(name=name, network=ipaddress.ip_network(subnet), comment=comment)


def test_create_address_posts_an_ipmask_object_to_the_vdom():
    _client(vdom="branch").create_address(_new())
    [(url, kw)] = _FakeSession.posts
    assert url == "https://fw.example.com/api/v2/cmdb/firewall/address"
    assert kw["params"] == {"vdom": "branch"}
    assert kw["json"] == {
        "name": "10.20.30.0/24",
        "type": "ipmask",
        "subnet": "10.20.30.0 255.255.255.0",
        "comment": "made here",
    }


def test_create_address_ipv6_goes_to_address6():
    _client().create_address(_new("2001:db8:1::/64", "v6", comment=""))
    [(url, kw)] = _FakeSession.posts
    assert url.endswith("/api/v2/cmdb/firewall/address6")
    assert kw["json"] == {"name": "v6", "type": "ipprefix", "ip6": "2001:db8:1::/64"}


def test_create_address_read_only_token_is_a_friendly_error():
    _FakeSession.post_result = _Resp(403, {})
    with pytest.raises(FirewallError, match="refused the write") as info:
        _client().create_address(_new())
    assert "read-write" in info.value.fix


def test_create_address_fortios_error_body_is_reported():
    _FakeSession.post_result = _Resp(
        500, {"status": "error", "http_status": 500, "error": -5, "cli_error": "duplicate"}
    )
    with pytest.raises(FirewallError, match=r"HTTP 500, FortiOS error -5: duplicate"):
        _client().create_address(_new())


def test_create_address_non_json_error_still_names_the_status():
    _FakeSession.post_result = _Resp(500, bad_json=True)
    with pytest.raises(FirewallError, match=r"HTTP 500\)"):
        _client().create_address(_new())


def test_create_address_unreachable():
    _FakeSession.post_result = requests.ConnectionError("boom")
    with pytest.raises(FirewallError, match="could not reach the firewall"):
        _client().create_address(_new())
