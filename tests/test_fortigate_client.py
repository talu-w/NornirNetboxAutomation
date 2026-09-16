"""Tests for the FortiGate REST client (fake requests.Session, no network)."""

from __future__ import annotations

import pytest
import requests

from bunnyauto.errors import FirewallError
from bunnyauto.firewall.fortigate import FortiGateClient


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
    """Minimal stand-in for requests.Session; routes GETs by URL suffix."""

    routes: dict[str, object] = {}

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

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_session(monkeypatch):
    _FakeSession.routes = {}
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
