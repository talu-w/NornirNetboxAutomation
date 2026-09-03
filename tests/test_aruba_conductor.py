"""Tests for the Aruba Conductor REST client (fake requests.Session, no network)."""

from __future__ import annotations

import pytest
import requests

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.errors import ArubaError


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
    """Minimal stand-in for requests.Session."""

    script: dict[str, object] = {}

    def __init__(self):
        self.verify = None
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []
        self.closed = False

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        result = _FakeSession.script.get("post")
        if isinstance(result, Exception):
            raise result
        if url.endswith("/login"):
            return _FakeSession.script.get("login", _Resp(200, {"_global_result": {}}))
        return _Resp(200, {})

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        result = _FakeSession.script.get("get")
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_session(monkeypatch):
    _FakeSession.script = {}
    monkeypatch.setattr(requests, "Session", _FakeSession)


def _ok_login():
    return _Resp(200, {"_global_result": {"status": "0", "UIDARUBA": "tok-123"}})


def test_login_captures_token_and_verify_default():
    _FakeSession.script["login"] = _ok_login()
    client = ArubaConductorClient("https://c:4343", "u", "p")
    client.login()
    assert client._token == "tok-123"
    assert client._session.verify is True


def test_login_rejected():
    _FakeSession.script["login"] = _Resp(401)
    with pytest.raises(ArubaError, match="rejected the login"):
        ArubaConductorClient("https://c:4343", "u", "p").login()


def test_login_unreachable():
    _FakeSession.script["post"] = requests.ConnectionError("boom")
    with pytest.raises(ArubaError, match="could not reach"):
        ArubaConductorClient("https://c:4343", "u", "p").login()


def test_login_no_token_in_response():
    _FakeSession.script["login"] = _Resp(200, {"_global_result": {"status_str": "bad password"}})
    with pytest.raises(ArubaError, match="did not succeed"):
        ArubaConductorClient("https://c:4343", "u", "p").login()


def test_showcommand_returns_payload_and_context_manager_logs_out():
    _FakeSession.script["login"] = _ok_login()
    _FakeSession.script["get"] = _Resp(200, {"AP Database": [{"Name": "ap1"}]})
    with ArubaConductorClient("https://c:4343", "u", "p") as client:
        rows = client.ap_database()
    assert rows == [{"Name": "ap1"}]
    assert client._session.closed is True
    assert ("POST", "https://c:4343/v1/api/logout") in client._session.calls


def test_showcommand_non_json():
    _FakeSession.script["login"] = _ok_login()
    _FakeSession.script["get"] = _Resp(200, bad_json=True)
    client = ArubaConductorClient("https://c:4343", "u", "p")
    with pytest.raises(ArubaError, match="was not JSON"):
        client.showcommand("show ap database long")


def test_showcommand_http_error():
    _FakeSession.script["login"] = _ok_login()
    _FakeSession.script["get"] = _Resp(500, {})
    client = ArubaConductorClient("https://c:4343", "u", "p")
    with pytest.raises(ArubaError, match="HTTP 500"):
        client.switches()
