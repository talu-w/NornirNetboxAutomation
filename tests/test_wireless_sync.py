"""Tests for the wireless-sync tool (fake Conductor client + fake pynetbox, no HTTP)."""

from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools import wireless_sync
from bunnyauto.tools.wireless_sync import TOOL

# --- fake pynetbox ---------------------------------------------------


class _Rec(SimpleNamespace):
    pass


class _Device(SimpleNamespace):
    def update(self, body):
        self.updated = body
        return True


class _Endpoint:
    def __init__(self, items=()):
        self._items = list(items)
        self.created: list[dict] = []

    def all(self):
        return list(self._items)

    def get(self, **kw):
        slug = kw.get("slug")
        for item in self._items:
            if getattr(item, "slug", None) == slug:
                return item
        return None

    def create(self, body):
        self.created.append(body)
        rec = _Rec(id=999, **{k: v for k, v in body.items() if k != "tags"})
        self._items.append(rec)
        return rec


class _NB:
    def __init__(self, *, roles, sites, types, devices, tags):
        self.version = "4.1"
        self.dcim = SimpleNamespace(
            device_roles=_Endpoint(roles),
            sites=_Endpoint(sites),
            device_types=_Endpoint(types),
            devices=_Endpoint(devices),
        )
        self.extras = SimpleNamespace(tags=_Endpoint(tags))


def _nb(*, devices=(), tags=("wireless",), with_role=True):
    return _NB(
        roles=[_Rec(id=7, slug="wireless", name="Wireless")] if with_role else [],
        sites=[
            _Rec(id=1, slug="hq", name="Headquarters"),
            _Rec(id=2, slug="branch-north", name="Branch North"),
        ],
        types=[
            _Rec(id=50, model="AP-515", slug="ap-515"),
            _Rec(id=51, model="A7210", slug="a7210"),
        ],
        devices=list(devices),
        tags=[_Rec(id=3, slug=s, name=s) for s in tags],
    )


class _Ctx:
    def __init__(self, nb, *, apply=False, aruba_url="https://cond.example.com:4343"):
        self.settings = SimpleNamespace(apply=apply)
        self.creds = SimpleNamespace(username="u", password="p")
        self.environment = SimpleNamespace(name="test", aruba_url=aruba_url)
        self.reporter = Reporter(json_mode=True)
        self._nb = nb

    def netbox(self):
        return self._nb


# --- fake Conductor client -----------------------------------------


def _fake_client(monkeypatch, *, switches=(), aps=(), enter_error=None):
    captured: dict = {}

    class FakeClient:
        def __init__(self, url, user, pw, *, verify=True, timeout=30.0):
            captured.update(url=url, user=user, password=pw, verify=verify)

        def __enter__(self):
            if enter_error:
                raise enter_error
            return self

        def __exit__(self, *_exc):
            return None

        def switches(self):
            return list(switches)

        def ap_database(self):
            return list(aps)

    monkeypatch.setattr(wireless_sync, "ArubaConductorClient", FakeClient)
    return captured


def _args(**over) -> argparse.Namespace:
    base = dict(
        aruba_url=None,
        aruba_insecure=False,
        default_site=None,
        only="all",
        device=None,
        status="active",
    )
    base.update(over)
    return argparse.Namespace(**base)


AP = {"Name": "hq-idf1-ap01", "AP Type": "515", "Serial #": "CN0001", "IP Address": "10.1.1.1"}
WLC = {"Name": "hq-wlc01", "Model": "A7210", "Serial Number": "CX0009"}


# --- config / credential guards ------------------------------------


def test_missing_aruba_url(monkeypatch):
    _fake_client(monkeypatch)
    with pytest.raises(ArubaError, match="no Aruba Conductor URL"):
        TOOL.run(_Ctx(_nb(), aruba_url=None), _args())


def test_missing_role(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    with pytest.raises(ToolError, match="device role with slug 'wireless'"):
        TOOL.run(_Ctx(_nb(with_role=False)), _args())


def test_login_failure_propagates(monkeypatch):
    _fake_client(monkeypatch, enter_error=ArubaError("could not reach the Aruba Conductor"))
    with pytest.raises(ArubaError, match="could not reach"):
        TOOL.run(_Ctx(_nb()), _args())


def test_cli_url_and_insecure_override(monkeypatch):
    captured = _fake_client(monkeypatch, aps=[AP])
    TOOL.run(
        _Ctx(_nb(), aruba_url=None), _args(aruba_url="https://x.example.com/", aruba_insecure=True)
    )
    assert captured["url"] == "https://x.example.com"
    assert captured["verify"] is False


# --- planning / applying -------------------------------------------


def test_plan_lists_creation(monkeypatch):
    _fake_client(monkeypatch, aps=[AP], switches=[WLC])
    nb = _nb()
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert any("would create" in c and "hq-idf1-ap01" in c for c in result.changes)
    assert any("would create" in c and "hq-wlc01" in c for c in result.changes)
    assert nb.dcim.devices.created == []


def test_apply_creates_device(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    nb = _nb()
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert result.exit_code == 20
    (body,) = nb.dcim.devices.created
    assert body["name"] == "hq-idf1-ap01"
    assert body["role"] == 7
    assert body["site"] == 1
    assert body["device_type"] == 50
    assert body["serial"] == "CN0001"
    assert body["status"] == "active"
    assert body["tags"] == [{"slug": "wireless"}]


def test_older_netbox_uses_device_role(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    nb = _nb()
    nb.version = "3.5"
    TOOL.run(_Ctx(nb, apply=True), _args())
    (body,) = nb.dcim.devices.created
    assert body["device_role"] == 7 and "role" not in body


def test_existing_device_missing_tag_is_tagged(monkeypatch):
    _fake_client(monkeypatch, switches=[WLC])
    existing = _Device(id=1, name="hq-wlc01", serial="CX0009", tags=[])
    nb = _nb(devices=[existing])

    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.status is Status.DRIFT
    assert any("add tag" in c for c in plan.changes)

    applied = TOOL.run(_Ctx(nb, apply=True), _args())
    assert applied.status is Status.CHANGED
    assert existing.updated == {"tags": [{"slug": "wireless"}]}


def test_existing_tagged_device_is_in_sync(monkeypatch):
    _fake_client(monkeypatch, switches=[WLC])
    existing = _Device(id=1, name="hq-wlc01", serial="CX0009", tags=[_Rec(slug="wireless")])
    nb = _nb(devices=[existing])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert result.changes == []


def test_match_by_name_when_serial_differs(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    existing = _Device(id=1, name="hq-idf1-ap01", serial="", tags=[_Rec(slug="wireless")])
    nb = _nb(devices=[existing])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK


# --- blocked devices ----------------------------------------------


def test_unknown_model_only_is_error(monkeypatch):
    _fake_client(monkeypatch, aps=[{"Name": "hq-ap9", "AP Type": "999", "Serial #": "Z9"}])
    result = TOOL.run(_Ctx(_nb()), _args())
    assert result.status is Status.ERROR
    assert "skipped" in result.summary


def test_blocked_plus_creatable_is_partial(monkeypatch):
    _fake_client(
        monkeypatch,
        aps=[AP, {"Name": "hq-ap9", "AP Type": "999", "Serial #": "Z9"}],
    )
    result = TOOL.run(_Ctx(_nb()), _args())
    assert result.status is Status.PARTIAL
    assert result.exit_code == 2


def test_no_site_match_is_blocked_then_default_site(monkeypatch):
    ap = {"Name": "warehouse-ap1", "AP Type": "515", "Serial #": "W1"}
    _fake_client(monkeypatch, aps=[ap])
    assert TOOL.run(_Ctx(_nb()), _args()).status is Status.ERROR

    _fake_client(monkeypatch, aps=[ap])
    nb = _nb()
    result = TOOL.run(_Ctx(nb, apply=True), _args(default_site="hq"))
    assert result.status is Status.CHANGED
    assert nb.dcim.devices.created[0]["site"] == 1


def test_bad_default_site_raises(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    with pytest.raises(ToolError, match="not a NetBox site slug"):
        TOOL.run(_Ctx(_nb()), _args(default_site="nope"))


# --- filters / tag creation --------------------------------------


def test_only_wlcs_skips_aps(monkeypatch):
    _fake_client(monkeypatch, switches=[WLC], aps=[AP])
    result = TOOL.run(_Ctx(_nb()), _args(only="wlcs"))
    assert set(result.data) == {"hq-wlc01"}


def test_device_filter(monkeypatch):
    _fake_client(monkeypatch, aps=[AP], switches=[WLC])
    result = TOOL.run(_Ctx(_nb()), _args(device="wlc"))
    assert set(result.data) == {"hq-wlc01"}


def test_missing_tag_is_created_on_apply(monkeypatch):
    _fake_client(monkeypatch, aps=[AP])
    nb = _nb(tags=())
    plan = TOOL.run(_Ctx(nb), _args())
    assert any("would create NetBox tag" in c for c in plan.changes)

    nb = _nb(tags=())
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.extras.tags.created == [{"name": "wireless", "slug": "wireless"}]


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["wireless-sync"] is TOOL
    assert TOOL.writes is True
