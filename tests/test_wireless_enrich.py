"""Tests for the wireless-enrich tool (fake WLC client + fake pynetbox, no HTTP)."""

from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools import wireless_enrich
from bunnyauto.tools.wireless_enrich import TOOL

# --- fake pynetbox ---------------------------------------------------


class _Rec(SimpleNamespace):
    def update(self, body):
        self.updated = body
        for key, value in body.items():
            setattr(self, key, value)
        return True


class _Endpoint:
    def __init__(self, items=()):
        self._items = list(items)
        self.created: list[dict] = []

    def all(self):
        return list(self._items)

    def get(self, **kw):
        for item in self._items:
            if all(getattr(item, k, None) == v for k, v in kw.items()):
                return item
        return None

    def filter(self, **kw):
        return [
            item for item in self._items if all(getattr(item, k, None) == v for k, v in kw.items())
        ]

    def create(self, body):
        self.created.append(body)
        rec = _Rec(id=999, **body)
        self._items.append(rec)
        return rec


class _DevicesEndpoint(_Endpoint):
    def filter(self, *, role=None, tag=None):
        result = list(self._items)
        if role is not None:
            result = [d for d in result if getattr(getattr(d, "role", None), "slug", None) == role]
        if tag is not None:
            result = [d for d in result if tag in [t.slug for t in getattr(d, "tags", [])]]
        return result


class _NB:
    def __init__(self, *, roles, devices, platforms=(), interfaces=(), cables=()):
        self.version = "4.1"
        self.dcim = SimpleNamespace(
            device_roles=_Endpoint(roles),
            devices=_DevicesEndpoint(devices),
            platforms=_Endpoint(platforms),
            interfaces=_Endpoint(interfaces),
            cables=_Endpoint(cables),
        )


_WLC_ROLE = _Rec(id=8, slug="wireless-controller", name="Wireless Controller")
_WIRELESS_TAG = _Rec(slug="nornirtest")


def _wlc(name="hq-wlc01", ip="10.1.0.5/24", with_role=True, tagged=True, id_=1):
    return _Rec(
        id=id_,
        name=name,
        role=_WLC_ROLE if with_role else None,
        tags=[_WIRELESS_TAG] if tagged else [],
        primary_ip4=_Rec(address=ip) if ip else None,
    )


def _ap(name="hq-idf1-ap01", id_=100, platform=None):
    return _Rec(id=id_, name=name, platform=platform)


def _switch(name="hq-idf1-sw01", id_=200):
    return _Rec(id=id_, name=name)


def _nb(*, wlcs=(), other_devices=(), platforms=(), interfaces=(), with_role=True):
    roles = [_WLC_ROLE] if with_role else []
    return _NB(
        roles=roles,
        devices=[*wlcs, *other_devices],
        platforms=platforms,
        interfaces=interfaces,
    )


class _Ctx:
    def __init__(self, nb, *, apply=False, tag="nornirtest"):
        self.settings = SimpleNamespace(apply=apply, target_tag=tag)
        self.creds = SimpleNamespace(username="u", password="p")
        self.environment = SimpleNamespace(name="test")
        self.reporter = Reporter(json_mode=True)
        self._nb = nb

    def netbox(self):
        return self._nb


# --- fake WLC client ---------------------------------------------------


def _fake_client(monkeypatch, *, aps=(), lldp=(), enter_error=None):
    captured: dict = {}

    class FakeClient:
        def __init__(self, url, user, pw, *, verify=True, timeout=30.0):
            captured.setdefault("urls", []).append(url)
            captured.update(url=url, user=user, password=pw, verify=verify)

        def __enter__(self):
            if enter_error:
                raise enter_error
            return self

        def __exit__(self, *_exc):
            return None

        def ap_database(self):
            return list(aps)

        def ap_lldp_neighbors(self):
            return list(lldp)

    monkeypatch.setattr(wireless_enrich, "ArubaConductorClient", FakeClient)
    return captured


def _args(**over) -> argparse.Namespace:
    base = dict(
        tag="nornirtest",
        force_tag=False,
        wlc_port=4343,
        wlc_insecure=False,
        device=None,
    )
    base.update(over)
    return argparse.Namespace(**base)


AP_ROW = {"Name": "hq-idf1-ap01", "AP Type": "515"}
AP_ROW_WITH_VERSION = {**AP_ROW, "Software Version": "8.10.0.5"}
LLDP_ROW = {
    "AP Name": "hq-idf1-ap01",
    "Neighbor System Name": "hq-idf1-sw01",
    "Neighbor Port": "Gi1/0/24",
}


# --- config / credential guards ------------------------------------


def test_missing_creds_raises(monkeypatch):
    _fake_client(monkeypatch)
    ctx = _Ctx(_nb(wlcs=[_wlc()]))
    ctx.creds = SimpleNamespace(username="", password="")
    with pytest.raises(ArubaError, match="NORNIR_USERNAME"):
        TOOL.run(ctx, _args())


def test_missing_wlc_role_raises(monkeypatch):
    _fake_client(monkeypatch)
    with pytest.raises(ToolError, match="device role with slug 'wireless-controller'"):
        TOOL.run(_Ctx(_nb(with_role=False)), _args())


def test_no_matching_wlcs_is_ok(monkeypatch):
    _fake_client(monkeypatch)
    result = TOOL.run(_Ctx(_nb()), _args())
    assert result.status is Status.OK
    assert "no NetBox devices" in result.summary


def test_wlc_not_tagged_is_excluded(monkeypatch):
    _fake_client(monkeypatch)
    result = TOOL.run(_Ctx(_nb(wlcs=[_wlc(tagged=False)])), _args())
    assert result.status is Status.OK


def test_device_filter(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW])
    nb = _nb(
        wlcs=[
            _wlc(name="hq-wlc01", ip="10.1.0.5/24"),
            _wlc(name="branch-wlc01", ip="10.2.0.5/24", id_=2),
        ],
        other_devices=[_ap()],
    )
    result = TOOL.run(_Ctx(nb), _args(device="branch"))
    assert set(result.data) == {"branch-wlc01"}


def test_wlc_url_built_from_primary_ip_and_custom_port(monkeypatch):
    captured = _fake_client(monkeypatch, aps=[AP_ROW])
    nb = _nb(wlcs=[_wlc(ip="10.1.0.5/24")], other_devices=[_ap()])
    TOOL.run(_Ctx(nb), _args(wlc_port=8443, wlc_insecure=True))
    assert captured["url"] == "https://10.1.0.5:8443"
    assert captured["verify"] is False


# --- WLC-level skip/failure handling --------------------------------


def test_wlc_without_primary_ip_is_skipped_not_fatal(monkeypatch):
    _fake_client(monkeypatch)
    wlc = _wlc(ip=None)
    result = TOOL.run(_Ctx(_nb(wlcs=[wlc])), _args())
    assert result.status is Status.ERROR  # nothing progressed, one blocked
    assert result.data["hq-wlc01"]["error"]


def test_wlc_login_failure_does_not_abort_other_wlcs(monkeypatch):
    _fake_client(monkeypatch, enter_error=ArubaError("could not reach"))
    nb = _nb(wlcs=[_wlc(name="wlc-a", id_=1), _wlc(name="wlc-b", id_=2)])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.ERROR
    assert set(result.data) == {"wlc-a", "wlc-b"}
    assert "could not reach" in result.data["wlc-a"]["error"]


def test_wlc_with_no_ap_data_is_informational(monkeypatch):
    _fake_client(monkeypatch, aps=[])
    result = TOOL.run(_Ctx(_nb(wlcs=[_wlc()])), _args())
    assert result.status is Status.OK
    assert "no data" in result.summary
    assert result.data["hq-wlc01"]["note"]


# --- AP not found in NetBox -----------------------------------------


def test_ap_not_found_in_netbox_is_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW])
    result = TOOL.run(_Ctx(_nb(wlcs=[_wlc()])), _args())
    assert result.status is Status.ERROR
    assert "not found in NetBox" in result.data["hq-wlc01"]["hq-idf1-ap01"]["note"]


# --- platform enrichment --------------------------------------------


def test_platform_plan_then_apply(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW_WITH_VERSION])
    ap_device = _ap()
    platform = _Rec(id=50, name="AOS 8", slug="aos-8")
    nb = _nb(wlcs=[_wlc()], other_devices=[ap_device], platforms=[platform])

    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.status is Status.DRIFT
    assert any("would set platform to 'AOS 8'" in c for c in plan.changes)

    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert ap_device.updated == {"platform": 50}
    assert result.data["hq-wlc01"]["hq-idf1-ap01"]["platform"] == "AOS 8"


def test_platform_already_in_sync_is_noop(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW_WITH_VERSION])
    platform = _Rec(id=50, name="AOS 8", slug="aos-8")
    ap_device = _ap(platform=_Rec(id=50))
    nb = _nb(wlcs=[_wlc()], other_devices=[ap_device], platforms=[platform])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert result.data["hq-wlc01"]["hq-idf1-ap01"]["platform"] == "AOS 8"


def test_no_version_field_is_informational_not_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[{"Name": "hq-idf1-ap01", "AP Type": "515"}])
    nb = _nb(wlcs=[_wlc()], other_devices=[_ap()])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert "no software/version field" in result.data["hq-wlc01"]["hq-idf1-ap01"]["platform_note"]


def test_unmatched_platform_version_is_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW_WITH_VERSION])
    nb = _nb(wlcs=[_wlc()], other_devices=[_ap()], platforms=[])  # no platforms at all
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.ERROR
    note = result.data["hq-wlc01"]["hq-idf1-ap01"]["platform_note"]
    assert "no NetBox platform matches" in note


# --- LLDP / cabling ---------------------------------------------------


def test_cable_plan_then_apply(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[LLDP_ROW])
    ap_device = _ap()
    switch = _switch()
    ap_iface = _Rec(id=300, device_id=100, name="E0", type="5gbase-t", cable=None)
    switch_iface = _Rec(
        id=400, device_id=200, name="GigabitEthernet1/0/24", type="1000base-t", cable=None
    )
    nb = _nb(
        wlcs=[_wlc()],
        other_devices=[ap_device, switch],
        interfaces=[ap_iface, switch_iface],
    )

    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.status is Status.DRIFT
    assert any(
        "hq-idf1-ap01:E0 <-> hq-idf1-sw01:GigabitEthernet1/0/24: would create cable" in c
        for c in plan.changes
    )

    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.cables.created
    assert body["a_terminations"] == [{"object_type": "dcim.interface", "object_id": 300}]
    assert body["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 400}]
    assert body["status"] == "connected"
    assert result.data["hq-wlc01"]["hq-idf1-ap01"]["cable"] == "hq-idf1-sw01:GigabitEthernet1/0/24"


def test_no_lldp_row_is_informational(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[])
    nb = _nb(wlcs=[_wlc()], other_devices=[_ap()])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert "no LLDP neighbor" in result.data["hq-wlc01"]["hq-idf1-ap01"]["cable_note"]


def test_unmatched_lldp_hostname_is_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[LLDP_ROW])
    nb = _nb(wlcs=[_wlc()], other_devices=[_ap()])  # no matching switch device at all
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.ERROR
    assert "matched no NetBox device" in result.data["hq-wlc01"]["hq-idf1-ap01"]["cable_note"]


def test_unmatched_switch_port_is_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[LLDP_ROW])
    switch = _switch()
    other_iface = _Rec(id=400, device_id=200, name="GigabitEthernet1/0/1", type="1000base-t")
    nb = _nb(wlcs=[_wlc()], other_devices=[_ap(), switch], interfaces=[other_iface])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.ERROR
    assert "matched no interface" in result.data["hq-wlc01"]["hq-idf1-ap01"]["cable_note"]


def test_ap_with_no_wired_interface_is_blocked(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[LLDP_ROW])
    switch = _switch()
    switch_iface = _Rec(id=400, device_id=200, name="GigabitEthernet1/0/24", type="1000base-t")
    radio_iface = _Rec(id=301, device_id=100, name="6GHz WiFi", type="ieee802.11ax")
    nb = _nb(
        wlcs=[_wlc()],
        other_devices=[_ap(), switch],
        interfaces=[switch_iface, radio_iface],
    )
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.ERROR
    assert "no wired interface" in result.data["hq-wlc01"]["hq-idf1-ap01"]["cable_note"]


def test_existing_cable_on_either_end_is_left_alone(monkeypatch):
    _fake_client(monkeypatch, aps=[AP_ROW], lldp=[LLDP_ROW])
    switch = _switch()
    ap_iface = _Rec(id=300, device_id=100, name="E0", type="5gbase-t", cable=_Rec(id=1))
    switch_iface = _Rec(
        id=400, device_id=200, name="GigabitEthernet1/0/24", type="1000base-t", cable=None
    )
    nb = _nb(
        wlcs=[_wlc()],
        other_devices=[_ap(), switch],
        interfaces=[ap_iface, switch_iface],
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.OK  # informational only, never blocks/fails
    assert nb.dcim.cables.created == []
    note = result.data["hq-wlc01"]["hq-idf1-ap01"]["cable_note"]
    assert "already has a cable" in note


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["wireless-enrich"] is TOOL
    assert TOOL.writes is True
