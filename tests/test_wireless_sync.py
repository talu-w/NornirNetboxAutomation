"""Tests for `wireless sync` (fake Conductor/WLC client + fake pynetbox, no HTTP)."""

from __future__ import annotations

import argparse
import itertools
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from bunnyauto.categories import DEFAULT_ROLES
from bunnyauto.errors import ArubaError, RoleScopeError, ToolError
from bunnyauto.netbox.records import related_id
from bunnyauto.netbox.roles import RoleTree
from bunnyauto.result import Status
from bunnyauto.scope import resolve_scope
from bunnyauto.tools.wireless import sync as wireless_sync
from bunnyauto.tools.wireless.sync import TOOL

# --- fake pynetbox ---------------------------------------------------

_IDS = itertools.count(1000)


class _Rec(SimpleNamespace):
    def update(self, body):
        self.__dict__.setdefault("updates", []).append(dict(body))
        for key, value in body.items():
            setattr(self, key, value)
        return True


class _Endpoint:
    def __init__(self, items=()):
        self._items = list(items)
        self.created: list[dict] = []
        self.bulk_updated: list[dict] = []

    def all(self):
        return list(self._items)

    def get(self, id_=None, **kw):  # like pynetbox: get(<id>) or get(field=value)
        if id_ is not None:
            kw["id"] = id_
        return next(iter(self.filter(**kw)), None)

    def filter(self, **kw):
        return [
            item for item in self._items if all(getattr(item, k, None) == v for k, v in kw.items())
        ]

    def update(self, objects):  # pynetbox's bulk PATCH: a list of {"id": ..., ...}
        self.bulk_updated.extend(objects)
        return True

    def create(self, body):
        self.created.append(body)
        rec = _Rec(id=next(_IDS), **body)
        if "device" in body:  # an interface: pynetbox filters it by device_id
            rec.device_id = body["device"]
        self._items.append(rec)
        return rec


class _Devices(_Endpoint):
    """Like NetBox: a new device gets its device type's interface template as interfaces."""

    def __init__(self, items, nb):
        super().__init__(items)
        self._nb = nb

    def create(self, body):
        device = super().create(body)
        for template in self._nb.dcim.interface_templates.all():
            if related_id(template.device_type) == body["device_type"]:
                self._nb.dcim.interfaces._items.append(
                    _Rec(
                        id=next(_IDS),
                        device_id=device.id,
                        name=template.name,
                        type=template.type,
                        cable=None,
                    )
                )
        return device


class _NB:
    def __init__(
        self,
        *,
        roles,
        sites,
        types,
        devices,
        tags,
        prefixes,
        ips,
        interfaces,
        templates,
        cables,
        wlans,
    ):
        self.version = "4.1"
        self.dcim = SimpleNamespace(
            device_roles=_Endpoint(roles),
            sites=_Endpoint(sites),
            device_types=_Endpoint(types),
            interfaces=_Endpoint(interfaces),
            interface_templates=_Endpoint(templates),
            platforms=_Endpoint(),
            cables=_Endpoint(cables),
        )
        self.dcim.devices = _Devices(devices, self)
        self.extras = SimpleNamespace(tags=_Endpoint(tags))
        self.ipam = SimpleNamespace(prefixes=_Endpoint(prefixes), ip_addresses=_Endpoint(ips))
        self.wireless = SimpleNamespace(wireless_lans=_Endpoint(wlans))


# The owner's wireless role branch (NetBox >= 4.3 nested roles):
# Wireless Network > Wireless Controller > Wireless Access Point.
_BRANCH_ROLE = _Rec(id=9, slug="wireless-network", name="Wireless Network", parent=None)
_TAG = _Rec(slug="nornirtest")

#: The AP-515's NetBox Data Exchange template: wired E0/E1 alongside radios.
AP_TEMPLATE = [
    ("E0", "2.5gbase-t"),
    ("E1", "1000base-t"),
    ("5GHz WiFi", "ieee802.11ax"),
    ("2.4GHz WiFi", "ieee802.11ax"),
    ("Bluetooth", "ieee802.15.1"),
]


def _nb(
    *,
    devices=(),
    tags=("nornirtest",),
    with_ap_role=True,
    with_wlc_role=True,
    with_branch=True,
    prefixes=(),
    ips=(),
    interfaces=(),
    ap_template=False,
    cables=(),
    wlans=(),
):
    roles = [_BRANCH_ROLE] if with_branch else []
    wlc_role = _Rec(
        id=8,
        slug="wireless-controller",
        name="Wireless Controller",
        parent=_BRANCH_ROLE if with_branch else None,
    )
    if with_wlc_role:
        roles.append(wlc_role)
    if with_ap_role:
        roles.append(
            _Rec(
                id=7,
                slug="wireless-access-point",
                name="Wireless Access Point",
                parent=wlc_role if with_wlc_role else _BRANCH_ROLE,
            )
        )
    templates = (
        [
            _Rec(id=60 + i, device_type=_Rec(id=50), name=n, type=t)
            for i, (n, t) in enumerate(AP_TEMPLATE)
        ]
        if ap_template
        else []
    )
    return _NB(
        roles=roles,
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
        prefixes=list(prefixes),
        ips=list(ips),
        interfaces=list(interfaces),
        templates=templates,
        cables=list(cables),
        wlans=list(wlans),
    )


def _prefix(cidr="10.1.1.0/24", vrf=None, id_=10):
    return _Rec(id=id_, prefix=cidr, vrf=vrf)


_AP_ROLE_REF = _Rec(slug="wireless-access-point")


def _ap(*, id_=100, name="hq-idf1-ap01", serial="CN0001", tagged=True, role=_AP_ROLE_REF, **extra):
    return _Rec(id=id_, name=name, serial=serial, tags=[_TAG] if tagged else [], role=role, **extra)


def _iface(id_, device_id, name, type_="2.5gbase-t", cable=None):
    return _Rec(id=id_, device_id=device_id, name=name, type=type_, cable=cable)


BR0_ID = 310


def _br0(device_id=100):
    return _iface(BR0_ID, device_id, "br0", "bridge")


def _ap_ports(device_id=100, *, e0_cable=None, e1_cable=None, br0=False, linked=()):
    """E0/E1 and a radio. ``br0`` adds the AP's bridge; ``linked`` ports are bridged to it."""
    ports = [
        _iface(300, device_id, "E0", cable=e0_cable),
        _iface(301, device_id, "E1", "1000base-t", cable=e1_cable),
        _iface(302, device_id, "5GHz WiFi", "ieee802.11ax"),
    ]
    for port in ports:
        if port.name in linked:
            port.bridge = _Rec(id=BR0_ID)
    if br0 or linked:
        ports.append(_br0(device_id))
    return ports


SWITCH = _Rec(id=200, name="hq-idf1-sw01")


def _switch_port(id_=400, device_id=200, name="GigabitEthernet1/0/24", cable=None):
    return _iface(id_, device_id, name, "1000base-t", cable=cable)


class _Reporter:
    def __init__(self):
        self.lines: list[tuple[str, str]] = []

    def step(self, message):
        self.lines.append(("step", message))

    def info(self, message):
        self.lines.append(("info", message))

    def success(self, message):
        self.lines.append(("success", message))

    def warn(self, message):
        self.lines.append(("warn", message))

    def error(self, message):
        self.lines.append(("error", message))

    @contextmanager
    def spinner(self, _description):
        yield

    def about(self, name):
        """(level, message) for the lines about one device."""
        return [(level, m) for level, m in self.lines if m.startswith(f"{name}:")]


CONDUCTOR = "https://cond.example.com:4343"


class _Ctx:
    def __init__(self, nb, *, apply=False, aruba_url=CONDUCTOR):
        self.settings = SimpleNamespace(
            apply=apply,
            target_tag="nornirtest",
            category="wireless",
            branch_role=DEFAULT_ROLES["wireless"],
            role=None,
            region=None,
            site=None,
        )
        self.creds = SimpleNamespace(username="u", password="p")
        self.environment = SimpleNamespace(
            name="test", aruba_url=aruba_url, roles=dict(DEFAULT_ROLES)
        )
        self.reporter = _Reporter()
        self._nb = nb

    def netbox(self):
        return self._nb

    def role_tree(self):
        return RoleTree.load(self._nb)

    def scope(self):
        return resolve_scope(self.settings, self.role_tree)


# --- fake Conductor / WLC client --------------------------------------


def _aruba(
    monkeypatch,
    *,
    switches=(),
    aps=(),
    wlc_aps=None,
    lldp=(),
    bss=(),
    errors=None,
    lldp_by_ap=None,
):
    """The Conductor answers at CONDUCTOR; any other URL is a WLC.

    A WLC's ``show ap database long`` returns ``wlc_aps`` (default: the same
    rows as the Conductor's); ``errors`` maps a URL to what logging in raises.
    ``lldp_by_ap`` makes every WLC's full LLDP table unreadable (the 9240's
    broken XML) and maps an AP name to what ``... ap-name <ap>`` returns: rows,
    or an exception to raise. Each call's ``asked`` lists the APs asked about.
    """
    calls: list[SimpleNamespace] = []

    class FakeClient:
        def __init__(self, url, user, pw, *, verify=True, timeout=30.0):
            self.url = url
            self.record = SimpleNamespace(url=url, user=user, password=pw, verify=verify, asked=[])
            calls.append(self.record)

        def __enter__(self):
            error = (errors or {}).get(self.url)
            if error:
                raise error
            return self

        def __exit__(self, *_exc):
            return None

        def switches(self):
            return list(switches)

        def ap_database(self):
            if self.url == CONDUCTOR or wlc_aps is None:
                return list(aps)
            return list(wlc_aps)

        def ap_lldp_neighbors(self, ap_name=None):
            if lldp_by_ap is None:
                return list(lldp)
            if ap_name is None:
                raise ArubaError("the Conductor response for 'show ap lldp neighbors' was not JSON")
            self.record.asked.append(ap_name)
            answer = lldp_by_ap.get(ap_name, [])
            if isinstance(answer, Exception):
                raise answer
            return list(answer)

        def ap_bss_table(self):
            return list(bss)

    monkeypatch.setattr(wireless_sync, "ArubaConductorClient", FakeClient)
    return calls


def _args(**over) -> argparse.Namespace:
    base = dict(
        aruba_url=None,
        aruba_insecure=False,
        wlc_port=4343,
        wlc_insecure=False,
        default_site=None,
        only="all",
        device=None,
        status="active",
    )
    base.update(over)
    return argparse.Namespace(**base)


AP = {"Name": "hq-idf1-ap01", "AP Type": "515", "Serial #": "CN0001", "IP Address": "10.1.1.1"}
WLC = {"Name": "hq-wlc01", "Model": "A7210", "Serial Number": "CX0009", "IP Address": "10.1.0.5"}
WLC_URL = "https://10.1.0.5:4343"
LLDP = {
    "AP": "hq-idf1-ap01",
    "Interface": "eth1",
    "Chassis Name/ID": "hq-idf1-sw01",
    "Port ID": "Gi1/0/24",
}


def _device(result, name="hq-idf1-ap01"):
    return result.data["devices"][name]


# --- config / credential guards ------------------------------------


def test_missing_aruba_url(monkeypatch):
    _aruba(monkeypatch)
    with pytest.raises(ArubaError, match="no Aruba Conductor URL"):
        TOOL.run(_Ctx(_nb(), aruba_url=None), _args())


def test_missing_wireless_branch_root_raises(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    with pytest.raises(RoleScopeError, match="'wireless-network'"):
        TOOL.run(_Ctx(_nb(with_branch=False)), _args())


def test_without_the_ap_role_or_the_wireless_role_the_run_fails_before_writing(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(with_ap_role=False, with_branch=False)
    with pytest.raises(RoleScopeError, match="'wireless-network'"):
        TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.dcim.devices.created == []


def test_role_outside_the_wireless_branch_refuses_creation(monkeypatch):
    """A device created with a role outside the branch would be invisible to
    every role-scoped tool — refuse rather than create it there."""
    _aruba(monkeypatch, aps=[AP])
    nb = _nb()
    stray = _Rec(id=40, slug="elsewhere", name="Elsewhere", parent=None)
    nb.dcim.device_roles.get(slug="wireless-access-point").parent = stray
    nb.dcim.device_roles._items.append(stray)
    with pytest.raises(ToolError, match="not inside the wireless branch"):
        TOOL.run(_Ctx(nb, apply=True), _args())


def test_missing_wlc_role_blocks_wlc_creation(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    with pytest.raises(ToolError, match="device role with slug 'wireless-controller'"):
        TOOL.run(_Ctx(_nb(with_wlc_role=False)), _args())


def test_missing_wlc_role_does_not_block_an_ap_only_run(monkeypatch):
    """The wireless-controller role is only required when a run actually
    needs to create one."""
    _aruba(monkeypatch, aps=[AP])
    result = TOOL.run(_Ctx(_nb(with_wlc_role=False, prefixes=[_prefix()])), _args())
    assert result.status is Status.DRIFT


def test_wlc_creation_uses_the_controller_role(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    nb = _nb(prefixes=[_prefix("10.1.0.0/24")])
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.devices.created
    assert body["role"] == 8


def test_conductor_login_failure_propagates(monkeypatch):
    _aruba(monkeypatch, errors={CONDUCTOR: ArubaError("could not reach the Aruba Conductor")})
    with pytest.raises(ArubaError, match="could not reach"):
        TOOL.run(_Ctx(_nb()), _args())


def test_cli_url_and_insecure_override(monkeypatch):
    calls = _aruba(monkeypatch, aps=[AP])
    TOOL.run(
        _Ctx(_nb(), aruba_url=None), _args(aruba_url="https://x.example.com/", aruba_insecure=True)
    )
    assert calls[0].url == "https://x.example.com"
    assert calls[0].verify is False


# --- creating devices ------------------------------------------------


def test_plan_lists_creation_and_writes_nothing(monkeypatch):
    _aruba(monkeypatch, aps=[AP], switches=[WLC])
    nb = _nb(prefixes=[_prefix(), _prefix("10.1.0.0/24", id_=11)])
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert any("would create AP" in c and "hq-idf1-ap01" in c for c in result.changes)
    assert any("would create WLC" in c and "hq-wlc01" in c for c in result.changes)
    assert nb.dcim.devices.created == []
    assert nb.ipam.ip_addresses.created == []


def test_apply_creates_device(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()])
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.CHANGED
    assert result.exit_code == 20
    (body,) = nb.dcim.devices.created
    assert body["name"] == "hq-idf1-ap01"
    assert body["role"] == 7
    assert body["site"] == 1
    assert body["device_type"] == 50
    assert body["serial"] == "CN0001"
    assert body["status"] == "active"
    assert body["tags"] == [{"slug": "nornirtest"}]  # the environment's tag, not 'wireless'
    assert ctx.reporter.about("hq-idf1-ap01") == [("success", "hq-idf1-ap01: created")]


def test_new_ap_gets_the_wireless_access_point_role(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()])
    plan = TOOL.run(_Ctx(nb), _args())
    assert (
        "hq-idf1-ap01: would create AP in site 'hq' (type 'AP-515', "
        "role 'wireless-access-point') tagged 'nornirtest'"
    ) in plan.changes
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.dcim.devices.created[0]["role"] == 7


def test_new_ap_is_filed_under_the_wireless_role_when_there_is_no_ap_role(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(with_ap_role=False, prefixes=[_prefix()])
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.CHANGED  # a note, not a problem
    assert nb.dcim.devices.created[0]["role"] == 9  # Wireless Network, the branch root
    assert any("role 'wireless-network'" in c for c in result.changes)
    assert any("NetBox has no 'wireless-access-point' role" in n for n in _device(result)["notes"])
    assert (
        "info",
        "NetBox has no 'wireless-access-point' device role — new APs are filed under "
        "'wireless-network'",
    ) in ctx.reporter.lines


def test_ap_role_outside_the_wireless_branch_is_refused(monkeypatch):
    """Moving or creating APs in it would put them out of every wireless tool's reach."""
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(devices=[_ap()])  # an update-only run
    stray = _Rec(id=40, slug="elsewhere", name="Elsewhere", parent=None)
    nb.dcim.device_roles.get(slug="wireless-access-point").parent = stray
    nb.dcim.device_roles._items.append(stray)
    with pytest.raises(ToolError, match="not inside the wireless branch"):
        TOOL.run(_Ctx(nb), _args())


def test_existing_ap_with_another_role_is_moved_to_the_ap_role(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])
    ap = _ap(role=_Rec(slug="wireless"))  # e.g. the pre-2026-09-23 AP role
    nb = _nb(devices=[ap])
    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.status is Status.DRIFT
    assert "hq-idf1-ap01: would set role to 'wireless-access-point' (was 'wireless')" in (
        plan.changes
    )

    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.CHANGED
    assert ap.updates == [{"role": 7}]
    assert ("success", "hq-idf1-ap01: updated") in ctx.reporter.lines


def test_existing_ap_on_older_netbox_is_moved_via_device_role(monkeypatch):
    """NetBox < 3.6 calls the field device_role."""
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])
    ap = _ap(role=None, device_role=_Rec(slug="wireless"))
    nb = _nb(devices=[ap])
    nb.version = "3.5"
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert ap.updates == [{"device_role": 7}]


def test_existing_ap_role_failing_to_change_is_yellow(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])

    class _Stubborn(_Rec):
        def update(self, body):
            raise RuntimeError("role is protected")

    ap = _Stubborn(id=100, name="hq-idf1-ap01", serial="CN0001", tags=[_TAG], role=None)
    result = TOOL.run(_Ctx(_nb(devices=[ap]), apply=True), _args())
    assert result.status is Status.PARTIAL
    assert "could not set role to 'wireless-access-point'" in _device(result)["issues"][0]


def test_existing_ap_without_an_ap_role_in_netbox_only_notes_its_role(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])
    ap = _ap(role=_Rec(slug="wireless-network"))
    nb = _nb(devices=[ap], with_ap_role=False, interfaces=[_br0()])
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.OK
    assert not hasattr(ap, "updates")
    assert _device(result)["notes"] == [
        "role is 'wireless-network' — NetBox has no 'wireless-access-point' role to move it to"
    ]
    assert (
        "info",
        "hq-idf1-ap01: role is 'wireless-network' — NetBox has no 'wireless-access-point' "
        "role to move it to",
    ) in ctx.reporter.lines


def test_existing_wlc_role_is_never_changed(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    wlc = _Rec(id=1, name="hq-wlc01", serial="CX0009", tags=[_TAG], role=_Rec(slug="elsewhere"))
    nb = _nb(devices=[wlc])
    nb.dcim.device_roles._items.append(_Rec(id=40, slug="elsewhere", parent=None))
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.OK
    assert not hasattr(wlc, "updates")


def test_older_netbox_uses_device_role(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb()
    nb.version = "3.5"
    TOOL.run(_Ctx(nb, apply=True), _args())
    (body,) = nb.dcim.devices.created
    assert body["device_role"] == 7 and "role" not in body


def test_ndx_style_device_type_is_matched_by_bare_model_number(monkeypatch):
    """Regression: NetBox Data Exchange device types (model "Aruba AP-655",
    slug "hpe-aruba-ap-655") were never matched by Aruba's bare "655"."""
    ap = {"Name": "hq-idf1-ap02", "AP Type": "655", "Serial #": "CN0655"}
    _aruba(monkeypatch, aps=[ap])
    nb = _nb()
    nb.dcim.device_types._items.append(_Rec(id=52, model="Aruba AP-655", slug="hpe-aruba-ap-655"))
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.devices.created
    assert body["device_type"] == 52


# --- red: a device that cannot be created ------------------------------


def test_unknown_model_is_red(monkeypatch):
    _aruba(monkeypatch, aps=[{"Name": "hq-ap9", "AP Type": "999", "Serial #": "Z9"}])
    ctx = _Ctx(_nb())
    result = TOOL.run(ctx, _args())
    assert result.status is Status.ERROR
    assert result.exit_code == 1
    assert "1 cannot be created" in result.summary
    assert _device(result, "hq-ap9")["status"] == "failed"
    ((level, message),) = ctx.reporter.about("hq-ap9")
    assert level == "error" and "no NetBox device type matches model '999'" in message


def test_one_uncreatable_device_makes_the_run_red_even_if_others_are_fine(monkeypatch):
    _aruba(monkeypatch, aps=[AP, {"Name": "hq-ap9", "AP Type": "999", "Serial #": "Z9"}])
    nb = _nb(prefixes=[_prefix()])
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.ERROR
    assert _device(result)["status"] == "ok"  # the good AP was still created
    assert [b["name"] for b in nb.dcim.devices.created] == ["hq-idf1-ap01"]


def test_netbox_refusing_the_device_is_red(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb()

    def refuse(body):
        raise RuntimeError("serial already in use")

    nb.dcim.devices.create = refuse
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.ERROR
    assert "serial already in use" in _device(result)["reason"]
    assert ctx.reporter.about("hq-idf1-ap01")[0][0] == "error"
    assert nb.ipam.ip_addresses.created == []  # nothing else attempted


def test_no_site_match_is_red_then_default_site(monkeypatch):
    ap = {"Name": "warehouse-ap1", "AP Type": "515", "Serial #": "W1"}
    _aruba(monkeypatch, aps=[ap])
    assert TOOL.run(_Ctx(_nb()), _args()).status is Status.ERROR

    nb = _nb()
    result = TOOL.run(_Ctx(nb, apply=True), _args(default_site="hq"))
    assert result.status is Status.CHANGED
    assert nb.dcim.devices.created[0]["site"] == 1


def test_bad_default_site_raises(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    with pytest.raises(ToolError, match="not a NetBox site slug"):
        TOOL.run(_Ctx(_nb()), _args(default_site="nope"))


# --- updating devices NetBox already has --------------------------------


def test_existing_device_missing_tag_is_tagged(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    existing = _Rec(id=1, name="hq-wlc01", serial="CX0009", tags=[])
    nb = _nb(devices=[existing])

    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.status is Status.DRIFT
    assert "hq-wlc01: would add tag 'nornirtest'" in plan.changes

    ctx = _Ctx(nb, apply=True)
    applied = TOOL.run(ctx, _args())
    assert applied.status is Status.CHANGED
    assert existing.updates == [{"tags": [{"slug": "nornirtest"}]}]
    assert ctx.reporter.about("hq-wlc01") == [("success", "hq-wlc01: updated")]


def test_device_with_only_the_old_wireless_tag_gets_the_environment_tag(monkeypatch):
    """Devices adopted before 2026-09-23 carry the old 'wireless' tag. They
    now need the environment's tag to be in scope; the old tag is kept."""
    _aruba(monkeypatch, switches=[WLC])
    existing = _Rec(id=1, name="hq-wlc01", serial="CX0009", tags=[_Rec(slug="wireless")])
    TOOL.run(_Ctx(_nb(devices=[existing]), apply=True), _args())
    assert existing.updates == [{"tags": [{"slug": "nornirtest"}, {"slug": "wireless"}]}]


def test_existing_tagged_device_is_in_sync(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    existing = _Rec(id=1, name="hq-wlc01", serial="CX0009", tags=[_TAG])
    ctx = _Ctx(_nb(devices=[existing]))
    result = TOOL.run(ctx, _args())
    assert result.status is Status.OK
    assert result.changes == []
    assert ("success", "hq-wlc01: in sync") in ctx.reporter.lines


def test_existing_wlc_ip_is_never_touched(monkeypatch):
    """An existing WLC's primary IPv4 is the address this tool logs into."""
    _aruba(monkeypatch, switches=[WLC])
    existing = _Rec(id=1, name="hq-wlc01", serial="CX0009", tags=[_TAG], primary_ip4=None)
    nb = _nb(devices=[existing], prefixes=[_prefix("10.1.0.0/24")])
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.OK
    assert nb.ipam.ip_addresses.created == []


def test_existing_device_outside_the_branch_gets_a_role_note(monkeypatch):
    """Its role is never changed, but say it's outside the branch."""
    _aruba(monkeypatch, switches=[WLC])
    existing = _Rec(
        id=1, name="hq-wlc01", serial="CX0009", tags=[_TAG], role=_Rec(slug="access-switch")
    )
    nb = _nb(devices=[existing])
    nb.dcim.device_roles._items.append(_Rec(id=30, slug="access-switch", parent=None))
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK  # informational only
    assert any("outside the wireless branch" in n for n in _device(result, "hq-wlc01")["notes"])


def test_serial_is_filled_or_corrected_on_a_device_matched_by_name(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    blank = _ap(serial="")
    plan = TOOL.run(_Ctx(_nb(devices=[blank])), _args())
    assert "hq-idf1-ap01: would set serial to 'CN0001'" in plan.changes

    swapped = _ap(serial="OLD123")  # an RMA'd AP keeps its name
    TOOL.run(_Ctx(_nb(devices=[swapped]), apply=True), _args())
    assert {"serial": "CN0001"} in swapped.updates


def test_name_mismatch_on_a_serial_match_is_only_noted(monkeypatch):
    """An unprovisioned AP reports its MAC as its name — never rename from that."""
    _aruba(monkeypatch, aps=[{**AP, "Name": "a8:bd:27:c0:ff:ee"}])
    existing = _ap(name="hq-idf1-ap01")
    result = TOOL.run(_Ctx(_nb(devices=[existing]), apply=True), _args())
    assert not any("name" in u for u in getattr(existing, "updates", []))
    notes = _device(result, "a8:bd:27:c0:ff:ee")["notes"]
    assert any("name left as is" in n for n in notes)


# --- filters / tag creation --------------------------------------------


def test_only_wlcs_skips_aps_and_never_logs_into_a_wlc(monkeypatch):
    calls = _aruba(monkeypatch, switches=[WLC], aps=[AP])
    result = TOOL.run(_Ctx(_nb()), _args(only="wlcs"))
    assert set(result.data["devices"]) == {"hq-wlc01"}
    assert [c.url for c in calls] == [CONDUCTOR]


def test_only_aps_still_reads_the_wlcs(monkeypatch):
    calls = _aruba(monkeypatch, switches=[WLC], aps=[AP])
    result = TOOL.run(_Ctx(_nb()), _args(only="aps"))
    assert set(result.data["devices"]) == {"hq-idf1-ap01"}
    assert [c.url for c in calls] == [CONDUCTOR, WLC_URL]


def test_device_filter(monkeypatch):
    _aruba(monkeypatch, aps=[AP], switches=[WLC])
    result = TOOL.run(_Ctx(_nb()), _args(device="wlc"))
    assert set(result.data["devices"]) == {"hq-wlc01"}


def test_missing_tag_is_created_on_apply(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    plan = TOOL.run(_Ctx(_nb(tags=())), _args())
    assert "would create NetBox tag 'nornirtest'" in plan.changes

    nb = _nb(tags=())
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.extras.tags.created == [{"name": "nornirtest", "slug": "nornirtest"}]


# --- IP and the AP's bridge: new devices ----------------------------------


def test_new_ap_gets_a_br0_that_holds_its_ip(monkeypatch):
    """An AP holds its IP on a software bridge (br0), never on E0/E1 or a radio."""
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()], ap_template=True)

    plan = TOOL.run(_Ctx(nb), _args())
    assert plan.changes[1:] == [
        "hq-idf1-ap01: would create interface 'br0' (bridge)",
        "hq-idf1-ap01: would create IP address 10.1.1.1/24, attach to 'br0' and set as "
        "primary IPv4",
    ]

    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    ap = nb.dcim.devices.get(name="hq-idf1-ap01")
    br0 = nb.dcim.interfaces.get(device_id=ap.id, name="br0")
    assert nb.dcim.interfaces.created == [{"device": ap.id, "name": "br0", "type": "bridge"}]
    (ip,) = nb.ipam.ip_addresses.created
    assert ip["assigned_object_id"] == br0.id
    assert ap.primary_ip4 == nb.ipam.ip_addresses.all()[0].id
    assert not hasattr(nb.dcim.interfaces.get(name="E0"), "updates")  # no LLDP: no port linked
    assert _device(result)["ip_interface"] == "br0"


def test_new_ap_without_a_template_still_gets_br0_not_ethernet0(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()])
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert [body["name"] for body in nb.dcim.interfaces.created] == ["br0"]


def test_new_wlc_ip_without_a_template_falls_back_to_ethernet0(monkeypatch):
    _aruba(monkeypatch, switches=[WLC])
    nb = _nb(prefixes=[_prefix("10.1.0.0/24")])

    plan = TOOL.run(_Ctx(nb), _args())
    assert (
        "hq-wlc01: would create IP address 10.1.0.5/24, attach to 'Ethernet0' "
        "(new interface) and set as primary IPv4"
    ) in plan.changes

    TOOL.run(_Ctx(nb, apply=True), _args())
    (iface,) = nb.dcim.interfaces.created
    assert iface["name"] == "Ethernet0" and iface["type"] == "other"


def test_new_ap_with_one_uplink_links_that_port_to_br0(monkeypatch):
    """LLDP says the AP is up on eth1: E1 is linked to br0 and cabled; the IP is on br0."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    nb = _nb(prefixes=[_prefix()], ap_template=True, devices=[SWITCH], interfaces=[_switch_port()])

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert plan.status is Status.DRIFT
    assert plan.changes[1:] == [
        "hq-idf1-ap01: would create interface 'br0' (bridge)",
        "hq-idf1-ap01: would link 'E1' to bridge 'br0'",
        "hq-idf1-ap01: would create IP address 10.1.1.1/24, attach to 'br0' and set as "
        "primary IPv4",
        "hq-idf1-ap01: would create cable E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24",
    ]

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    ap = nb.dcim.devices.get(name="hq-idf1-ap01")
    br0 = nb.dcim.interfaces.get(device_id=ap.id, name="br0")
    e1 = nb.dcim.interfaces.get(device_id=ap.id, name="E1")
    assert e1.updates == [{"bridge": br0.id}]
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == br0.id
    (cable,) = nb.dcim.cables.created
    assert cable["a_terminations"] == [{"object_type": "dcim.interface", "object_id": e1.id}]
    assert cable["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 400}]
    assert (_device(result)["bond"], _device(result)["uplinks"]) == (None, ["E1"])


def test_new_device_without_wired_ports_gets_the_lldp_port_created(monkeypatch):
    """No template at all: create the port the AP reports, so its cable can land."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    nb = _nb(prefixes=[_prefix()], devices=[SWITCH], interfaces=[_switch_port()])

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert "hq-idf1-ap01: would create interface 'eth1'" in plan.changes
    assert "hq-idf1-ap01: would create cable eth1 <-> hq-idf1-sw01:GigabitEthernet1/0/24" in (
        plan.changes
    )

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    assert [(b["name"], b["type"]) for b in nb.dcim.interfaces.created] == [
        ("br0", "bridge"),
        ("eth1", "other"),
    ]
    assert len(nb.dcim.cables.created) == 1


def test_ip_prefix_vrf_is_carried_onto_the_created_ip(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix(vrf=_Rec(id=4))])
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.ipam.ip_addresses.created[0]["vrf"] == 4


def test_narrowest_prefix_wins(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix("10.0.0.0/8", id_=1), _prefix("10.1.1.0/24", id_=2)])
    TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.ipam.ip_addresses.created[0]["address"] == "10.1.1.1/24"


def test_ip_already_in_netbox_unassigned_is_attached_not_recreated(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    loose = _Rec(id=99, address="10.1.1.1/24", vrf=None, assigned_object_id=None)
    nb = _nb(prefixes=[_prefix()], ips=[loose], ap_template=True)
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created == []
    assert loose.assigned_object_id == nb.dcim.interfaces.get(name="br0").id
    assert nb.dcim.devices.get(name="hq-idf1-ap01").primary_ip4 == 99


# --- yellow: created, but something else could not be ------------------


def test_no_containing_prefix_is_yellow_but_the_device_is_created(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb()  # no prefixes
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.PARTIAL
    assert result.exit_code == 2
    assert nb.dcim.devices.created
    assert nb.ipam.ip_addresses.created == []
    issue = _device(result)["issues"][0]
    assert (
        "IP address could not be added/assigned at this time due to lack of an "
        "established prefix/IP range within NetBox." in issue
    )
    ((level, message),) = ctx.reporter.about("hq-idf1-ap01")
    assert level == "warn" and message.startswith("hq-idf1-ap01: created, but IP 10.1.1.1")


def test_unparseable_ip_is_yellow_not_a_crash(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": "not-an-ip"}])
    result = TOOL.run(_Ctx(_nb(prefixes=[_prefix()])), _args())
    assert result.status is Status.PARTIAL
    assert "unparseable" in _device(result)["issues"][0]


def test_ip_create_failure_is_yellow_and_the_device_still_exists(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()])

    def boom(body):
        raise RuntimeError("duplicate address")

    nb.ipam.ip_addresses.create = boom
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.PARTIAL
    assert nb.dcim.devices.created
    assert "duplicate address" in _device(result)["issues"][0]


def test_ip_held_by_another_device_is_never_taken(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    theirs = _Rec(id=99, address="10.1.1.1/24", vrf=None, assigned_object_id=7777)
    nb = _nb(prefixes=[_prefix()], ips=[theirs], devices=[_ap()], interfaces=_ap_ports())
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.PARTIAL
    assert not hasattr(theirs, "updates")
    assert "another device's interface" in _device(result)["issues"][0]


# --- IP and the AP's bridge: devices NetBox already has -------------------


def _ip_on(interface_id, address="10.1.1.1/24", id_=99):
    return _Rec(
        id=id_,
        address=address,
        vrf=None,
        assigned_object_type="dcim.interface",
        assigned_object_id=interface_id,
    )


SW2 = _Rec(id=201, name="hq-idf1-sw02")
LLDP_E0 = {**LLDP, "Interface": "eth0"}
LLDP_E1_SW2 = {**LLDP, "Chassis Name/ID": "hq-idf1-sw02", "Port ID": "Gi1/0/7"}


def test_ap_cabled_to_two_switches_gets_bond0_and_both_cables(monkeypatch):
    """Each of the AP's ports goes to its own switch: E0 + E1 are bonded into
    bond0, bond0 is linked to br0, the IP moves from E0 (where it was before
    2026-09-28) to br0, and each port is cabled to its own switch."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP_E0, LLDP_E1_SW2])
    ip = _ip_on(300)  # E0
    ap = _ap(primary_ip4=_Rec(id=99))
    nb = _nb(
        prefixes=[_prefix()],
        ips=[ip],
        devices=[ap, SWITCH, SW2],
        interfaces=[*_ap_ports(), _switch_port(), _switch_port(401, 201, "GigabitEthernet1/0/7")],
    )

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert plan.status is Status.DRIFT
    assert plan.changes == [
        "hq-idf1-ap01: would create interface 'br0' (bridge)",
        "hq-idf1-ap01: would create interface 'bond0' (LAG) in bridge 'br0'",
        "hq-idf1-ap01: would add 'E0' to LAG 'bond0'",
        "hq-idf1-ap01: would add 'E1' to LAG 'bond0'",
        "hq-idf1-ap01: would move IP address 10.1.1.1/24 from 'E0' to 'br0'",
        "hq-idf1-ap01: would create cable E0 <-> hq-idf1-sw01:GigabitEthernet1/0/24",
        "hq-idf1-ap01: would create cable E1 <-> hq-idf1-sw02:GigabitEthernet1/0/7",
    ]

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    br0 = nb.dcim.interfaces.get(device_id=100, name="br0")
    bond0 = nb.dcim.interfaces.get(device_id=100, name="bond0")
    assert (br0.type, bond0.type, bond0.bridge) == ("bridge", "lag", br0.id)
    for port in ("E0", "E1"):
        assert nb.dcim.interfaces.get(device_id=100, name=port).updates == [{"lag": bond0.id}]
    assert ip.assigned_object_id == br0.id
    assert not hasattr(ap, "updates")  # it was already the primary IP
    pairs = {
        (c["a_terminations"][0]["object_id"], c["b_terminations"][0]["object_id"])
        for c in nb.dcim.cables.created
    }
    assert pairs == {(300, 400), (301, 401)}
    assert (_device(result)["bond"], _device(result)["uplinks"]) == ("bond0", ["E0", "E1"])

    again = TOOL.run(_Ctx(nb), _args(only="aps"))  # and the next run finds nothing to do
    assert [c for c in again.changes if "cable" not in c] == []


def test_single_uplink_ap_gaining_a_second_uplink_moves_into_a_bond(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}], lldp=[LLDP_E0, LLDP_E1_SW2])
    nb = _nb(
        devices=[_ap(), SWITCH, SW2],
        interfaces=[
            *_ap_ports(linked=("E0",)),
            _switch_port(),
            _switch_port(401, 201, "GigabitEthernet1/0/7"),
        ],
    )
    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert "hq-idf1-ap01: would add 'E0' to LAG 'bond0' and clear its own bridge link" in (
        plan.changes
    )
    TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    bond0 = nb.dcim.interfaces.get(device_id=100, name="bond0")
    e0 = nb.dcim.interfaces.get(device_id=100, name="E0")
    assert e0.updates == [{"lag": bond0.id, "bridge": None}]


def test_existing_ap_ip_on_a_port_moves_to_br0(monkeypatch):
    """Wap-A-1's IP is on E0 in NetBox from before; it belongs on br0."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    ip = _ip_on(300)  # E0
    ap = _ap(primary_ip4=_Rec(id=99))
    nb = _nb(
        prefixes=[_prefix()],
        ips=[ip],
        devices=[ap, SWITCH],
        interfaces=[*_ap_ports(), _switch_port()],
    )

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert "hq-idf1-ap01: would move IP address 10.1.1.1/24 from 'E0' to 'br0'" in plan.changes

    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args(only="aps"))
    assert result.status is Status.CHANGED
    assert ip.assigned_object_id == nb.dcim.interfaces.get(device_id=100, name="br0").id
    assert not hasattr(ap, "updates")  # already its primary: no device write
    assert ("success", "hq-idf1-ap01: updated") in ctx.reporter.lines


def test_existing_ap_ip_moves_to_br0_even_without_lldp(monkeypatch):
    """br0 is where an AP's IP lives, whatever LLDP says, so no evidence is needed."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP])  # no LLDP rows
    ip = _ip_on(301)  # E1
    nb = _nb(
        prefixes=[_prefix()],
        ips=[ip],
        devices=[_ap(primary_ip4=_Rec(id=99))],
        interfaces=_ap_ports(br0=True),
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    assert ip.assigned_object_id == BR0_ID
    assert _device(result)["ip_interface_source"] == "requested"


def test_existing_ap_missing_its_ip_gets_it_on_br0(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    ap = _ap(primary_ip4=None)
    nb = _nb(prefixes=[_prefix()], devices=[ap], interfaces=_ap_ports(br0=True))
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == BR0_ID
    assert ap.updates == [{"primary_ip4": nb.ipam.ip_addresses.all()[0].id}]


def test_existing_ap_with_a_new_ip_gets_it_as_primary_old_one_left(monkeypatch):
    """A DHCP'd AP whose address changed: the new IP becomes primary, the old one stays."""
    _aruba(monkeypatch, aps=[{**AP, "IP Address": "10.1.1.9"}])
    old = _ip_on(BR0_ID, "10.1.1.1/24", id_=98)
    ap = _ap(primary_ip4=_Rec(id=98))
    nb = _nb(prefixes=[_prefix()], ips=[old], devices=[ap], interfaces=_ap_ports(br0=True))
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created[0]["address"] == "10.1.1.9/24"
    assert old in nb.ipam.ip_addresses.all()
    assert ap.primary_ip4 != 98


def test_existing_ap_already_right_is_left_alone(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP_E0])
    ip = _ip_on(BR0_ID)
    ap = _ap(primary_ip4=_Rec(id=99))
    nb = _nb(
        prefixes=[_prefix()],
        ips=[ip],
        devices=[ap, SWITCH],
        interfaces=[
            *_ap_ports(e0_cable=_Rec(id=5), linked=("E0",)),
            _switch_port(cable=_Rec(id=5)),
        ],
    )
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args(only="aps"))
    assert result.status is Status.OK
    assert result.changes == []
    assert not hasattr(ip, "updates") and not hasattr(ap, "updates")
    assert _device(result)["cables"][0]["status"] == "in-sync"
    assert ctx.reporter.about("hq-idf1-ap01") == [("success", "hq-idf1-ap01: in sync")]


def test_a_bridge_that_cannot_be_created_leaves_the_ip_unplaced(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    ip = _ip_on(300)
    nb = _nb(prefixes=[_prefix()], ips=[ip], devices=[_ap()], interfaces=_ap_ports())

    def refuse(body):
        raise RuntimeError("permission denied")

    nb.dcim.interfaces.create = refuse
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.PARTIAL
    assert _device(result)["issues"] == [
        "could not create interface 'br0' (bridge): permission denied",
        "IP 10.1.1.1: not placed, because its bridge couldn't be created",
    ]
    assert ip.assigned_object_id == 300  # left where it was


# --- platform ------------------------------------------------------------


def test_platform_plan_then_apply(monkeypatch):
    ap_row = {**AP, "Software Version": "8.10.0.5", "IP Address": ""}
    _aruba(monkeypatch, switches=[WLC], aps=[ap_row])
    ap = _ap()
    nb = _nb(devices=[ap])
    nb.dcim.platforms._items.append(_Rec(id=50, name="AOS 8", slug="aos-8"))

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert "hq-idf1-ap01: would set platform to 'AOS 8'" in plan.changes

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    assert {"platform": 50} in ap.updates
    assert _device(result)["platform"] == "AOS 8"


def test_platform_comes_from_the_wlc_when_the_conductor_lacks_it(monkeypatch):
    _aruba(
        monkeypatch,
        switches=[WLC],
        aps=[{**AP, "IP Address": ""}],
        wlc_aps=[{**AP, "Software Version": "8.10.0.5"}],
    )
    ap = _ap()
    nb = _nb(devices=[ap])
    nb.dcim.platforms._items.append(_Rec(id=50, name="AOS 8", slug="aos-8"))
    result = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert "hq-idf1-ap01: would set platform to 'AOS 8'" in result.changes


def test_new_ap_gets_its_platform_after_creation(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "Software Version": "8.10.0.5"}])
    nb = _nb(prefixes=[_prefix()])
    nb.dcim.platforms._items.append(_Rec(id=50, name="AOS 8", slug="aos-8"))
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert "platform" not in nb.dcim.devices.created[0]  # creation never depends on it
    assert nb.dcim.devices.get(name="hq-idf1-ap01").platform == 50


def test_platform_already_in_sync_is_a_noop(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "Software Version": "8.10.0.5", "IP Address": ""}])
    nb = _nb(devices=[_ap(platform=_Rec(id=50))], interfaces=[_br0()])
    nb.dcim.platforms._items.append(_Rec(id=50, name="AOS 8", slug="aos-8"))
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert _device(result)["platform"] == "AOS 8"


def test_no_version_field_is_informational(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])
    result = TOOL.run(_Ctx(_nb(devices=[_ap()], interfaces=[_br0()])), _args())
    assert result.status is Status.OK
    assert "no software/version field" in _device(result)["platform_note"]


def test_unmatched_platform_version_is_yellow(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "Software Version": "8.10.0.5", "IP Address": ""}])
    result = TOOL.run(_Ctx(_nb(devices=[_ap()])), _args())
    assert result.status is Status.PARTIAL
    assert "no NetBox platform matches" in _device(result)["issues"][0]


# --- querying the WLCs ---------------------------------------------------


def test_wlc_reached_at_its_netbox_primary_ip_with_custom_port(monkeypatch):
    calls = _aruba(monkeypatch, switches=[WLC], aps=[AP])
    wlc = _Rec(
        id=1, name="hq-wlc01", serial="CX0009", tags=[_TAG], primary_ip4=_Rec(address="10.9.9.9/24")
    )
    TOOL.run(_Ctx(_nb(devices=[wlc])), _args(only="aps", wlc_port=8443, wlc_insecure=True))
    assert calls[1].url == "https://10.9.9.9:8443"
    assert calls[1].verify is False


def test_wlc_netbox_does_not_have_yet_is_reached_at_the_conductors_ip(monkeypatch):
    calls = _aruba(monkeypatch, switches=[WLC], aps=[AP])
    TOOL.run(_Ctx(_nb()), _args())
    assert calls[1].url == WLC_URL


def test_wlc_with_no_address_is_yellow(monkeypatch):
    _aruba(monkeypatch, switches=[{**WLC, "IP Address": ""}], aps=[AP])
    result = TOOL.run(_Ctx(_nb(prefixes=[_prefix()])), _args(only="aps"))
    assert result.status is Status.PARTIAL
    assert "no address" in result.data["wlcs"]["hq-wlc01"]["error"]
    assert "not every WLC could be queried" in _device(result)["cable_note"]


def test_wlc_login_failure_is_yellow_and_the_other_wlcs_are_still_read(monkeypatch):
    wlc_b = {
        "Name": "hq-wlc02",
        "Model": "A7210",
        "Serial Number": "CX0010",
        "IP Address": "10.1.0.6",
    }
    _aruba(
        monkeypatch,
        switches=[WLC, wlc_b],
        aps=[AP],
        lldp=[LLDP],
        errors={WLC_URL: ArubaError("could not reach")},
    )
    nb = _nb(
        prefixes=[_prefix(), _prefix("10.1.0.0/24", id_=11)],
        ap_template=True,
        devices=[SWITCH],
        interfaces=[_switch_port()],
    )
    ctx = _Ctx(nb)
    result = TOOL.run(ctx, _args())
    assert result.status is Status.PARTIAL
    assert "could not reach" in result.data["wlcs"]["hq-wlc01"]["error"]
    assert result.data["wlcs"]["hq-wlc02"]["lldp_neighbors"] == 1
    assert any("cable E1 <-> hq-idf1-sw01" in c for c in result.changes)  # wlc02's data used
    assert _device(result, "hq-wlc01")["status"] == "partial"
    assert ctx.reporter.about("hq-wlc01")[0][0] == "warn"


def test_failed_wlc_outside_the_device_filter_is_still_reported(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP], errors={WLC_URL: ArubaError("timed out")})
    ctx = _Ctx(_nb(prefixes=[_prefix()]))
    result = TOOL.run(ctx, _args(only="aps"))
    assert result.status is Status.PARTIAL
    assert ("warn", "hq-wlc01: could not read its APs' LLDP/version/radio data — timed out") in (
        ctx.reporter.lines
    )


def test_wlc_with_no_ap_data_is_informational(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP], wlc_aps=[])
    result = TOOL.run(_Ctx(_nb(prefixes=[_prefix()])), _args(only="aps"))
    assert result.status is Status.DRIFT
    assert result.data["wlcs"]["hq-wlc01"] == {
        "url": WLC_URL,
        "aps": 0,
        "lldp_neighbors": 0,
        "bss": 0,
    }


# --- LLDP read one AP at a time (Aruba 9240 bug workaround) ---------------

_NOT_JSON = "the Conductor response for 'show ap lldp neighbors' was not JSON"


def _per_ap_run(monkeypatch, lldp_by_ap, *, bss=None):
    if bss is None:  # air-monitor rows: they name the AP without bringing in radio updates
        bss = [_bss("Corp", kind="am"), _bss("Corp", band="2.4", channel="6", width=20, kind="am")]
    calls = _aruba(
        monkeypatch,
        switches=[WLC],
        aps=[{**AP, "IP Address": ""}],
        bss=bss,
        lldp_by_ap=lldp_by_ap,
    )
    ctx = _Ctx(_cabling_nb())
    result = TOOL.run(ctx, _args(only="aps"))
    (wlc_call,) = [c for c in calls if c.url == WLC_URL]
    return wlc_call.asked, ctx, result


def test_unreadable_lldp_table_is_read_one_ap_at_a_time(monkeypatch):
    asked, ctx, result = _per_ap_run(monkeypatch, {"hq-idf1-ap01": [LLDP]})
    assert asked == ["hq-idf1-ap01"]  # once, though the bss-table lists it twice
    assert result.status is Status.DRIFT
    assert "hq-idf1-ap01: would create cable E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24" in (
        result.changes
    )
    assert _device(result)["status"] == "ok"
    wlc = result.data["wlcs"]["hq-wlc01"]
    assert wlc["lldp_neighbors"] == 1
    assert wlc["bss"] == 2  # the bss-table isn't lost with the LLDP table
    assert wlc["lldp_per_ap"] == {"reason": _NOT_JSON, "asked": 1, "failed": {}}
    assert (
        "info",
        f"hq-wlc01: its LLDP table couldn't be read ({_NOT_JSON}); asked its 1 AP(s) one at a time",
    ) in ctx.reporter.lines


def test_ap_its_wlc_cannot_report_on_its_own_is_yellow(monkeypatch):
    asked, ctx, result = _per_ap_run(monkeypatch, {"hq-idf1-ap01": ArubaError("timed out")})
    assert asked == ["hq-idf1-ap01"]
    assert result.status is Status.PARTIAL
    assert _device(result)["status"] == "partial"
    assert "could not read its LLDP neighbors — hq-wlc01: timed out" in _device(result)["issues"]
    assert result.data["wlcs"]["hq-wlc01"]["lldp_per_ap"]["failed"] == {"hq-idf1-ap01": "timed out"}
    assert any(
        m.endswith("asked its 1 AP(s) one at a time, 1 of them failed")
        for _level, m in ctx.reporter.lines
    )


def test_unreadable_lldp_table_with_no_ap_to_ask_leaves_the_wlc_unread(monkeypatch):
    asked, _ctx, result = _per_ap_run(monkeypatch, {}, bss=[])
    assert asked == []
    assert result.status is Status.PARTIAL
    assert result.data["wlcs"]["hq-wlc01"] == {"url": WLC_URL, "error": _NOT_JSON}


# --- cables ---------------------------------------------------------------


def _cabling_nb(*, ap_ports=None, switch_ports=None, devices=(), prefixes=(), cables=()):
    return _nb(
        prefixes=list(prefixes),
        devices=[_ap(), SWITCH, *devices],
        interfaces=[
            *(_ap_ports(linked=("E1",)) if ap_ports is None else ap_ports),
            *([_switch_port()] if switch_ports is None else switch_ports),
        ],
        cables=list(cables),
    )


def _cable(id_, a, b):
    """A NetBox cable between two ``(interface id, device name, port name)`` ends,
    shaped like pynetbox's terminations (``object_type``/``object_id``/``object``)."""

    def end(interface_id, device, port, object_type="dcim.interface"):
        return {
            "object_type": object_type,
            "object_id": interface_id,
            "object": {"name": port, "device": {"name": device}},
        }

    return _Rec(id=id_, a_terminations=[end(*a)], b_terminations=[end(*b)])


AP_E0 = (300, "hq-idf1-ap01", "E0")
AP_E1 = (301, "hq-idf1-ap01", "E1")
SW_24 = (400, "hq-idf1-sw01", "GigabitEthernet1/0/24")
SW_5 = (405, "hq-idf1-sw01", "GigabitEthernet1/0/5")


def _cabling_run(monkeypatch, nb, rows, *, apply=False):
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}], lldp=rows)
    return TOOL.run(_Ctx(nb, apply=apply), _args(only="aps"))


def test_cable_plan_then_apply(monkeypatch):
    nb = _cabling_nb()
    plan = _cabling_run(monkeypatch, nb, [LLDP])
    assert plan.status is Status.DRIFT
    assert "hq-idf1-ap01: would create cable E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24" in (
        plan.changes
    )

    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.cables.created
    assert body["a_terminations"] == [{"object_type": "dcim.interface", "object_id": 301}]
    assert body["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 400}]
    assert body["status"] == "connected"


def test_row_without_an_interface_column_uses_the_first_wired_port(monkeypatch):
    row = {k: v for k, v in LLDP.items() if k != "Interface"}
    result = _cabling_run(monkeypatch, _cabling_nb(), [row])
    assert any("create cable E0 <-> " in c for c in result.changes)


def test_cable_falls_back_to_chassis_id_when_chassis_name_does_not_match(monkeypatch):
    row = {
        "AP Name": "hq-idf1-ap01",
        "Interface": "eth0",
        "Chassis Name": "aa:bb:cc:dd:ee:ff",
        "Chassis ID": "hq-idf1-sw01",
        "Port ID": "Gi1/0/24",
    }
    result = _cabling_run(monkeypatch, _cabling_nb(), [row])
    assert result.status is Status.DRIFT
    assert any("would create cable" in c for c in result.changes)


def test_cable_resolves_the_correct_stack_member(monkeypatch):
    """A stack shares one LLDP chassis identity; each member is its own NetBox
    device. The member number in the port id picks the right one."""
    row = {**LLDP, "Port ID": "GigabitEthernet2/0/24"}
    member1 = _Rec(id=201, name="hq-idf1-sw01-1")
    member2 = _Rec(id=202, name="hq-idf1-sw01-2")
    nb = _nb(
        devices=[_ap(), member1, member2],
        interfaces=[
            *_ap_ports(),
            _switch_port(401, 201, "GigabitEthernet2/0/24"),
            _switch_port(402, 202, "GigabitEthernet2/0/24"),
        ],
    )
    result = _cabling_run(monkeypatch, nb, [row], apply=True)
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.cables.created
    assert body["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 402}]


def test_cable_resolves_the_correct_stack_member_with_fqdn_naming(monkeypatch):
    row = {**LLDP, "Chassis Name/ID": "hq-idf1-sw01.ect.net", "Port ID": "GigabitEthernet2/0/24"}
    member2 = _Rec(id=202, name="hq-idf1-sw01-2.ect.net")
    nb = _nb(
        devices=[_ap(), member2],
        interfaces=[*_ap_ports(), _switch_port(402, 202, "GigabitEthernet2/0/24")],
    )
    result = _cabling_run(monkeypatch, nb, [row], apply=True)
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.cables.created
    assert body["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 402}]


def test_cable_falls_back_to_bare_hostname_when_switch_is_not_stacked(monkeypatch):
    row = {**LLDP, "Port ID": "GigabitEthernet1/0/24"}
    result = _cabling_run(monkeypatch, _cabling_nb(), [row])
    assert any("would create cable" in c for c in result.changes)


def test_no_lldp_row_is_informational(monkeypatch):
    result = _cabling_run(monkeypatch, _cabling_nb(), [])
    assert result.status is Status.OK
    assert "no LLDP neighbor" in _device(result)["cable_note"]


def test_unmatched_lldp_hostname_is_yellow(monkeypatch):
    nb = _nb(devices=[_ap()], interfaces=_ap_ports())  # the switch isn't in NetBox
    result = _cabling_run(monkeypatch, nb, [LLDP])
    assert result.status is Status.PARTIAL
    assert "matched no NetBox device" in _device(result)["issues"][0]


def test_unmatched_switch_port_is_yellow(monkeypatch):
    nb = _cabling_nb(switch_ports=[_switch_port(name="GigabitEthernet1/0/1")])
    result = _cabling_run(monkeypatch, nb, [LLDP])
    assert result.status is Status.PARTIAL
    assert "matched no interface" in _device(result)["issues"][0]


def test_ap_without_the_reported_port_is_yellow(monkeypatch):
    """NetBox says the AP has only E0; the AP says it's cabled on eth1. Don't guess."""
    nb = _cabling_nb(ap_ports=[_iface(300, 100, "E0"), _br0()])
    result = _cabling_run(monkeypatch, nb, [LLDP])
    assert result.status is Status.PARTIAL
    assert _device(result)["issues"] == ["cable: 'hq-idf1-ap01' has no interface matching 'eth1'"]


def test_ap_moved_to_another_switch_port_gets_its_cable_repointed(monkeypatch):
    """NetBox has E1 on Gi1/0/5; LLDP says Gi1/0/24. The same cable is re-pointed."""
    nb = _cabling_nb(
        ap_ports=_ap_ports(e1_cable=_Rec(id=7), linked=("E1",)),
        switch_ports=[
            _switch_port(),
            _switch_port(405, name="GigabitEthernet1/0/5", cable=_Rec(id=7)),
        ],
        cables=[_cable(7, AP_E1, SW_5)],
    )
    plan = _cabling_run(monkeypatch, nb, [LLDP])
    assert plan.status is Status.DRIFT
    assert plan.changes == [
        "hq-idf1-ap01: would update cable #7: hq-idf1-sw01:GigabitEthernet1/0/5 -> "
        "hq-idf1-sw01:GigabitEthernet1/0/24, now E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24"
    ]
    assert nb.dcim.cables.bulk_updated == []

    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.CHANGED
    assert nb.dcim.cables.bulk_updated == [
        {
            "id": 7,
            "a_terminations": [{"object_type": "dcim.interface", "object_id": 301}],
            "b_terminations": [{"object_type": "dcim.interface", "object_id": 400}],
        }
    ]
    assert nb.dcim.cables.created == []  # re-pointed, not recreated
    assert _device(result)["cables"][0]["cable_id"] == 7


def test_cable_on_the_aps_other_port_is_moved_to_the_reported_port(monkeypatch):
    """The old cable is on E0 (the pre-merge first-wired pick); the AP reports eth1.
    The cable's AP end moves from E0 to E1."""
    nb = _cabling_nb(
        ap_ports=_ap_ports(e0_cable=_Rec(id=7), linked=("E1",)),
        switch_ports=[_switch_port(cable=_Rec(id=7))],
        cables=[_cable(7, AP_E0, SW_24)],
    )
    plan = _cabling_run(monkeypatch, nb, [LLDP])
    assert plan.changes == [
        "hq-idf1-ap01: would update cable #7: hq-idf1-ap01:E0 -> hq-idf1-ap01:E1, now "
        "E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24"
    ]
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.CHANGED
    (body,) = nb.dcim.cables.bulk_updated
    assert body["a_terminations"] == [{"object_type": "dcim.interface", "object_id": 301}]
    assert body["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 400}]


def test_both_ports_cabled_elsewhere_is_yellow_and_nothing_is_deleted(monkeypatch):
    nb = _cabling_nb(
        ap_ports=_ap_ports(e1_cable=_Rec(id=7), linked=("E1",)),
        switch_ports=[_switch_port(cable=_Rec(id=8))],
        cables=[_cable(7, AP_E1, SW_5), _cable(8, (999, "hq-idf1-ap09", "E0"), SW_24)],
    )
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.PARTIAL
    assert nb.dcim.cables.bulk_updated == [] and nb.dcim.cables.created == []
    (issue,) = _device(result)["issues"]
    assert "are each cabled to something else in NetBox" in issue
    assert "would delete a cable" in issue


def test_patch_panel_path_that_reaches_the_reported_port_is_in_sync(monkeypatch):
    e1 = _iface(301, 100, "E1", "1000base-t", cable=_Rec(id=9))
    e1.bridge = _Rec(id=BR0_ID)
    e1.link_peers_type = "dcim.frontport"
    e1.connected_endpoints_type = "dcim.interface"
    e1.connected_endpoints = [_Rec(id=400)]
    nb = _cabling_nb(ap_ports=[_iface(300, 100, "E0"), e1, _br0()])
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.OK
    assert _device(result)["cables"][0]["status"] == "in-sync"


def test_patch_panel_cable_that_goes_elsewhere_is_only_noted(monkeypatch):
    """NetBox can't be corrected from one LLDP report once a patch panel is in the
    path, so it's left alone and noted, never re-pointed."""
    e1 = _iface(301, 100, "E1", "1000base-t", cable=_Rec(id=9))
    e1.bridge = _Rec(id=BR0_ID)
    e1.link_peers_type = "dcim.frontport"
    panel_port = {
        "object_type": "dcim.frontport",
        "object_id": 77,
        "object": {"name": "1", "device": {"name": "idf1-panel"}},
    }
    cable = _cable(9, AP_E1, SW_5)
    cable.b_terminations = [panel_port]
    nb = _cabling_nb(ap_ports=[_iface(300, 100, "E0"), e1, _br0()], cables=[cable])
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.OK
    assert nb.dcim.cables.bulk_updated == []
    (note,) = _device(result)["notes"]
    assert "runs into a patch panel" in note and "left alone" in note


def test_a_port_freed_by_one_ap_is_cabled_to_the_next(monkeypatch):
    """AP1 moved from Gi1/0/5 to Gi1/0/24 and AP2 took Gi1/0/5, in the same run: AP1's
    cable is re-pointed first, and AP2 then sees Gi1/0/5 as free and gets a new
    cable, instead of taking AP1's."""
    ap2_row = {"Name": "hq-idf1-ap02", "AP Type": "515", "Serial #": "CN0002"}
    lldp = [
        LLDP,
        {
            "AP": "hq-idf1-ap02",
            "Interface": "eth0",
            "Chassis Name/ID": "hq-idf1-sw01",
            "Port ID": "Gi1/0/5",
        },
    ]
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}, ap2_row], lldp=lldp)
    ap2 = _ap(id_=110, name="hq-idf1-ap02", serial="CN0002")
    nb = _nb(
        devices=[_ap(), ap2, SWITCH],
        interfaces=[
            *_ap_ports(e1_cable=_Rec(id=7), linked=("E1",)),
            _iface(310, 110, "E0"),
            _iface(311, 110, "br0", "bridge"),
            _switch_port(),
            _switch_port(405, name="GigabitEthernet1/0/5", cable=_Rec(id=7)),
        ],
        cables=[_cable(7, AP_E1, SW_5)],
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    assert [u["id"] for u in nb.dcim.cables.bulk_updated] == [7]
    (created,) = nb.dcim.cables.created
    assert created["a_terminations"] == [{"object_type": "dcim.interface", "object_id": 310}]
    assert created["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 405}]


def test_cable_update_failure_is_yellow(monkeypatch):
    nb = _cabling_nb(
        ap_ports=_ap_ports(e1_cable=_Rec(id=7), linked=("E1",)),
        switch_ports=[
            _switch_port(),
            _switch_port(405, name="GigabitEthernet1/0/5", cable=_Rec(id=7)),
        ],
        cables=[_cable(7, AP_E1, SW_5)],
    )

    def boom(objects):
        raise RuntimeError("cable is locked")

    nb.dcim.cables.update = boom
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.PARTIAL
    assert "could not update cable #7" in _device(result)["issues"][0]


def test_cable_create_failure_is_yellow(monkeypatch):
    nb = _cabling_nb()

    def boom(body):
        raise RuntimeError("termination already occupied")

    nb.dcim.cables.create = boom
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.PARTIAL
    assert "termination already occupied" in _device(result)["issues"][0]


# --- radios: channel, power, SSIDs ------------------------------------------


def _radio(id_, name, device_id=100, **rf):
    return _Rec(id=id_, device_id=device_id, name=name, type="ieee802.11ax", cable=None, **rf)


def _bss(ssid, band="5", channel="52E", width=80, eirp="18.0", ap="hq-idf1-ap01", kind="ap"):
    return {
        "ap name": ap,
        "ess": ssid,
        "band/ht-mode/bandwidth": f"{band}GHz/HE/{width}MHz",
        "ch/EIRP/max-EIRP": f"{channel}/{eirp}/23.0",
        "type": kind,
    }


GUEST = "DavesAuto-Wireless-Guest"
CORP_WLAN = _Rec(id=70, ssid="Corp")


def _radio_run(monkeypatch, radios, bss, *, apply=False, wlans=(CORP_WLAN,)):
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}], bss=bss)
    nb = _nb(
        devices=[_ap()],
        interfaces=[_iface(300, 100, "E0"), _iface(301, 100, "E1", "1000base-t"), _br0(), *radios],
        wlans=list(wlans),
    )
    return nb, TOOL.run(_Ctx(nb, apply=apply), _args(only="aps"))


def test_radios_get_channel_power_and_ssids_and_missing_wlans_are_created(monkeypatch):
    radios = [_radio(320, "2.4GHz WiFi"), _radio(321, "5GHz WiFi")]
    bss = [
        _bss(GUEST, band="2.4", channel="1", width=20, eirp="10.0"),
        _bss(GUEST),
        _bss("Corp"),
    ]
    _, plan = _radio_run(monkeypatch, radios, bss)
    assert plan.status is Status.DRIFT
    assert plan.changes == [
        f"would create wireless LAN {GUEST!r}",
        "hq-idf1-ap01: would set radio '2.4GHz WiFi': role 'ap', channel 1 (20 MHz), "
        f"tx power 10 dBm, SSIDs {GUEST}",
        "hq-idf1-ap01: would set radio '5GHz WiFi': role 'ap', channel 52E (80 MHz), "
        f"tx power 18 dBm, SSIDs Corp, {GUEST}",
    ]

    nb, result = _radio_run(monkeypatch, radios, bss, apply=True)
    assert result.status is Status.CHANGED
    (created,) = nb.wireless.wireless_lans.created
    assert created == {"ssid": GUEST}
    guest_id = nb.wireless.wireless_lans.get(ssid=GUEST).id
    assert radios[0].updates == [
        {
            "rf_role": "ap",
            "rf_channel": "2.4g-1-2412-22",
            "rf_channel_frequency": 2412.0,
            "rf_channel_width": 22.0,
            "tx_power": 10,
            "wireless_lans": [guest_id],
        }
    ]
    assert radios[1].updates[0]["rf_channel"] == "5g-58-5290-80"
    assert radios[1].updates[0]["wireless_lans"] == [70, guest_id]
    assert [r["status"] for r in _device(result)["radios"]] == ["changed", "changed"]


def test_radios_that_already_match_are_in_sync(monkeypatch):
    radio = _radio(
        321,
        "5GHz WiFi",
        rf_role="ap",
        rf_channel="5g-58-5290-80",
        rf_channel_frequency=5290.0,
        rf_channel_width=80.0,
        tx_power=18,
        wireless_lans=[_Rec(id=70)],
    )
    _, result = _radio_run(monkeypatch, [radio], [_bss("Corp")], apply=True)
    assert result.status is Status.OK
    assert result.changes == [] and not hasattr(radio, "updates")
    assert _device(result)["radios"][0]["status"] == "in-sync"


def test_an_airmatch_channel_change_updates_only_the_channel(monkeypatch):
    radio = _radio(
        321,
        "5GHz WiFi",
        rf_role="ap",
        rf_channel="5g-42-5210-80",
        rf_channel_frequency=5210.0,
        rf_channel_width=80.0,
        tx_power=18,
        wireless_lans=[_Rec(id=70)],
    )
    _, result = _radio_run(monkeypatch, [radio], [_bss("Corp")], apply=True)
    assert result.changes == ["hq-idf1-ap01: set radio '5GHz WiFi': channel 52E (80 MHz)"]
    assert radio.updates == [
        {"rf_channel": "5g-58-5290-80", "rf_channel_frequency": 5290.0, "rf_channel_width": 80.0}
    ]


def test_a_band_netbox_has_no_radio_for_is_yellow(monkeypatch):
    bss = [_bss("Corp", band="6", channel="37S", width=160)]
    _, result = _radio_run(monkeypatch, [_radio(321, "5GHz WiFi")], bss)
    assert result.status is Status.PARTIAL
    assert _device(result)["issues"] == [
        "radio 6 GHz: NetBox has no 6 GHz radio interface on it (named like '6GHz WiFi')"
    ]


def test_two_radios_on_one_band_are_skipped_with_a_note(monkeypatch):
    """An AP in dual-5GHz mode: the table can't say which radio is which."""
    bss = [_bss("Corp", channel="36E"), _bss("Corp", channel="149E")]
    radio = _radio(321, "5GHz WiFi")
    _, result = _radio_run(monkeypatch, [radio], bss, apply=True)
    assert result.status is Status.OK
    assert not hasattr(radio, "updates")
    assert "can't be told apart" in _device(result)["notes"][0]


def test_duplicate_wlans_leave_the_radios_wlan_list_alone(monkeypatch):
    radio = _radio(321, "5GHz WiFi")
    wlans = (CORP_WLAN, _Rec(id=71, ssid="Corp"))
    _, result = _radio_run(monkeypatch, [radio], [_bss("Corp")], apply=True, wlans=wlans)
    assert result.status is Status.CHANGED  # a note, not a problem
    assert "wireless_lans" not in radio.updates[0]
    assert "NetBox has 2 wireless LANs with SSID 'Corp'" in _device(result)["notes"][0]


def test_a_wlan_that_cannot_be_created_is_yellow(monkeypatch):
    radio = _radio(321, "5GHz WiFi")
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}], bss=[_bss(GUEST)])
    nb = _nb(devices=[_ap()], interfaces=[_iface(300, 100, "E0"), _br0(), radio])

    def refuse(body):
        raise RuntimeError("permission denied")

    nb.wireless.wireless_lans.create = refuse
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.PARTIAL
    assert "wireless_lans" not in radio.updates[0]
    assert "couldn't be created: permission denied" in _device(result)["issues"][0]


def test_a_new_aps_radios_are_filled_from_its_template(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[{**AP, "IP Address": ""}], bss=[_bss("Corp")])
    nb = _nb(ap_template=True, wlans=[CORP_WLAN])
    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert (
        "hq-idf1-ap01: would set radio '5GHz WiFi': role 'ap', channel 52E (80 MHz), "
        "tx power 18 dBm, SSIDs Corp"
    ) in plan.changes

    TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    ap = nb.dcim.devices.get(name="hq-idf1-ap01")
    radio = nb.dcim.interfaces.get(device_id=ap.id, name="5GHz WiFi")
    assert radio.updates[0]["rf_channel"] == "5g-58-5290-80"
    assert radio.updates[0]["wireless_lans"] == [70]


def test_air_monitors_have_no_radio_data(monkeypatch):
    radio = _radio(321, "5GHz WiFi")
    _, result = _radio_run(monkeypatch, [radio], [_bss("", kind="am")], apply=True)
    assert result.status is Status.OK
    assert not hasattr(radio, "updates")
    assert _device(result)["radio_note"] == "no radio data reported for this AP"


# --- registration ---------------------------------------------------------


def test_tool_is_registered_and_enrich_is_gone():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["wireless"] == {"sync": TOOL}
    assert TOOL.writes is True
