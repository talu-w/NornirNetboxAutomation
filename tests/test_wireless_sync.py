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

    def all(self):
        return list(self._items)

    def get(self, **kw):
        return next(iter(self.filter(**kw)), None)

    def filter(self, **kw):
        return [
            item for item in self._items if all(getattr(item, k, None) == v for k, v in kw.items())
        ]

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
    def __init__(self, *, roles, sites, types, devices, tags, prefixes, ips, interfaces, templates):
        self.version = "4.1"
        self.dcim = SimpleNamespace(
            device_roles=_Endpoint(roles),
            sites=_Endpoint(sites),
            device_types=_Endpoint(types),
            interfaces=_Endpoint(interfaces),
            interface_templates=_Endpoint(templates),
            platforms=_Endpoint(),
            cables=_Endpoint(),
        )
        self.dcim.devices = _Devices(devices, self)
        self.extras = SimpleNamespace(tags=_Endpoint(tags))
        self.ipam = SimpleNamespace(prefixes=_Endpoint(prefixes), ip_addresses=_Endpoint(ips))


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
    )


def _prefix(cidr="10.1.1.0/24", vrf=None, id_=10):
    return _Rec(id=id_, prefix=cidr, vrf=vrf)


def _ap(*, id_=100, name="hq-idf1-ap01", serial="CN0001", tagged=True, **extra):
    return _Rec(id=id_, name=name, serial=serial, tags=[_TAG] if tagged else [], **extra)


def _iface(id_, device_id, name, type_="2.5gbase-t", cable=None):
    return _Rec(id=id_, device_id=device_id, name=name, type=type_, cable=cable)


def _ap_ports(device_id=100, *, e0_cable=None, e1_cable=None):
    return [
        _iface(300, device_id, "E0", cable=e0_cable),
        _iface(301, device_id, "E1", "1000base-t", cable=e1_cable),
        _iface(302, device_id, "5GHz WiFi", "ieee802.11ax"),
    ]


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


def _aruba(monkeypatch, *, switches=(), aps=(), wlc_aps=None, lldp=(), errors=None):
    """The Conductor answers at CONDUCTOR; any other URL is a WLC.

    A WLC's ``show ap database long`` returns ``wlc_aps`` (default: the same
    rows as the Conductor's); ``errors`` maps a URL to what logging in raises.
    """
    calls: list[SimpleNamespace] = []

    class FakeClient:
        def __init__(self, url, user, pw, *, verify=True, timeout=30.0):
            self.url = url
            calls.append(SimpleNamespace(url=url, user=user, password=pw, verify=verify))

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

        def ap_lldp_neighbors(self):
            return list(lldp)

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


def test_missing_role(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    with pytest.raises(ToolError, match="device role with slug 'wireless-access-point'"):
        TOOL.run(_Ctx(_nb(with_ap_role=False)), _args())


def test_missing_wireless_branch_root_raises(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    with pytest.raises(RoleScopeError, match="'wireless-network'"):
        TOOL.run(_Ctx(_nb(with_branch=False)), _args())


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


# --- IP: new devices -----------------------------------------------------


def test_new_device_ip_without_a_template_falls_back_to_ethernet0(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()])

    plan = TOOL.run(_Ctx(nb), _args())
    assert (
        "hq-idf1-ap01: would create IP address 10.1.1.1/24, attach to 'Ethernet0' "
        "(new interface) and set as primary IPv4"
    ) in plan.changes

    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    (device,) = nb.dcim.devices.created
    (iface,) = nb.dcim.interfaces.created
    assert iface["name"] == "Ethernet0" and iface["type"] == "other"
    (body,) = nb.ipam.ip_addresses.created
    assert body["address"] == "10.1.1.1/24"
    assert body["status"] == "active"
    assert body["assigned_object_type"] == "dcim.interface"
    new_device = nb.dcim.devices.get(name="hq-idf1-ap01")
    assert new_device.primary_ip4 == nb.ipam.ip_addresses.all()[0].id


def test_new_device_without_lldp_uses_the_templates_first_wired_port_never_a_radio(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    nb = _nb(prefixes=[_prefix()], ap_template=True)

    plan = TOOL.run(_Ctx(nb), _args())
    assert (
        "hq-idf1-ap01: would create IP address 10.1.1.1/24, attach to 'E0' and set as primary IPv4"
    ) in plan.changes

    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert nb.dcim.interfaces.created == []  # E0 came with the device, never recreated
    e0 = nb.dcim.interfaces.get(name="E0")
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == e0.id
    assert _device(result)["ip_interface"] == "E0"
    assert _device(result)["ip_interface_source"] == "first-wired"


def test_new_ap_ip_goes_on_the_port_its_lldp_reports(monkeypatch):
    """The whole point of merging sync + enrich: `show ap lldp neighbors`
    says the AP is up on eth1, so its IP lands on E1, not the E0 default."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    nb = _nb(prefixes=[_prefix()], ap_template=True, devices=[SWITCH], interfaces=[_switch_port()])

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert plan.status is Status.DRIFT
    assert (
        "hq-idf1-ap01: would create IP address 10.1.1.1/24, attach to 'E1' "
        "(the AP's LLDP uplink) and set as primary IPv4"
    ) in plan.changes
    assert "hq-idf1-ap01: would create cable E1 <-> hq-idf1-sw01:GigabitEthernet1/0/24" in (
        plan.changes
    )

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    ap = nb.dcim.devices.get(name="hq-idf1-ap01")
    e1 = nb.dcim.interfaces.get(device_id=ap.id, name="E1")
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == e1.id
    (cable,) = nb.dcim.cables.created
    assert cable["a_terminations"] == [{"object_type": "dcim.interface", "object_id": e1.id}]
    assert cable["b_terminations"] == [{"object_type": "dcim.interface", "object_id": 400}]
    assert _device(result)["ip_interface_source"] == "live"


def test_new_device_without_wired_ports_gets_the_lldp_port_created(monkeypatch):
    """No template at all: create the port the AP reports, not a guessed 'Ethernet0'."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    nb = _nb(prefixes=[_prefix()], devices=[SWITCH], interfaces=[_switch_port()])

    plan = TOOL.run(_Ctx(nb), _args(only="aps"))
    assert any("attach to 'eth1' (new interface)" in c for c in plan.changes)
    assert "hq-idf1-ap01: would create cable eth1 <-> hq-idf1-sw01:GigabitEthernet1/0/24" in (
        plan.changes
    )

    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    (iface,) = nb.dcim.interfaces.created
    assert iface["name"] == "eth1"
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
    assert loose.assigned_object_id == nb.dcim.interfaces.get(name="E0").id
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


# --- IP: devices NetBox already has ------------------------------------


def _ip_on(interface_id, address="10.1.1.1/24", id_=99):
    return _Rec(
        id=id_,
        address=address,
        vrf=None,
        assigned_object_type="dcim.interface",
        assigned_object_id=interface_id,
    )


def test_existing_ap_ip_is_moved_to_the_port_lldp_reports(monkeypatch):
    """Wap-A-1 is on E0 in NetBox from before; its LLDP says eth1 now."""
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
    assert plan.status is Status.DRIFT
    assert (
        "hq-idf1-ap01: would move IP address 10.1.1.1/24 from 'E0' to 'E1' (the AP's LLDP uplink)"
    ) in plan.changes

    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args(only="aps"))
    assert result.status is Status.CHANGED
    assert ip.assigned_object_id == 301  # E1
    assert not hasattr(ap, "updates")  # already its primary: no device write
    assert ("success", "hq-idf1-ap01: updated") in ctx.reporter.lines


def test_existing_ap_ip_is_never_moved_without_lldp(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP])  # no LLDP rows
    ip = _ip_on(301)  # E1
    ap = _ap(primary_ip4=_Rec(id=99))
    nb = _nb(prefixes=[_prefix()], ips=[ip], devices=[ap], interfaces=_ap_ports())
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.OK
    assert ip.assigned_object_id == 301
    assert _device(result)["ip_interface_source"] == "netbox"


def test_existing_ap_missing_its_ip_gets_it(monkeypatch):
    _aruba(monkeypatch, aps=[AP])
    ap = _ap(primary_ip4=None)
    nb = _nb(prefixes=[_prefix()], devices=[ap], interfaces=_ap_ports())
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == 300  # E0
    assert ap.updates == [{"primary_ip4": nb.ipam.ip_addresses.all()[0].id}]


def test_existing_ap_with_a_new_ip_gets_it_as_primary_old_one_left(monkeypatch):
    """A DHCP'd AP whose address changed: the new IP becomes primary, the old one stays."""
    _aruba(monkeypatch, aps=[{**AP, "IP Address": "10.1.1.9"}])
    old = _ip_on(300, "10.1.1.1/24", id_=98)
    ap = _ap(primary_ip4=_Rec(id=98))
    nb = _nb(prefixes=[_prefix()], ips=[old], devices=[ap], interfaces=_ap_ports())
    result = TOOL.run(_Ctx(nb, apply=True), _args())
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created[0]["address"] == "10.1.1.9/24"
    assert old in nb.ipam.ip_addresses.all()
    assert ap.primary_ip4 != 98


def test_existing_ap_ip_already_right_is_left_alone(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[{**LLDP, "Interface": "eth0"}])
    ip = _ip_on(300)
    ap = _ap(primary_ip4=_Rec(id=99))
    nb = _nb(
        prefixes=[_prefix()],
        ips=[ip],
        devices=[ap, SWITCH],
        interfaces=[*_ap_ports(e0_cable=_Rec(id=5)), _switch_port(cable=_Rec(id=5))],
    )
    ctx = _Ctx(nb, apply=True)
    result = TOOL.run(ctx, _args(only="aps"))
    assert result.status is Status.OK
    assert result.changes == []
    assert not hasattr(ip, "updates") and not hasattr(ap, "updates")
    assert _device(result)["cables"][0]["status"] == "in-sync"
    assert ctx.reporter.about("hq-idf1-ap01") == [("success", "hq-idf1-ap01: in sync")]


def test_lldp_port_the_device_does_not_have_is_yellow(monkeypatch):
    """NetBox says the AP only has E0; the AP says it's up on eth1. Don't guess."""
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=[LLDP])
    ap = _ap()
    nb = _nb(
        prefixes=[_prefix()],
        devices=[ap, SWITCH],
        interfaces=[_iface(300, 100, "E0"), _switch_port()],
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.PARTIAL
    assert nb.ipam.ip_addresses.created == []
    issues = _device(result)["issues"]
    assert any("reports it's connected on eth1" in i for i in issues)
    assert any("no interface matching 'eth1'" in i for i in issues)


def test_two_uplinks_get_two_cables_and_the_ip_on_the_first(monkeypatch):
    rows = [
        {**LLDP, "Interface": "eth1", "Chassis Name/ID": "hq-idf1-sw02", "Port ID": "Gi1/0/7"},
        {**LLDP, "Interface": "eth0"},
    ]
    _aruba(monkeypatch, switches=[WLC], aps=[AP], lldp=rows)
    sw2 = _Rec(id=201, name="hq-idf1-sw02")
    nb = _nb(
        prefixes=[_prefix()],
        devices=[_ap(), SWITCH, sw2],
        interfaces=[
            *_ap_ports(),
            _switch_port(),
            _switch_port(401, 201, "GigabitEthernet1/0/7"),
        ],
    )
    result = TOOL.run(_Ctx(nb, apply=True), _args(only="aps"))
    assert result.status is Status.CHANGED
    assert nb.ipam.ip_addresses.created[0]["assigned_object_id"] == 300  # E0
    pairs = {
        (c["a_terminations"][0]["object_id"], c["b_terminations"][0]["object_id"])
        for c in nb.dcim.cables.created
    }
    assert pairs == {(301, 401), (300, 400)}


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
    nb = _nb(devices=[_ap(platform=_Rec(id=50))])
    nb.dcim.platforms._items.append(_Rec(id=50, name="AOS 8", slug="aos-8"))
    result = TOOL.run(_Ctx(nb), _args())
    assert result.status is Status.OK
    assert _device(result)["platform"] == "AOS 8"


def test_no_version_field_is_informational(monkeypatch):
    _aruba(monkeypatch, aps=[{**AP, "IP Address": ""}])
    result = TOOL.run(_Ctx(_nb(devices=[_ap()])), _args())
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
    assert ("warn", "hq-wlc01: could not read its APs' LLDP/version data — timed out") in (
        ctx.reporter.lines
    )


def test_wlc_with_no_ap_data_is_informational(monkeypatch):
    _aruba(monkeypatch, switches=[WLC], aps=[AP], wlc_aps=[])
    result = TOOL.run(_Ctx(_nb(prefixes=[_prefix()])), _args(only="aps"))
    assert result.status is Status.DRIFT
    assert result.data["wlcs"]["hq-wlc01"] == {"url": WLC_URL, "aps": 0, "lldp_neighbors": 0}


# --- cables ---------------------------------------------------------------


def _cabling_nb(*, ap_ports=None, switch_ports=None, devices=(), prefixes=()):
    return _nb(
        prefixes=list(prefixes),
        devices=[_ap(), SWITCH, *devices],
        interfaces=[
            *(_ap_ports() if ap_ports is None else ap_ports),
            *([_switch_port()] if switch_ports is None else switch_ports),
        ],
    )


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
    nb = _cabling_nb(ap_ports=[_iface(302, 100, "5GHz WiFi", "ieee802.11ax")])
    result = _cabling_run(monkeypatch, nb, [LLDP])
    assert result.status is Status.PARTIAL
    assert "no interface matching 'eth1'" in _device(result)["issues"][0]


def test_existing_cable_on_either_end_is_left_alone(monkeypatch):
    nb = _cabling_nb(switch_ports=[_switch_port(cable=_Rec(id=1))])
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.OK  # informational only, never a failure
    assert nb.dcim.cables.created == []
    assert any("already has a cable" in n for n in _device(result)["notes"])


def test_switch_port_cabled_to_the_aps_other_port_is_explained_not_moved(monkeypatch):
    """The old cable is on E0; the AP now reports eth1. Existing cables are
    never touched, but the note says exactly what's stale."""
    nb = _cabling_nb(
        ap_ports=_ap_ports(e0_cable=_Rec(id=7)), switch_ports=[_switch_port(cable=_Rec(id=7))]
    )
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.OK
    assert nb.dcim.cables.created == []
    (note,) = _device(result)["notes"]
    assert "cabled to hq-idf1-ap01:E0" in note and "reports this link on E1" in note
    assert "move it in NetBox" in note


def test_cable_create_failure_is_yellow(monkeypatch):
    nb = _cabling_nb()

    def boom(body):
        raise RuntimeError("termination already occupied")

    nb.dcim.cables.create = boom
    result = _cabling_run(monkeypatch, nb, [LLDP], apply=True)
    assert result.status is Status.PARTIAL
    assert "termination already occupied" in _device(result)["issues"][0]


# --- registration ---------------------------------------------------------


def test_tool_is_registered_and_enrich_is_gone():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["wireless"] == {"sync": TOOL}
    assert TOOL.writes is True
