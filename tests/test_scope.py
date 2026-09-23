"""Tests for category role-branch targeting: role tree, roles: config, scope, Context.

The fake role tree mirrors the owner's NetBox (2026-09-23)::

    networking
    ├── wired-network > routing, switching > core-switch > distribution-switch > access-switch
    ├── wireless-network > wireless-controller > wireless-access-point
    └── network-security > firewalls
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from bunnyauto.categories import CATEGORIES, DEFAULT_ROLES
from bunnyauto.context import Context, Credentials, Settings, build_context
from bunnyauto.environments import Environment, load_environments
from bunnyauto.errors import ConfigError, RoleScopeError
from bunnyauto.netbox.roles import RoleTree, device_role_slug, role_field
from bunnyauto.reporting import make_reporter
from bunnyauto.scope import Scope, resolve_scope
from bunnyauto.tools import build_registry

# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------

_TREE = [
    ("networking", None),
    ("wired-network", "networking"),
    ("routing", "wired-network"),
    ("switching", "wired-network"),
    ("core-switch", "switching"),
    ("distribution-switch", "core-switch"),
    ("access-switch", "distribution-switch"),
    ("wireless-network", "networking"),
    ("wireless-controller", "wireless-network"),
    ("wireless-access-point", "wireless-controller"),
    ("network-security", "networking"),
    ("firewalls", "network-security"),
]


def _roles(tree=_TREE):
    records: dict[str, SimpleNamespace] = {}
    for index, (slug, parent) in enumerate(tree, start=1):
        records[slug] = SimpleNamespace(
            id=index, slug=slug, name=slug, parent=records[parent] if parent else None
        )
    return list(records.values())


class _Devices:
    def __init__(self, devices):
        self._devices = devices
        self.last_filters = None

    def filter(self, **filters):
        self.last_filters = filters
        return list(self._devices)


def _nb(roles=None, devices=()):
    items = _roles() if roles is None else roles
    return SimpleNamespace(
        version="4.3",
        dcim=SimpleNamespace(
            device_roles=SimpleNamespace(all=lambda: list(items)),
            devices=_Devices(list(devices)),
        ),
    )


def _settings(**over) -> Settings:
    base = dict(
        environment="test",
        nb_url="https://nb.example.com",
        config_file=Path("config.yaml"),
        target_tag="nornirtest",
        category="wired",
        branch_role="wired-network",
    )
    base.update(over)
    return Settings(**base)


def _context(nb, **settings_over) -> Context:
    return Context(
        settings=_settings(**settings_over),
        creds=Credentials(username="u", password="p", nb_token="t"),
        reporter=make_reporter(json_mode=True),
        environment=Environment(
            name="test", nb_url="https://nb", default_tag="nornirtest", token_env="T"
        ),
        _nb=nb,
    )


# ---------------------------------------------------------------------------
# RoleTree
# ---------------------------------------------------------------------------


def test_role_tree_walks_the_owners_hierarchy():
    tree = RoleTree.load(_nb())
    assert tree.is_within("access-switch", "wired-network")
    assert tree.is_within("access-switch", "switching")
    assert tree.is_within("wired-network", "wired-network")
    assert not tree.is_within("routing", "switching")
    assert not tree.is_within("firewalls", "wired-network")
    # Wireless Access Point is nested *under* Wireless Controller.
    assert tree.is_within("wireless-access-point", "wireless-controller")


def test_role_tree_branch_is_depth_first():
    tree = RoleTree.load(_nb())
    assert tree.branch("wired-network") == [
        "wired-network",
        "routing",
        "switching",
        "core-switch",
        "distribution-switch",
        "access-switch",
    ]
    assert tree.branch("nope") == []


def test_role_tree_lookup_is_case_insensitive():
    tree = RoleTree.load(_nb())
    assert tree.find("Wired-Network") == "wired-network"
    assert "WIRELESS-NETWORK" in tree
    assert "nope" not in tree


def test_role_tree_on_netbox_before_nested_roles_is_flat():
    flat = [SimpleNamespace(id=1, slug="switch"), SimpleNamespace(id=2, slug="router")]
    tree = RoleTree.load(_nb(roles=flat))
    assert tree.branch("switch") == ["switch"]
    assert not tree.is_within("router", "switch")


def test_role_tree_survives_a_parent_cycle():
    a = SimpleNamespace(id=1, slug="a", parent=None)
    b = SimpleNamespace(id=2, slug="b", parent=a)
    a.parent = b
    tree = RoleTree.load(_nb(roles=[a, b]))
    assert not tree.is_within("a", "zzz")
    assert tree.branch("a") == ["a", "b"]


def test_device_role_slug_reads_every_shape():
    assert device_role_slug(SimpleNamespace(role=SimpleNamespace(slug="access-switch"))) == (
        "access-switch"
    )
    assert device_role_slug(SimpleNamespace(role={"slug": "firewalls"})) == "firewalls"
    assert device_role_slug(SimpleNamespace(device_role=SimpleNamespace(slug="old"))) == "old"
    assert device_role_slug(SimpleNamespace()) is None


def test_role_field_by_netbox_version():
    assert role_field(SimpleNamespace(version="4.3")) == "role"
    assert role_field(SimpleNamespace(version="3.5")) == "device_role"


# ---------------------------------------------------------------------------
# roles: in bunnyauto.yaml
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "bunnyauto.yaml"
    path.write_text(textwrap.dedent(text).strip(), encoding="utf-8")
    return path


def test_roles_default_to_netbox_auto_slugs(env_file):
    envs = load_environments(env_file)
    assert dict(envs["test"].roles) == DEFAULT_ROLES
    assert envs["test"].roles["wireless-access-point"] == "wireless-access-point"


def test_roles_override_top_level_then_per_environment(tmp_path):
    path = _write(
        tmp_path,
        """
        roles:
          wired: wired-net
          wireless-access-point: wireless
        environments:
          test:
            nb_url: https://a.example.com
            default_tag: nornirtest
            token_env: A
          prod:
            nb_url: https://b.example.com
            default_tag: networking-active
            token_env: B
            roles:
              wired: prod-wired
        """,
    )
    envs = load_environments(path)
    assert envs["test"].roles["wired"] == "wired-net"
    assert envs["test"].roles["wireless-access-point"] == "wireless"
    assert envs["prod"].roles["wired"] == "prod-wired"
    assert envs["prod"].roles["wireless-access-point"] == "wireless"
    assert envs["prod"].roles["security"] == "network-security"


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("roles:\n  wirless: x\n", "unknown key"),
        ("roles:\n  wired: ''\n", "needs a role slug"),
        ("roles: wired-network\n", "must be a mapping"),
    ],
)
def test_bad_roles_block_is_a_config_error(tmp_path, block, message):
    path = tmp_path / "bunnyauto.yaml"
    path.write_text(
        block + "environments:\n  test:\n    nb_url: https://a.example.com\n"
        "    default_tag: t\n    token_env: A\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match=message):
        load_environments(path)


# ---------------------------------------------------------------------------
# build_context: category -> branch role
# ---------------------------------------------------------------------------


@pytest.fixture
def _ready(env_file, tmp_path, monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "tok")
    config = tmp_path / "config.yaml"
    config.write_text(
        "inventory:\n  plugin: NetBoxInventory2\n  options:\n    nb_url: https://x.example.com\n",
        encoding="utf-8",
    )
    return {"env": "test", "env_file": env_file, "config_file": config}


def test_build_context_sets_the_categorys_branch(_ready):
    ctx = build_context(reporter=make_reporter(), category=CATEGORIES["wireless"], **_ready)
    assert ctx.settings.category == "wireless"
    assert ctx.settings.branch_role == "wireless-network"
    assert ctx.settings.role is None


def test_build_context_carries_a_role_narrowing(_ready):
    ctx = build_context(
        reporter=make_reporter(), category=CATEGORIES["wired"], role=" access-switch ", **_ready
    )
    assert ctx.settings.role == "access-switch"


def test_build_context_without_netbox_has_no_branch(_ready):
    ctx = build_context(
        reporter=make_reporter(),
        category=CATEGORIES["security"],
        need_devices=False,
        need_netbox=False,
        **_ready,
    )
    assert ctx.settings.branch_role is None


def test_build_context_rejects_role_for_an_unscoped_tool(_ready):
    with pytest.raises(RoleScopeError, match="doesn't apply"):
        build_context(
            reporter=make_reporter(), category=CATEGORIES["netbox"], role="access-switch", **_ready
        )


# ---------------------------------------------------------------------------
# resolve_scope — the role guards
# ---------------------------------------------------------------------------


def _tree():
    return RoleTree.load(_nb())


def test_scope_defaults_to_the_whole_branch():
    scope = resolve_scope(_settings(site="hq"), _tree)
    assert scope == Scope(tag="nornirtest", role="wired-network", branch="wired-network", site="hq")
    assert scope.location_filters() == {"role": "wired-network", "site": "hq"}
    assert scope.device_filters() == {"role": "wired-network", "site": "hq", "tag": "nornirtest"}


def test_scope_narrows_to_a_role_inside_the_branch():
    scope = resolve_scope(_settings(role="Access-Switch"), _tree)
    assert scope.role == "access-switch"
    assert scope.branch == "wired-network"


def test_scope_refuses_a_role_from_another_category():
    with pytest.raises(RoleScopeError, match="outside the wired branch") as excinfo:
        resolve_scope(_settings(role="firewalls"), _tree)
    assert "access-switch" in excinfo.value.fix  # the fix lists the branch's roles


def test_scope_refuses_an_unknown_role():
    with pytest.raises(RoleScopeError, match="no device role 'acess-switch'"):
        resolve_scope(_settings(role="acess-switch"), _tree)


def test_scope_needs_the_branch_root_to_exist():
    # Drop the wired-network role; its children become roots.
    tree = [
        (slug, None if parent == "wired-network" else parent)
        for slug, parent in _TREE
        if slug != "wired-network"
    ]
    with pytest.raises(RoleScopeError, match="no device role 'wired-network'") as excinfo:
        resolve_scope(_settings(), lambda: RoleTree.load(_nb(roles=_roles(tree))))
    assert "roles.wired" in excinfo.value.fix


def test_unscoped_category_never_touches_netbox():
    def _boom():
        raise AssertionError("the role tree must not be fetched")

    scope = resolve_scope(_settings(category="netbox", branch_role=None, region="south"), _boom)
    assert scope.role is None
    assert scope.device_filters() == {"region": "south", "tag": "nornirtest"}


def test_describe_names_every_narrowing():
    text = Scope(tag="t", role="switching", branch="wired-network", region="south").describe()
    assert text == "tag 't', role 'switching' (and its child roles), region 'south'"


# ---------------------------------------------------------------------------
# Context — the one place tools get their devices from
# ---------------------------------------------------------------------------


def test_target_devices_queries_netbox_with_the_whole_scope():
    nb = _nb(devices=[SimpleNamespace(name="sw1")])
    ctx = _context(nb, region="south")
    assert [d.name for d in ctx.target_devices()] == ["sw1"]
    assert nb.dcim.devices.last_filters == {
        "role": "wired-network",
        "region": "south",
        "tag": "nornirtest",
    }


def test_nornir_is_pulled_with_role_region_site_but_not_the_tag(monkeypatch):
    captured = {}

    def fake_build_nornir(settings, creds, *, filters=None):
        captured["filters"] = filters
        return "NR"

    monkeypatch.setattr("bunnyauto.context.build_nornir", fake_build_nornir)
    ctx = _context(_nb(), role="switching", site="hq")
    assert ctx.nornir() == "NR"
    assert captured["filters"] == {"role": "switching", "site": "hq"}


def test_scope_and_role_tree_are_fetched_once():
    calls = []
    nb = _nb()
    original = nb.dcim.device_roles.all
    nb.dcim.device_roles.all = lambda: calls.append(1) or original()
    ctx = _context(nb)
    ctx.scope()
    ctx.scope()
    ctx.role_tree()
    assert len(calls) == 1


def test_banner_shows_the_role(capsys):
    ctx = _context(_nb(), role="access-switch")
    ctx.reporter = make_reporter()
    ctx.banner()
    assert "role=access-switch" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# the registry
# ---------------------------------------------------------------------------


class _T:
    def __init__(self, name, category):
        self.name, self.category = name, category


def test_registry_groups_by_category_in_category_order():
    registry = build_registry([_T("b", "wireless"), _T("a", "wired")])
    assert list(registry) == ["wired", "wireless"]


def test_registry_rejects_an_unknown_category():
    with pytest.raises(ValueError, match="unknown category"):
        build_registry([_T("x", "voice")])


def test_registry_rejects_a_duplicate_name_within_a_category():
    with pytest.raises(ValueError, match="two 'wired' tools"):
        build_registry([_T("x", "wired"), _T("x", "wired")])


def test_same_name_in_two_categories_is_fine():
    registry = build_registry([_T("sync", "wired"), _T("sync", "wireless")])
    assert set(registry) == {"wired", "wireless"}
