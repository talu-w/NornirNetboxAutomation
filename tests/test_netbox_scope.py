"""Tests for ``netbox scope`` — the per-category targeting preview (fake NetBox, no HTTP)."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

from bunnyauto.context import Context, Credentials, Settings
from bunnyauto.environments import Environment
from bunnyauto.reporting import make_reporter
from bunnyauto.result import Status
from bunnyauto.tools import REGISTRY
from bunnyauto.tools.netbox.scope import TOOL

_TREE = [
    ("networking", None),
    ("wired-network", "networking"),
    ("switching", "wired-network"),
    ("access-switch", "switching"),
    ("wireless-network", "networking"),
    ("wireless-controller", "wireless-network"),
    ("wireless-access-point", "wireless-controller"),
    ("network-security", "networking"),
    ("firewalls", "network-security"),
    ("server", None),  # not networking gear at all
]


def _roles(tree):
    records: dict[str, SimpleNamespace] = {}
    for index, (slug, parent) in enumerate(tree, start=1):
        records[slug] = SimpleNamespace(
            id=index, slug=slug, name=slug, parent=records[parent] if parent else None
        )
    return list(records.values())


def _device(name, role, tags=("nornirtest",)):
    return SimpleNamespace(
        id=hash(name) % 10_000,
        name=name,
        role=SimpleNamespace(slug=role),
        tags=[SimpleNamespace(slug=t) for t in tags],
    )


class _Devices:
    def __init__(self, devices):
        self._devices = devices
        self.last_filters = None

    def filter(self, **filters):
        self.last_filters = filters
        tag = filters.get("tag")
        return [d for d in self._devices if tag in [t.slug for t in d.tags]]


def _ctx(devices, tree=_TREE, roles=None) -> Context:
    items = _roles(tree)
    nb = SimpleNamespace(
        dcim=SimpleNamespace(
            device_roles=SimpleNamespace(all=lambda: list(items)),
            devices=_Devices(devices),
        )
    )
    environment = Environment(
        name="test", nb_url="https://nb", default_tag="nornirtest", token_env="T"
    )
    if roles is not None:
        environment = Environment(
            name="test",
            nb_url="https://nb",
            default_tag="nornirtest",
            token_env="T",
            roles={**environment.roles, **roles},
        )
    return Context(
        settings=Settings(
            environment="test",
            nb_url="https://nb",
            config_file=Path("config.yaml"),
            target_tag="nornirtest",
            category="netbox",
        ),
        creds=Credentials(username="", password="", nb_token="t"),
        reporter=make_reporter(json_mode=True),
        environment=environment,
        _nb=nb,
    )


def _args(list_devices=False):
    return argparse.Namespace(list_devices=list_devices)


FLEET = [
    _device("hq-sw01", "access-switch"),
    _device("hq-sw02", "access-switch"),
    _device("hq-wlc01", "wireless-controller"),
    _device("hq-ap01", "wireless-access-point"),
    _device("hq-fw01", "firewalls"),
    _device("hq-srv01", "server"),
    _device("lab-sw09", "access-switch", tags=("some-other-tag",)),  # not this network
]


def test_sorts_every_tagged_device_into_its_category():
    ctx = _ctx(FLEET)
    result = TOOL.run(ctx, _args())

    assert result.status is Status.OK
    categories = result.data["categories"]
    assert categories["wired"]["devices"] == {"access-switch": ["hq-sw01", "hq-sw02"]}
    assert categories["wireless"]["devices"] == {
        "wireless-access-point": ["hq-ap01"],
        "wireless-controller": ["hq-wlc01"],
    }
    assert categories["security"]["count"] == 1
    assert result.data["outside"] == {"server": ["hq-srv01"]}
    assert "outside every category 1" in result.summary
    # only this network's tag is asked for
    assert ctx.netbox().dcim.devices.last_filters == {"tag": "nornirtest"}


def test_a_missing_branch_root_is_an_error():
    tree = [row for row in _TREE if row[0] != "network-security"]
    tree = [(slug, None if parent == "network-security" else parent) for slug, parent in tree]
    result = TOOL.run(_ctx(FLEET, tree=tree), _args())

    assert result.status is Status.ERROR
    assert result.data["categories"]["security"] == {"branch": "network-security", "exists": False}
    assert any("roles.security" in problem for problem in result.data["problems"])
    # the firewall has nowhere to go now
    assert result.data["outside"]["firewalls"] == ["hq-fw01"]


def test_a_leaf_role_outside_its_branch_is_an_error():
    tree = [
        (slug, "networking" if slug == "wireless-controller" else parent) for slug, parent in _TREE
    ]
    result = TOOL.run(_ctx(FLEET, tree=tree), _args())
    assert result.status is Status.ERROR
    assert any(
        "'wireless-controller' is not inside the wireless branch" in problem
        for problem in result.data["problems"]
    )


def test_configured_slugs_are_honoured():
    tree = [(("wired" if slug == "wired-network" else slug), parent) for slug, parent in _TREE]
    tree = [(slug, "wired" if parent == "wired-network" else parent) for slug, parent in tree]
    result = TOOL.run(_ctx(FLEET, tree=tree, roles={"wired": "wired"}), _args())
    assert result.status is Status.OK
    assert result.data["categories"]["wired"]["branch"] == "wired"
    assert result.data["categories"]["wired"]["count"] == 2


def test_preview_is_short_unless_asked_to_list():
    many = [_device(f"ap{i:03d}", "wireless-access-point") for i in range(20)]
    reporter_lines: list[str] = []
    ctx = _ctx(many)
    ctx.reporter.info = reporter_lines.append
    TOOL.run(ctx, _args())
    assert any("(+12 more)" in line for line in reporter_lines)

    reporter_lines.clear()
    ctx = _ctx(many)
    ctx.reporter.info = reporter_lines.append
    TOOL.run(ctx, _args(list_devices=True))
    assert not any("more)" in line for line in reporter_lines)
    assert any("ap019" in line for line in reporter_lines)


def test_tool_is_registered_under_netbox():
    assert REGISTRY["netbox"]["scope"] is TOOL
    assert TOOL.writes is False
    assert TOOL.needs_devices is False
