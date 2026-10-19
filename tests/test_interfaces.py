"""Tests for ``wired interfaces``: the create step, then the sync step, in one run.

Each step has its own suite (``test_create_interfaces.py``, ``test_sync_interfaces.py``).
These cover the hand-off between them against one fake NetBox that both steps
read and write: what a plan says about interfaces not created yet, what an
apply does with them, which hosts the sync step skips, and how the two
results combine.
"""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from bunnyauto import cli
from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.hub import prompt_for_args
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status, ToolResult
from bunnyauto.scope import Scope
from bunnyauto.sync import engine
from bunnyauto.tools import REGISTRY
from bunnyauto.tools.wired import create_interfaces, interfaces, sync_interfaces
from bunnyauto.tools.wired.create_interfaces import DiscoveredInterface, Discovery
from bunnyauto.tools.wired.interfaces import TOOL

# ---------------------------------------------------------------------------
# a fake NetBox both steps share
# ---------------------------------------------------------------------------


class _Device:
    def __init__(self, id_: int, name: str):
        self.id = id_
        self.name = name
        self.primary_ip = None
        self.virtual_chassis = None
        self.vc_position = None


class _Iface:
    """A NetBox interface record: remembers every update it receives."""

    def __init__(self, id_, device_id, name, *, type_="1000base-t", enabled=True, description=""):
        self.id = id_
        self.device = {"id": device_id}
        self.name = name
        self.type = {"value": type_, "label": type_}
        self.enabled = enabled
        self.description = description
        self.mode = None
        self.untagged_vlan = None
        self.tagged_vlans = []
        self.updates: list[dict] = []

    def update(self, payload):
        self.updates.append(dict(payload))
        for key, value in payload.items():
            setattr(self, key, value)
        return True


class _Interfaces:
    def __init__(self, records):
        self.records = list(records)
        self.created: list[dict] = []

    def filter(self, device_id=None):
        return [r for r in self.records if r.device["id"] == device_id]

    def get(self, id_):
        return next((r for r in self.records if r.id == id_), None)

    def choices(self):
        return {"type": [{"value": "1000base-t"}, {"value": "lag"}, {"value": "virtual"}]}

    def create(self, payload):
        made = []
        for item in payload:
            self.created.append(dict(item))
            record = _Iface(
                1000 + len(self.records),
                item["device"],
                item["name"],
                type_=item["type"],
                enabled=item.get("enabled", True),
                description=item.get("description", ""),
            )
            self.records.append(record)
            made.append(record)
        return made

    def update(self, payload):
        for item in payload:
            record = self.get(item["id"])
            record.update({k: v for k, v in item.items() if k != "id"})
        return payload

    def on(self, device_id: int, name: str) -> _Iface:
        return next(r for r in self.records if r.device["id"] == device_id and r.name == name)


class _Devices:
    def __init__(self, devices):
        self._devices = devices

    def filter(self, **filters):
        if "virtual_chassis_id" in filters:
            return []
        if "name__isw" in filters:
            prefix = filters["name__isw"].casefold()
            return [d for d in self._devices if d.name.casefold().startswith(prefix)]
        return list(self._devices)

    def get(self, id_=None, name=None):
        return next((d for d in self._devices if d.id == id_ or d.name == name), None)


class _NB:
    def __init__(self, devices, records):
        self.dcim = argparse.Namespace(
            devices=_Devices(devices),
            interfaces=_Interfaces(records),
            inventory_items=SimpleNamespace(filter=lambda **kw: [], create=lambda p: p),
            virtual_chassis=argparse.Namespace(get=lambda id_: None),
            locations=None,
        )


# ---------------------------------------------------------------------------
# a fake Nornir: each step's task gets that step's collected data
# ---------------------------------------------------------------------------


class _Host:
    def __init__(self, name: str, device_id: int):
        self.name = name
        self.data = {"netbox_device_id": device_id}

    def get(self, key, default=None):
        return self.data.get(key, default)


class _Item:
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception


class _Multi(list):
    def __init__(self, items, *, failed=False):
        super().__init__(items)
        self.failed = failed


class _Selected:
    """A tagged inventory; ``runs`` logs ``(step, hosts)`` for every task run on it."""

    def __init__(self, hosts, results, runs):
        self.inventory = argparse.Namespace(hosts=hosts)
        self._results = results
        self.runs = runs

    def run(self, *, task, **kwargs):
        step = "create" if task is create_interfaces._collect else "sync"
        self.runs.append((step, sorted(self.inventory.hosts)))
        return {name: self._results[step][name] for name in self.inventory.hosts}

    def filter(self, *, filter_func):
        hosts = {n: h for n, h in self.inventory.hosts.items() if filter_func(h)}
        return _Selected(hosts, self._results, self.runs)


@dataclass
class _Ctx:
    settings: Settings
    reporter: Reporter
    _nb: object = None

    def netbox(self):
        return self._nb

    def nornir(self):
        return object()

    def scope(self):
        return Scope(tag=self.settings.target_tag, role="wired-network", branch="wired-network")

    def target_devices(self):
        return list(self._nb.dcim.devices.filter(**self.scope().device_filters()))


def _ctx(nb, *, apply=False, stream=None) -> _Ctx:
    return _Ctx(
        settings=Settings(
            environment="test",
            nb_url="https://nb",
            config_file="config.yaml",
            target_tag="nornirtest",
            apply=apply,
            connect_retries=0,
        ),
        reporter=(
            Reporter(json_mode=True) if stream is None else Reporter(use_rich=False, stream=stream)
        ),
        _nb=nb,
    )


def _args(**overrides) -> argparse.Namespace:
    values = {
        "device": None,
        "only": None,
        "include_virtual": False,
        "voice_vlan_model": "tagged",
        "access_vlan_placement": "clear",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture
def network(monkeypatch):
    """Wire a fake network: ``reported`` maps a host to its ports, ``existing`` a
    device id to its NetBox interfaces. Every port reports link state up and the
    description ``"seen <port>"``. ``unreachable`` hosts never open an SSH session.
    Returns ``(nb, runs)``.
    """

    def _wire(*, reported, existing, unreachable=()):
        devices = [_Device(n, name) for n, name in enumerate(reported, start=1)]
        by_name = {d.name: d for d in devices}
        records = [
            _Iface(device_id * 100 + n, device_id, port, description=description)
            for device_id, ports in existing.items()
            for n, (port, description) in enumerate(ports)
        ]
        nb = _NB(devices, records)
        down = _Multi([_Item(exception=OSError("TCP connection timed out"))], failed=True)
        results = {
            "create": {
                host: down
                if host in unreachable
                else _Multi([_Item(result=Discovery([DiscoveredInterface(p) for p in ports]))])
                for host, ports in reported.items()
            },
            "sync": {
                host: down
                if host in unreachable
                else _Multi(
                    [
                        _Item(
                            result=engine.CollectedDevice(
                                inventory_name=host,
                                netbox_device_id=by_name[host].id,
                                interfaces=[],
                                interface_metadata=[
                                    engine.InterfaceMetadataState(
                                        name=port,
                                        enabled=True,
                                        description=f"seen {port}",
                                        device_status="connected",
                                    )
                                    for port in ports
                                ],
                            )
                        )
                    ]
                )
                for host, ports in reported.items()
            },
        }
        runs: list[tuple[str, list[str]]] = []

        def _select(nr, tagged):
            names = {str(d.name) for d in tagged}
            hosts = {h: _Host(h, by_name[h].id) for h in reported if h in names}
            return _Selected(hosts, results, runs)

        monkeypatch.setattr(create_interfaces, "select_tagged_inventory", _select)
        monkeypatch.setattr(sync_interfaces, "select_tagged_inventory", _select)
        monkeypatch.setattr(
            engine,
            "build_vlan_cache",
            lambda nb_: engine.VlanCache(by_vid={}, by_id={}, groups_by_id={}),
        )
        return nb, runs

    return _wire


# ---------------------------------------------------------------------------
# registration and options
# ---------------------------------------------------------------------------


def test_one_interfaces_tool_replaces_the_two_old_ones():
    wired = REGISTRY["wired"]
    assert "interfaces" in wired
    assert "create-interfaces" not in wired
    assert "sync-interfaces" not in wired
    assert wired["interfaces"].writes is True


def test_every_option_of_both_steps_is_accepted():
    args = cli.build_parser().parse_args(
        [
            "--env",
            "test",
            "wired",
            "interfaces",
            "--device",
            "sw1",
            "--include-virtual",
            "--voice-vlan-model",
            "access",
            "--access-vlan-placement",
            "untagged",
            "--only",
            "sync",
        ]
    )
    assert (args.category, args.tool) == ("wired", "interfaces")
    assert args.device == "sw1"
    assert args.include_virtual is True
    assert args.voice_vlan_model == "access"
    assert args.access_vlan_placement == "untagged"
    assert args.only == "sync"


def test_the_old_tool_names_are_gone_from_the_cli():
    parser = cli.build_parser()
    for old in ("create-interfaces", "sync-interfaces"):
        with pytest.raises(SystemExit):
            parser.parse_args(["--env", "test", "wired", old])


def test_the_hub_asks_only_yes_no_questions_and_runs_both_steps():
    asked: list[str] = []

    def _answer(question):
        asked.append(question)
        return ""

    args = prompt_for_args(TOOL, input_fn=_answer)
    assert args.only is None  # both steps
    assert args.voice_vlan_model == "tagged"
    assert args.access_vlan_placement == "clear"
    assert len(asked) == 2  # --include-virtual, --apply


# ---------------------------------------------------------------------------
# the hand-off between the steps
# ---------------------------------------------------------------------------


def test_plan_lists_new_interfaces_as_awaiting_sync_not_as_errors(network):
    nb, runs = network(reported={"sw1": ["Gi1/0/1", "Gi1/0/2"]}, existing={1: [("Gi1/0/1", "")]})

    result = TOOL.run(_ctx(nb), _args())

    assert result.status is Status.DRIFT
    assert any("would create Gi1/0/2" in c for c in result.changes)
    assert any("DRY-RUN sw1/Gi1/0/1" in c for c in result.changes)
    sync = result.data["sync"]["sw1"]
    assert sync["errors"] == []
    assert sync["awaiting_creation"] == ["Gi1/0/2"]
    assert "1 new interface(s) will be synced once created" in result.summary
    assert nb.dcim.interfaces.created == []
    assert all(r.updates == [] for r in nb.dcim.interfaces.records)
    assert runs == [("create", ["sw1"]), ("sync", ["sw1"])]


def test_apply_creates_the_interface_then_syncs_it_in_the_same_run(network):
    nb, _ = network(reported={"sw1": ["Gi1/0/1", "Gi1/0/2"]}, existing={1: [("Gi1/0/1", "old")]})

    result = TOOL.run(_ctx(nb, apply=True), _args())

    assert result.status is Status.CHANGED
    assert [c["name"] for c in nb.dcim.interfaces.created] == ["Gi1/0/2"]
    new = nb.dcim.interfaces.on(1, "Gi1/0/2")
    assert new.description == "seen Gi1/0/2"  # synced right after it was created
    assert nb.dcim.interfaces.on(1, "Gi1/0/1").description == "seen Gi1/0/1"
    assert any("VERIFIED sw1/Gi1/0/2" in c for c in result.changes)
    assert "awaiting_creation" not in result.data["sync"]["sw1"]
    assert result.summary.startswith("create: created 1 interface(s) | sync: updated 2")


def test_in_sync_network_is_ok(network):
    nb, _ = network(reported={"sw1": ["Gi1/0/1"]}, existing={1: [("Gi1/0/1", "seen Gi1/0/1")]})

    result = TOOL.run(_ctx(nb), _args())

    assert result.status is Status.OK
    assert result.changes == []


def test_a_host_the_create_step_could_not_reach_is_not_tried_again(network):
    nb, runs = network(
        reported={"sw1": ["Gi1/0/1"], "sw2": ["Gi1/0/1"]},
        existing={1: [("Gi1/0/1", "")], 2: [("Gi1/0/1", "")]},
        unreachable={"sw2"},
    )

    result = TOOL.run(_ctx(nb), _args())

    assert runs == [("create", ["sw1", "sw2"]), ("sync", ["sw1"])]
    assert result.status is Status.PARTIAL
    assert "create step" in result.data["sync"]["sw2"]["error"]


def test_every_host_unreachable_is_an_error_and_the_sync_step_opens_no_session(network):
    nb, runs = network(reported={"sw1": ["Gi1/0/1"]}, existing={1: []}, unreachable={"sw1"})

    result = TOOL.run(_ctx(nb), _args())

    assert runs == [("create", ["sw1"])]
    assert result.status is Status.ERROR


def test_device_limits_both_steps(network):
    nb, runs = network(
        reported={"sw1": ["Gi1/0/1"], "sw2": ["Gi1/0/1"]},
        existing={1: [("Gi1/0/1", "")], 2: [("Gi1/0/1", "")]},
    )

    result = TOOL.run(_ctx(nb), _args(device="sw2"))

    assert runs == [("create", ["sw2"]), ("sync", ["sw2"])]
    assert set(result.data["sync"]) == {"sw2"}


def test_unknown_device_stops_before_any_ssh(network):
    nb, runs = network(reported={"sw1": ["Gi1/0/1"]}, existing={1: []})

    with pytest.raises(ToolError, match="was not found"):
        TOOL.run(_ctx(nb), _args(device="sw99"))
    assert runs == []


@pytest.mark.parametrize(("only", "step"), [("create", "create"), ("sync", "sync")])
def test_only_runs_one_step(network, only, step):
    nb, runs = network(reported={"sw1": ["Gi1/0/1", "Gi1/0/2"]}, existing={1: [("Gi1/0/1", "")]})

    result = TOOL.run(_ctx(nb), _args(only=only))

    assert runs == [(step, ["sw1"])]
    assert "create" not in result.data  # the step's own result, not a combined one


def test_only_sync_reports_a_missing_interface_as_before(network):
    nb, _ = network(reported={"sw1": ["Gi1/0/1", "Gi1/0/2"]}, existing={1: [("Gi1/0/1", "")]})

    result = TOOL.run(_ctx(nb), _args(only="sync"))

    # Without the create step there's nothing pending: the gap is an error, as it was.
    assert any("Gi1/0/2" in e and "does not exist" in e for e in result.data["sw1"]["errors"])
    assert "awaiting_creation" not in result.data["sw1"]


def test_progress_names_both_steps(network):
    nb, _ = network(reported={"sw1": ["Gi1/0/1"]}, existing={1: [("Gi1/0/1", "")]})
    stream = io.StringIO()

    TOOL.run(_ctx(nb, stream=stream), _args())

    out = stream.getvalue()
    assert "step 1/2 — create" in out
    assert "step 2/2 — sync" in out


# ---------------------------------------------------------------------------
# combining the two results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("create", "sync", "combined"),
    [
        (Status.OK, Status.OK, Status.OK),
        (Status.DRIFT, Status.OK, Status.DRIFT),
        (Status.OK, Status.DRIFT, Status.DRIFT),
        (Status.CHANGED, Status.OK, Status.CHANGED),
        (Status.CHANGED, Status.DRIFT, Status.CHANGED),
        (Status.PARTIAL, Status.CHANGED, Status.PARTIAL),
        (Status.ERROR, Status.CHANGED, Status.PARTIAL),
        (Status.OK, Status.ERROR, Status.PARTIAL),
        (Status.ERROR, Status.ERROR, Status.ERROR),
    ],
)
def test_combined_status(create, sync, combined):
    result = interfaces.combine(
        ToolResult(status=create, summary="a", changes=["c1"], data={"sw1": 1}),
        ToolResult(status=sync, summary="b", changes=["s1"], data={"sw1": 2}),
    )
    assert result.status is combined
    assert result.summary == "create: a | sync: b"
    assert result.changes == ["c1", "s1"]
    assert result.data == {"create": {"sw1": 1}, "sync": {"sw1": 2}}
