"""Tests for the send-command tool — no real Nornir or devices."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pytest

from bunnyauto.context import Settings
from bunnyauto.errors import ToolError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools import send_command
from bunnyauto.tools.send_command import TOOL

# --- fakes -----------------------------------------------------------------


class _Item:
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception


class _Multi(list):
    def __init__(self, items, *, failed=False):
        super().__init__(items)
        self.failed = failed


class _Inventory:
    def __init__(self, hosts):
        self.hosts = hosts


class _Targets:
    def __init__(self, hosts, run_result):
        self.inventory = _Inventory(hosts)
        self._run_result = run_result
        self.run_kwargs = None

    def run(self, **kwargs):
        self.run_kwargs = kwargs
        return self._run_result


@dataclass
class _Ctx:
    settings: Settings
    reporter: Reporter
    _nr: object = None

    def nornir(self):
        return self._nr


def _ctx(**settings_over) -> _Ctx:
    base = dict(
        environment="test",
        nb_url="https://nb.example.com",
        config_file="config.yaml",
        target_tag="nornirtest",
        read_timeout=180.0,
    )
    base.update(settings_over)
    return _Ctx(settings=Settings(**base), reporter=Reporter(json_mode=True))


def _args(command: str, *, config_mode: bool = False) -> argparse.Namespace:
    return argparse.Namespace(command=command, config_mode=config_mode)


def _patch_targets(monkeypatch, hosts, run_result):
    targets = _Targets(hosts, run_result)
    monkeypatch.setattr(send_command, "filter_by_tag", lambda nr, tag: targets)
    return targets


# --- guard ---------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["configure terminal", "conf t", "write memory", "wr mem", "reload", "no shutdown"],
)
def test_state_changing_commands_are_blocked(command):
    with pytest.raises(ToolError, match="state"):
        TOOL.run(_ctx(), _args(command))


@pytest.mark.parametrize("command", ["show version", "show ip int brief", "clear counters"])
def test_show_commands_pass_the_guard(monkeypatch, command):
    _patch_targets(monkeypatch, {}, {})
    result = TOOL.run(_ctx(), _args(command))
    assert result.status is Status.OK


def test_config_mode_bypasses_the_guard(monkeypatch):
    _patch_targets(monkeypatch, {"sw1": object()}, {"sw1": _Multi([_Item(result="done")])})
    result = TOOL.run(_ctx(), _args("configure terminal", config_mode=True))
    assert result.status is Status.OK


def test_empty_command_is_rejected():
    with pytest.raises(ToolError):
        TOOL.run(_ctx(), _args("   "))


# --- execution ---------------------------------------------------------


def test_no_matching_devices(monkeypatch):
    _patch_targets(monkeypatch, {}, {})
    result = TOOL.run(_ctx(), _args("show version"))
    assert result.status is Status.OK
    assert "nornirtest" in result.summary
    assert result.data["devices"] == {}


def test_all_devices_succeed(monkeypatch):
    run_result = {
        "sw1": _Multi([_Item(result="IOS 17.9")]),
        "sw2": _Multi([_Item(result="IOS 17.6")]),
    }
    targets = _patch_targets(monkeypatch, {"sw1": 1, "sw2": 1}, run_result)
    result = TOOL.run(_ctx(), _args("show version"))

    assert result.status is Status.OK
    assert result.data["devices"]["sw1"] == {"failed": False, "output": "IOS 17.9"}
    assert targets.run_kwargs["command"] == "show version"
    assert targets.run_kwargs["read_timeout"] == 180.0


def test_partial_failure(monkeypatch):
    run_result = {
        "sw1": _Multi([_Item(result="ok")]),
        "sw2": _Multi([_Item(exception=RuntimeError("auth failed"))], failed=True),
    }
    _patch_targets(monkeypatch, {"sw1": 1, "sw2": 1}, run_result)
    result = TOOL.run(_ctx(), _args("show version"))

    assert result.status is Status.PARTIAL
    assert result.data["devices"]["sw2"]["failed"] is True
    assert "auth failed" in result.data["devices"]["sw2"]["output"]


def test_total_failure(monkeypatch):
    run_result = {
        "sw1": _Multi([_Item(exception=RuntimeError("x"))], failed=True),
    }
    _patch_targets(monkeypatch, {"sw1": 1}, run_result)
    result = TOOL.run(_ctx(), _args("show version"))
    assert result.status is Status.ERROR
    assert result.exit_code == 1
