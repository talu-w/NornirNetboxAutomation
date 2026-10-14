"""Tests for retrying the devices that fail to connect — over a real (in-memory) Nornir.

The helper leans on Nornir's own failed-host bookkeeping, so these run a real
``Nornir`` with a task that fails the way a Netmiko login does, instead of faking
the run: what is verified is that the right devices are re-run, that the final
results hold each device's last attempt, and that nothing else is ever retried.
"""

from __future__ import annotations

import argparse
import io
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from nornir.core import Nornir
from nornir.core.configuration import Config
from nornir.core.inventory import Defaults, Groups, Host, Hosts, Inventory
from nornir.core.task import Result, Task
from nornir.plugins.runners import SerialRunner
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

from bunnyauto import retry
from bunnyauto.common import first_error
from bunnyauto.context import Settings
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.retry import is_connect_failure, run_with_retries
from bunnyauto.tools.wired import send_command

# --- a real Nornir and a task that fails like a login ----------------------


def _nornir(*names: str) -> Nornir:
    hosts = Hosts({name: Host(name=name, hostname=name) for name in names})
    inventory = Inventory(hosts=hosts, groups=Groups(), defaults=Defaults())
    return Nornir(inventory=inventory, runner=SerialRunner(), config=Config())


class _Script:
    """What each attempt on each host does: ``None`` connects, an exception fails.

    A ``("open", exc)`` entry fails *after* the session came up, as a command
    that times out would. The last entry repeats once a host runs out of them.
    """

    def __init__(self, **outcomes):
        self.outcomes = outcomes
        self.calls: dict[str, int] = {}

    def next(self, host: str):
        count = self.calls.get(host, 0)
        self.calls[host] = count + 1
        steps = self.outcomes.get(host, [None])
        return steps[min(count, len(steps) - 1)]


def _log_in(task: Task, script: _Script) -> str:
    step = script.next(task.host.name)
    if isinstance(step, tuple):  # the session opened, then a command failed
        task.host.connections["netmiko"] = object()
        raise step[1]
    if step is not None:
        raise step
    task.host.connections["netmiko"] = object()
    return "connected"


def _task(task: Task, script: _Script) -> None:
    """A tool task: the login happens in a subtask, so a failure arrives wrapped."""
    task.run(task=_log_in, script=script)


def _swallowing_task(task: Task, script: _Script) -> Result:
    """The health collector's shape: catches the subtask's failure, returns normally."""
    try:
        task.run(task=_log_in, script=script)
    except Exception:
        return Result(host=task.host, result={"reachable": False})
    return Result(host=task.host, result={"reachable": True})


TIMEOUT = NetmikoTimeoutException("TCP connection to device failed.")


def _ctx(**settings) -> SimpleNamespace:
    out = io.StringIO()
    base = dict(
        environment="test",
        nb_url="https://nb",
        config_file="config.yaml",
        target_tag="nornirtest",
        retry_delay=0.0,
    )
    base.update(settings)
    return SimpleNamespace(
        settings=Settings(**base),
        reporter=Reporter(use_rich=False, stream=out),
        out=out,
    )


def _run(ctx, nr, script, task=_task):
    return run_with_retries(ctx, nr, task=task, name="test", description="test", script=script)


@pytest.fixture(autouse=True)
def _no_sleeping(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(retry.time, "sleep", slept.append)
    return slept


# --- the retry loop ----------------------------------------------------------


def test_nothing_is_retried_when_every_device_connects():
    ctx, script = _ctx(), _Script()
    results = _run(ctx, _nornir("sw1", "sw2"), script)

    assert script.calls == {"sw1": 1, "sw2": 1}
    assert not results.failed
    assert "retry" not in ctx.out.getvalue()


def test_a_device_that_fails_to_connect_is_retried_once_the_others_are_done():
    ctx = _ctx()
    script = _Script(sw1=[TIMEOUT, TIMEOUT, None])
    nr = _nornir("sw1", "sw2")

    results = _run(ctx, nr, script)

    assert not results.failed
    assert script.calls == {"sw1": 3, "sw2": 1}  # only the failed device is re-run
    assert nr.data.failed_hosts == set()  # recovered, so Nornir no longer skips it
    log = ctx.out.getvalue()
    assert "retry 1/3" in log and "retry 2/3" in log and "retry 3/3" not in log
    assert "sw1: connected on retry 2/3" in log
    assert "still failed" not in log


def test_a_device_that_never_connects_is_reported_after_the_last_retry():
    ctx = _ctx()
    script = _Script(sw1=[TIMEOUT], sw2=[None])

    results = _run(ctx, _nornir("sw1", "sw2"), script)

    assert script.calls == {"sw1": 4, "sw2": 1}  # the first pass plus three retries
    assert results["sw1"].failed and not results["sw2"].failed
    assert first_error(results["sw1"], "?").startswith("NetmikoTimeoutException")
    assert "1 device(s) still failed to connect after 3 retries: sw1" in ctx.out.getvalue()


def test_the_number_of_retries_is_a_setting():
    script = _Script(sw1=[TIMEOUT])
    _run(_ctx(connect_retries=1), _nornir("sw1"), script)
    assert script.calls == {"sw1": 2}


def test_zero_retries_means_one_attempt_and_no_retry_chatter():
    ctx, script = _ctx(connect_retries=0), _Script(sw1=[TIMEOUT])
    results = _run(ctx, _nornir("sw1"), script)

    assert script.calls == {"sw1": 1}
    assert results["sw1"].failed
    assert "retry" not in ctx.out.getvalue() and "still failed" not in ctx.out.getvalue()


def test_each_retry_waits_for_the_configured_delay(_no_sleeping):
    script = _Script(sw1=[TIMEOUT, TIMEOUT, None])
    _run(_ctx(retry_delay=2.5), _nornir("sw1"), script)
    assert _no_sleeping == [2.5, 2.5]


def test_there_is_no_wait_when_nothing_needs_retrying(_no_sleeping):
    _run(_ctx(retry_delay=2.5), _nornir("sw1"), _Script())
    assert _no_sleeping == []


def test_a_failure_the_task_swallows_is_still_a_connect_failure():
    """``wired health`` records "unreachable" and returns normally; the failed subtask shows."""
    script = _Script(sw1=[TIMEOUT, None])
    results = _run(_ctx(), _nornir("sw1"), script, task=_swallowing_task)

    assert script.calls == {"sw1": 2}
    assert results["sw1"][0].result == {"reachable": True}


# --- what is never retried -------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        NetmikoAuthenticationException("Authentication to device failed."),
        AuthenticationException("Authentication failed."),
        BadHostKeyException("sw1", None, None),
        ValueError("Either ip or host must be set"),
        RuntimeError("a bug"),
    ],
    ids=lambda failure: type(failure).__name__,
)
def test_failures_a_second_try_cannot_fix_are_not_retried(failure):
    script = _Script(sw1=[failure])
    results = _run(_ctx(), _nornir("sw1"), script)

    assert script.calls == {"sw1": 1}
    assert results["sw1"].failed


@pytest.mark.parametrize(
    "failure",
    [
        TIMEOUT,
        SSHException("Error reading SSH protocol banner"),
        TimeoutError("timed out"),
        ConnectionResetError("Connection reset by peer"),
        OSError("No route to host"),
        EOFError(),
        ReadTimeout("Pattern not detected"),
    ],
    ids=lambda failure: type(failure).__name__,
)
def test_connection_errors_are_retried(failure):
    script = _Script(sw1=[failure, None])
    results = _run(_ctx(), _nornir("sw1"), script)

    assert script.calls == {"sw1": 2}
    assert not results.failed


def test_a_command_that_fails_on_an_open_session_is_not_retried():
    """It may have partly run (``send-command --config-mode``) and isn't a connect problem."""
    script = _Script(sw1=[("open", TIMEOUT)])
    results = _run(_ctx(), _nornir("sw1"), script)

    assert script.calls == {"sw1": 1}
    assert results["sw1"].failed


def test_only_the_devices_that_fail_to_connect_are_retried():
    script = _Script(
        down=[TIMEOUT, None],
        wrong_password=[NetmikoAuthenticationException("Authentication to device failed.")],
        mid_command=[("open", TIMEOUT)],
        fine=[None],
    )
    results = _run(_ctx(), _nornir("down", "wrong_password", "mid_command", "fine"), script)

    assert script.calls == {"down": 2, "wrong_password": 1, "mid_command": 1, "fine": 1}
    assert set(results.failed_hosts) == {"wrong_password", "mid_command"}


def test_is_connect_failure_ignores_a_device_that_did_not_fail():
    nr = _nornir("sw1")
    results = nr.run(task=_task, script=_Script())
    assert is_connect_failure(nr.inventory.hosts["sw1"], results["sw1"]) is False


# --- through a real tool ------------------------------------------------------------


@dataclass
class _ToolCtx:
    settings: Settings
    reporter: Reporter
    targets: Nornir

    def target_hosts(self):
        return self.targets

    def scope(self):  # only used for the "no devices" summary
        raise AssertionError("not needed")


def test_send_command_recovers_a_device_that_connects_on_a_retry(monkeypatch):
    script = _Script(sw1=[TIMEOUT, None], sw2=[TIMEOUT])

    def fake_send(task: Task, command: str, read_timeout: float) -> str:
        _log_in(task, script)
        return f"output of {command} on {task.host.name}"

    monkeypatch.setattr(send_command, "_send", fake_send)
    ctx = _ToolCtx(
        settings=_ctx().settings, reporter=Reporter(json_mode=True), targets=_nornir("sw1", "sw2")
    )

    result = send_command.TOOL.run(
        ctx, argparse.Namespace(command="show version", config_mode=False)
    )

    assert script.calls == {"sw1": 2, "sw2": 4}
    assert result.status is Status.PARTIAL  # sw2 never connected
    assert result.data["devices"]["sw1"] == {
        "failed": False,
        "output": "output of show version on sw1",
    }
    assert result.data["devices"]["sw2"]["failed"] is True
    assert "NetmikoTimeoutException" in result.data["devices"]["sw2"]["output"]
