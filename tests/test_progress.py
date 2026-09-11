"""Tests for live progress — the HostProgressProcessor and the
Reporter.track()/spinner() context managers that wire it to Rich.

HostProgressProcessor must never let the live-rendered region grow with the
size of the inventory (that's what broke scrolling on a large tag): only
in-flight hosts get a bar, and each is removed the moment it completes.
"""

from __future__ import annotations

import io

from bunnyauto.progress import HostProgressProcessor
from bunnyauto.reporting import Reporter

# --- HostProgressProcessor (pure, no Rich Live involved) -------------------


class _FakeProgress:
    def __init__(self):
        self.tasks: dict[int, dict] = {}
        self._next_id = 0
        self.removed: list[int] = []

    def add_task(self, description, total=1):
        task_id = self._next_id
        self._next_id += 1
        self.tasks[task_id] = {"description": description, "completed": 0, "total": total}
        return task_id

    def update(self, task_id, **kwargs):
        self.tasks[task_id].update(kwargs)

    def advance(self, task_id, amount=1):
        self.tasks[task_id]["completed"] += amount

    def remove_task(self, task_id):
        self.removed.append(task_id)
        del self.tasks[task_id]


class _FakeConsole:
    def __init__(self):
        self.lines: list[str] = []

    def print(self, message, **kwargs):
        self.lines.append(message)


class _FakeTask:
    def __init__(self, name):
        self.name = name


class _FakeHost:
    def __init__(self, name):
        self.name = name


class _FakeMultiResult:
    def __init__(self, failed=False):
        self.failed = failed


def _processor(progress, console=None, overall_id=None):
    if overall_id is None:
        overall_id = progress.add_task("overall", total=1)
    return HostProgressProcessor(progress, console or _FakeConsole(), overall_id)


def test_task_instance_started_adds_one_bar_for_that_host():
    progress = _FakeProgress()
    overall_id = progress.add_task("overall", total=1)
    processor = _processor(progress, overall_id=overall_id)

    processor.task_instance_started(_FakeTask("send-command: show version"), _FakeHost("sw1"))

    host_tasks = {tid: t for tid, t in progress.tasks.items() if tid != overall_id}
    assert len(host_tasks) == 1
    (task,) = host_tasks.values()
    assert task["description"] == "sw1: send-command: show version"


def test_subtask_instance_started_updates_that_hosts_bar_in_place():
    progress = _FakeProgress()
    overall_id = progress.add_task("overall", total=1)
    processor = _processor(progress, overall_id=overall_id)
    processor.task_instance_started(_FakeTask("backup"), _FakeHost("sw1"))

    processor.subtask_instance_started(_FakeTask("show running-config"), _FakeHost("sw1"))

    host_tasks = {tid: t for tid, t in progress.tasks.items() if tid != overall_id}
    assert len(host_tasks) == 1  # still one bar, not a second
    (task,) = host_tasks.values()
    assert task["description"] == "sw1: show running-config"


def test_task_instance_completed_removes_the_hosts_bar_and_advances_overall():
    progress = _FakeProgress()
    overall_id = progress.add_task("send-command", total=1)
    processor = _processor(progress, overall_id=overall_id)
    processor.task_instance_started(_FakeTask("x"), _FakeHost("sw1"))

    processor.task_instance_completed(_FakeTask("x"), _FakeHost("sw1"), _FakeMultiResult())

    assert progress.tasks.keys() == {overall_id}  # the per-host bar is gone
    assert progress.tasks[overall_id]["completed"] == 1


def test_task_instance_completed_prints_a_scrolling_line_not_a_bar():
    progress = _FakeProgress()
    console = _FakeConsole()
    processor = _processor(progress, console=console)
    processor.task_instance_started(_FakeTask("x"), _FakeHost("sw1"))

    processor.task_instance_completed(_FakeTask("x"), _FakeHost("sw1"), _FakeMultiResult())

    assert any("sw1" in line and "done" in line for line in console.lines)


def test_task_instance_completed_marks_failed_hosts_in_the_scrolling_line():
    progress = _FakeProgress()
    console = _FakeConsole()
    processor = _processor(progress, console=console)
    processor.task_instance_started(_FakeTask("x"), _FakeHost("sw1"))

    processor.task_instance_completed(
        _FakeTask("x"), _FakeHost("sw1"), _FakeMultiResult(failed=True)
    )

    assert any("sw1" in line and "failed" in line for line in console.lines)


def test_live_region_never_exceeds_in_flight_hosts_for_a_large_inventory():
    """The bug this guards: 200 devices used to mean 200 permanent bars — more
    than any terminal can show, and Rich's Live can't scroll past that."""
    progress = _FakeProgress()
    overall_id = progress.add_task("send-command", total=200)
    processor = _processor(progress, overall_id=overall_id)

    for i in range(200):
        host = _FakeHost(f"sw{i}")
        processor.task_instance_started(_FakeTask("x"), host)
        assert len(progress.tasks) <= 6  # in-flight bar(s) + the overall bar
        processor.task_instance_completed(_FakeTask("x"), host, _FakeMultiResult())

    assert progress.tasks.keys() == {overall_id}
    assert progress.tasks[overall_id]["completed"] == 200


def test_unknown_host_completion_is_ignored_not_errored():
    progress = _FakeProgress()
    overall_id = progress.add_task("x", total=1)
    processor = _processor(progress, overall_id=overall_id)

    processor.task_instance_completed(_FakeTask("x"), _FakeHost("ghost"), _FakeMultiResult())

    assert progress.removed == []
    assert progress.tasks[overall_id]["completed"] == 1  # overall still advances


# --- Reporter.track() / spinner() -------------------------------------------


class _FakeInventory:
    def __init__(self, hosts):
        self.hosts = hosts


class _FakeNornir:
    def __init__(self, hosts):
        self.inventory = _FakeInventory(hosts)
        self.with_processors_called_with = None

    def with_processors(self, processors):
        self.with_processors_called_with = processors
        return self


def test_track_is_a_noop_outside_an_interactive_console():
    # json_mode forces use_rich off, matching CI / --json behaviour.
    reporter = Reporter(json_mode=True)
    nr = _FakeNornir({"sw1": object()})

    with reporter.track(nr, description="send-command: show version") as tracked:
        assert tracked is nr

    assert nr.with_processors_called_with is None


def test_track_attaches_one_processor_when_interactive():
    reporter = Reporter(use_rich=True, stream=io.StringIO())
    nr = _FakeNornir({"sw1": object(), "sw2": object()})

    with reporter.track(nr, description="send-command: show version") as tracked:
        assert tracked is nr
        assert nr.with_processors_called_with is not None
        assert len(nr.with_processors_called_with) == 1
        assert isinstance(nr.with_processors_called_with[0], HostProgressProcessor)


def test_spinner_is_a_noop_outside_an_interactive_console():
    reporter = Reporter(json_mode=True)
    with reporter.spinner("querying NetBox inventory...") as result:
        assert result is None


def test_spinner_runs_without_error_when_interactive():
    reporter = Reporter(use_rich=True, stream=io.StringIO())
    with reporter.spinner("querying NetBox inventory..."):
        pass
