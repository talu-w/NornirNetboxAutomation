"""Tests for live per-host progress — the HostProgressProcessor and the
Reporter.track()/spinner() context managers that wire it to Rich.
"""

from __future__ import annotations

import io

from bunnyauto.progress import HostProgressProcessor
from bunnyauto.reporting import Reporter

# --- HostProgressProcessor (pure, no Rich Live involved) -------------------


class _FakeProgress:
    def __init__(self):
        self.updates: list[tuple[int, dict]] = []

    def update(self, task_id, **kwargs):
        self.updates.append((task_id, kwargs))


class _FakeTask:
    def __init__(self, name):
        self.name = name


class _FakeHost:
    def __init__(self, name):
        self.name = name


class _FakeMultiResult:
    def __init__(self, failed=False):
        self.failed = failed


def test_task_instance_started_sets_description_to_current_step():
    progress = _FakeProgress()
    processor = HostProgressProcessor(progress, {"sw1": 0})

    processor.task_instance_started(_FakeTask("send-command: show version"), _FakeHost("sw1"))

    task_id, kwargs = progress.updates[-1]
    assert task_id == 0
    assert kwargs["description"] == "sw1: send-command: show version"


def test_subtask_instance_started_updates_description_too():
    progress = _FakeProgress()
    processor = HostProgressProcessor(progress, {"sw1": 0})

    processor.subtask_instance_started(_FakeTask("netmiko_send_command"), _FakeHost("sw1"))

    assert progress.updates[-1][1]["description"] == "sw1: netmiko_send_command"


def test_task_instance_completed_marks_done_and_full():
    progress = _FakeProgress()
    processor = HostProgressProcessor(progress, {"sw1": 0})

    processor.task_instance_completed(
        _FakeTask("x"), _FakeHost("sw1"), _FakeMultiResult(failed=False)
    )

    task_id, kwargs = progress.updates[-1]
    assert task_id == 0
    assert kwargs["completed"] == 1
    assert "done" in kwargs["description"]


def test_task_instance_completed_marks_failed():
    progress = _FakeProgress()
    processor = HostProgressProcessor(progress, {"sw1": 0})

    processor.task_instance_completed(
        _FakeTask("x"), _FakeHost("sw1"), _FakeMultiResult(failed=True)
    )

    assert "failed" in progress.updates[-1][1]["description"]


def test_unknown_host_is_ignored_not_errored():
    progress = _FakeProgress()
    processor = HostProgressProcessor(progress, {})

    processor.task_instance_started(_FakeTask("x"), _FakeHost("ghost"))
    processor.task_instance_completed(_FakeTask("x"), _FakeHost("ghost"), _FakeMultiResult())

    assert progress.updates == []


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


def test_track_attaches_one_processor_per_host_when_interactive():
    reporter = Reporter(use_rich=True, stream=io.StringIO())
    nr = _FakeNornir({"sw1": object(), "sw2": object()})

    with reporter.track(nr, description="send-command: show version") as tracked:
        assert tracked is nr
        assert nr.with_processors_called_with is not None
        assert len(nr.with_processors_called_with) == 1
        processor = nr.with_processors_called_with[0]
        assert isinstance(processor, HostProgressProcessor)
        assert set(processor._task_ids) == {"sw1", "sw2"}


def test_spinner_is_a_noop_outside_an_interactive_console():
    reporter = Reporter(json_mode=True)
    with reporter.spinner("querying NetBox inventory...") as result:
        assert result is None


def test_spinner_runs_without_error_when_interactive():
    reporter = Reporter(use_rich=True, stream=io.StringIO())
    with reporter.spinner("querying NetBox inventory..."):
        pass
