"""Per-host progress tracking for the interactive hub.

:class:`HostProgressProcessor` is a Nornir ``Processor`` (see
``nornir.core.processor``) that drives a ``rich.progress.Progress`` — one bar
per host, its description updated as each host's task/subtask changes and
marked done/failed on completion. It knows nothing about Rich's ``Live``
rendering or about the ``Reporter``; :meth:`bunnyauto.reporting.Reporter.track`
is what builds the ``Progress``, wires this processor to it, and decides
whether any of this runs at all (never in ``--json`` or non-TTY output).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nornir.core.inventory import Host
    from nornir.core.task import AggregatedResult, MultiResult, Task
    from rich.progress import Progress


class HostProgressProcessor:
    """Updates one ``Progress`` task-id per host as Nornir runs a task."""

    def __init__(self, progress: Progress, task_ids: dict[str, int]) -> None:
        self._progress = progress
        self._task_ids = task_ids

    def task_started(self, task: Task) -> None:  # noqa: D102 - Processor protocol
        pass

    def task_completed(self, task: Task, result: AggregatedResult) -> None:  # noqa: D102
        pass

    def task_instance_started(self, task: Task, host: Host) -> None:
        self._describe(host.name, task.name)

    def task_instance_completed(self, task: Task, host: Host, result: MultiResult) -> None:
        task_id = self._task_ids.get(host.name)
        if task_id is None:
            return
        failed = getattr(result, "failed", False)
        style = "red" if failed else "green"
        label = "failed" if failed else "done"
        self._progress.update(
            task_id, description=f"[{style}]{host.name}: {label}[/{style}]", completed=1
        )

    def subtask_instance_started(self, task: Task, host: Host) -> None:
        self._describe(host.name, task.name)

    def subtask_instance_completed(self, task: Task, host: Host, result: MultiResult) -> None:  # noqa: D102
        pass

    def _describe(self, host_name: str, step: str) -> None:
        task_id = self._task_ids.get(host_name)
        if task_id is not None:
            self._progress.update(task_id, description=f"{host_name}: {step}")


def build_host_progress(progress: Progress, host_names: Any) -> HostProgressProcessor:
    """Add one queued task per host to ``progress`` and return its processor."""
    task_ids = {name: progress.add_task(f"{name}: queued", total=1) for name in host_names}
    return HostProgressProcessor(progress, task_ids)
