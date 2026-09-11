"""Per-host progress tracking for the interactive hub.

:class:`HostProgressProcessor` is a Nornir ``Processor`` (see
``nornir.core.processor``) that drives a ``rich.progress.Progress``: one pinned
"overall" bar (``X/N`` devices done) plus one bar per host **currently in
flight**. A host's bar is created when its task starts and removed the moment
it finishes — bounding the live-rendered region to however many hosts Nornir
is actually running at once (``num_workers`` in the Nornir config, default 10
here), never the size of the whole inventory. Rich's ``Live`` display cannot
scroll: content taller than the terminal is silently truncated, which is what
made a large inventory's progress look "stuck" showing only a handful of
devices. Each host's outcome is printed as a normal line through the same
console instead, so it lands in real, scrollable terminal history — Rich
composes that correctly above the still-live region.

This class knows nothing about ``Live`` rendering setup or the ``Reporter``;
:meth:`bunnyauto.reporting.Reporter.track` builds the ``Progress``, wires this
processor to it, and decides whether any of this runs at all (never in
``--json`` or non-TTY output).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nornir.core.inventory import Host
    from nornir.core.task import AggregatedResult, MultiResult, Task
    from rich.console import Console
    from rich.progress import Progress


class HostProgressProcessor:
    """One pinned overall bar + one bar per in-flight host."""

    def __init__(self, progress: Progress, console: Console, overall_id: int) -> None:
        self._progress = progress
        self._console = console
        self._overall_id = overall_id
        self._host_tasks: dict[str, int] = {}

    def task_started(self, task: Task) -> None:  # noqa: D102 - Processor protocol
        pass

    def task_completed(self, task: Task, result: AggregatedResult) -> None:  # noqa: D102
        pass

    def task_instance_started(self, task: Task, host: Host) -> None:
        self._host_tasks[host.name] = self._progress.add_task(f"{host.name}: {task.name}", total=1)

    def task_instance_completed(self, task: Task, host: Host, result: MultiResult) -> None:
        task_id = self._host_tasks.pop(host.name, None)
        failed = bool(getattr(result, "failed", False))
        style = "red" if failed else "green"
        label = "failed" if failed else "done"
        self._console.print(f"  [{style}]{host.name}: {label}[/{style}]")
        if task_id is not None:
            self._progress.remove_task(task_id)
        self._progress.advance(self._overall_id)

    def subtask_instance_started(self, task: Task, host: Host) -> None:
        task_id = self._host_tasks.get(host.name)
        if task_id is not None:
            self._progress.update(task_id, description=f"{host.name}: {task.name}")

    def subtask_instance_completed(self, task: Task, host: Host, result: MultiResult) -> None:  # noqa: D102
        pass


def build_host_progress(
    progress: Progress, console: Console, total: int, description: str
) -> HostProgressProcessor:
    """Add the pinned overall task to ``progress`` and return its processor."""
    overall_id = progress.add_task(description, total=total)
    return HostProgressProcessor(progress, console, overall_id)
