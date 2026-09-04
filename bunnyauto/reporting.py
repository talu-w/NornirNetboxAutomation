"""One output sink so tools never call ``print()``, ``logging``, or ``rich``.

A tool takes input through ``args`` and emits everything through the
``Reporter`` on its ``Context`` plus the ``ToolResult`` it returns. The Reporter
decides how that lands:

* interactive terminal  -> Rich formatting and colour;
* CI / non-TTY           -> plain, timestamped lines, no ANSI;
* ``--json``             -> prose is suppressed and ``render()`` prints the
  result as a single JSON object on stdout.

This keeps one code path serving both the hub and the pipeline.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from bunnyauto.environments import Environment
    from bunnyauto.result import ToolResult

_STATUS_STYLE = {
    "ok": ("green", "OK"),
    "drift": ("yellow", "DRIFT"),
    "changed": ("cyan", "CHANGED"),
    "partial": ("yellow", "PARTIAL"),
    "error": ("red", "ERROR"),
}


class Reporter:
    """Render progress and results for humans or machines.

    Prefer :func:`make_reporter` over constructing this directly.
    """

    def __init__(
        self,
        *,
        json_mode: bool = False,
        use_rich: bool | None = None,
        stream: TextIO | None = None,
    ) -> None:
        self.json_mode = json_mode
        self._stream = stream or sys.stdout
        if use_rich is None:
            use_rich = self._stream.isatty() and not json_mode
        self._console = None
        if use_rich:
            try:  # Rich is a hard dependency, but degrade gracefully if absent.
                from rich.console import Console

                self._console = Console(file=self._stream, highlight=False)
            except ImportError:
                self._console = None

    # -- plain user-facing text (menus, prompts, headers) ----------------------

    def say(self, message: str = "") -> None:
        """Print text with no log decoration. For interactive chrome only."""
        if self.json_mode:
            return
        if self._console is not None:
            self._console.print(message)
        else:
            self._stream.write(f"{message}\n")
            self._stream.flush()

    # -- lifecycle-style messages ------------------------------------------------

    def banner(self, environment: Environment, tag: str) -> None:
        """The environment header shown before any work begins."""
        if self.json_mode:
            return
        marker = "PRODUCTION" if environment.protected else environment.name.upper()
        line = f" {marker}  {environment.nb_url}  tag={tag} "
        if self._console is not None:
            colour = "bold white on red" if environment.protected else "bold white on blue"
            self._console.print(line, style=colour)
        else:
            self.say(f"── {marker}  {environment.nb_url}  tag={tag} ──")

    def step(self, message: str) -> None:
        self._emit(message, style="dim", level="STEP")

    def info(self, message: str) -> None:
        self._emit(message, style=None, level="INFO")

    def success(self, message: str) -> None:
        self._emit(message, style="green", level="INFO")

    def warn(self, message: str) -> None:
        self._emit(message, style="yellow", level="WARN")

    def error(self, message: str) -> None:
        self._emit(message, style="red", level="ERROR", err=True)

    # -- the final result ------------------------------------------------------

    def render(self, result: ToolResult) -> None:
        if self.json_mode:
            json.dump(result.as_dict(), self._stream, indent=2, sort_keys=True, default=str)
            self._stream.write("\n")
            self._stream.flush()
            return

        colour, label = _STATUS_STYLE.get(result.status.value, ("white", result.status.value))
        if self._console is not None:
            self._console.print(f"\n[{colour}]● {label}[/] {result.summary}")
            for change in result.changes:
                self._console.print(f"  [dim]·[/] {change}")
            for artifact in result.artifacts:
                self._console.print(f"  [dim]saved[/] {artifact}")
        else:
            self._plain(f"{label}: {result.summary}")
            for change in result.changes:
                self._plain(f"  - {change}")
            for artifact in result.artifacts:
                self._plain(f"  saved {artifact}")

    # -- live progress -----------------------------------------------------

    @contextmanager
    def track(self, nr: Any, *, description: str = "") -> Iterator[Any]:
        """Run a Nornir task under a live per-host progress bar, if interactive.

        Yields something to call ``.run()`` on. Outside an interactive TTY (CI,
        ``--json``) this is a no-op that yields ``nr`` unchanged, so callers can
        use it unconditionally: ``with ctx.reporter.track(targets) as tracked:``.
        """
        if self._console is None:
            yield nr
            return

        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

        from bunnyauto.progress import build_host_progress

        if description:
            self._console.print(description, style="dim")

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self._console,
        )
        with progress:
            processor = build_host_progress(progress, list(nr.inventory.hosts))
            yield nr.with_processors([processor])

    @contextmanager
    def spinner(self, description: str) -> Iterator[None]:
        """A single indeterminate status line for non-Nornir work (a NetBox call)."""
        if self._console is None:
            yield
            return

        from rich.progress import Progress, SpinnerColumn, TextColumn

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self._console,
        )
        with progress:
            progress.add_task(description, total=None)
            yield

    # -- internals -----------------------------------------------------------

    def _emit(
        self,
        message: str,
        *,
        style: str | None,
        level: str,
        err: bool = False,
    ) -> None:
        if self.json_mode:
            if err:
                sys.stderr.write(f"{message}\n")
            return
        if self._console is not None:
            target = self._console
            text = f"[{style}]{message}[/]" if style else message
            target.print(text, style=None)
        else:
            self._plain(f"{level}: {message}", err=err)

    def _plain(self, message: str, *, err: bool = False) -> None:
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        stream = sys.stderr if err else self._stream
        stream.write(f"{stamp} | {message}\n")
        stream.flush()


def make_reporter(*, json_mode: bool = False, quiet_rich: bool = False) -> Reporter:
    """Build the Reporter appropriate for the current process."""
    return Reporter(json_mode=json_mode, use_rich=None if not quiet_rich else False)
