"""The structured value every tool's ``run()`` returns.

Keeping this in its own module (rather than in ``tools/base.py``) lets
:mod:`bunnyauto.reporting` render a result without importing the tool layer.
``tools/base.py`` re-exports these names and adds the ``Tool`` protocol.

The status drives the process exit code, which is what a CI pipeline branches
on: a clean plan, drift found, and changes applied are three different outcomes
and get three different codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Status(StrEnum):
    OK = "ok"  # ran; nothing to change
    DRIFT = "drift"  # plan mode found changes to make (not applied)
    CHANGED = "changed"  # --apply wrote changes
    PARTIAL = "partial"  # some hosts succeeded, some failed
    ERROR = "error"  # could not run


EXIT_CODES: dict[Status, int] = {
    Status.OK: 0,
    Status.DRIFT: 10,
    Status.CHANGED: 20,
    Status.PARTIAL: 2,
    Status.ERROR: 1,
}


@dataclass(slots=True)
class ToolResult:
    """What a tool produced, in a form both a human and a pipeline can read."""

    status: Status
    summary: str
    changes: list[str] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]

    def as_dict(self) -> dict[str, Any]:
        """JSON-friendly view, used by ``--json`` output."""
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "changes": list(self.changes),
            "artifacts": [str(path) for path in self.artifacts],
            "data": self.data,
        }
