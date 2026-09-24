"""Putting a question to the person running bunnyauto.

Tools never call ``input()``. The hub answers every question through its own
``input_fn``; the CLI hands the Context :func:`terminal_input` — ``input`` when
someone is at a terminal, ``None`` otherwise — so a CI run (no TTY) or a
``--json`` run is never left waiting on a prompt. A tool asks through its
:class:`~bunnyauto.context.Context` (``confirm`` / ``ask`` / ``confirm_protected``).
"""

from __future__ import annotations

import sys
from collections.abc import Callable

InputFn = Callable[[str], str]


def ask(prompt: str, *, default: str | None = None, input_fn: InputFn = input) -> str:
    """A free-text answer; Enter keeps ``default``."""
    suffix = f" [{default}]" if default else ""
    raw = input_fn(f"{prompt}{suffix}: ").strip()
    return raw or (default or "")


def ask_bool(prompt: str, *, default: bool = False, input_fn: InputFn = input) -> bool:
    """A yes/no answer; Enter keeps ``default``, anything but y/yes is no."""
    hint = "Y/n" if default else "y/N"
    raw = input_fn(f"{prompt} [{hint}]: ").strip().casefold()
    if not raw:
        return default
    return raw in {"y", "yes"}


def terminal_input() -> InputFn | None:
    """``input`` when someone is at a terminal to answer, else ``None``."""
    return input if sys.stdin.isatty() and sys.stdout.isatty() else None
