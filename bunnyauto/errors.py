"""One exception tree for bunnyauto, each node able to explain itself in a line.

The entry points catch :class:`BunnyautoError` and print ``exc.friendly()`` —
a short sentence naming what is wrong and, where possible, the exact command to
fix it. Full tracebacks are shown only when ``--debug`` / ``BUNNYAUTO_DEBUG=1``
is set. Tools and core code should raise these instead of bare ``ValueError`` /
``RuntimeError`` so the engineer never sees a stack trace for an expected
problem.
"""

from __future__ import annotations

from collections.abc import Iterable

_PREFIX = "bunnyauto:"


class BunnyautoError(Exception):
    """Base class for every expected, explainable bunnyauto failure.

    ``fix`` is an optional second line with a concrete remedy (usually a shell
    command). ``friendly()`` renders the message the entry points display.
    """

    fix: str | None = None

    def __init__(self, message: str, *, fix: str | None = None) -> None:
        super().__init__(message)
        if fix is not None:
            self.fix = fix

    def friendly(self) -> str:
        text = f"{_PREFIX} {self}"
        if self.fix:
            text += f"\n{' ' * len(_PREFIX)} Fix:  {self.fix}"
        return text


class ConfigError(BunnyautoError):
    """A configuration file is missing, malformed, or internally inconsistent."""


class UnknownEnvironmentError(ConfigError):
    """``--env`` named an environment that is not defined in ``bunnyauto.yaml``."""

    def __init__(self, name: str, available: Iterable[str]) -> None:
        options = ", ".join(sorted(available)) or "(none defined)"
        super().__init__(
            f"unknown environment {name!r}. Defined environments: {options}",
            fix="add it to bunnyauto.yaml, or pass --env with one of the names above",
        )


class EnvVarError(BunnyautoError):
    """A required environment variable is unset or only partially configured."""

    def __init__(self, message: str, *, fix: str | None = None) -> None:
        super().__init__(message, fix=fix)


class TagMismatchError(BunnyautoError):
    """``--tag`` does not belong to the selected environment (cross-wiring guard)."""

    def __init__(self, tag: str, environment: str, expected: str) -> None:
        super().__init__(
            f"tag {tag!r} is not the default tag for environment {environment!r} "
            f"(expected {expected!r}). Refusing to run to avoid touching the wrong "
            f"network.",
            fix="drop --tag to use the environment's default, or pass --force-tag "
            "if you really mean it",
        )


class InventoryError(BunnyautoError):
    """Nornir could not be initialized, or the tag matched no devices."""


class NetBoxError(BunnyautoError):
    """A direct NetBox API client could not be built or reached."""


class ToolError(BunnyautoError):
    """A tool could not complete for an expected, explainable reason."""
