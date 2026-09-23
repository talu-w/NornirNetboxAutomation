"""Read values off pynetbox records, whatever shape they arrive in.

Pure — no I/O. A related object or a choice field can come back from pynetbox as
a nested ``Record``, a plain ``dict`` (brief/nested API output), a bare id or
string, or ``None``; these flatten all of them so callers compare plain values.
"""

from __future__ import annotations

from typing import Any


def related_id(value: Any) -> int | None:
    """The id of a related object (``Record``, ``{"id": ...}``, or an int), else ``None``."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        value = value.get("id")
    else:
        value = getattr(value, "id", None)
    return int(value) if value is not None else None


def choice_value(value: Any) -> str | None:
    """The machine value of a choice field (interface ``type``, ``mode``, ...), else ``None``."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("value")
    return getattr(value, "value", str(value))
