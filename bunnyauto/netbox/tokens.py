"""Match a terse vendor string to a NetBox record by token containment.

Used for device types (``wireless sync``: Aruba's ``"655"`` -> the NetBox
device type ``"Aruba AP-655"``) and for platforms (``wireless enrich``: a
reported ``"8.10.0.5"`` becomes the candidate ``"AOS 8"`` -> the NetBox
platform ``"AOS 8"``). Any NetBox record with name-like fields works the same
way; pass the fields to compare as ``key_fields``.

Pure — no I/O. A device reports a terse model string (Aruba: ``"655"``,
``"AP-655"``); a real NetBox device type's ``model``/``slug`` is usually longer
and more specific (imported from NetBox Data Exchange: model
``"Aruba AP-655"``, slug ``"hpe-aruba-ap-655"``). Requiring an *exact* match on
either field misses that entirely — the candidate is a substring, not the
whole string.

Instead, both sides are tokenized on any run of non-alphanumeric characters,
and a device type matches if the candidate's tokens appear as a *contiguous*
run inside the device type's tokens — e.g. candidate tokens ``["655"]`` or
``["ap", "655"]`` both match slug tokens ``["hpe", "aruba", "ap", "655"]``, but
``["655"]`` would not spuriously match a token like ``"8655"`` (tokens don't
split mid-word).
"""

from __future__ import annotations

import re
from typing import Any

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def tokens(value: str) -> list[str]:
    """Lowercase and split on any run of non-alphanumeric characters."""
    normalized = _NON_ALNUM.sub("-", str(value).casefold()).strip("-")
    return [t for t in normalized.split("-") if t]


def _contains_contiguous(haystack: list[str], needle: list[str]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    span = len(needle)
    return any(haystack[i : i + span] == needle for i in range(len(haystack) - span + 1))


def match_record(
    candidates: list[str],
    records: list[Any],
    *,
    key_fields: tuple[str, ...] = ("model", "slug"),
) -> Any | None:
    """Return the one record matching a candidate string, or ``None``.

    Tries each of ``candidates`` in order (best guess first — for a device
    type, typically the bare model number, then a more specific
    ``"AP-<model>"`` form). A candidate is accepted the moment it identifies
    exactly one record (checking ``key_fields`` on each); a candidate matching
    zero or more than one record is skipped in favor of the next, more
    specific candidate. ``None`` if no candidate ever resolves to exactly one.
    """
    for candidate in candidates:
        needle = tokens(candidate)
        if not needle:
            continue
        matched: dict[int, Any] = {}
        for record in records:
            for field in key_fields:
                raw = getattr(record, field, "")
                if raw and _contains_contiguous(tokens(raw), needle):
                    matched[id(record)] = record
                    break
        if len(matched) == 1:
            return next(iter(matched.values()))
    return None
