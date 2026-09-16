"""Match a short vendor model string to a NetBox device type by model/slug.

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


def match_device_type(
    model_candidates: list[str],
    device_types: list[Any],
    *,
    key_fields: tuple[str, ...] = ("model", "slug"),
) -> Any | None:
    """Return the one device type matching a model candidate, or ``None``.

    Tries each of ``model_candidates`` in order (best guess first — typically
    the bare model number, then a more specific ``"AP-<model>"`` form). A
    candidate is accepted the moment it identifies exactly one device type
    (checking ``key_fields`` on each); a candidate matching zero or more than
    one device type is skipped in favor of the next, more specific candidate.
    ``None`` if no candidate ever resolves to exactly one.
    """
    for candidate in model_candidates:
        needle = tokens(candidate)
        if not needle:
            continue
        matched: dict[int, Any] = {}
        for device_type in device_types:
            for field in key_fields:
                raw = getattr(device_type, field, "")
                if raw and _contains_contiguous(tokens(raw), needle):
                    matched[id(device_type)] = device_type
                    break
        if len(matched) == 1:
            return next(iter(matched.values()))
    return None
