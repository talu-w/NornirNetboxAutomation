"""NetBox device roles: the role tree, and the role lookups every tool shares.

NetBox 4.3 made device roles hierarchical (a role may have a ``parent``), and its
device ``role`` filter is hierarchical too: ``?role=wired-network`` returns
devices whose role is ``wired-network`` *or any role beneath it*, exactly like
``?region=`` already does for sites. That server-side filter does the actual
device selection (see :mod:`bunnyauto.scope`). :class:`RoleTree` is a
client-side copy of the tree used only to *validate* first ("does this role
exist?", "is this --role inside the category's branch?"), so a typo fails with
a clear message instead of silently matching nothing.

On NetBox < 4.3 every role is a root (there is no ``parent`` field), so the tree
is flat and a branch is just its one role.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from bunnyauto.errors import ToolError
from bunnyauto.netbox.records import related_id


@dataclass(frozen=True, slots=True)
class RoleTree:
    """Every device-role slug, mapped to its parent's slug (``None`` for a root)."""

    parents: Mapping[str, str | None]

    @classmethod
    def load(cls, nb: Any) -> RoleTree:
        """Fetch every device role once and index the hierarchy by slug."""
        roles = list(nb.dcim.device_roles.all())
        slug_by_id = {int(role.id): str(role.slug) for role in roles}
        parents: dict[str, str | None] = {}
        for role in roles:
            parent_id = related_id(getattr(role, "parent", None))
            parents[str(role.slug)] = slug_by_id.get(parent_id) if parent_id is not None else None
        return cls(parents=parents)

    def find(self, slug: str | None) -> str | None:
        """The real slug matching ``slug`` case-insensitively, or ``None`` if NetBox has none."""
        if not slug:
            return None
        wanted = slug.strip().casefold()
        return next((s for s in self.parents if s.casefold() == wanted), None)

    def __contains__(self, slug: object) -> bool:
        return isinstance(slug, str) and self.find(slug) is not None

    def is_within(self, slug: str | None, root: str) -> bool:
        """True if ``slug`` is ``root`` itself or any role beneath it."""
        target = self.find(root)
        current = self.find(slug)
        seen: set[str] = set()
        while current is not None and current not in seen:
            if current == target:
                return True
            seen.add(current)
            current = self.parents.get(current)
        return False

    def branch(self, root: str) -> list[str]:
        """``root`` followed by every role beneath it: depth-first, siblings by slug."""
        top = self.find(root)
        if top is None:
            return []
        children: dict[str, list[str]] = {}
        for slug, parent in self.parents.items():
            if parent is not None:
                children.setdefault(parent, []).append(slug)
        ordered: list[str] = []
        seen: set[str] = set()
        stack = [top]
        while stack:
            slug = stack.pop()
            if slug in seen:  # defensive: a parent cycle in bad data
                continue
            seen.add(slug)
            ordered.append(slug)
            stack.extend(sorted(children.get(slug, []), reverse=True))
        return ordered


def device_role_slug(device: Any) -> str | None:
    """A device's role slug (``role`` on NetBox >= 3.6, ``device_role`` before)."""
    role = getattr(device, "role", None) or getattr(device, "device_role", None)
    if role is None:
        return None
    slug = role.get("slug") if isinstance(role, dict) else getattr(role, "slug", None)
    return str(slug) if slug else None


def require_role(nb: Any, slug: str) -> Any:
    """The NetBox device role with ``slug``, or a friendly error if there isn't one."""
    role = nb.dcim.device_roles.get(slug=slug)
    if role is None:
        raise ToolError(
            f"NetBox has no device role with slug {slug!r}",
            fix=f"create a {slug!r} device role in NetBox, or point the matching roles: "
            "entry in bunnyauto.yaml at the slug you use",
        )
    return role


def role_field(nb: Any) -> str:
    """The device field that holds its role: ``role`` on NetBox >= 3.6, else ``device_role``."""
    try:
        major, minor = (int(p) for p in str(nb.version).split(".")[:2])
        return "role" if (major, minor) >= (3, 6) else "device_role"
    except Exception:
        return "role"
