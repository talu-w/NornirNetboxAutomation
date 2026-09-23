"""Which NetBox devices a run may touch. Every device query is built here.

Three independent narrowings, all applied by NetBox's own device filters:

* **tag**, which network. It must be the environment's ``default_tag`` unless
  ``--force-tag`` (the cross-wiring guard in :func:`bunnyauto.context.build_context`).
* **role**, which category. Each category owns one branch of the device-role
  tree (:mod:`bunnyauto.categories`). NetBox >= 4.3's ``?role=`` filter is
  hierarchical (the same shape as ``?region=``), so the branch root's slug
  alone selects every device whose role sits anywhere beneath it, with no
  tree-walking here. ``--role`` narrows to a sub-branch, but only one *inside*
  the category's branch, so a wired tool can't be pointed at firewalls.
* **region / site**, where.

The roles are checked against NetBox's role tree before any device query goes
out. A missing branch role or an out-of-branch ``--role`` fails with a clear
:class:`~bunnyauto.errors.RoleScopeError` instead of silently matching nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from bunnyauto.categories import CATEGORIES
from bunnyauto.errors import RoleScopeError

if TYPE_CHECKING:
    from bunnyauto.context import Settings
    from bunnyauto.netbox.roles import RoleTree


@dataclass(frozen=True, slots=True)
class Scope:
    """The resolved narrowing for one run. ``role`` is ``None`` for an unscoped category."""

    tag: str
    #: The effective role slug: the branch root, or a ``--role`` inside it.
    role: str | None = None
    #: The category's branch-root slug (for messages; equals ``role`` unless narrowed).
    branch: str | None = None
    region: str | None = None
    site: str | None = None

    def location_filters(self) -> dict[str, str]:
        """``role``/``region``/``site`` NetBox device filters — everything but the tag.

        The Nornir inventory is pulled with these; the tag is applied to it
        afterwards, so "nothing in this role/region/site" (an error — probably a
        wrong slug or unassigned roles) stays distinguishable from "nothing
        carries the tag" (fine — nothing to do).
        """
        filters: dict[str, str] = {}
        if self.role:
            filters["role"] = self.role
        if self.region:
            filters["region"] = self.region
        if self.site:
            filters["site"] = self.site
        return filters

    def device_filters(self) -> dict[str, str]:
        """Every narrowing, tag included — for a direct NetBox device query."""
        return {**self.location_filters(), "tag": self.tag}

    def describe(self) -> str:
        """``"tag 'nornirtest', role 'wired-network' (and its child roles), site 'hq'"``."""
        parts = [f"tag {self.tag!r}"]
        if self.role:
            parts.append(f"role {self.role!r} (and its child roles)")
        if self.region:
            parts.append(f"region {self.region!r}")
        if self.site:
            parts.append(f"site {self.site!r}")
        return ", ".join(parts)


def resolve_scope(settings: Settings, role_tree: Callable[[], RoleTree]) -> Scope:
    """Validate the settings' branch / ``--role`` against NetBox and return the ``Scope``.

    ``role_tree`` is only called for a role-scoped category, so a tool in an
    unscoped category never makes the extra NetBox request.
    """
    branch = settings.branch_role
    if branch is None:
        return Scope(tag=settings.target_tag, region=settings.region, site=settings.site)

    tree = role_tree()
    category = settings.category or "this"
    root = tree.find(branch)
    if root is None:
        raise RoleScopeError(
            f"NetBox has no device role {branch!r} — the root of the {category!r} "
            "category's role branch, so its tools have no devices to work on",
            fix=f"create a {branch!r} device role in NetBox (with your {category} roles "
            f"beneath it), or set roles.{_role_key(settings)} in bunnyauto.yaml to your slug",
        )

    role = root
    if settings.role:
        requested = tree.find(settings.role)
        inside = ", ".join(tree.branch(root))
        if requested is None:
            raise RoleScopeError(
                f"NetBox has no device role {settings.role!r}",
                fix=f"use a role in the {category} branch: {inside}",
            )
        if not tree.is_within(requested, root):
            raise RoleScopeError(
                f"role {requested!r} is outside the {category} branch ({root!r}). Refusing "
                f"so a {category} tool never touches another category's devices.",
                fix=f"use a role in the {category} branch: {inside}",
            )
        role = requested

    return Scope(
        tag=settings.target_tag,
        role=role,
        branch=root,
        region=settings.region,
        site=settings.site,
    )


def _role_key(settings: Settings) -> str:
    """The ``roles:`` key in bunnyauto.yaml that names this category's branch root."""
    category = CATEGORIES.get(settings.category or "")
    return (category.branch if category else None) or "<category>"
