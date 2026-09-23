"""``netbox scope`` — which devices each category's role + tag targeting reaches.

Read-only. For the selected network (its tag, plus any ``--region``/``--site``)
it shows, per device-scoped category, the NetBox role branch that category
owns and how many tagged devices sit in it, broken down by role. It also shows
the reason this command exists: every tagged device whose role sits in **no**
category's branch. No tool will ever touch those. After a role-tree
reorganization, a device left on an old role, or never moved under
Wired/Wireless/Security, silently drops out of scope; this is how you find it.

It also checks the role slugs bunnyauto is configured to use (``roles:`` in
bunnyauto.yaml, see :mod:`bunnyauto.categories`). Each category's branch root
must exist, and each leaf role (the WLC/AP roles ``wireless sync`` assigns)
must sit inside its category's branch. A missing or misplaced one is an
``ERROR`` (exit 1), because the tools that rely on it would refuse to run.
Devices outside every branch are warnings only (``OK``, exit 0), since some
tagged devices (a UPS, a server) may legitimately belong to no category.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.categories import CATEGORIES, ROLE_HOMES
from bunnyauto.netbox.roles import device_role_slug
from bunnyauto.tools.base import Status, ToolResult, add_scope_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context

#: Names printed per role before collapsing to "(+N more)"; ``--list`` prints all.
_PREVIEW_NAMES = 8


@dataclass(slots=True)
class ShowScope:
    name: str = "scope"
    summary: str = "Show which devices each category's role + tag targeting reaches"
    writes: bool = False
    category: str = "netbox"
    needs_devices: bool = False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_scope_arguments(parser, role=False)
        parser.add_argument(
            "--list",
            dest="list_devices",
            action="store_true",
            help="list every device by name instead of a short preview per role",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        tree = ctx.role_tree()
        roles = ctx.environment.roles
        scope = ctx.scope()
        limit = None if args.list_devices else _PREVIEW_NAMES

        # -- is the configured role tree actually there? ----------------------
        problems: list[str] = []
        branches: dict[str, str] = {}  # category key -> branch-root slug
        for category in CATEGORIES.values():
            if category.branch is None:
                continue
            slug = roles[category.branch]
            root = tree.find(slug)
            if root is None:
                problems.append(
                    f"{category.key}: NetBox has no device role {slug!r} (the branch root) — "
                    f"create it, or set roles.{category.branch} in bunnyauto.yaml"
                )
            else:
                branches[category.key] = root
        for key, home in ROLE_HOMES.items():
            slug = roles[key]
            if tree.find(slug) is None:
                problems.append(
                    f"{home}: NetBox has no device role {slug!r} — create it, or set "
                    f"roles.{key} in bunnyauto.yaml"
                )
            elif home in branches and not tree.is_within(slug, branches[home]):
                problems.append(
                    f"{home}: device role {slug!r} is not inside the {home} branch "
                    f"({branches[home]!r}) — set its parent in NetBox"
                )

        # -- sort every tagged device into the branch that owns its role ------
        by_category: dict[str, dict[str, list[str]]] = {key: {} for key in branches}
        outside: dict[str, list[str]] = {}
        devices = ctx.target_devices()
        for device in devices:
            role = device_role_slug(device) or "(no role)"
            home = next((key for key, root in branches.items() if tree.is_within(role, root)), None)
            bucket = by_category[home] if home is not None else outside
            bucket.setdefault(role, []).append(str(getattr(device, "name", "") or device.id))

        # -- report ----------------------------------------------------------
        ctx.reporter.step(f"{len(devices)} device(s) in NetBox with {scope.describe()}")
        data_categories: dict[str, Any] = {}
        for category in CATEGORIES.values():
            if category.branch is None:
                continue
            root = branches.get(category.key)
            if root is None:
                data_categories[category.key] = {"branch": roles[category.branch], "exists": False}
                continue
            found = by_category[category.key]
            count = sum(len(names) for names in found.values())
            ctx.reporter.info(
                f"{category.key}: {count} device(s) in role branch {root!r} "
                f"(roles: {', '.join(tree.branch(root))})"
            )
            for role, names in sorted(found.items()):
                ctx.reporter.info(f"    {role} ({len(names)}): {_preview(names, limit)}")
            data_categories[category.key] = {
                "branch": root,
                "exists": True,
                "roles": tree.branch(root),
                "count": count,
                "devices": {role: sorted(names) for role, names in found.items()},
            }

        outside_count = sum(len(names) for names in outside.values())
        if outside_count:
            ctx.reporter.warn(
                f"{outside_count} tagged device(s) have a role in no category's branch — "
                "no tool will touch them:"
            )
            for role, names in sorted(outside.items()):
                ctx.reporter.warn(f"    {role} ({len(names)}): {_preview(names, limit)}")
        for problem in problems:
            ctx.reporter.error(problem)

        counts = " · ".join(
            f"{key} {data_categories[key].get('count', 'n/a')}" for key in data_categories
        )
        summary = f"{counts} · outside every category {outside_count} (tag {scope.tag!r})"
        if problems:
            summary += f" — {len(problems)} role problem(s)"
        return ToolResult(
            status=Status.ERROR if problems else Status.OK,
            summary=summary,
            data={
                "tag": scope.tag,
                "region": scope.region,
                "site": scope.site,
                "categories": data_categories,
                "outside": {role: sorted(names) for role, names in outside.items()},
                "problems": problems,
            },
        )


def _preview(names: list[str], limit: int | None) -> str:
    ordered = sorted(names)
    if limit is None or len(ordered) <= limit:
        return ", ".join(ordered)
    return f"{', '.join(ordered[:limit])} (+{len(ordered) - limit} more)"


TOOL = ShowScope()
