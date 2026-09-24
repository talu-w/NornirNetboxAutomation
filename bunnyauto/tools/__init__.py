"""The tool registry, grouped by category.

Each tool is a small object (see :mod:`bunnyauto.tools.base`) whose ``category``
attribute names its :data:`~bunnyauto.categories.CATEGORIES` entry. Both entry
points build their menus and subcommands from ``REGISTRY``
(``{category: {tool name: tool}}``, in display order), so adding a tool is a
one-line change to ``_TOOLS``. The tool module lives in the matching
``tools/<category>/`` package.
"""

from __future__ import annotations

from collections.abc import Iterable

from bunnyauto.categories import CATEGORIES
from bunnyauto.tools.base import Tool
from bunnyauto.tools.netbox import import_device_type
from bunnyauto.tools.netbox import scope as netbox_scope
from bunnyauto.tools.security import subnet_check
from bunnyauto.tools.wired import backup, create_interfaces, health, send_command, sync_interfaces
from bunnyauto.tools.wireless import sync as wireless_sync

_TOOLS: tuple[Tool, ...] = (
    send_command.TOOL,
    backup.TOOL,
    create_interfaces.TOOL,
    sync_interfaces.TOOL,
    health.TOOL,
    wireless_sync.TOOL,
    subnet_check.TOOL,
    import_device_type.TOOL,
    netbox_scope.TOOL,
)


def build_registry(tools: Iterable[Tool]) -> dict[str, dict[str, Tool]]:
    """Group tools by category, in :data:`CATEGORIES` order; empty categories are dropped."""
    registry: dict[str, dict[str, Tool]] = {key: {} for key in CATEGORIES}
    for tool in tools:
        if tool.category not in registry:
            raise ValueError(f"tool {tool.name!r} names unknown category {tool.category!r}")
        if tool.name in registry[tool.category]:
            raise ValueError(f"two {tool.category!r} tools are named {tool.name!r}")
        registry[tool.category][tool.name] = tool
    return {key: tools for key, tools in registry.items() if tools}


REGISTRY: dict[str, dict[str, Tool]] = build_registry(_TOOLS)

__all__ = ["REGISTRY", "Tool", "build_registry"]
