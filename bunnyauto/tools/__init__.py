"""The tool registry.

Each tool is a small object (see :mod:`bunnyauto.tools.base`) registered here by
name. Both entry points — the CLI (:mod:`bunnyauto.cli`) and the hub — build their
command list from ``REGISTRY``, so adding a tool is a one-line change here.
"""

from __future__ import annotations

from bunnyauto.tools import (
    backup,
    create_interfaces,
    health_elaborate,
    health_simple,
    send_command,
    sync_interfaces,
)
from bunnyauto.tools.base import Tool

REGISTRY: dict[str, Tool] = {
    tool.name: tool
    for tool in (
        send_command.TOOL,
        backup.TOOL,
        create_interfaces.TOOL,
        sync_interfaces.TOOL,
        health_simple.TOOL,
        health_elaborate.TOOL,
    )
}

__all__ = ["REGISTRY", "Tool"]
