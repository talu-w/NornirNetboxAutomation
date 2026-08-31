"""What every tool is, and the argument helpers they share.

A tool is not a class hierarchy — it is any object with the four members in the
:class:`Tool` protocol. Keeping it structural means a tool is trivial to write
and to fake in a test.

``Status``, ``ToolResult`` and ``EXIT_CODES`` are re-exported from
:mod:`bunnyauto.result` so tool modules only need one import.
"""

from __future__ import annotations

import argparse
import os
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from bunnyauto.common import env_flag, positive_float
from bunnyauto.result import EXIT_CODES, Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

__all__ = [
    "Tool",
    "Status",
    "ToolResult",
    "EXIT_CODES",
    "COMMON_ARG_DESTS",
    "add_common_arguments",
    "timeouts_from_args",
]

#: argparse ``dest`` names contributed by :func:`add_common_arguments`. The hub
#: skips prompting for these (they all have safe defaults / resolve later).
COMMON_ARG_DESTS = frozenset(
    {
        "config",
        "tag",
        "force_tag",
        "legacy_ssh",
        "connect_timeout",
        "auth_timeout",
        "banner_timeout",
        "read_timeout",
        "delay_factor",
    }
)


@runtime_checkable
class Tool(Protocol):
    """The shape the registry and both entry points rely on."""

    #: CLI subcommand and hub menu key, e.g. ``"send-command"``.
    name: str
    #: One line shown in ``--help`` and the hub menu.
    summary: str
    #: ``True`` ⇒ the tool builds a direct NetBox client and honours ``--apply``.
    writes: bool

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register the tool's own options on its subparser."""
        ...

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        """Do the work and return a structured result."""
        ...


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Options every tool accepts. Used as the subparser ``parents=[...]`` base."""
    selection = parser.add_argument_group("target selection")
    selection.add_argument(
        "--config",
        default=os.getenv("BUNNYAUTO_CONFIG", "config.yaml"),
        help="Nornir base config file (default: config.yaml)",
    )
    selection.add_argument(
        "--tag",
        default=os.getenv("BUNNYAUTO_TAG"),
        help="NetBox tag to target (default: the environment's default_tag)",
    )
    selection.add_argument(
        "--force-tag",
        action="store_true",
        help="allow a --tag that is not the selected environment's default_tag",
    )

    ssh = parser.add_argument_group("SSH tuning")
    ssh.add_argument(
        "--legacy-ssh",
        action="store_true",
        default=env_flag("BUNNYAUTO_LEGACY_SSH"),
        help="enable compatibility for older SSH servers without RSA-SHA2",
    )
    ssh.add_argument("--connect-timeout", type=positive_float, default=None, dest="connect_timeout")
    ssh.add_argument("--auth-timeout", type=positive_float, default=None, dest="auth_timeout")
    ssh.add_argument("--banner-timeout", type=positive_float, default=None, dest="banner_timeout")
    ssh.add_argument("--read-timeout", type=positive_float, default=None, dest="read_timeout")
    ssh.add_argument(
        "--global-delay-factor", type=positive_float, default=None, dest="delay_factor"
    )


def timeouts_from_args(args: argparse.Namespace) -> dict[str, float]:
    """Collect the timeout overrides the user actually passed (skip the unset ones)."""
    keys = ("connect_timeout", "auth_timeout", "banner_timeout", "read_timeout", "delay_factor")
    return {key: float(getattr(args, key)) for key in keys if getattr(args, key, None) is not None}
