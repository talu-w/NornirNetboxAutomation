"""``send-command`` — run one show command on every tagged device.

This is the reference tool: the smallest thing that exercises the whole
contract (declare args, take a Context, return a ToolResult) without any
NetBox writes. It replaces the top-level ``send_command.py`` script.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING

from nornir.core.task import Task
from nornir_netmiko.tasks import netmiko_send_command

from bunnyauto.common import filter_by_tag
from bunnyauto.errors import ToolError
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from nornir.core.task import MultiResult

    from bunnyauto.context import Context

# Leading tokens that mean the command changes device state or configuration.
# send-command is for show-style output only; these need --config-mode.
_STATE_CHANGING = (
    "configure",
    "conf t",
    "conf ",
    "config ",
    "write",
    "wr ",
    "wr\t",
    "copy ",
    "reload",
    "erase",
    "delete",
    "format ",
    "boot ",
    "archive ",
    "rename ",
    "license ",
    "no ",
)


@dataclass(slots=True)
class SendCommand:
    name: str = "send-command"
    summary: str = "Run one show command on every device carrying the tag"
    writes: bool = False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument("command", help="the command to run, e.g. 'show version'")
        parser.add_argument(
            "--config-mode",
            action="store_true",
            help="run even if the command looks like it changes device state",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        command = str(args.command).strip()
        if not command:
            raise ToolError("no command was given")
        if not args.config_mode and _is_state_changing(command):
            raise ToolError(
                f"{command!r} looks like it changes device state — send-command is "
                f"for show commands only",
                fix="re-run with --config-mode if you are sure",
            )

        targets = filter_by_tag(ctx.nornir(), ctx.settings.target_tag)
        host_count = len(targets.inventory.hosts)
        if host_count == 0:
            return ToolResult(
                status=Status.OK,
                summary=f"no devices carry tag {ctx.settings.target_tag!r}",
                data={"tag": ctx.settings.target_tag, "command": command, "devices": {}},
            )

        ctx.reporter.step(f"running {command!r} on {host_count} device(s)")
        with ctx.reporter.track(targets, description=f"send-command: {command}") as tracked:
            run_result = tracked.run(
                task=_send,
                name=f"send-command: {command}",
                command=command,
                read_timeout=ctx.settings.read_timeout,
            )

        devices: dict[str, dict[str, object]] = {}
        failures: list[str] = []
        for host, multi in run_result.items():
            if multi.failed:
                message = _first_error(multi)
                devices[host] = {"failed": True, "output": message}
                failures.append(host)
                ctx.reporter.error(f"{host}: {message}")
            else:
                output = multi[-1].result or ""
                devices[host] = {"failed": False, "output": output}
                ctx.reporter.info(f"\n===== {host} =====\n{output}")

        succeeded = host_count - len(failures)
        if failures and succeeded:
            status = Status.PARTIAL
        elif failures:
            status = Status.ERROR
        else:
            status = Status.OK

        return ToolResult(
            status=status,
            summary=(
                f"ran {command!r} on {host_count} device(s) — "
                f"{succeeded} ok, {len(failures)} failed"
            ),
            data={"tag": ctx.settings.target_tag, "command": command, "devices": devices},
        )


def _send(task: Task, command: str, read_timeout: float) -> None:
    task.run(
        task=netmiko_send_command,
        name=f"{command} on {task.host.name}",
        command_string=command,
        read_timeout=read_timeout,
    )


def _is_state_changing(command: str) -> bool:
    head = command.strip().casefold()
    return any(head == token.strip() or head.startswith(token) for token in _STATE_CHANGING)


def _first_error(multi: MultiResult) -> str:
    for item in reversed(list(multi)):
        exc = getattr(item, "exception", None)
        if exc is not None:
            return f"{type(exc).__name__}: {exc}"
    return "command failed"


TOOL = SendCommand()
