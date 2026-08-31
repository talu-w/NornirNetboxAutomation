"""``backup`` — save running-config, environment, and interface state per device.

Merges the old ``perform_backup.py`` and ``perform_backup_safe.py`` (D2). The
config is redacted by default; ``--raw`` writes it verbatim. Files land under
``<output-dir>/<year>/<month>/<day>/<hostname>/``.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from bunnyauto.backup.collect import HostBackup, collect_device_backup
from bunnyauto.common import filter_by_tag
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from nornir.core.task import MultiResult

    from bunnyauto.context import Context

_DEFAULT_ROOT = os.getenv("BUNNYAUTO_BACKUP_DIR", "./network-backups")


@dataclass(slots=True)
class Backup:
    name: str = "backup"
    summary: str = "Save running-config, environment, and interface state per device"
    writes: bool = False  # writes to local disk, not NetBox

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "--raw",
            action="store_true",
            help="write the running-config verbatim (default: redact secrets)",
        )
        parser.add_argument(
            "--output-dir",
            dest="output_dir",
            default=_DEFAULT_ROOT,
            help=f"backup root; a dated subtree is created under it (default: {_DEFAULT_ROOT})",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        sanitize = not args.raw
        targets = filter_by_tag(ctx.nornir(), ctx.settings.target_tag)
        hosts = list(targets.inventory.hosts)
        if not hosts:
            return ToolResult(
                status=Status.OK,
                summary=f"no devices carry tag {ctx.settings.target_tag!r}",
                data={"tag": ctx.settings.target_tag, "devices": {}},
            )

        now = datetime.now()
        dated_dir = (
            Path(args.output_dir).expanduser()
            / now.strftime("%Y")
            / now.strftime("%m")
            / now.strftime("%d")
        )
        note = "" if sanitize else "  [RAW — secrets are NOT redacted]"
        ctx.reporter.step(f"backing up {len(hosts)} device(s) to {dated_dir}{note}")

        run_result = targets.run(
            name="bunnyauto backup",
            task=collect_device_backup,
            output_dir=dated_dir,
            sanitize=sanitize,
            read_timeout=ctx.settings.read_timeout,
        )

        devices: dict[str, dict[str, object]] = {}
        artifacts: list[Path] = []
        failures: list[str] = []
        for host, multi in run_result.items():
            record = _record(multi)
            if record is None or record.error or multi.failed:
                message = record.error if record and record.error else _first_error(multi)
                devices[host] = {"ok": False, "error": message}
                failures.append(host)
                ctx.reporter.error(f"{host}: {message}")
                continue

            devices[host] = {
                "ok": True,
                "sanitized": record.sanitized,
                "config": str(record.config_path),
                "environment": str(record.environment_path),
                "workbook": str(record.workbook_path),
                "warnings": list(record.warnings),
            }
            if record.directory is not None:
                artifacts.append(record.directory)
            for warning in record.warnings:
                ctx.reporter.warn(f"{host}: {warning}")
            ctx.reporter.info(f"{host}: saved to {record.directory}")

        succeeded = len(hosts) - len(failures)
        if failures and succeeded:
            status = Status.PARTIAL
        elif failures:
            status = Status.ERROR
        else:
            status = Status.OK

        return ToolResult(
            status=status,
            summary=(
                f"backed up {succeeded}/{len(hosts)} device(s) to {dated_dir}"
                f"{' (raw)' if args.raw else ''}"
            ),
            artifacts=artifacts,
            data={
                "tag": ctx.settings.target_tag,
                "output_dir": str(dated_dir),
                "sanitized": sanitize,
                "devices": devices,
            },
        )


def _record(multi: MultiResult) -> HostBackup | None:
    for item in multi:
        if isinstance(item.result, HostBackup):
            return item.result
    return None


def _first_error(multi: MultiResult) -> str:
    for item in reversed(list(multi)):
        exc = getattr(item, "exception", None)
        if exc is not None:
            return f"{type(exc).__name__}: {exc}"
    return "backup failed"


TOOL = Backup()
