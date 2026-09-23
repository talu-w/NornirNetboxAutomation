"""``wired health`` — the network-health report, in one of two depths.

Merges the old ``health-simple`` and ``health-elaborate`` tools (they were
near-identical shells over the same collect/record/status machinery). The first
argument picks the report:

* ``simple`` — the management scorecard (``health.collect`` +
  ``simple_workbook``): firmware, interface usage, CPU, environment.
* ``elaborate`` — the engineer workbook (``health.elaborate_collect`` +
  ``elaborate_workbook``): the above plus interface error counters, EtherChannel
  member state, port-security, and control-plane/DAI/DHCP-snooping drops.

Read-only either way. Output goes to ``--output`` (an exact path), else a dated
file in ``--output-dir``, else the report's own ``$BUNNYAUTO_HEALTH_SIMPLE_DIR`` /
``$BUNNYAUTO_HEALTH_ELABORATE_DIR``, else the shared ``$BUNNYAUTO_HEALTH_DIR``,
else the working directory.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from bunnyauto.errors import ToolError
from bunnyauto.health import collect as _simple_collect
from bunnyauto.health import elaborate_collect as _elaborate_collect
from bunnyauto.health.elaborate_workbook import create_elaborate_health_workbook
from bunnyauto.health.simple_workbook import create_health_workbook
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from types import ModuleType

    from bunnyauto.context import Context


@dataclass(frozen=True, slots=True)
class _Report:
    """One report flavour: where to collect from and how to render it."""

    label: str  # human phrase for the result summary
    stub: str  # default filename stem (a ``_<date>.xlsx`` is appended)
    dir_env: str  # this report's own output-directory env var
    collect_mod: ModuleType  # exposes ``collect_device_health`` + ``extract_records``
    workbook: Callable[[list[dict], str, Path], object]


#: shared fallback, used when a report's own ``dir_env`` is unset
SHARED_DIR_ENV = "BUNNYAUTO_HEALTH_DIR"

REPORTS: dict[str, _Report] = {
    "simple": _Report(
        label="health scorecard",
        stub="Network_Health_Report",
        dir_env="BUNNYAUTO_HEALTH_SIMPLE_DIR",
        collect_mod=_simple_collect,
        workbook=create_health_workbook,
    ),
    "elaborate": _Report(
        label="engineer health workbook",
        stub="Network_Elaborate_Health_Report",
        dir_env="BUNNYAUTO_HEALTH_ELABORATE_DIR",
        collect_mod=_elaborate_collect,
        workbook=create_elaborate_health_workbook,
    ),
}


def _resolve_output(args: argparse.Namespace, report: _Report) -> Path:
    if getattr(args, "output", None):
        path = Path(args.output).expanduser()
    else:
        date = datetime.now().astimezone().strftime("%Y-%m-%d")
        directory = (
            getattr(args, "output_dir", None)
            or os.getenv(report.dir_env)
            or os.getenv(SHARED_DIR_ENV)
        )
        base = Path(directory).expanduser() if directory else Path()
        path = base / f"{report.stub}_{date}.xlsx"
    if path.suffix.casefold() != ".xlsx":
        raise ToolError("--output must end in .xlsx")
    return path


@dataclass(slots=True)
class Health:
    name: str = "health"
    summary: str = "Create Network Health Reports - Reports are written in Excel format"
    writes: bool = False
    category: str = "wired"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "report",
            choices=tuple(REPORTS),
            help=(
                "Type either: 'simple' (Basic Device Health / Interface usage) "
                "or 'elaborate' (Detailed Health Report)"
            ),
        )
        parser.add_argument(
            "--output",
            default=None,
            help="exact Excel output path (overrides --output-dir)",
        )
        parser.add_argument(
            "--output-dir",
            dest="output_dir",
            default=None,
            help=(
                "directory for the dated report file. If unset, falls back to "
                "$BUNNYAUTO_HEALTH_SIMPLE_DIR / $BUNNYAUTO_HEALTH_ELABORATE_DIR, "
                "then $BUNNYAUTO_HEALTH_DIR, then the working directory"
            ),
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        try:
            report = REPORTS[args.report]
        except KeyError:
            raise ToolError(
                f"unknown report {args.report!r} — choose 'simple' or 'elaborate'"
            ) from None

        output_path = _resolve_output(args, report)
        targets = ctx.target_hosts()
        hosts = targets.inventory.hosts
        if not hosts:
            return ToolResult(
                status=Status.OK,
                summary=f"no devices in scope ({ctx.scope().describe()})",
                data={"report": args.report, "tag": ctx.settings.target_tag, "devices": 0},
            )

        ctx.reporter.step(f"collecting {report.label} from {len(hosts)} device(s)")
        description = f"health-{args.report}: collect"
        with ctx.reporter.track(targets, description=description) as tracked:
            results = tracked.run(
                name=description,
                task=report.collect_mod.collect_device_health,
                read_timeout=ctx.settings.read_timeout,
            )
        records = report.collect_mod.extract_records(results, hosts)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report.workbook(records, ctx.settings.target_tag, output_path)

        reachable = sum(bool(record.get("reachable")) for record in records)
        status = Status.OK if reachable == len(records) else Status.PARTIAL
        for record in records:
            if not record.get("reachable"):
                ctx.reporter.warn(
                    f"{record['hostname']}: unreachable — in the report with NetBox data only"
                )
        ctx.reporter.success(f"wrote {output_path}")

        return ToolResult(
            status=status,
            summary=(
                f"{report.label} for {len(records)} device(s) "
                f"({reachable} reachable) → {output_path}"
            ),
            artifacts=[output_path],
            data={
                "report": args.report,
                "tag": ctx.settings.target_tag,
                "output": str(output_path),
                "devices": len(records),
                "reachable": reachable,
                "records": records,
            },
        )


TOOL = Health()
