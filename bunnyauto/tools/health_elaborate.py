"""``health-elaborate`` — the engineer-facing network-health workbook.

Ported from ``network_elaborate_health_report.py``. Read-only. Same collection
core as ``health-simple`` plus interface error counters, EtherChannel member
state, port-security, and control-plane/DAI/DHCP-snooping drop counters; renders
an Engineer Health overview and an Issue Details table.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from bunnyauto.common import filter_by_tag
from bunnyauto.errors import ToolError
from bunnyauto.health.elaborate_collect import collect_device_health, extract_records
from bunnyauto.health.elaborate_workbook import create_elaborate_health_workbook
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context


def _resolve_output(raw: str | None) -> Path:
    if raw:
        path = Path(raw).expanduser()
    else:
        date = datetime.now().astimezone().strftime("%Y-%m-%d")
        path = Path(f"Network_Elaborate_Health_Report_{date}.xlsx")
    if path.suffix.casefold() != ".xlsx":
        raise ToolError("--output must end in .xlsx")
    return path


@dataclass(slots=True)
class HealthElaborate:
    name: str = "health-elaborate"
    summary: str = "Engineer network-health workbook (Excel): interfaces, EtherChannel, security"
    writes: bool = False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "--output",
            default=None,
            help="Excel output path (default: ./Network_Elaborate_Health_Report_<date>.xlsx)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        output_path = _resolve_output(args.output)
        targets = filter_by_tag(ctx.nornir(), ctx.settings.target_tag)
        hosts = targets.inventory.hosts
        if not hosts:
            return ToolResult(
                status=Status.OK,
                summary=f"no devices carry tag {ctx.settings.target_tag!r}",
                data={"tag": ctx.settings.target_tag, "devices": 0},
            )

        ctx.reporter.step(f"collecting engineer health from {len(hosts)} device(s)")
        results = targets.run(
            name="health-elaborate: collect",
            task=collect_device_health,
            read_timeout=ctx.settings.read_timeout,
        )
        records = extract_records(results, hosts)
        create_elaborate_health_workbook(records, ctx.settings.target_tag, output_path)

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
                f"engineer health workbook for {len(records)} device(s) "
                f"({reachable} reachable) → {output_path}"
            ),
            artifacts=[output_path],
            data={
                "tag": ctx.settings.target_tag,
                "output": str(output_path),
                "devices": len(records),
                "reachable": reachable,
                "records": records,
            },
        )


TOOL = HealthElaborate()
