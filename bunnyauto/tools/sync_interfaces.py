"""``sync-interfaces`` — reconcile Cisco interface VLAN state into NetBox.

Ported from ``netbox_interfaces_update.py``. Collects access/voice/trunk/
link-state/description data, resolves ambiguous voice VLANs via SVI addresses,
and patches only the NetBox interfaces that differ. Never creates VLANs or
interfaces. Plans by default; ``--apply`` writes.
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.errors import ToolError
from bunnyauto.netbox_match import select_tagged_inventory
from bunnyauto.sync import engine
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context


class _ReporterLogHandler(logging.Handler):
    """Forward the engine's ``logging`` output to the run's Reporter."""

    def __init__(self, reporter: Any) -> None:
        super().__init__(logging.INFO)
        self._reporter = reporter

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if record.levelno >= logging.ERROR:
            self._reporter.error(message)
        elif record.levelno >= logging.WARNING:
            self._reporter.warn(message)
        else:
            self._reporter.info(message)


@dataclass(slots=True)
class SyncInterfaces:
    name: str = "sync-interfaces"
    summary: str = "Reconcile Cisco interface VLAN assignments into NetBox"
    writes: bool = True

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "--voice-vlan-model",
            choices=("access", "tagged"),
            default="tagged",
            dest="voice_vlan_model",
            help=(
                "how to model Cisco access ports with a voice VLAN: 'tagged' records "
                "both access and voice VLANs in tagged_vlans when access placement is "
                "clear (default); 'access' keeps NetBox mode access and omits the "
                "tagged voice VLAN"
            ),
        )
        parser.add_argument(
            "--access-vlan-placement",
            choices=("clear", "untagged"),
            default="clear",
            dest="access_vlan_placement",
            help=(
                "how to handle Cisco access VLANs in NetBox: 'clear' removes "
                "untagged_vlan from access ports (default); 'untagged' records the "
                "Cisco access VLAN as NetBox untagged_vlan"
            ),
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        dry_run = not ctx.settings.apply
        handler = _ReporterLogHandler(ctx.reporter)
        engine.LOGGER.addHandler(handler)
        engine.LOGGER.setLevel(logging.INFO)
        try:
            return self._run(ctx, args, dry_run=dry_run)
        finally:
            engine.LOGGER.removeHandler(handler)

    def _run(self, ctx: Context, args: argparse.Namespace, *, dry_run: bool) -> ToolResult:
        nb = ctx.netbox()
        tag = ctx.settings.target_tag

        ctx.reporter.info(
            f"voice-vlan model={args.voice_vlan_model}, "
            f"access-vlan placement={args.access_vlan_placement}, "
            f"{'PLAN (no writes)' if dry_run else 'APPLY'}"
        )

        tagged_devices = list(nb.dcim.devices.filter(tag=tag))
        if not tagged_devices:
            return ToolResult(status=Status.OK, summary=f"no NetBox devices carry tag {tag!r}")

        selected = select_tagged_inventory(ctx.nornir(), tagged_devices)
        if not selected.inventory.hosts:
            raise ToolError("no tagged NetBox devices matched the Nornir inventory")

        vlan_cache = engine.build_vlan_cache(nb)
        ambiguous_vlan_ids = {
            vlan_id for vlan_id, candidates in vlan_cache.by_vid.items() if len(candidates) > 1
        }

        ctx.reporter.step(
            f"collecting interface state from {len(selected.inventory.hosts)} device(s)"
        )
        with ctx.reporter.track(selected, description="sync-interfaces: collect") as tracked:
            results = tracked.run(
                task=engine.collect_device_state,
                name="sync-interfaces: collect",
                ambiguous_vlan_ids=ambiguous_vlan_ids,
                voice_vlan_model=args.voice_vlan_model,
                access_vlan_placement=args.access_vlan_placement,
            )

        collected_devices: list[Any] = []
        failed_hosts: list[str] = []
        for host_name, multi_result in results.items():
            if multi_result.failed:
                failed_hosts.append(host_name)
                ctx.reporter.error(f"{host_name}: collection failed — {_first_error(multi_result)}")
                continue
            collected = engine.find_collected_result(multi_result)
            if collected is None:
                failed_hosts.append(host_name)
                ctx.reporter.error(f"{host_name}: returned no collected interface state")
                continue
            collected_devices.append(collected)

        voice_vlan_ids = {
            vlan_id for collected in collected_devices for vlan_id in collected.vlan_svi_addresses
        }
        engine.load_vlan_prefixes(nb, vlan_cache, voice_vlan_ids)

        changes: list[str] = []
        data: dict[str, Any] = {}
        total_updated = 0
        devices_with_errors: list[str] = []

        for collected in collected_devices:
            try:
                summary = engine.sync_device(
                    nb=nb,
                    collected=collected,
                    vlan_cache=vlan_cache,
                    dry_run=dry_run,
                )
            except Exception as exc:  # engine raises varied NetBox/parse errors
                devices_with_errors.append(collected.inventory_name)
                data[collected.inventory_name] = {"error": str(exc)}
                ctx.reporter.error(f"{collected.inventory_name}: sync failed: {exc}")
                continue

            verb = "would update" if dry_run else "updated"
            prefix = collected.inventory_name
            for change in summary.changes:
                changes.append(f"{prefix}: {change}")
            for warning in summary.warnings:
                ctx.reporter.warn(f"{prefix}: {warning}")
            for error in summary.errors:
                ctx.reporter.error(f"{prefix}: {error}")

            total_updated += summary.updated
            if summary.errors:
                devices_with_errors.append(prefix)
            ctx.reporter.info(
                f"{prefix}: {verb}={summary.updated} unchanged={summary.unchanged} "
                f"skipped={summary.skipped}"
            )
            data[prefix] = {
                "updated": summary.updated,
                "unchanged": summary.unchanged,
                "skipped": summary.skipped,
                "changes": list(summary.changes),
                "warnings": list(summary.warnings),
                "errors": list(summary.errors),
            }

        return _result(
            dry_run=dry_run,
            changes=changes,
            data=data,
            total_updated=total_updated,
            failed_hosts=failed_hosts,
            devices_with_errors=devices_with_errors,
            device_count=len(collected_devices),
        )


def _result(
    *,
    dry_run: bool,
    changes: list[str],
    data: dict[str, Any],
    total_updated: int,
    failed_hosts: list[str],
    devices_with_errors: list[str],
    device_count: int,
) -> ToolResult:
    had_failures = bool(failed_hosts or devices_with_errors)
    some_ok = device_count > len(devices_with_errors)

    if had_failures and some_ok:
        status = Status.PARTIAL
    elif had_failures and not changes and not total_updated:
        status = Status.ERROR
    elif dry_run and total_updated:
        status = Status.DRIFT
    elif not dry_run and total_updated:
        status = Status.CHANGED
    else:
        status = Status.OK

    if dry_run:
        summary = (
            f"{total_updated} interface(s) would change across {device_count} device(s)"
            if total_updated
            else f"NetBox is in sync across {device_count} device(s)"
        )
    else:
        summary = f"updated {total_updated} interface(s) across {device_count} device(s)"
    failures = len(set(failed_hosts) | set(devices_with_errors))
    if failures:
        summary += f" ({failures} device(s) failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


def _first_error(multi_result: Any) -> str:
    for item in reversed(list(multi_result)):
        exc = getattr(item, "exception", None)
        if exc is not None:
            return f"{type(exc).__name__}: {exc}"
    return "collection failed (no exception detail)"


TOOL = SyncInterfaces()
