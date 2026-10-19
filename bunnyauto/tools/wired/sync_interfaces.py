"""The sync step of ``wired interfaces``: reconcile Cisco interface VLAN state into NetBox.

Ported from ``netbox_interfaces_update.py`` (and formerly its own tool,
``wired sync-interfaces``). Collects access/voice/trunk/link-state/description
data, resolves ambiguous voice VLANs via SVI addresses, and patches only the
NetBox interfaces that differ. Never creates VLANs or interfaces itself:
:mod:`bunnyauto.tools.wired.interfaces` runs the create step first, so with
``--apply`` the interfaces it just made are synced here in the same run. In a
plan they don't exist yet; the create step passes them in as ``pending`` and
they are listed as awaiting creation rather than reported as missing. Plans by
default; ``--apply`` writes.

**Stacks.** SSH to a stack reports every member's ports, but NetBox keeps each
member as its own device. Ports are matched where the create step puts
them (:mod:`bunnyauto.netbox.stacks`): ``Gi2/0/1`` is updated on ``SwitchA-2``,
under its IOS name or the device type's member-1 name, and never through a
same-named copy left on ``SwitchA-1`` by older runs (reported instead, never
deleted). A change that lands on another member says so in the plan line
(``SwitchA-2/Gi2/0/1 [stack member 2]``), and the summary counts them. A member
with no in-scope NetBox device gets nothing: its ports are reported and the run
is ``PARTIAL``. A stack reached through two hosts is synced once, and a member
host that can't be reached on its own is covered by its stack.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.common import first_error
from bunnyauto.errors import ToolError
from bunnyauto.netbox.devices import inventory_device_id, select_tagged_inventory
from bunnyauto.retry import run_with_retries
from bunnyauto.sync import engine
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments
from bunnyauto.tools.wired.create_interfaces import add_device_argument, select_device

if TYPE_CHECKING:
    from bunnyauto.context import Context
    from bunnyauto.netbox.stacks import Stack


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


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """The sync step's own options (``--device`` is added by :func:`add_device_argument`)."""
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


@dataclass(slots=True)
class SyncInterfaces:
    """The sync step. Not a registered tool: ``wired interfaces`` runs it."""

    name: str = "sync"
    summary: str = "Reconcile Cisco interface VLAN assignments into NetBox"
    writes: bool = True
    category: str = "wired"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Everything this step accepts on its own (used by its tests)."""
        add_common_arguments(parser)
        add_device_argument(parser)
        add_arguments(parser)

    def run(
        self,
        ctx: Context,
        args: argparse.Namespace,
        *,
        pending: Iterable[tuple[int, str]] = (),
        skip_hosts: Iterable[str] = (),
    ) -> ToolResult:
        """Sync the scope's devices.

        ``pending`` is the create step's ``(NetBox device id, port name)`` list of
        interfaces it would create but hasn't (a plan): reported as awaiting
        creation, not as missing. ``skip_hosts`` are hosts the create step
        couldn't reach: not tried again, reported as not synced.
        """
        dry_run = not ctx.settings.apply
        handler = _ReporterLogHandler(ctx.reporter)
        engine.LOGGER.addHandler(handler)
        engine.LOGGER.setLevel(logging.INFO)
        try:
            return self._run(
                ctx,
                args,
                dry_run=dry_run,
                pending=tuple(pending),
                skip_hosts=frozenset(skip_hosts),
            )
        finally:
            engine.LOGGER.removeHandler(handler)

    def _run(
        self,
        ctx: Context,
        args: argparse.Namespace,
        *,
        dry_run: bool,
        pending: tuple[tuple[int, str], ...],
        skip_hosts: frozenset[str],
    ) -> ToolResult:
        nb = ctx.netbox()
        voice_vlan_model = getattr(args, "voice_vlan_model", "tagged")
        access_vlan_placement = getattr(args, "access_vlan_placement", "clear")

        ctx.reporter.info(
            f"voice-vlan model={voice_vlan_model}, "
            f"access-vlan placement={access_vlan_placement}, "
            f"{'PLAN (no writes)' if dry_run else 'APPLY'}"
        )

        tagged_devices = ctx.target_devices()
        targets = select_device(ctx, tagged_devices, getattr(args, "device", None))
        if not targets:
            return ToolResult(
                status=Status.OK,
                summary=f"no NetBox devices in scope ({ctx.scope().describe()})",
            )

        selected = select_tagged_inventory(ctx.nornir(), targets)
        if not selected.inventory.hosts:
            raise ToolError("no tagged NetBox devices matched the Nornir inventory")
        all_hosts = selected.inventory.hosts
        skipped = {name for name in all_hosts if name in skip_hosts}
        if skipped:
            selected = selected.filter(filter_func=lambda host: host.name not in skipped)

        vlan_cache = engine.build_vlan_cache(nb)
        ambiguous_vlan_ids = {
            vlan_id for vlan_id, candidates in vlan_cache.by_vid.items() if len(candidates) > 1
        }

        collected_devices: list[Any] = []
        unreachable: dict[str, str] = {}  # host -> why its collection failed
        for host_name in sorted(skipped):
            unreachable[host_name] = "not reachable over SSH (see the create step) — not synced"

        results: dict[str, Any] = {}
        if len(skipped) < len(all_hosts):
            ctx.reporter.step(
                f"collecting interface state from {len(all_hosts) - len(skipped)} device(s)"
            )
            results = run_with_retries(
                ctx,
                selected,
                description="interfaces (sync): collect",
                name="interfaces (sync): collect",
                task=engine.collect_device_state,
                ambiguous_vlan_ids=ambiguous_vlan_ids,
                voice_vlan_model=voice_vlan_model,
                access_vlan_placement=access_vlan_placement,
            )
        for host_name, multi_result in results.items():
            if multi_result.failed:
                message = first_error(multi_result, "collection failed (no exception detail)")
                unreachable[host_name] = f"collection failed — {message}"
                continue
            collected = engine.find_collected_result(multi_result)
            if collected is None:
                unreachable[host_name] = "returned no collected interface state"
                continue
            collected_devices.append(collected)

        voice_vlan_ids = {
            vlan_id for collected in collected_devices for vlan_id in collected.vlan_svi_addresses
        }
        engine.load_vlan_prefixes(nb, vlan_cache, voice_vlan_ids)

        changes: list[str] = []
        data: dict[str, Any] = {}
        total_updated = routed = blocked_ports = misplaced = duplicates = awaiting = 0
        failed_hosts: list[str] = []
        devices_with_errors: list[str] = []
        stacks_seen: dict[tuple[str, Any], str] = {}  # stack key -> host it was synced through
        covered: dict[int, str] = {}  # NetBox device id -> host its stack was synced through
        scope_label = ctx.scope().describe()

        for collected in collected_devices:
            prefix = collected.inventory_name
            try:
                scope = engine.build_interface_search_scope(
                    nb, collected, tagged_devices, scope_label=scope_label, pending=pending
                )
                if scope.stack.key in stacks_seen:
                    via = stacks_seen[scope.stack.key]
                    ctx.reporter.info(f"{prefix}: same stack as {via} — already synced")
                    data[prefix] = {"same_stack_as": via}
                    duplicates += 1
                    continue
                summary = engine.sync_device(
                    nb=nb,
                    collected=collected,
                    scope=scope,
                    vlan_cache=vlan_cache,
                    dry_run=dry_run,
                )
            except Exception as exc:  # engine raises varied NetBox/parse errors
                devices_with_errors.append(prefix)
                data[prefix] = {"error": str(exc)}
                ctx.reporter.error(f"{prefix}: sync failed: {exc}")
                continue

            stacks_seen[scope.stack.key] = prefix
            for device in scope.stack.devices():
                covered.setdefault(int(device.id), prefix)

            verb = "would update" if dry_run else "updated"
            for change in summary.changes:
                changes.append(f"{prefix}: {change}")
            for warning in summary.warnings:
                ctx.reporter.warn(f"{prefix}: {warning}")
            for error in summary.errors:
                ctx.reporter.error(f"{prefix}: {error}")

            total_updated += summary.updated
            routed += summary.routed
            blocked_ports += sum(len(item.ports) for item in summary.blocked)
            misplaced += len(summary.misplaced)
            awaiting += len(summary.pending)
            if summary.errors:
                devices_with_errors.append(prefix)
            waiting = f" awaiting-creation={len(summary.pending)}" if summary.pending else ""
            ctx.reporter.info(
                f"{prefix}: {verb}={summary.updated} unchanged={summary.unchanged} "
                f"skipped={summary.skipped}{waiting}"
            )
            data[prefix] = _device_data(summary, scope.stack)

        for host_name, message in unreachable.items():
            via = covered.get(inventory_device_id(all_hosts[host_name]))
            if via is not None and via != host_name:
                # A stack member without its own management IP: expected, and covered.
                ctx.reporter.info(
                    f"{host_name}: not reachable on its own ({message}) — "
                    f"its interfaces were synced through {via}, the same stack"
                )
                data[host_name] = {"synced_through": via}
                continue
            failed_hosts.append(host_name)
            data[host_name] = {"error": message}
            ctx.reporter.error(f"{host_name}: {message}")

        return _result(
            dry_run=dry_run,
            changes=changes,
            data=data,
            total_updated=total_updated,
            routed=routed,
            blocked_ports=blocked_ports,
            misplaced=misplaced,
            failed_hosts=failed_hosts,
            devices_with_errors=devices_with_errors,
            device_count=len(collected_devices) - duplicates,
            awaiting=awaiting,
        )


def _device_data(summary: engine.SyncSummary, stack: Stack) -> dict[str, Any]:
    """One synced host's ``--json`` entry; stack keys only when there's a stack."""
    entry: dict[str, Any] = {
        "updated": summary.updated,
        "unchanged": summary.unchanged,
        "skipped": summary.skipped,
        "changes": list(summary.changes),
        "warnings": list(summary.warnings),
        "errors": list(summary.errors),
    }
    if stack.is_stack:
        entry["stack"] = {
            "source": stack.source,
            "members": {n: str(device.name) for n, device in sorted(stack.members.items())},
            "unresolved": dict(sorted(stack.unresolved.items())),
        }
    if summary.routed:
        entry["routed"] = summary.routed
    if summary.blocked:
        entry["blocked"] = [
            {"member": item.member, "reason": item.reason, "ports": list(item.ports)}
            for item in summary.blocked
        ]
    if summary.misplaced:
        entry["misplaced"] = dict(summary.misplaced)
    if summary.pending:
        entry["awaiting_creation"] = list(summary.pending)
    return entry


def _result(
    *,
    dry_run: bool,
    changes: list[str],
    data: dict[str, Any],
    total_updated: int,
    routed: int,
    blocked_ports: int,
    misplaced: int,
    failed_hosts: list[str],
    devices_with_errors: list[str],
    device_count: int,
    awaiting: int = 0,
) -> ToolResult:
    had_failures = bool(failed_hosts or devices_with_errors)
    some_ok = device_count > len(devices_with_errors)

    if had_failures and some_ok:
        status = Status.PARTIAL
    elif had_failures and not changes and not total_updated:
        status = Status.ERROR
    elif blocked_ports:
        status = Status.PARTIAL
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
    if routed:
        summary += (
            f", {routed} of them on another stack member's NetBox device "
            "(lines marked [stack member N])"
        )
    if blocked_ports:
        summary += (
            f"; {blocked_ports} stack port(s) skipped — their member has no NetBox device in scope"
        )
    if misplaced:
        summary += (
            f"; {misplaced} interface(s) sitting on the wrong stack member left as-is, "
            "no longer synced"
        )
    if awaiting:
        summary += f"; {awaiting} new interface(s) will be synced once created"
    failures = len(set(failed_hosts) | set(devices_with_errors))
    if failures:
        summary += f" ({failures} device(s) failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


STEP = SyncInterfaces()
