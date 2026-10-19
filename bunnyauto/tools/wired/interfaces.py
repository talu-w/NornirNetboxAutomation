"""``wired interfaces`` — create the interfaces NetBox is missing and sync all of them.

One tool for what used to be two (``wired create-interfaces``, then
``wired sync-interfaces``). It runs two steps in order, against the same scope
and the same SSH sessions (Nornir keeps each host's session open between the
steps, and the run closes them at the end):

1. **Create** (:mod:`bunnyauto.tools.wired.create_interfaces`): create the
   interfaces NetBox is missing, correct wrong interface types and stack member
   numbers, and record transceivers as inventory items.
2. **Sync** (:mod:`bunnyauto.tools.wired.sync_interfaces`): reconcile every
   interface's 802.1Q mode, access/voice/trunk VLANs, enabled state and
   description with what the device reports.

Plans by default; ``--apply`` writes. With ``--apply`` the sync step runs after
the create step has written, so a new interface gets its VLANs, state and
description in the same run. In a plan nothing has been created yet, so the
sync step can't diff those interfaces; it lists them as awaiting creation
instead of reporting them as missing. A host the create step could not reach
is not tried again by the sync step.

``--only create`` / ``--only sync`` runs one step by itself, as the old tools
did. Every option of both steps is accepted, and ``--device`` limits both.

The result's ``changes`` hold the create step's lines, then the sync step's.
``data`` holds each step's own data under ``"create"`` and ``"sync"``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING

from bunnyauto.tools.base import Status, ToolResult, add_common_arguments
from bunnyauto.tools.wired import create_interfaces, sync_interfaces

if TYPE_CHECKING:
    from bunnyauto.context import Context

#: ``--only`` choices, in the order the steps run.
STEPS = ("create", "sync")


@dataclass(slots=True)
class Interfaces:
    name: str = "interfaces"
    summary: str = (
        "Create the interfaces NetBox is missing (types, stack numbers, optics) "
        "and sync their VLANs, state and descriptions"
    )
    writes: bool = True
    category: str = "wired"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        create_interfaces.add_device_argument(parser)
        parser.add_argument(
            "--only",
            choices=STEPS,
            default=None,
            help=(
                "run one step by itself: 'create' (missing interfaces, types, stack "
                "numbers, optics) or 'sync' (VLANs, enabled state, descriptions); "
                "default: both, create first"
            ),
        )
        create = parser.add_argument_group("create step")
        create_interfaces.add_arguments(create)
        sync = parser.add_argument_group("sync step")
        sync_interfaces.add_arguments(sync)

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        only = getattr(args, "only", None)
        if only == "create":
            return create_interfaces.STEP.run(ctx, args)
        if only == "sync":
            return sync_interfaces.STEP.run(ctx, args)

        ctx.reporter.step("step 1/2 — create: missing interfaces, types, stack numbers, optics")
        created = create_interfaces.STEP.execute(ctx, args)
        ctx.reporter.info(f"create: {created.result.summary}")

        ctx.reporter.step("step 2/2 — sync: VLANs, enabled state, descriptions")
        synced = sync_interfaces.STEP.run(
            ctx, args, pending=created.pending, skip_hosts=created.unreachable
        )
        ctx.reporter.info(f"sync: {synced.summary}")
        return combine(created.result, synced)


def combine(created: ToolResult, synced: ToolResult) -> ToolResult:
    """One result for the two steps: the more serious status, both summaries and changes."""
    return ToolResult(
        status=_status(created.status, synced.status),
        summary=f"create: {created.summary} | sync: {synced.summary}",
        changes=[*created.changes, *synced.changes],
        artifacts=[*created.artifacts, *synced.artifacts],
        data={"create": created.data, "sync": synced.data},
    )


def _status(first: Status, second: Status) -> Status:
    """The combined status of the two steps.

    Both failing is an ``ERROR``; one failing while the other got somewhere is
    ``PARTIAL``. Otherwise written changes win over planned ones, and planned
    ones over none: ``CHANGED`` > ``DRIFT`` > ``OK``.
    """
    statuses = {first, second}
    if statuses == {Status.ERROR}:
        return Status.ERROR
    if Status.ERROR in statuses or Status.PARTIAL in statuses:
        return Status.PARTIAL
    for status in (Status.CHANGED, Status.DRIFT):
        if status in statuses:
            return status
    return Status.OK


TOOL = Interfaces()
