"""``wireless enrich`` — pull AP platform + LLDP-neighbor cabling from each WLC.

Unlike ``wireless sync`` (which talks to the Conductor's own aggregated view
to create/tag devices), this tool logs into each **WLC directly** — the
Conductor's aggregation doesn't carry the per-AP data this needs (see the
design discussion this was built from: a Conductor's REST API is a config/
licensing/summary plane, not a live replica of each WLC's own runtime
database). It assumes the APs and WLCs it touches already exist in NetBox
(created by ``wireless sync``, or by hand) — this tool never creates a
device, only enriches ones that are already there.

Targeting is NetBox-only, through the same scope every tool uses
(:mod:`bunnyauto.scope`): devices in the wireless role branch carrying the
run's tag (plus any ``--region``/``--site``), then **exactly** the
``wireless-controller`` role. Exactly, not "and beneath": NetBox's role filter
is hierarchical, and the Wireless Access Point role sits *under* Wireless
Controller, so a plain ``role=wireless-controller`` query returns every AP too
— and this tool would try to log into each AP as if it were a WLC. A WLC's IP
comes from its own NetBox ``primary_ip4`` — no separate URL list to maintain in
``bunnyauto.yaml``, NetBox stays the only source of truth. Auth is the shared
device login (``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``), same as ``wireless
sync``. REST only, via the same client class the Conductor itself uses (see
``bunnyauto/aruba/conductor.py`` — every WLC in the AOS 8 fleet runs the
identical ``/v1/api/login`` service).

For each AP a WLC reports (``show ap database long``):

* Its software/version string (e.g. ``"8.10.0.5"``) is matched (**never
  created**) against an existing NetBox **Platform** like ``"AOS 8"`` — the
  major version is extracted and tried as ``"AOS <major>"`` / ``"ArubaOS
  <major>"`` against the same token-containment matching ``wireless sync``
  uses for device types (see ``_aos_version_candidates``). No recognized
  version field, or no matching Platform, is reported and left alone — never
  a guess.
* Its wired LLDP neighbor (``show ap lldp neighbors`` — command name *and*
  field names confirmed against real AOS 8 hardware) is turned into a NetBox
  cable by :func:`bunnyauto.netbox.cabling.plan_neighbor_cable`, shared with
  any future wired cable sync: the neighbor's reported names (``Chassis
  Name/ID`` and fallbacks — one may be a MAC, depending on how *that* switch
  advertises itself) are tried in turn against NetBox, with a stack member's
  ``<hostname>-<member>`` name tried first when the port id carries a member
  number (a virtual stack shares one chassis identity, but each member is its
  own NetBox device — never collapsed to one shared name, since different APs
  can be homed to different members of the same stack); the reported port
  (``Port ID`` / ``Port Desc``) is matched to that device's actual interface,
  tolerating vendor abbreviations like ``Gi1/0/24``. If both resolve and
  neither interface already has a **Cable**, one is created between the AP's
  first wired interface and the matched switch port. An interface that already
  has a cable is **never touched** — reported as an informational note, not a
  failure, since deliberately not touching existing physical wiring beats
  risking a silent mis-correction.

A WLC that returns no AP data at all (no APs, or none with LLDP neighbors) is
reported as an informational note, not an error — not every WLC in the fleet
necessarily has APs attached. A WLC with no NetBox ``primary_ip4``, or an
unreachable/rejecting one, does not abort the run — it is skipped and
reported, and the rest of the fleet is still processed.

Plans by default; ``--apply`` writes. TLS verification is on by default per
WLC unless ``--wlc-insecure``.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.aruba.inventory import WirelessDevice, parse_ap_database
from bunnyauto.aruba.lldp import LldpNeighbor, parse_lldp_neighbors
from bunnyauto.common import env_flag
from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.netbox.cabling import CablePlan, create_cable, plan_neighbor_cable
from bunnyauto.netbox.roles import device_role_slug, require_role
from bunnyauto.netbox.tokens import match_record
from bunnyauto.tools.base import Status, ToolResult, add_scope_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context

_DEFAULT_WLC_PORT = 4343
_LEADING_MAJOR_VERSION = re.compile(r"^(\d+)")


@dataclass(slots=True)
class _PlatformPlan:
    action: str  # "none" | "in-sync" | "set" | "blocked"
    platform_id: int = 0
    platform_name: str = ""
    note: str = ""


@dataclass(slots=True)
class WirelessEnrich:
    name: str = "enrich"
    summary: str = "Enrich NetBox APs with platform + LLDP-neighbor cabling, pulled from their WLCs"
    writes: bool = True
    category: str = "wireless"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_scope_arguments(parser)
        parser.add_argument(
            "--wlc-port",
            dest="wlc_port",
            type=int,
            default=_DEFAULT_WLC_PORT,
            help=f"TCP port each WLC's REST API listens on (default: {_DEFAULT_WLC_PORT})",
        )
        parser.add_argument(
            "--wlc-insecure",
            dest="wlc_insecure",
            action="store_true",
            default=env_flag("BUNNYAUTO_WLC_INSECURE"),
            help="do not verify each WLC's TLS certificate (default: verify)",
        )
        parser.add_argument(
            "--device",
            default=None,
            help="only NetBox WLCs whose name contains this string (for testing)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        if not (ctx.creds.username and ctx.creds.password):  # pragma: no cover - preflight guards
            raise ArubaError(
                "NORNIR_USERNAME / NORNIR_PASSWORD are needed to log in to each WLC",
                fix="export NORNIR_USERNAME='<user>' NORNIR_PASSWORD='<password>'",
            )

        nb = ctx.netbox()
        apply = ctx.settings.apply

        wlc_slug = ctx.environment.roles["wireless-controller"]
        require_role(nb, wlc_slug)
        scope = ctx.scope()
        if scope.branch is not None and not ctx.role_tree().is_within(wlc_slug, scope.branch):
            raise ToolError(
                f"device role {wlc_slug!r} is not inside the wireless branch ({scope.branch!r})",
                fix=f"set {wlc_slug!r}'s parent to {scope.branch!r} in NetBox",
            )

        # Exact role, not the hierarchical branch: APs sit *under* the WLC role.
        wlcs = [
            d
            for d in ctx.target_devices()
            if (device_role_slug(d) or "").casefold() == wlc_slug.casefold()
        ]
        if args.device:
            needle = args.device.casefold()
            wlcs = [d for d in wlcs if needle in str(d.name).casefold()]
        if not wlcs:
            return ToolResult(
                status=Status.OK,
                summary=f"no NetBox devices with role {wlc_slug!r} in scope ({scope.describe()})",
            )

        platforms = list(nb.dcim.platforms.all())
        all_devices = list(nb.dcim.devices.all())
        by_name = {str(d.name).casefold(): d for d in all_devices if getattr(d, "name", "")}

        verify = not args.wlc_insecure
        changes: list[str] = []
        data: dict[str, Any] = {}
        platform_applied = platform_planned = 0
        cables_applied = cables_planned = 0
        failures: list[str] = []
        blocked: list[str] = []
        already_cabled: list[str] = []
        empty_wlcs: list[str] = []
        interface_cache: dict[int, list[Any]] = {}

        for wlc in wlcs:
            wlc_name = str(wlc.name)
            primary_ip = getattr(wlc, "primary_ip4", None)
            if primary_ip is None:
                blocked.append(wlc_name)
                data[wlc_name] = {"error": "no primary IPv4 set in NetBox — cannot connect"}
                ctx.reporter.warn(f"{wlc_name}: no primary IPv4 in NetBox — skipped")
                continue

            address = str(primary_ip.address).split("/")[0]
            base_url = f"https://{address}:{args.wlc_port}"

            try:
                with (
                    ctx.reporter.spinner(f"{wlc_name}: querying {base_url}..."),
                    ArubaConductorClient(
                        base_url, ctx.creds.username, ctx.creds.password, verify=verify
                    ) as client,
                ):
                    aps = parse_ap_database(client.ap_database())
                    lldp_rows = parse_lldp_neighbors(client.ap_lldp_neighbors())
            except ArubaError as exc:
                failures.append(wlc_name)
                data[wlc_name] = {"error": str(exc)}
                ctx.reporter.error(f"{wlc_name}: {exc}")
                continue

            if not aps:
                empty_wlcs.append(wlc_name)
                data[wlc_name] = {"note": "no AP/LLDP data returned from this WLC"}
                ctx.reporter.info(f"{wlc_name}: no AP/LLDP data returned")
                continue

            lldp_by_ap = {row.ap_name.casefold(): row for row in lldp_rows if row.ap_name}
            wlc_data: dict[str, Any] = {}

            for ap in aps:
                ap_device = by_name.get(ap.name.casefold())
                entry: dict[str, Any] = {}
                if ap_device is None:
                    blocked.append(f"{ap.name}:not-in-netbox")
                    entry["note"] = "AP not found in NetBox — run wireless sync first"
                    ctx.reporter.warn(f"{ap.name}: not found in NetBox — run wireless sync first")
                    wlc_data[ap.name] = entry
                    continue

                platform_plan = _plan_platform(ap, ap_device, platforms)
                self._apply_platform(ctx, apply, ap, ap_device, platform_plan, entry, changes)
                if platform_plan.action == "set":
                    if "platform_error" in entry:
                        failures.append(f"{ap.name}:platform")
                    elif apply:
                        platform_applied += 1
                    else:
                        platform_planned += 1
                elif platform_plan.action == "blocked":
                    blocked.append(f"{ap.name}:platform")

                lldp = lldp_by_ap.get(ap.name.casefold())
                cable_plan = _plan_cable(nb, interface_cache, ap_device, lldp, all_devices)
                self._apply_cable(ctx, nb, apply, ap, cable_plan, entry, changes)
                if cable_plan.action == "create":
                    if "cable_error" in entry:
                        failures.append(f"{ap.name}:cable")
                    elif apply:
                        cables_applied += 1
                    else:
                        cables_planned += 1
                elif cable_plan.action == "blocked":
                    blocked.append(f"{ap.name}:cable")
                elif cable_plan.action == "conflict":
                    already_cabled.append(f"{ap.name}:cable")

                wlc_data[ap.name] = entry

            data[wlc_name] = wlc_data

        return _result(
            apply=apply,
            changes=changes,
            data=data,
            platform_applied=platform_applied,
            platform_planned=platform_planned,
            cables_applied=cables_applied,
            cables_planned=cables_planned,
            failures=failures,
            blocked=blocked,
            already_cabled=already_cabled,
            empty_wlcs=empty_wlcs,
            total_wlcs=len(wlcs),
        )

    # ------------------------------------------------------------------

    def _apply_platform(
        self,
        ctx: Context,
        apply: bool,
        ap: WirelessDevice,
        ap_device: Any,
        plan: _PlatformPlan,
        entry: dict[str, Any],
        changes: list[str],
    ) -> None:
        if plan.note:
            entry["platform_note"] = plan.note
        if plan.action == "in-sync":
            entry["platform"] = plan.platform_name
        elif plan.action == "blocked":
            ctx.reporter.warn(f"{ap.name}: {plan.note}")
        elif plan.action == "set":
            verb = "set" if apply else "would set"
            changes.append(f"{ap.name}: {verb} platform to {plan.platform_name!r}")
            if apply:
                try:
                    ap_device.update({"platform": plan.platform_id})
                    entry["platform"] = plan.platform_name
                    ctx.reporter.success(f"{ap.name}: platform set to {plan.platform_name!r}")
                except Exception as exc:  # pynetbox RequestError etc.
                    entry["platform_error"] = str(exc)
                    ctx.reporter.error(f"{ap.name}: platform update failed — {exc}")

    def _apply_cable(
        self,
        ctx: Context,
        nb: Any,
        apply: bool,
        ap: WirelessDevice,
        plan: CablePlan,
        entry: dict[str, Any],
        changes: list[str],
    ) -> None:
        if plan.note:
            entry["cable_note"] = plan.note
        if plan.action == "blocked":
            ctx.reporter.warn(f"{ap.name}: {plan.note}")
        elif plan.action == "conflict":
            ctx.reporter.info(f"{ap.name}: {plan.note}")
        elif plan.action == "create":
            verb = "create" if apply else "would create"
            changes.append(
                f"{ap.name}:{plan.a_interface_name} <-> "
                f"{plan.b_device_name}:{plan.b_interface_name}: {verb} cable"
            )
            if apply:
                try:
                    create_cable(nb, plan)
                    entry["cable"] = f"{plan.b_device_name}:{plan.b_interface_name}"
                    ctx.reporter.success(
                        f"{ap.name}: cabled to {plan.b_device_name}:{plan.b_interface_name}"
                    )
                except Exception as exc:  # pynetbox RequestError etc.
                    entry["cable_error"] = str(exc)
                    ctx.reporter.error(f"{ap.name}: cable create failed — {exc}")


# ----------------------------------------------------------------------


def _aos_version_candidates(raw: str) -> list[str]:
    """Build platform-name candidates from a raw AOS version string.

    Aruba reports an over-specific build string (``"8.10.0.5"``); the NetBox
    Platform it should match is a coarse family name like ``"AOS 8"`` or
    ``"ArubaOS 8"``. Matching the raw string wholesale against
    :func:`~bunnyauto.netbox.tokens.match_record`'s substring containment can
    never work — the raw string is *longer and more specific* than the platform
    name, the reverse of device-type matching's usual shape (a terse candidate
    found inside a longer type string). Matching on the bare major-version digit
    alone (``"8"``) would be too promiscuous against NetBox's full, unscoped
    platform list, so every candidate here is prefixed with a known AOS family
    name to keep the containment check specific.
    """
    match = _LEADING_MAJOR_VERSION.match(raw.strip())
    if not match:
        return []
    major = match.group(1)
    return [f"AOS {major}", f"AOS-{major}", f"ArubaOS {major}", f"ArubaOS-{major}"]


def _plan_platform(ap: WirelessDevice, ap_device: Any, platforms: list[Any]) -> _PlatformPlan:
    if not ap.os_version:
        return _PlatformPlan(
            action="none", note="no software/version field recognized from this WLC"
        )

    candidates = _aos_version_candidates(ap.os_version)
    platform = match_record(candidates, platforms, key_fields=("name", "slug"))
    if platform is None:
        return _PlatformPlan(
            action="blocked", note=f"no NetBox platform matches reported version {ap.os_version!r}"
        )

    current = getattr(ap_device, "platform", None)
    current_id = getattr(current, "id", None)
    if current_id is not None and int(current_id) == int(platform.id):
        return _PlatformPlan(
            action="in-sync", platform_id=int(platform.id), platform_name=str(platform.name)
        )
    return _PlatformPlan(
        action="set", platform_id=int(platform.id), platform_name=str(platform.name)
    )


def _plan_cable(
    nb: Any,
    interface_cache: dict[int, list[Any]],
    ap_device: Any,
    lldp: LldpNeighbor | None,
    all_devices: list[Any],
) -> CablePlan:
    if lldp is None:
        return CablePlan(action="none", note="no LLDP neighbor reported for this AP")
    return plan_neighbor_cable(
        nb,
        local_device=ap_device,
        neighbor_names=lldp.remote_system_candidates,
        neighbor_ports=lldp.remote_port_candidates,
        devices=all_devices,
        interface_cache=interface_cache,
    )


def _result(
    *,
    apply: bool,
    changes: list[str],
    data: dict[str, Any],
    platform_applied: int,
    platform_planned: int,
    cables_applied: int,
    cables_planned: int,
    failures: list[str],
    blocked: list[str],
    already_cabled: list[str],
    empty_wlcs: list[str],
    total_wlcs: int,
) -> ToolResult:
    progressed = bool(platform_applied or platform_planned or cables_applied or cables_planned)
    if failures or blocked:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and (platform_applied or cables_applied):
        status = Status.CHANGED
    elif platform_planned or cables_planned:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"set platform on {platform_applied} AP(s), created {cables_applied} cable(s)"
    elif platform_planned or cables_planned:
        summary = (
            f"{platform_planned} platform update(s), {cables_planned} cable(s) to create "
            "— run with --apply"
        )
    else:
        summary = f"NetBox already matches what {total_wlcs} WLC(s) reported"
    if blocked:
        summary += f" ({len(blocked)} skipped — see notes)"
    if already_cabled:
        summary += f" ({len(already_cabled)} already cabled elsewhere)"
    if failures:
        summary += f" ({len(failures)} failed)"
    if empty_wlcs:
        summary += f" ({len(empty_wlcs)} WLC(s) had no data)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


TOOL = WirelessEnrich()
