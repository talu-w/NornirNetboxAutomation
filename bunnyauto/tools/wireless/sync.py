"""``wireless sync`` — bring NetBox in line with the wireless network, in one pass.

Merged 2026-09-24 from the old ``wireless sync`` (create and tag devices from the
Conductor) and ``wireless enrich`` (platform and cabling from each WLC), so an
AP's device record, IP, platform and cables are all built from the same run's
live data.

**Where the data comes from**

* The **Conductor** (``show switches`` + ``show ap database long``) says which
  WLCs and APs exist: name, serial, model, IP. Each is matched to NetBox by
  serial, then name.
* **Each WLC, directly** (``show ap database long`` + ``show ap lldp
  neighbors``), because the Conductor's aggregated view doesn't carry this
  per-AP runtime data. Per AP: its software version, and its live wired uplinks,
  meaning which of the AP's own ports (the LLDP ``Interface`` column, e.g.
  ``eth1``) connects to which switch port. A WLC is reached at its NetBox
  primary IPv4, or, if NetBox doesn't have one yet, at the IP the Conductor
  reports for it. Every WLC runs the same REST service as the Conductor
  (``--wlc-port``, default 4343).

**Per device**

* **Missing from NetBox: created.** The device type is matched from the Aruba
  model by token containment (:mod:`bunnyauto.netbox.tokens`), the site from the
  hostname prefix (or ``--default-site``), and the device gets the
  environment's tag. The role (slugs from the environment's ``roles:``): a WLC
  gets ``wireless-controller``, which must exist. An AP gets
  ``wireless-access-point``, or, when NetBox has no such role, is filed under
  the wireless branch root (``wireless-network``, "Wireless Network"). With
  neither, the run fails before anything is written. A role the tool would use
  that sits outside the wireless branch is refused: devices given it would be
  invisible to role-scoped tools.
* **Already in NetBox: updated** to what the network reports. The
  environment's tag is added and a changed serial is corrected (a swapped AP
  keeps its name); for APs, the role, platform, IP and cables below. An AP
  whose role isn't ``wireless-access-point`` is **moved to it**; when NetBox has
  no such role, the AP's current role is only noted. A WLC's role, and every
  device's site, device type and name, are never changed. A name that differs
  from the Conductor's (the device was matched by serial) is only noted, since
  an unprovisioned AP reports its MAC as its name.
* **Platform** (APs): the reported version (``"8.10.0.5"``) is matched, never
  created, against a NetBox Platform like ``"AOS 8"``.
* **IP** (every new device, and every AP): the reported IP, with the mask and
  VRF of the most specific NetBox Prefix containing it, as the device's primary
  IP (:mod:`bunnyauto.netbox.ipam`), on the port the AP reports as its LLDP
  uplink. An IP NetBox has on another of the AP's interfaces is **moved**: an AP
  NetBox has on ``E0`` that reports ``eth1`` ends up on ``E1``. Without LLDP
  data an IP is never moved; a new device's goes on its first wired interface
  and an existing one stays where it is. A WLC's IP is only set when this tool
  creates the WLC: an existing WLC's primary IPv4 is the address this tool logs
  into, so Conductor data never changes it. An IP no Prefix contains is not
  created (no Prefix or IP Range is ever created).
* **Cables** (APs): one per LLDP neighbor, from the AP's reported port to the
  switch port (:mod:`bunnyauto.netbox.cabling`, stack members resolved by
  ``<host>-<member>``). An interface that already has a cable is **never
  touched**, only noted. The note says so when the switch port is cabled to a
  different port on the same AP; moving that cable is left to a person.

**Outcome.** Each device's line, and the run, is one of:

* red, ``ERROR`` (exit 1): a device could not be created (no device-type or
  site match, or NetBox refused it);
* yellow, ``PARTIAL`` (exit 2): the device exists or was created, but something
  else couldn't be done: an IP (including "no containing Prefix"), a
  platform, a cable, a tag or serial update, or a WLC that couldn't be queried;
* green: everything the network reported is in NetBox: ``CHANGED`` (20) after
  ``--apply``, ``DRIFT`` (10) for a plan with changes, ``OK`` (0) when in sync.

These are informational only, never a failure: an AP with no LLDP neighbor, no
recognized version field, an existing cable left alone, a WLC role outside the
wireless branch, and an AP role noted because NetBox has no AP role.

Nothing is ever deleted, and no device type, site, role or platform is ever
created. Plans by default; ``--apply`` writes. Auth is the shared device login
(``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``). TLS is verified unless
``--aruba-insecure`` / ``--wlc-insecure``.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.aruba.inventory import WirelessDevice, parse_ap_database, parse_switches
from bunnyauto.aruba.lldp import LldpNeighbor, parse_lldp_neighbors
from bunnyauto.aruba.sitematch import Site, match_site
from bunnyauto.common import env_flag, normalize_tags
from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.netbox.cabling import create_cable, plan_neighbor_cable
from bunnyauto.netbox.devices import add_tag
from bunnyauto.netbox.ipam import (
    IpPlan,
    Prefix,
    apply_ip_plan,
    find_prefix,
    load_prefixes,
    plan_primary_ip,
)
from bunnyauto.netbox.records import related_id
from bunnyauto.netbox.roles import RoleTree, device_role_slug, require_role, role_field
from bunnyauto.netbox.tokens import match_record
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

#: Which ``roles:`` key names the role each kind of device is created with.
_ROLE_KEY_BY_KIND = {"ap": "wireless-access-point", "wlc": "wireless-controller"}
_DEFAULT_WLC_PORT = 4343
_LEADING_MAJOR_VERSION = re.compile(r"^(\d+)")
_NO_PREFIX = (
    "IP address could not be added/assigned at this time due to lack of an "
    "established prefix/IP range within NetBox."
)
_WLC_UNREAD = "could not read its APs' LLDP/version data"


@dataclass(slots=True)
class _Match:
    """A Conductor device next to NetBox, before anything is written."""

    device: WirelessDevice
    action: str  # "create" | "update" | "blocked"
    existing: Any = None
    site: Site | None = None
    device_type: Any = None
    reason: str = ""  # why it can't be created


@dataclass(slots=True)
class _Live:
    """What the WLCs reported about their APs, keyed by casefolded AP name."""

    uplinks: dict[str, list[LldpNeighbor]] = field(default_factory=dict)
    versions: dict[str, str] = field(default_factory=dict)
    #: WLC name -> why its AP data couldn't be read.
    failed: dict[str, str] = field(default_factory=dict)
    #: WLC name -> what querying it returned (the ``--json`` view).
    wlcs: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class _Report:
    """One device's outcome: red (``failed``), yellow (``issues``), else green."""

    name: str
    kind: str
    action: str  # "create" | "update" | "blocked"
    changes: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    failed: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.failed:
            return "failed"
        return "partial" if self.issues else "ok"


@dataclass(slots=True)
class _Run:
    """What every device in one run shares."""

    ctx: Context
    nb: Any
    apply: bool
    tag_slug: str
    new_status: str  # --status for created devices
    tree: RoleTree
    branch: str | None
    live: _Live
    devices: list[Any]  # every NetBox device: the candidates for a cable's far end
    prefixes: list[Prefix]
    platforms: list[Any]
    templates_by_type: dict[int, list[Any]]
    role_by_kind: dict[str, Any]  # the role each kind of device is created with
    role_key: str
    #: The AP role every AP belongs in, and its slug; ``ap_role`` is ``None``
    #: when NetBox has no such role.
    ap_role: Any
    ap_role_slug: str
    interface_cache: dict[int, list[Any]] = field(default_factory=dict)


@dataclass(slots=True)
class WirelessSync:
    name: str = "sync"
    summary: str = (
        "Create/update NetBox WLCs and APs from the Conductor and each WLC: "
        "IP on the AP's live uplink, platform, LLDP cabling"
    )
    writes: bool = True
    category: str = "wireless"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--aruba-url",
            dest="aruba_url",
            default=None,
            help="Aruba Conductor REST API base URL (default: the environment's aruba_url)",
        )
        parser.add_argument(
            "--aruba-insecure",
            dest="aruba_insecure",
            action="store_true",
            default=env_flag("BUNNYAUTO_ARUBA_INSECURE"),
            help="do not verify the Conductor's TLS certificate (default: verify)",
        )
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
            "--default-site",
            dest="default_site",
            default=None,
            help="NetBox site slug to use when a hostname matches no site",
        )
        parser.add_argument(
            "--only",
            choices=("all", "aps", "wlcs"),
            default="all",
            help="limit the run to access points or controllers (default: all)",
        )
        parser.add_argument(
            "--device",
            default=None,
            help="only Conductor devices whose name contains this string (for testing)",
        )
        parser.add_argument(
            "--status",
            default="active",
            help="NetBox status for newly created devices (default: active)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        aruba_url = (args.aruba_url or ctx.environment.aruba_url or "").strip().rstrip("/")
        if not aruba_url:
            raise ArubaError(
                f"no Aruba Conductor URL for environment {ctx.environment.name!r}",
                fix="add 'aruba_url' to that environment in bunnyauto.yaml, or pass --aruba-url",
            )
        if not (ctx.creds.username and ctx.creds.password):  # pragma: no cover - preflight guards
            raise ArubaError(
                "NORNIR_USERNAME / NORNIR_PASSWORD are needed to log in to the Conductor and WLCs",
                fix="export NORNIR_USERNAME='<user>' NORNIR_PASSWORD='<password>'",
            )

        nb = ctx.netbox()
        apply = ctx.settings.apply
        tag_slug = ctx.settings.target_tag
        branch = ctx.scope().branch  # validates the wireless branch root exists
        tree = ctx.role_tree()

        sites = [
            Site(slug=str(s.slug), id=int(s.id), name=str(s.name)) for s in nb.dcim.sites.all()
        ]
        default_site: Site | None = None
        if args.default_site:
            wanted = args.default_site.strip().casefold()
            default_site = next((s for s in sites if s.slug.casefold() == wanted), None)
            if default_site is None:
                raise ToolError(f"--default-site {args.default_site!r} is not a NetBox site slug")

        device_types = list(nb.dcim.device_types.all())
        devices = list(nb.dcim.devices.all())
        by_serial = {str(d.serial).casefold(): d for d in devices if getattr(d, "serial", "")}
        by_name = {str(d.name).casefold(): d for d in devices if getattr(d, "name", "")}

        # -- 1. the Conductor: which devices exist ---------------------------
        ctx.reporter.step(f"querying the Aruba Conductor at {aruba_url}")
        with (
            ctx.reporter.spinner(f"querying the Aruba Conductor at {aruba_url}..."),
            ArubaConductorClient(
                aruba_url, ctx.creds.username, ctx.creds.password, verify=not args.aruba_insecure
            ) as client,
        ):
            switches = parse_switches(client.switches())
            aps = parse_ap_database(client.ap_database()) if args.only != "wlcs" else []

        wireless = [*(switches if args.only != "aps" else []), *aps]
        if args.device:
            needle = args.device.casefold()
            wireless = [d for d in wireless if needle in d.name.casefold()]
        if not wireless:
            return ToolResult(
                status=Status.OK, summary="the Conductor returned no matching devices"
            )
        n_wlc = sum(d.kind == "wlc" for d in wireless)
        ctx.reporter.info(
            f"Conductor reported {len(wireless)} device(s) "
            f"({n_wlc} WLC, {len(wireless) - n_wlc} AP)"
        )

        # -- 2. each WLC: what its APs run and are cabled to -----------------
        live = _Live()
        if any(d.kind == "ap" for d in wireless):
            live = _query_wlcs(ctx, args, switches, by_serial, by_name)

        # -- 3. compare with NetBox, then act on each device ------------------
        matches = [
            _classify(d, by_serial, by_name, device_types, sites, default_site) for d in wireless
        ]

        # The AP role is looked up whenever APs are in the run: new APs are created
        # with it and existing APs are moved to it. When NetBox has no such role,
        # new APs are filed under the wireless branch root instead (it must exist:
        # ctx.scope() above already refused to run without it) and existing APs
        # only get a note. The WLC role is required only if a WLC is created.
        roles = ctx.environment.roles
        has_aps = any(d.kind == "ap" for d in wireless)
        ap_role_slug = roles[_ROLE_KEY_BY_KIND["ap"]]
        ap_role = _find_role_in_branch(nb, tree, ap_role_slug, branch) if has_aps else None
        role_by_kind: dict[str, Any] = {}
        if any(m.action == "create" and m.device.kind == "wlc" for m in matches):
            wlc_slug = roles[_ROLE_KEY_BY_KIND["wlc"]]
            role_by_kind["wlc"] = _require_role_in_branch(nb, tree, wlc_slug, branch)
        if any(m.action == "create" and m.device.kind == "ap" for m in matches):
            role_by_kind["ap"] = ap_role or require_role(nb, roles["wireless"])
            if ap_role is None:
                ctx.reporter.info(
                    f"NetBox has no {ap_role_slug!r} device role — new APs are filed under "
                    f"{str(role_by_kind['ap'].slug)!r}"
                )

        run_changes: list[str] = []
        needs_tag = any(
            m.action == "create" or (m.action == "update" and not _has_tag(m.existing, tag_slug))
            for m in matches
        )
        if needs_tag and nb.extras.tags.get(slug=tag_slug) is None:
            if apply:
                nb.extras.tags.create({"name": tag_slug, "slug": tag_slug})
                run_changes.append(f"create NetBox tag {tag_slug!r}")
            else:
                run_changes.append(f"would create NetBox tag {tag_slug!r}")

        creating = any(m.action == "create" for m in matches)
        run = _Run(
            ctx=ctx,
            nb=nb,
            apply=apply,
            tag_slug=tag_slug,
            new_status=args.status,
            tree=tree,
            branch=branch,
            live=live,
            devices=devices,
            prefixes=load_prefixes(nb) if any(d.ip for d in wireless) else [],
            platforms=list(nb.dcim.platforms.all()) if has_aps else [],
            # Plan mode previews a new device's interfaces from its device type's
            # template: NetBox creates exactly those along with the device.
            templates_by_type=_load_interface_templates(nb) if creating and not apply else {},
            role_by_kind=role_by_kind,
            role_key=role_field(nb),
            ap_role=ap_role,
            ap_role_slug=ap_role_slug,
        )

        reports: list[_Report] = []
        for match in matches:
            report = _sync_device(run, match)
            reports.append(report)
            _say(run, report)
        shown = {r.name for r in reports}
        for wlc_name, error in live.failed.items():
            if wlc_name not in shown:
                ctx.reporter.warn(f"{wlc_name}: {_WLC_UNREAD} — {error}")

        return _result(run, reports, run_changes)


# ----------------------------------------------------------------------
# gathering
# ----------------------------------------------------------------------


def _query_wlcs(
    ctx: Context,
    args: argparse.Namespace,
    switches: list[WirelessDevice],
    by_serial: dict[str, Any],
    by_name: dict[str, Any],
) -> _Live:
    """Log into every WLC the Conductor reports and collect its APs' version + LLDP data.

    A WLC that can't be reached (or has no address to reach) is recorded in
    ``failed`` and the rest are still queried.
    """
    live = _Live()
    if not switches:
        ctx.reporter.info("the Conductor reported no WLCs — no LLDP or version data for the APs")
        return live

    ctx.reporter.step(f"querying {len(switches)} WLC(s) for their APs' LLDP neighbors")
    for wlc in switches:
        existing = _existing(wlc, by_serial, by_name)
        primary = getattr(existing, "primary_ip4", None) if existing is not None else None
        address = str(primary.address).split("/")[0] if primary is not None else wlc.ip
        if not address:
            error = "no address: NetBox has no primary IPv4 for it and the Conductor reported none"
            live.failed[wlc.name] = error
            live.wlcs[wlc.name] = {"error": error}
            continue

        url = f"https://{address}:{args.wlc_port}"
        try:
            with (
                ctx.reporter.spinner(f"{wlc.name}: querying {url}..."),
                ArubaConductorClient(
                    url, ctx.creds.username, ctx.creds.password, verify=not args.wlc_insecure
                ) as client,
            ):
                wlc_aps = parse_ap_database(client.ap_database())
                rows = parse_lldp_neighbors(client.ap_lldp_neighbors())
        except ArubaError as exc:
            live.failed[wlc.name] = str(exc)
            live.wlcs[wlc.name] = {"url": url, "error": str(exc)}
            continue

        live.wlcs[wlc.name] = {"url": url, "aps": len(wlc_aps), "lldp_neighbors": len(rows)}
        for ap in wlc_aps:
            if ap.os_version:
                live.versions.setdefault(ap.name.casefold(), ap.os_version)
        for row in rows:
            seen = live.uplinks.setdefault(row.ap_name.casefold(), [])
            if row not in seen:  # an AP both a WLC and its standby report
                seen.append(row)
    return live


def _existing(d: WirelessDevice, by_serial: dict[str, Any], by_name: dict[str, Any]) -> Any:
    if d.serial and d.serial.casefold() in by_serial:
        return by_serial[d.serial.casefold()]
    if d.name and d.name.casefold() in by_name:
        return by_name[d.name.casefold()]
    return None


def _classify(
    d: WirelessDevice,
    by_serial: dict[str, Any],
    by_name: dict[str, Any],
    device_types: list[Any],
    sites: list[Site],
    default_site: Site | None,
) -> _Match:
    existing = _existing(d, by_serial, by_name)
    if existing is not None:
        return _Match(d, "update", existing=existing)

    device_type = match_record(d.model_candidates, device_types)
    if device_type is None:
        return _Match(d, "blocked", reason=f"no NetBox device type matches model {d.model!r}")
    site = match_site(d.name, sites) or default_site
    if site is None:
        return _Match(
            d,
            "blocked",
            device_type=device_type,
            reason=f"hostname {d.name!r} matched no NetBox site (pass --default-site)",
        )
    return _Match(d, "create", site=site, device_type=device_type)


# ----------------------------------------------------------------------
# one device
# ----------------------------------------------------------------------


def _sync_device(run: _Run, match: _Match) -> _Report:
    d = match.device
    report = _Report(name=d.name, kind=d.kind, action=match.action)
    report.detail.update(serial=d.serial, ip=d.ip)
    if match.action == "blocked":
        report.failed = match.reason
        return report

    if match.action == "create":
        device = _create(run, match, report)
        if device is None:
            return report
    else:
        device = match.existing
        _update_identity(run, match, report)

    if d.kind == "wlc" and d.name in run.live.failed:
        report.issues.append(f"{_WLC_UNREAD} — {run.live.failed[d.name]}")

    uplinks = run.live.uplinks.get(d.name.casefold(), []) if d.kind == "ap" else []
    interfaces: list[Any] | None = None
    if d.kind == "ap":
        _sync_platform(run, d, device, report)
    if d.ip and (match.action == "create" or d.kind == "ap"):
        interfaces = _sync_ip(run, match, device, _interfaces(run, match, device), uplinks, report)
    if d.kind == "ap":
        _sync_cables(run, match, device, interfaces, uplinks, report)
    return report


def _create(run: _Run, match: _Match, report: _Report) -> Any:
    """Create the device (or, in plan mode, return a preview of it). ``None`` if NetBox refused."""
    d = match.device
    assert match.site is not None and match.device_type is not None
    model = str(getattr(match.device_type, "model", ""))
    role = run.role_by_kind[d.kind]
    report.detail.update(site=match.site.slug, device_type=model, role=str(role.slug))
    what = (
        f"create {d.kind.upper()} in site {match.site.slug!r} (type {model!r}, "
        f"role {str(role.slug)!r}) tagged {run.tag_slug!r}"
    )
    if d.kind == "ap" and run.ap_role is None:
        report.notes.append(
            f"filed under role {str(role.slug)!r} — NetBox has no {run.ap_role_slug!r} role"
        )
    if not run.apply:
        report.changes.append(f"would {what}")
        return SimpleNamespace(id=0, name=d.name, platform=None, primary_ip4=None)

    body: dict[str, Any] = {
        "name": d.name,
        "device_type": int(match.device_type.id),
        run.role_key: int(role.id),
        "site": match.site.id,
        "status": run.new_status,
        "tags": [{"slug": run.tag_slug}],
    }
    if d.serial:
        body["serial"] = d.serial
    try:
        device = run.nb.dcim.devices.create(body)
    except Exception as exc:  # pynetbox RequestError etc.
        report.failed = f"NetBox refused it: {exc}"
        return None
    report.changes.append(what)
    return device


def _update_identity(run: _Run, match: _Match, report: _Report) -> None:
    """Tag, serial and (APs) role of a device NetBox already has. Name, site and type are kept."""
    d, device = match.device, match.existing
    if d.kind == "ap":
        _sync_ap_role(run, device, report)
    else:
        role_note = _role_note(device, run.tree, run.branch)
        if role_note:
            report.notes.append(role_note)
    nb_name = str(getattr(device, "name", "") or "")
    if nb_name and nb_name.casefold() != d.name.casefold():
        report.notes.append(
            f"NetBox calls it {nb_name!r} (matched by serial); the Conductor reports "
            f"{d.name!r} — name left as is"
        )

    if not _has_tag(device, run.tag_slug):
        _change(run, report, f"add tag {run.tag_slug!r}", lambda: add_tag(device, run.tag_slug))

    current = str(getattr(device, "serial", "") or "")
    if d.serial and current.casefold() != d.serial.casefold():
        was = f" (was {current!r})" if current else ""
        what = f"set serial to {d.serial!r}{was}"
        _change(run, report, what, lambda: device.update({"serial": d.serial}))


def _sync_ap_role(run: _Run, device: Any, report: _Report) -> None:
    """An existing AP belongs in the AP role: moved there, or noted when NetBox has none."""
    current = device_role_slug(device)
    if run.ap_role is None:
        shown = repr(current) if current else "not set"
        report.notes.append(
            f"role is {shown} — NetBox has no {run.ap_role_slug!r} role to move it to"
        )
        return
    wanted = str(run.ap_role.slug)
    if current is not None and current.casefold() == wanted.casefold():
        return
    was = f" (was {current!r})" if current else ""
    role_id = int(run.ap_role.id)
    _change(
        run,
        report,
        f"set role to {wanted!r}{was}",
        lambda: device.update({run.role_key: role_id}),
    )


def _sync_platform(run: _Run, d: WirelessDevice, device: Any, report: _Report) -> None:
    version = run.live.versions.get(d.name.casefold()) or d.os_version
    if not version:
        report.detail["platform_note"] = "no software/version field recognized from the WLC"
        return
    platform = match_record(
        _aos_version_candidates(version), run.platforms, key_fields=("name", "slug")
    )
    if platform is None:
        report.issues.append(f"platform: no NetBox platform matches reported version {version!r}")
        return
    report.detail["platform"] = str(platform.name)
    if related_id(getattr(device, "platform", None)) == int(platform.id):
        return
    _change(
        run,
        report,
        f"set platform to {platform.name!r}",
        lambda: device.update({"platform": int(platform.id)}),
    )


def _sync_ip(
    run: _Run,
    match: _Match,
    device: Any,
    interfaces: list[Any],
    uplinks: list[LldpNeighbor],
    report: _Report,
) -> list[Any]:
    """Put the reported IP where it belongs. Returns the interfaces, plus any it had to add."""
    d = match.device
    try:
        addr = ipaddress.ip_address(d.ip)
    except ValueError:
        report.issues.append(f"IP: the Conductor reported an unparseable IP address {d.ip!r}")
        return interfaces
    prefix = find_prefix(addr, run.prefixes)
    if prefix is None:
        report.issues.append(f"IP {addr}: {_NO_PREFIX}")
        return interfaces

    cidr = f"{addr}/{prefix.network.prefixlen}"
    primary_field = "primary_ip6" if addr.version == 6 else "primary_ip4"
    plan = plan_primary_ip(
        address=cidr,
        vrf_id=prefix.vrf_id,
        interfaces=interfaces,
        live_ports=[row.local_port for row in uplinks if row.local_port],
        existing_ips=list(run.nb.ipam.ip_addresses.filter(address=cidr)),
        primary_ip_id=related_id(getattr(device, primary_field, None)),
    )
    report.detail["ip_cidr"] = cidr
    report.detail["ip_interface"] = plan.interface_name
    report.detail["ip_interface_source"] = plan.source
    if plan.blocked:
        report.issues.append(f"IP {cidr}: {plan.note}")
        return interfaces
    if plan.in_sync:
        return interfaces

    ok = _change(run, report, _describe_ip(plan), lambda: apply_ip_plan(run.nb, device, plan))
    if plan.interface_id is None:  # the IP's interface had to be created
        if not run.apply:
            preview = SimpleNamespace(id=0, name=plan.interface_name, type="other", cable=None)
            return [*interfaces, preview]
        if ok:
            return list(run.nb.dcim.interfaces.filter(device_id=int(device.id)))
    return interfaces


def _sync_cables(
    run: _Run,
    match: _Match,
    device: Any,
    interfaces: list[Any] | None,
    uplinks: list[LldpNeighbor],
    report: _Report,
) -> None:
    if not uplinks:
        note = "no LLDP neighbor reported for this AP"
        if run.live.failed:
            note += " (not every WLC could be queried)"
        report.detail["cable_note"] = note
        return
    if interfaces is None:
        interfaces = _interfaces(run, match, device)

    cables: list[dict[str, Any]] = []
    for row in uplinks:
        plan = plan_neighbor_cable(
            run.nb,
            local_device=device,
            neighbor_names=row.remote_system_candidates,
            neighbor_ports=row.remote_port_candidates,
            devices=run.devices,
            local_port=row.local_port or None,
            local_interfaces=interfaces,
            interface_cache=run.interface_cache,
        )
        far = f"{plan.b_device_name}:{plan.b_interface_name}"
        entry: dict[str, Any] = {
            "local": plan.a_interface_name or row.local_port,
            "neighbor": far if plan.b_interface_name else "",
            "status": plan.action,
        }
        if plan.note:
            entry["note"] = plan.note
        cables.append(entry)

        if plan.action == "blocked":
            report.issues.append(f"cable: {plan.note}")
        elif plan.action == "conflict":
            report.notes.append(plan.note)
        elif plan.action == "create":
            _change(
                run,
                report,
                f"create cable {plan.a_interface_name} <-> {far}",
                lambda plan=plan: create_cable(run.nb, plan),
            )
    report.detail["cables"] = cables


def _interfaces(run: _Run, match: _Match, device: Any) -> list[Any]:
    """The device's NetBox interfaces — or, for a plan-mode preview, its type's template."""
    if int(device.id) == 0:
        assert match.device_type is not None
        return [
            SimpleNamespace(id=0, name=str(t.name), type=getattr(t, "type", None), cable=None)
            for t in run.templates_by_type.get(int(match.device_type.id), [])
        ]
    return list(run.nb.dcim.interfaces.filter(device_id=int(device.id)))


def _change(run: _Run, report: _Report, what: str, write: Callable[[], Any]) -> bool:
    """Record one change and, under ``--apply``, make it.

    ``what`` starts with a verb ("add tag ..."); plan mode records it as "would
    ...". A write that raises, or returns error text (``add_tag``,
    ``apply_ip_plan``), becomes one of the device's issues. ``False`` if it failed.
    """
    if not run.apply:
        report.changes.append(f"would {what}")
        return True
    try:
        outcome = write()
    except Exception as exc:  # pynetbox RequestError etc.
        outcome = str(exc)
    if isinstance(outcome, str):
        report.issues.append(f"could not {what}: {outcome}")
        return False
    report.changes.append(what)
    return True


def _describe_ip(plan: IpPlan) -> str:
    primary = "primary IPv6" if plan.primary_field == "primary_ip6" else "primary IPv4"
    target = repr(plan.interface_name)
    if plan.interface_id is None:
        target += " (new interface)"
    if plan.source == "live":
        target += " (the AP's LLDP uplink)"
    if plan.ip is None:
        return f"create IP address {plan.address}, attach to {target} and set as {primary}"
    if plan.moved_from:
        text = f"move IP address {plan.address} from {plan.moved_from!r} to {target}"
    elif plan.attach:
        text = f"attach existing IP address {plan.address} to {target}"
    else:
        return f"set {primary} to {plan.address}"
    return f"{text} and set as {primary}" if plan.set_primary else text


def _say(run: _Run, report: _Report) -> None:
    """One coloured line per device: red failed, yellow partial, green OK."""
    reporter = run.ctx.reporter
    if report.failed:
        verb = "could not be created" if run.apply else "cannot be created"
        reporter.error(f"{report.name}: {verb} — {report.failed}")
        return
    if report.action == "create":
        head = "created" if run.apply else "would be created"
    elif report.changes:
        head = "updated" if run.apply else "would be updated"
    else:
        head = "already in NetBox" if report.issues else "in sync"
    if report.issues:
        reporter.warn(f"{report.name}: {head}, but " + "; ".join(report.issues))
    else:
        reporter.success(f"{report.name}: {head}")
    for note in report.notes:
        reporter.info(f"{report.name}: {note}")


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _has_tag(device: Any, slug: str) -> bool:
    return slug.casefold() in normalize_tags(getattr(device, "tags", []))


def _require_role_in_branch(nb: Any, tree: RoleTree, slug: str, branch: str | None) -> Any:
    """The role to create a device with — it must exist *and* sit in the wireless branch."""
    role = require_role(nb, slug)
    _check_in_branch(tree, slug, branch)
    return role


def _find_role_in_branch(nb: Any, tree: RoleTree, slug: str, branch: str | None) -> Any:
    """The role with ``slug``, or ``None`` if NetBox has none. One outside the branch is refused."""
    role = nb.dcim.device_roles.get(slug=slug)
    if role is not None:
        _check_in_branch(tree, slug, branch)
    return role


def _check_in_branch(tree: RoleTree, slug: str, branch: str | None) -> None:
    if branch is not None and not tree.is_within(slug, branch):
        raise ToolError(
            f"device role {slug!r} is not inside the wireless branch ({branch!r}), so "
            "devices given it would be invisible to every role-scoped wireless tool",
            fix=f"set {slug!r}'s parent to {branch!r} (or a role beneath it) in NetBox",
        )


def _role_note(device: Any, tree: RoleTree, branch: str | None) -> str:
    """A note if an existing device's role puts it outside the wireless branch."""
    slug = device_role_slug(device)
    if branch is None or slug is None or tree.is_within(slug, branch):
        return ""
    return (
        f"exists in NetBox with role {slug!r}, outside the wireless branch ({branch!r}) — "
        "its role is left as is; role-scoped tools and 'netbox scope' won't count it "
        "until it's moved into that branch"
    )


def _load_interface_templates(nb: Any) -> dict[int, list[Any]]:
    """device_type id -> its interface-template records."""
    by_type: dict[int, list[Any]] = {}
    for template in nb.dcim.interface_templates.all():
        device_type = getattr(template, "device_type", None)
        if device_type is None:
            continue
        by_type.setdefault(int(device_type.id), []).append(template)
    return by_type


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


def _result(run: _Run, reports: list[_Report], run_changes: list[str]) -> ToolResult:
    changes = [*run_changes, *(f"{r.name}: {c}" for r in reports for c in r.changes)]
    failed = [r for r in reports if r.status == "failed"]
    partial = [r for r in reports if r.status == "partial"]
    created = sum(r.action == "create" and not r.failed for r in reports)
    updated = sum(r.action == "update" and bool(r.changes) for r in reports)
    in_sync = sum(r.action == "update" and not r.changes for r in reports)

    if failed:
        status = Status.ERROR
    elif partial or run.live.failed:
        status = Status.PARTIAL
    elif changes:
        status = Status.CHANGED if run.apply else Status.DRIFT
    else:
        status = Status.OK

    if status is Status.OK:
        summary = f"NetBox matches the wireless network across {len(reports)} device(s)"
    else:
        if run.apply:
            parts = [f"{created} created", f"{updated} updated"]
        else:
            parts = [f"{created} to create", f"{updated} to update"]
        parts.append(f"{in_sync} in sync")
        if partial:
            parts.append(f"{len(partial)} with problems")
        if failed:
            parts.append(f"{len(failed)} {'could not' if run.apply else 'cannot'} be created")
        if run.live.failed:
            parts.append(f"{len(run.live.failed)} WLC(s) not queried")
        summary = f"{len(reports)} device(s): " + ", ".join(parts)
        if not run.apply and changes:
            summary += " — run with --apply"

    data = {
        "devices": {
            r.name: {
                "kind": r.kind,
                "action": r.action,
                "status": r.status,
                **({"reason": r.failed} if r.failed else {}),
                "changes": r.changes,
                "issues": r.issues,
                "notes": r.notes,
                **r.detail,
            }
            for r in reports
        },
        "wlcs": run.live.wlcs,
    }
    return ToolResult(status=status, summary=summary, changes=changes, data=data)


TOOL = WirelessSync()
