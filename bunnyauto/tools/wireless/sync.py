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
  neighbors`` + ``show ap bss-table``), because the Conductor's aggregated view
  doesn't carry this per-AP runtime data. Per AP: its software version, its
  live wired uplinks (which of the AP's own ports, the LLDP ``Interface`` column
  e.g. ``eth1``, connects to which switch port), and each radio's channel,
  width, EIRP and SSIDs. A WLC is reached at its NetBox
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
* **Bridge and bond** (APs, :mod:`bunnyauto.netbox.bridging`; 2026-09-28): an
  AP holds its IP on a software bridge, not a port, so every AP gets a ``br0``
  interface (type ``bridge``). The ports the AP's LLDP reports a neighbor on are
  its uplinks: one is linked straight to ``br0`` (its ``bridge`` field); two
  (``E0`` and ``E1``, each to its own switch) become members of a ``bond0`` LAG,
  which is linked to ``br0``. Nothing is unlinked or removed: ``bond0`` stays
  once it exists.
* **IP** (every new device, and every AP): the reported IP, with the mask and
  VRF of the most specific NetBox Prefix containing it, as the device's primary
  IP (:mod:`bunnyauto.netbox.ipam`). An AP's goes on ``br0``, and an IP NetBox
  has on one of its ports (``E0``/``E1``, from before 2026-09-28) is **moved**
  there. A new WLC's goes on its first wired interface. A WLC's IP is only set
  when this tool creates the WLC: an existing WLC's primary IPv4 is the address
  this tool logs into, so Conductor data never changes it. An IP no Prefix
  contains is not created (no Prefix or IP Range is ever created).
* **Cables** (APs): one per LLDP neighbor, from the AP's reported port to the
  switch port, so an AP with each port on its own switch gets both cables
  (:mod:`bunnyauto.netbox.cabling`, stack members resolved by
  ``<host>-<member>``). **NetBox is corrected to what LLDP reports** (owner
  decision 2026-09-28, replacing the 2026-09-22 never-touch rule): a cable
  NetBox has on one of the two ports but to the wrong place (the AP re-patched
  to another switch port, or its E0 cable now on E1) is **re-pointed**, keeping
  the cable object; nothing is deleted. Both ports cabled to different places
  would need a deletion, so that's yellow for a person to fix. A path through a
  patch panel is in sync if it ends at the right port, else only noted.

* **Radios** (APs, :mod:`bunnyauto.netbox.radios`; 2026-09-28, owner request):
  each band's ``show ap bss-table`` rows fill the matching NetBox radio
  interface (``2.4GHz WiFi`` / ``5GHz WiFi`` / ``6GHz WiFi``, as NetBox Data
  Exchange device types name them) on every run: wireless role ``ap``, the
  channel (Aruba's primary channel + width, e.g. ``52E``, converted to NetBox's
  centre-channel value ``5g-58-5290-80``; frequency and width are sent with
  it), transmit power (the reported EIRP, rounded) and its wireless LANs,
  exactly the SSIDs it broadcasts. A reported SSID with no NetBox wireless LAN
  gets one created (SSID only). A band NetBox has no radio interface for is
  yellow; two radios on one band (dual 5 GHz), an unplaceable channel and an
  SSID with two NetBox wireless LANs are notes.

**Outcome.** Each device's line, and the run, is one of:

* red, ``ERROR`` (exit 1): a device could not be created (no device-type or
  site match, or NetBox refused it);
* yellow, ``PARTIAL`` (exit 2): the device exists or was created, but something
  else couldn't be done: an IP (including "no containing Prefix"), a
  platform, a cable (including one NetBox has wired differently that can't be
  re-pointed), a tag or serial update, or a WLC that couldn't be queried;
* green: everything the network reported is in NetBox: ``CHANGED`` (20) after
  ``--apply``, ``DRIFT`` (10) for a plan with changes, ``OK`` (0) when in sync.

These are informational only, never a failure: an AP with no LLDP neighbor, no
recognized version field, a cable path through a patch panel left alone, a WLC
role outside the wireless branch, and an AP role noted because NetBox has no AP
role.

Nothing is ever deleted, and no device type, site, role or platform is ever
created (wireless LANs are, SSID only). Plans by default; ``--apply`` writes.
Auth is the shared device login (``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``).
TLS is verified unless ``--aruba-insecure`` / ``--wlc-insecure``.
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
from bunnyauto.aruba.radios import Bss, parse_bss_table
from bunnyauto.aruba.sitematch import Site, match_site
from bunnyauto.common import env_flag, normalize_tags
from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.netbox.bridging import apply_bridge_step, plan_uplink_bridge
from bunnyauto.netbox.cabling import (
    create_cable,
    plan_neighbor_cable,
    record_cable,
    update_cable,
)
from bunnyauto.netbox.devices import add_tag
from bunnyauto.netbox.ipam import (
    IpPlan,
    Prefix,
    apply_ip_plan,
    find_prefix,
    load_prefixes,
    plan_primary_ip,
)
from bunnyauto.netbox.radios import (
    load_channel_values,
    load_wireless_lans,
    plan_radio,
    radio_interface,
    rf_channel,
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
_WLC_UNREAD = "could not read its APs' LLDP/version/radio data"
_BAND_ORDER = {"2.4": 0, "5": 1, "6": 2}


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
    #: ``show ap bss-table`` rows: one per SSID per radio.
    radios: dict[str, list[Bss]] = field(default_factory=dict)
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
    #: The rf_channel values NetBox accepts (None: it wouldn't say).
    channel_values: frozenset[str] | None = None
    #: SSID -> its NetBox wireless LAN's id (0: one plan mode would create).
    wlan_ids: dict[str, int] = field(default_factory=dict)
    #: SSID -> (why it has no usable wireless LAN, whether that's a problem).
    wlan_problems: dict[str, tuple[str, bool]] = field(default_factory=dict)
    interface_cache: dict[int, list[Any]] = field(default_factory=dict)


@dataclass(slots=True)
class WirelessSync:
    name: str = "sync"
    summary: str = (
        "Create/update NetBox WLCs and APs from the Conductor and each WLC: "
        "br0/bond0 and IP, platform, LLDP cabling, radio channels/power/SSIDs"
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

        reported_ssids = sorted(
            {
                entry.ssid
                for d in wireless
                if d.kind == "ap"
                for entry in live.radios.get(d.name.casefold(), [])
                if entry.kind == "ap" and entry.ssid
            }
        )
        wlan_ids, wlan_problems = _sync_wireless_lans(ctx, nb, reported_ssids, apply, run_changes)

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
            channel_values=load_channel_values(nb) if has_aps and live.radios else None,
            wlan_ids=wlan_ids,
            wlan_problems=wlan_problems,
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
                bss = parse_bss_table(client.ap_bss_table())
        except ArubaError as exc:
            live.failed[wlc.name] = str(exc)
            live.wlcs[wlc.name] = {"url": url, "error": str(exc)}
            continue

        live.wlcs[wlc.name] = {
            "url": url,
            "aps": len(wlc_aps),
            "lldp_neighbors": len(rows),
            "bss": len(bss),
        }
        for ap in wlc_aps:
            if ap.os_version:
                live.versions.setdefault(ap.name.casefold(), ap.os_version)
        for row in rows:
            seen = live.uplinks.setdefault(row.ap_name.casefold(), [])
            if row not in seen:  # an AP both a WLC and its standby report
                seen.append(row)
        for entry in bss:
            known = live.radios.setdefault(entry.ap_name.casefold(), [])
            if entry not in known:
                known.append(entry)
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

    if d.kind == "ap":
        _sync_platform(run, d, device, report)
        uplinks = run.live.uplinks.get(d.name.casefold(), [])
        interfaces, bridge = _sync_bridge(run, match, device, uplinks, report)
        if d.ip and bridge is None:
            report.issues.append(f"IP {d.ip}: not placed, because its bridge couldn't be created")
        elif d.ip:
            interfaces = _sync_ip(run, match, device, interfaces, report, target=bridge)
        _sync_cables(run, device, interfaces, uplinks, report)
        _sync_radios(run, d, interfaces, report)
    elif d.ip and match.action == "create":  # a new WLC; an existing one's IP is never touched
        _sync_ip(run, match, device, _interfaces(run, match, device), report)
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


def _sync_bridge(
    run: _Run, match: _Match, device: Any, uplinks: list[LldpNeighbor], report: _Report
) -> tuple[list[Any], str | None]:
    """Give an AP its ``br0``, plus ``bond0`` when two uplinks are cabled.

    Returns the AP's interfaces afterwards (previews in plan mode) and the
    bridge's name, or ``None`` if the bridge couldn't be created.
    """
    interfaces = _interfaces(run, match, device)
    plan = plan_uplink_bridge(interfaces, [row.local_port for row in uplinks if row.local_port])
    report.detail.update(bridge=plan.bridge, bond=plan.bond or None, uplinks=plan.uplinks)
    report.notes.extend(plan.notes)

    records = {str(i.name): i for i in interfaces}
    for step in plan.steps:
        written = _change(
            run,
            report,
            step.text,
            lambda step=step: apply_bridge_step(run.nb, device, step, records),
        )
        if not written:
            break  # the later steps build on this one
        if not run.apply and step.create_type:
            records[step.interface] = SimpleNamespace(
                id=0, name=step.interface, type=step.create_type, cable=None
            )
    return list(records.values()), plan.bridge if plan.bridge in records else None


def _sync_ip(
    run: _Run,
    match: _Match,
    device: Any,
    interfaces: list[Any],
    report: _Report,
    *,
    target: str | None = None,
) -> list[Any]:
    """Put the reported IP on ``target`` (an AP's bridge), or where it already is.

    Without a target (a new WLC), the device's first wired interface. Returns the
    interfaces, plus any it had to add.
    """
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
        interface_name=target,
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
    device: Any,
    interfaces: list[Any],
    uplinks: list[LldpNeighbor],
    report: _Report,
) -> None:
    if not uplinks:
        note = "no LLDP neighbor reported for this AP"
        if run.live.failed:
            note += " (not every WLC could be queried)"
        report.detail["cable_note"] = note
        return

    report.detail["cables"] = [_sync_cable(run, device, interfaces, row, report) for row in uplinks]


def _sync_cable(
    run: _Run, device: Any, interfaces: list[Any], row: LldpNeighbor, report: _Report
) -> dict[str, Any]:
    """Make NetBox's cable for one LLDP neighbor match it. Returns its ``--json`` entry.

    A missing cable is created; a cable NetBox has on one of the two ports but
    to the wrong place is re-pointed (never deleted). Both ports cabled to
    different places can't be fixed without deleting one (yellow); a path
    through a patch panel is only noted.
    """
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
    everywhere = [interfaces, *run.interface_cache.values()]

    if plan.action in ("blocked", "conflict"):
        report.issues.append(f"cable: {plan.note}")
    elif plan.action == "untouched":
        report.notes.append(plan.note)
    elif plan.action == "create":
        created: list[Any] = []
        text = f"create cable {plan.a_interface_name} <-> {far}"
        if _change(run, report, text, lambda: created.append(create_cable(run.nb, plan))):
            if created:  # written, not planned: later APs in this run see the new cable
                record_cable(plan, related_id(created[0]) or 0, everywhere)
    elif plan.action == "update":
        entry.update(cable_id=plan.cable_id, replaced=plan.replaced)
        text = (
            f"update cable #{plan.cable_id}: {plan.replaced} -> {plan.replacement}, now "
            f"{plan.a_interface_name} <-> {far}"
        )
        if _change(run, report, text, lambda: update_cable(run.nb, plan)) and run.apply:
            record_cable(plan, plan.cable_id, everywhere)
    return entry


def _sync_wireless_lans(
    ctx: Context, nb: Any, ssids: list[str], apply: bool, run_changes: list[str]
) -> tuple[dict[str, int], dict[str, tuple[str, bool]]]:
    """Each reported SSID's NetBox wireless LAN, creating the missing ones (SSID only).

    Returns ``(SSID -> id, SSID -> (problem, is it a failure))``. In plan mode a
    missing wireless LAN gets id 0. Two wireless LANs with one SSID are
    ambiguous: neither is picked.
    """
    ids: dict[str, int] = {}
    problems: dict[str, tuple[str, bool]] = {}
    if not ssids:
        return ids, problems
    existing = load_wireless_lans(nb)
    for ssid in ssids:
        found = existing.get(ssid, [])
        if len(found) == 1:
            ids[ssid] = int(found[0].id)
        elif found:
            problems[ssid] = (f"NetBox has {len(found)} wireless LANs with SSID {ssid!r}", False)
        elif not apply:
            ids[ssid] = 0
            run_changes.append(f"would create wireless LAN {ssid!r}")
        else:
            try:
                ids[ssid] = int(nb.wireless.wireless_lans.create({"ssid": ssid}).id)
            except Exception as exc:  # pynetbox RequestError etc.
                problems[ssid] = (f"wireless LAN {ssid!r} couldn't be created: {exc}", True)
                ctx.reporter.warn(f"could not create wireless LAN {ssid!r} — {exc}")
            else:
                run_changes.append(f"create wireless LAN {ssid!r}")
    return ids, problems


def _sync_radios(run: _Run, d: WirelessDevice, interfaces: list[Any], report: _Report) -> None:
    """Fill each radio interface with what ``show ap bss-table`` reports for its band."""
    rows = [entry for entry in run.live.radios.get(d.name.casefold(), []) if entry.kind == "ap"]
    if not rows:
        note = "no radio data reported for this AP"
        if run.live.failed:
            note += " (not every WLC could be queried)"
        report.detail["radio_note"] = note
        return
    by_band: dict[str, list[Bss]] = {}
    for entry in rows:
        by_band.setdefault(entry.band, []).append(entry)
    report.detail["radios"] = [
        _sync_radio(run, interfaces, band, by_band[band], report)
        for band in sorted(by_band, key=lambda band: _BAND_ORDER.get(band, 9))
    ]


def _sync_radio(
    run: _Run, interfaces: list[Any], band: str, rows: list[Bss], report: _Report
) -> dict[str, Any]:
    """Make one radio interface match one band's rows. Returns its ``--json`` entry."""
    first = rows[0]
    ssids = sorted({entry.ssid for entry in rows if entry.ssid})
    entry: dict[str, Any] = {
        "band": band,
        "channel": first.channel_label,
        "width": first.width,
        "ssids": ssids,
    }
    if not band:
        report.notes.append(
            f"radio: SSIDs {', '.join(ssids)} were reported without a band — skipped"
        )
        return {**entry, "status": "skipped"}
    channels = sorted({e.channel_label for e in rows})
    if len(channels) > 1:
        report.notes.append(
            f"radio: {band} GHz is on more than one channel ({', '.join(channels)}), so two "
            f"{band} GHz radios can't be told apart — skipped"
        )
        return {**entry, "status": "skipped"}
    interface, why = radio_interface(interfaces, band)
    if interface is None:
        report.issues.append(f"radio {band} GHz: {why}")
        return {**entry, "status": "blocked"}
    name = str(interface.name)

    channel = rf_channel(
        band, first.channel, first.width, first.direction, values=run.channel_values
    )
    if channel is None:
        report.notes.append(
            f"radio {name!r}: channel {first.channel_label!r} ({first.width or '?'} MHz) can't "
            "be placed in NetBox — channel left as is"
        )
    eirps = [e.eirp for e in rows if e.eirp is not None]
    tx_power = max(-40, min(127, round(eirps[0]))) if eirps else None
    problems = [run.wlan_problems[s] for s in ssids if s in run.wlan_problems]
    for problem, is_issue in problems:
        (report.issues if is_issue else report.notes).append(
            f"radio {name!r}: {problem} — its wireless LANs are left as they are"
        )
    wlan_ids = None if problems else [run.wlan_ids[s] for s in ssids]

    body = plan_radio(interface, channel=channel, tx_power=tx_power, wireless_lan_ids=wlan_ids)
    entry.update(
        interface=name,
        rf_channel=channel.value if channel else None,
        tx_power=tx_power,
        status="in-sync" if not body else "changed",
    )
    if body:
        parts = []
        if "rf_role" in body:
            parts.append("role 'ap'")
        if "rf_channel" in body:
            parts.append(f"channel {first.channel_label} ({first.width} MHz)")
        if "tx_power" in body:
            parts.append(f"tx power {tx_power} dBm")
        if "wireless_lans" in body:
            parts.append(f"SSIDs {', '.join(ssids) if ssids else '(none)'}")
        text = f"set radio {name!r}: " + ", ".join(parts)
        if not _change(run, report, text, lambda: interface.update(body)):
            entry["status"] = "failed"
    return entry


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
