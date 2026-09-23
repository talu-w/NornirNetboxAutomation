"""``wireless sync`` — create NetBox WLCs/APs from an Aruba Conductor, tagged for this network.

Reads the Conductor's device inventory over its read-only REST API
(``show switches`` + ``show ap database long``), compares it to NetBox by serial
then name, and:

* creates every WLC/AP NetBox is missing. A WLC gets the ``wireless-controller``
  role and an AP the ``wireless-access-point`` role (slugs from the
  environment's ``roles:``, see :mod:`bunnyauto.categories`). Only whichever
  role a run actually needs to create is required to exist, and it must sit
  inside the wireless branch (``wireless-network``), because a device created
  outside it would be invisible to every wireless tool. The device type is
  matched from the Aruba model string (e.g. Aruba's bare ``"655"`` against a
  device type with model ``"Aruba AP-655"`` / slug ``"hpe-aruba-ap-655"``) by
  token-boundary *containment*, not an exact match (see
  :mod:`bunnyauto.netbox.tokens`). The site is derived from the hostname prefix.
  Each device is stamped with the **environment's tag** (``nornirtest`` /
  ``networking-active``, the tag every other tool targets), so a new WLC is
  immediately visible to ``wireless enrich``. The role now says "wireless",
  so the old separate ``wireless`` tag is no longer applied (2026-09-23);
* adds the environment's tag to Conductor devices that already exist in NetBox
  but don't carry it yet. An existing device's role is never changed; if it
  sits outside the wireless branch, that's reported as a note, since no
  wireless tool will see it until its role is fixed;
* for each **newly created** device that reported an IP, creates that IP in
  NetBox IPAM (``address/mask``, the mask taken from the most specific NetBox
  Prefix containing it) — provided such a Prefix exists — attaches it to a
  wired interface and sets it as the device's primary IPv4
  (:func:`bunnyauto.netbox.ipam.assign_primary_ip`). If no Prefix contains the
  IP, the device is still created; only the IP is skipped, with a note.
  Existing (already-matched) devices never have their IP touched.

The interface an IP is attached to is never a guessed literal name: a real
NetBox device type (e.g. one imported from NetBox Data Exchange) carries an
interface template with wired ports (``E0``, ``E1``, ...) alongside any Wi-Fi/
Bluetooth/Zigbee radios (``6GHz WiFi``, ``Bluetooth``, ...), and NetBox
auto-creates those interfaces along with the device. The device's *actual*
interfaces are read and the first wired one, alphabetically by name, is used
(:func:`bunnyauto.netbox.interfaces.pick_wired_record`) — radio and
virtual/lag/bridge interfaces are never candidates. ``--ip-interface`` forces a
specific interface by name instead (created if the device doesn't have it); a
device type with no interface template at all falls back to creating one named
``Ethernet0``.

It never updates or deletes an existing device (beyond adding the tag), and
never creates a device type, a site, a role, a Prefix or an IP Range. A device
whose model has no matching NetBox device type, or whose hostname maps to no
site (and no ``--default-site`` was given), is reported and skipped.

**Known limitation**: which physical port actually carries the AP's IP is not
queried live from the Conductor — the pick is the device type's first wired
interface by name, not necessarily the port that's actually up.

Plans by default; ``--apply`` writes. Auth is the shared device login
(``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``); TLS verification is always on unless
``--aruba-insecure`` is passed.
"""

from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.aruba.inventory import WirelessDevice, parse_ap_database, parse_switches
from bunnyauto.aruba.sitematch import Site, match_site
from bunnyauto.common import env_flag, normalize_tags
from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.netbox.devices import add_tag
from bunnyauto.netbox.interfaces import pick_wired_record
from bunnyauto.netbox.ipam import (
    FALLBACK_INTERFACE_NAME,
    Prefix,
    assign_primary_ip,
    find_prefix,
    load_prefixes,
)
from bunnyauto.netbox.roles import RoleTree, device_role_slug, require_role, role_field
from bunnyauto.netbox.tokens import match_record
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

#: Which ``roles:`` key names the role each kind of device is created with.
_ROLE_KEY_BY_KIND = {"ap": "wireless-access-point", "wlc": "wireless-controller"}


@dataclass(slots=True)
class _Outcome:
    device: WirelessDevice
    action: str  # "in-sync" | "tag" | "create" | "blocked"
    existing: Any = None  # the matched NetBox device, for "in-sync" / "tag"
    site: str = ""
    device_type: str = ""  # display string, e.g. "Aruba AP-655"
    device_type_id: int = 0
    reason: str = ""
    ip_cidr: str = ""  # "10.1.1.11/24" — set only when a containing Prefix was found
    ip_vrf_id: int | None = None
    ip_note: str = ""  # why the IP was not created, if it wasn't
    ip_interface: str = ""  # preview of the interface it would attach to


@dataclass(slots=True)
class WirelessSync:
    name: str = "sync"
    summary: str = "Create NetBox WLCs/APs from an Aruba Conductor, tagged for this network"
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
            "--default-site",
            dest="default_site",
            default=None,
            help="NetBox site slug to use when a hostname matches no site",
        )
        parser.add_argument(
            "--only",
            choices=("all", "aps", "wlcs"),
            default="all",
            help="limit the pull to access points or controllers (default: all)",
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
        parser.add_argument(
            "--ip-interface",
            dest="ip_interface",
            default=None,
            help="force the interface a newly created device's IP is attached to "
            "(created if the device doesn't have it) instead of auto-picking the "
            "device's first wired interface",
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
                "NORNIR_USERNAME / NORNIR_PASSWORD are needed to log in to the Conductor",
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
        sites_by_slug = {s.slug.casefold(): s for s in sites}
        default_site: Site | None = None
        if args.default_site:
            default_site = sites_by_slug.get(args.default_site.strip().casefold())
            if default_site is None:
                raise ToolError(f"--default-site {args.default_site!r} is not a NetBox site slug")

        device_types = list(nb.dcim.device_types.all())

        devices = list(nb.dcim.devices.all())
        by_serial = {str(d.serial).casefold(): d for d in devices if getattr(d, "serial", "")}
        by_name = {str(d.name).casefold(): d for d in devices if getattr(d, "name", "")}

        # -- pull from the Conductor ---------------------------------------
        ctx.reporter.step(f"querying the Aruba Conductor at {aruba_url}")
        verify = not args.aruba_insecure
        with (
            ctx.reporter.spinner(f"querying the Aruba Conductor at {aruba_url}..."),
            ArubaConductorClient(
                aruba_url, ctx.creds.username, ctx.creds.password, verify=verify
            ) as client,
        ):
            wireless: list[WirelessDevice] = []
            if args.only in ("all", "wlcs"):
                wireless += parse_switches(client.switches())
            if args.only in ("all", "aps"):
                wireless += parse_ap_database(client.ap_database())

        if args.device:
            needle = args.device.casefold()
            wireless = [d for d in wireless if needle in d.name.casefold()]
        if not wireless:
            return ToolResult(
                status=Status.OK,
                summary="the Conductor returned no matching devices",
            )
        n_wlc = sum(d.kind == "wlc" for d in wireless)
        ctx.reporter.info(
            f"Conductor reported {len(wireless)} device(s) "
            f"({n_wlc} WLC, {len(wireless) - n_wlc} AP)"
        )

        need_ip_work = any(d.ip for d in wireless)
        prefixes = load_prefixes(nb) if need_ip_work else []
        templates_by_type = _load_interface_templates(nb) if need_ip_work else {}

        outcomes = [
            self._classify(
                d,
                by_serial,
                by_name,
                device_types,
                sites,
                default_site,
                prefixes,
                templates_by_type,
                args.ip_interface,
                tag_slug,
            )
            for d in wireless
        ]

        # Only require a role to exist if this run actually needs to create a
        # device of that kind — a run that only tags or is all in-sync needs
        # neither, and one that only ever creates APs doesn't need the WLC
        # role (or vice versa).
        role_by_kind: dict[str, Any] = {}
        for kind in ("ap", "wlc"):
            if any(o.action == "create" and o.device.kind == kind for o in outcomes):
                slug = ctx.environment.roles[_ROLE_KEY_BY_KIND[kind]]
                role_by_kind[kind] = _require_role_in_branch(nb, tree, slug, branch)
        role_key = role_field(nb)

        # -- ensure the tag exists --------------------------------------
        changes: list[str] = []
        tag = nb.extras.tags.get(slug=tag_slug)
        need_tag_create = tag is None and any(o.action in ("create", "tag") for o in outcomes)
        if need_tag_create:
            if apply:
                tag = nb.extras.tags.create({"name": tag_slug, "slug": tag_slug})
                ctx.reporter.success(f"created NetBox tag {tag_slug!r}")
            else:
                changes.append(f"would create NetBox tag {tag_slug!r}")

        # -- act on each device ---------------------------------------
        data: dict[str, Any] = {}
        created = tagged = create_planned = tag_planned = ip_created = 0
        failures: list[str] = []
        blocked: list[str] = []
        ip_failures: list[str] = []

        for out in outcomes:
            d = out.device
            data[d.name] = {
                "kind": d.kind,
                "serial": d.serial,
                "action": out.action,
                "site": out.site,
                "device_type": out.device_type,
                "reason": out.reason,
                "ip": d.ip,
                "ip_cidr": out.ip_cidr,
                "ip_note": out.ip_note,
            }
            if out.existing is not None:
                role_note = _role_note(out.existing, tree, branch)
                if role_note:
                    data[d.name]["role_note"] = role_note
                    ctx.reporter.warn(f"{d.name}: {role_note}")

            if out.action == "in-sync":
                ctx.reporter.info(f"{d.name}: already in NetBox and tagged {tag_slug!r}")
            elif out.action == "blocked":
                blocked.append(d.name)
                ctx.reporter.warn(f"{d.name}: skipped — {out.reason}")
            elif out.action == "tag":
                verb = "add tag" if apply else "would add tag"
                changes.append(f"{d.name}: {verb} {tag_slug!r}")
                if apply:
                    ok = add_tag(out.existing, tag_slug)
                    if ok is True:
                        tagged += 1
                        ctx.reporter.success(f"{d.name}: tagged {tag_slug!r}")
                    else:
                        failures.append(d.name)
                        data[d.name]["error"] = ok
                        ctx.reporter.error(f"{d.name}: tagging failed — {ok}")
                else:
                    tag_planned += 1
            elif out.action == "create":
                verb = "create" if apply else "would create"
                changes.append(
                    f"{d.name}: {verb} {d.kind.upper()} in site {out.site!r} "
                    f"(type {out.device_type!r}) tagged {tag_slug!r}"
                )
                if out.ip_cidr:
                    changes.append(
                        f"{d.name}: {verb} IP address {out.ip_cidr}, attach to "
                        f"{out.ip_interface!r} and set as primary IPv4"
                    )
                elif out.ip_note:
                    changes.append(f"{d.name}: {out.ip_note}")
                    ctx.reporter.warn(f"{d.name}: {out.ip_note}")

                if apply:
                    device, err = _create_device(
                        nb,
                        name=d.name,
                        device_type_id=out.device_type_id,
                        role_key=role_key,
                        role_id=int(role_by_kind[d.kind].id),
                        site_id=int(sites_by_slug[out.site.casefold()].id),
                        serial=d.serial,
                        status=args.status,
                        tag_slug=tag_slug,
                    )
                    if err is None:
                        created += 1
                        ctx.reporter.success(f"{d.name}: created in site {out.site!r}")
                        if out.ip_cidr:
                            ip_status, ip_detail = assign_primary_ip(
                                nb,
                                device=device,
                                address=out.ip_cidr,
                                vrf_id=out.ip_vrf_id,
                                interface_name=args.ip_interface,
                            )
                            if ip_status == "error":
                                ip_failures.append(d.name)
                                data[d.name]["ip_error"] = ip_detail
                                ctx.reporter.error(f"{d.name}: IP create failed — {ip_detail}")
                            else:
                                if ip_status == "created":
                                    ip_created += 1
                                data[d.name]["ip_status"] = ip_status
                                data[d.name]["ip_interface"] = ip_detail
                                ctx.reporter.success(
                                    f"{d.name}: IP {out.ip_cidr} {ip_status}, primary IPv4 "
                                    f"on {ip_detail!r}"
                                )
                    else:
                        failures.append(d.name)
                        data[d.name]["error"] = err
                        ctx.reporter.error(f"{d.name}: create failed — {err}")
                else:
                    create_planned += 1

        return _result(
            apply=apply,
            tag_slug=tag_slug,
            changes=changes,
            data=data,
            created=created,
            tagged=tagged,
            create_planned=create_planned,
            tag_planned=tag_planned,
            failures=failures,
            blocked=blocked,
            ip_created=ip_created,
            ip_failures=ip_failures,
            total=len(wireless),
        )

    # ------------------------------------------------------------------

    def _classify(
        self,
        d: WirelessDevice,
        by_serial: dict[str, Any],
        by_name: dict[str, Any],
        device_types: list[Any],
        sites: list[Site],
        default_site: Site | None,
        prefixes: list[Prefix],
        templates_by_type: dict[int, list[Any]],
        ip_interface_override: str | None,
        tag_slug: str,
    ) -> _Outcome:
        match = None
        if d.serial and d.serial.casefold() in by_serial:
            match = by_serial[d.serial.casefold()]
        elif d.name and d.name.casefold() in by_name:
            match = by_name[d.name.casefold()]

        if match is not None:
            if tag_slug.casefold() in normalize_tags(getattr(match, "tags", [])):
                return _Outcome(d, "in-sync", existing=match)
            return _Outcome(d, "tag", existing=match)

        device_type = match_record(d.model_candidates, device_types)
        if device_type is None:
            return _Outcome(d, "blocked", reason=f"no NetBox device type matches model {d.model!r}")

        site = match_site(d.name, sites) or default_site
        if site is None:
            return _Outcome(
                d,
                "blocked",
                device_type=str(getattr(device_type, "model", "")),
                device_type_id=int(device_type.id),
                reason=f"hostname {d.name!r} matched no NetBox site (pass --default-site)",
            )

        ip_cidr = ""
        ip_vrf_id: int | None = None
        ip_note = ""
        ip_interface = ""
        if d.ip:
            try:
                addr = ipaddress.ip_address(d.ip)
            except ValueError:
                ip_note = f"the Conductor reported an unparseable IP address {d.ip!r}"
            else:
                prefix = find_prefix(addr, prefixes)
                if prefix is None:
                    ip_note = (
                        "IP address could not be added/assigned at this time due to lack "
                        "of an established prefix/IP range within NetBox."
                    )
                else:
                    ip_cidr = f"{addr}/{prefix.network.prefixlen}"
                    ip_vrf_id = prefix.vrf_id
                    if ip_interface_override:
                        ip_interface = ip_interface_override
                    else:
                        template = pick_wired_record(templates_by_type.get(int(device_type.id), []))
                        ip_interface = (
                            str(template.name) if template is not None else FALLBACK_INTERFACE_NAME
                        )

        return _Outcome(
            d,
            "create",
            site=site.slug,
            device_type=str(getattr(device_type, "model", "")),
            device_type_id=int(device_type.id),
            ip_cidr=ip_cidr,
            ip_vrf_id=ip_vrf_id,
            ip_note=ip_note,
            ip_interface=ip_interface,
        )


def _require_role_in_branch(nb: Any, tree: RoleTree, slug: str, branch: str | None) -> Any:
    """The role to create a device with — it must exist *and* sit in the wireless branch."""
    role = require_role(nb, slug)
    if branch is not None and not tree.is_within(slug, branch):
        raise ToolError(
            f"device role {slug!r} is not inside the wireless branch ({branch!r}), so "
            "devices created with it would be invisible to every wireless tool",
            fix=f"set {slug!r}'s parent to {branch!r} (or a role beneath it) in NetBox",
        )
    return role


def _role_note(device: Any, tree: RoleTree, branch: str | None) -> str:
    """A warning if an existing device's role puts it outside the wireless branch."""
    slug = device_role_slug(device)
    if branch is None or slug is None or tree.is_within(slug, branch):
        return ""
    return (
        f"exists in NetBox with role {slug!r}, outside the wireless branch ({branch!r}) — "
        "wireless tools won't target it until its role is moved into that branch"
    )


def _load_interface_templates(nb: Any) -> dict[int, list[Any]]:
    """device_type id -> its interface-template records.

    This is what lets plan mode preview the interface an IP would attach to
    without creating anything: NetBox auto-creates a device's interfaces from
    its device type's interface template, so the template is a faithful
    preview of what the device will actually have.
    """
    by_type: dict[int, list[Any]] = {}
    for template in nb.dcim.interface_templates.all():
        device_type = getattr(template, "device_type", None)
        if device_type is None:
            continue
        by_type.setdefault(int(device_type.id), []).append(template)
    return by_type


def _create_device(
    nb: Any,
    *,
    name: str,
    device_type_id: int,
    role_key: str,
    role_id: int,
    site_id: int,
    serial: str,
    status: str,
    tag_slug: str,
) -> tuple[Any, str | None]:
    """Create one NetBox device. Returns ``(device, None)``, or ``(None, error text)``."""
    body: dict[str, Any] = {
        "name": name,
        "device_type": device_type_id,
        role_key: role_id,
        "site": site_id,
        "status": status,
        "tags": [{"slug": tag_slug}],
    }
    if serial:
        body["serial"] = serial
    try:
        device = nb.dcim.devices.create(body)
    except Exception as exc:  # pynetbox RequestError etc.
        return None, str(exc)
    return device, None


def _result(
    *,
    apply: bool,
    tag_slug: str,
    changes: list[str],
    data: dict[str, Any],
    created: int,
    tagged: int,
    create_planned: int,
    tag_planned: int,
    failures: list[str],
    blocked: list[str],
    ip_created: int,
    ip_failures: list[str],
    total: int,
) -> ToolResult:
    progressed = bool(created or tagged or create_planned or tag_planned)
    if failures or ip_failures or blocked:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and (created or tagged):
        status = Status.CHANGED
    elif create_planned or tag_planned:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"created {created} device(s), tagged {tagged} existing device(s)"
        if ip_created:
            summary += f", created {ip_created} IP address(es)"
    elif create_planned or tag_planned:
        summary = (
            f"{create_planned} device(s) missing from NetBox, "
            f"{tag_planned} need the {tag_slug!r} tag — run with --apply"
        )
    else:
        summary = f"NetBox is in sync with the Conductor across {total} device(s)"
    if blocked:
        summary += f" ({len(blocked)} skipped)"
    if failures:
        summary += f" ({len(failures)} failed)"
    if ip_failures:
        summary += f" ({len(ip_failures)} IP failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


TOOL = WirelessSync()
