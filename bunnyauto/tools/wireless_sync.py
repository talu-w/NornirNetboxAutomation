"""``wireless-sync`` — create NetBox WLCs/APs from an Aruba Conductor, tag them ``wireless``.

Reads the Conductor's device inventory over its read-only REST API
(``show switches`` + ``show ap database long``), compares it to NetBox by serial
then name, and:

* creates every WLC/AP NetBox is missing — role ``wireless``, device type matched
  from the Aruba model string, site derived from the hostname prefix — each
  stamped with the ``wireless`` tag;
* adds the ``wireless`` tag to Conductor devices that already exist in NetBox but
  are not yet tagged;
* for each **newly created** device that reported an IP, creates that IP in
  NetBox IPAM (``address/mask``, the mask taken from the most specific NetBox
  Prefix containing it) — provided such a Prefix exists — attaches it to a
  wired interface and sets it as the device's primary IPv4. If no Prefix
  contains the IP, the device is still created; only the IP is skipped, with a
  note. Existing (already-matched) devices never have their IP touched.

The interface an IP is attached to is never a guessed literal name: a real
NetBox device type (e.g. one imported from NetBox Data Exchange) carries an
interface template with wired ports (``E0``, ``E1``, ...) alongside any Wi-Fi/
Bluetooth/Zigbee radios (``6GHz WiFi``, ``Bluetooth``, ...), and NetBox
auto-creates those interfaces along with the device. This tool reads that
device's *actual* interfaces and picks the first wired one, alphabetically by
name (see ``bunnyauto/interface_match.py``) — radio and virtual/lag/bridge
interfaces are never candidates, so an IP never lands on a radio. Pass
``--ip-interface`` to force a specific interface by name instead (created if
the device doesn't have it); a device type with no interface template at all
(no wired candidates found) falls back to creating one named ``Ethernet0``.

It never updates or deletes an existing device, and never creates a device
type or a site (interfaces are the one exception, and only as a last resort —
see above). It never creates a NetBox Prefix/IP Range. A device whose model
has no matching NetBox device type, or whose hostname maps to no site (and no
``--default-site`` was given), is reported and skipped.

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
from bunnyauto.interface_match import pick_wired_interface
from bunnyauto.ipam_match import Prefix, find_prefix
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

_TAG_SLUG = "wireless"
_ROLE_SLUG = "wireless"
#: Used only when a device has no wired interface at all — no template, and no
#: --ip-interface override. Should be rare once device types carry real templates.
_FALLBACK_INTERFACE_NAME = "Ethernet0"


@dataclass(slots=True)
class _Outcome:
    device: WirelessDevice
    action: str  # "in-sync" | "tag" | "create" | "blocked"
    site: str = ""
    device_type: str = ""
    reason: str = ""
    ip_cidr: str = ""  # "10.1.1.11/24" — set only when a containing Prefix was found
    ip_vrf_id: int | None = None
    ip_note: str = ""  # why the IP was not created, if it wasn't
    ip_interface: str = ""  # preview of the interface it would attach to


@dataclass(slots=True)
class WirelessSync:
    name: str = "wireless-sync"
    summary: str = "Create NetBox WLCs/APs from an Aruba Conductor and tag them 'wireless'"
    writes: bool = True

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

        role = nb.dcim.device_roles.get(slug=_ROLE_SLUG)
        if role is None:
            raise ToolError(
                f"NetBox has no device role with slug {_ROLE_SLUG!r}",
                fix=f"create a {_ROLE_SLUG!r} device role in NetBox first",
            )

        sites = [
            Site(slug=str(s.slug), id=int(s.id), name=str(s.name)) for s in nb.dcim.sites.all()
        ]
        sites_by_slug = {s.slug.casefold(): s for s in sites}
        default_site: Site | None = None
        if args.default_site:
            default_site = sites_by_slug.get(args.default_site.strip().casefold())
            if default_site is None:
                raise ToolError(f"--default-site {args.default_site!r} is not a NetBox site slug")

        types_by_key: dict[str, Any] = {}
        for dt in nb.dcim.device_types.all():
            for key in (getattr(dt, "model", ""), getattr(dt, "slug", "")):
                if key:
                    types_by_key.setdefault(str(key).casefold(), dt)

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
        prefixes = _load_prefixes(nb) if need_ip_work else []
        templates_by_type = _load_interface_templates(nb) if need_ip_work else {}

        role_key = _role_key(nb)
        outcomes = [
            self._classify(
                d,
                by_serial,
                by_name,
                types_by_key,
                sites,
                default_site,
                prefixes,
                templates_by_type,
                args.ip_interface,
            )
            for d in wireless
        ]

        # -- ensure the tag exists --------------------------------------
        changes: list[str] = []
        tag = nb.extras.tags.get(slug=_TAG_SLUG)
        need_tag_create = tag is None and any(o.action in ("create", "tag") for o in outcomes)
        if need_tag_create:
            if apply:
                tag = nb.extras.tags.create({"name": _TAG_SLUG, "slug": _TAG_SLUG})
                ctx.reporter.success(f"created NetBox tag {_TAG_SLUG!r}")
            else:
                changes.append(f"would create NetBox tag {_TAG_SLUG!r}")

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
            if out.action == "in-sync":
                ctx.reporter.info(f"{d.name}: already in NetBox and tagged {_TAG_SLUG!r}")
            elif out.action == "blocked":
                blocked.append(d.name)
                ctx.reporter.warn(f"{d.name}: skipped — {out.reason}")
            elif out.action == "tag":
                verb = "add tag" if apply else "would add tag"
                changes.append(f"{d.name}: {verb} {_TAG_SLUG!r}")
                if apply:
                    ok = _add_tag(by_serial.get(d.serial.casefold()) or by_name[d.name.casefold()])
                    if ok is True:
                        tagged += 1
                        ctx.reporter.success(f"{d.name}: tagged {_TAG_SLUG!r}")
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
                    f"(type {out.device_type!r}) tagged {_TAG_SLUG!r}"
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
                        device_type_id=int(types_by_key[out.device_type.casefold()].id),
                        role_key=role_key,
                        role_id=int(role.id),
                        site_id=int(sites_by_slug[out.site.casefold()].id),
                        serial=d.serial,
                        status=args.status,
                    )
                    if err is None:
                        created += 1
                        ctx.reporter.success(f"{d.name}: created in site {out.site!r}")
                        if out.ip_cidr:
                            ip_status, ip_detail = _assign_ip(
                                nb,
                                device=device,
                                interface_name=args.ip_interface,
                                address=out.ip_cidr,
                                vrf_id=out.ip_vrf_id,
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
        types_by_key: dict[str, Any],
        sites: list[Site],
        default_site: Site | None,
        prefixes: list[Prefix],
        templates_by_type: dict[int, list[tuple[str, str]]],
        ip_interface_override: str | None,
    ) -> _Outcome:
        match = None
        if d.serial and d.serial.casefold() in by_serial:
            match = by_serial[d.serial.casefold()]
        elif d.name and d.name.casefold() in by_name:
            match = by_name[d.name.casefold()]

        if match is not None:
            if _TAG_SLUG in normalize_tags(getattr(match, "tags", [])):
                return _Outcome(d, "in-sync")
            return _Outcome(d, "tag")

        device_type = next(
            (
                types_by_key[c.casefold()]
                for c in d.model_candidates
                if c.casefold() in types_by_key
            ),
            None,
        )
        if device_type is None:
            return _Outcome(d, "blocked", reason=f"no NetBox device type matches model {d.model!r}")

        site = match_site(d.name, sites) or default_site
        if site is None:
            return _Outcome(
                d,
                "blocked",
                device_type=str(getattr(device_type, "model", "")),
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
                        rows = templates_by_type.get(int(device_type.id), [])
                        ip_interface = pick_wired_interface(rows) or _FALLBACK_INTERFACE_NAME

        return _Outcome(
            d,
            "create",
            site=site.slug,
            device_type=str(getattr(device_type, "model", "")),
            ip_cidr=ip_cidr,
            ip_vrf_id=ip_vrf_id,
            ip_note=ip_note,
            ip_interface=ip_interface,
        )


def _load_prefixes(nb: Any) -> list[Prefix]:
    """All NetBox Prefixes, parsed to CIDR networks. Malformed ones are skipped."""
    prefixes: list[Prefix] = []
    for p in nb.ipam.prefixes.all():
        try:
            network = ipaddress.ip_network(str(p.prefix), strict=False)
        except ValueError:
            continue
        vrf = getattr(p, "vrf", None)
        vrf_id = int(vrf.id) if vrf is not None else None
        prefixes.append(Prefix(id=int(p.id), network=network, vrf_id=vrf_id))
    return prefixes


def _load_interface_templates(nb: Any) -> dict[int, list[tuple[str, str]]]:
    """device_type id -> [(interface name, type), ...] from its interface templates.

    This is what lets plan mode preview the interface an IP would attach to
    without creating anything: NetBox auto-creates a device's interfaces from
    its device type's interface template, so the template is a faithful
    preview of what the device will actually have.
    """
    by_type: dict[int, list[tuple[str, str]]] = {}
    for t in nb.dcim.interface_templates.all():
        dt = getattr(t, "device_type", None)
        dt_id = int(dt.id) if dt is not None else None
        if dt_id is None:
            continue
        by_type.setdefault(dt_id, []).append((str(getattr(t, "name", "")), _type_value(t)))
    return by_type


def _type_value(record: Any) -> str:
    """Normalize a pynetbox choice field: a nested ``{value, label}`` record or a plain string."""
    t = getattr(record, "type", "")
    return str(getattr(t, "value", t))


def _role_key(nb: Any) -> str:
    """NetBox >= 3.6 names the device-role field ``role``; older ones ``device_role``."""
    try:
        major, minor = (int(p) for p in str(nb.version).split(".")[:2])
        return "role" if (major, minor) >= (3, 6) else "device_role"
    except Exception:
        return "role"


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
) -> tuple[Any, str | None]:
    """Create one NetBox device. Returns ``(device, None)``, or ``(None, error text)``."""
    body: dict[str, Any] = {
        "name": name,
        "device_type": device_type_id,
        role_key: role_id,
        "site": site_id,
        "status": status,
        "tags": [{"slug": _TAG_SLUG}],
    }
    if serial:
        body["serial"] = serial
    try:
        device = nb.dcim.devices.create(body)
    except Exception as exc:  # pynetbox RequestError etc.
        return None, str(exc)
    return device, None


def _assign_ip(
    nb: Any,
    *,
    device: Any,
    interface_name: str | None,
    address: str,
    vrf_id: int | None,
) -> tuple[str, str]:
    """Create/attach ``address`` on ``device`` and make it the primary IPv4.

    ``interface_name``, if given, is used exactly (created if the device
    doesn't have it — an explicit override, so it's trusted as-is). Otherwise
    the device's own interfaces — normally already populated from its NetBox
    device type's interface template (wired ports alongside any radios) — are
    searched for the first wired-Ethernet interface by name
    (:func:`bunnyauto.interface_match.pick_wired_interface`); a device with no
    wired interface at all (no template) gets a generic one created as a last
    resort.

    Returns ``(status, detail)``: ``status`` is ``"created"``, ``"exists"``, or
    ``"error"``; ``detail`` is the interface name used on success, or the error
    text on failure.
    """
    try:
        interfaces = list(nb.dcim.interfaces.filter(device_id=int(device.id)))
        if interface_name:
            interface = next((i for i in interfaces if str(i.name) == interface_name), None)
            if interface is None:
                interface = nb.dcim.interfaces.create(
                    {"device": int(device.id), "name": interface_name, "type": "other"}
                )
        else:
            picked = pick_wired_interface([(str(i.name), _type_value(i)) for i in interfaces])
            interface = (
                next((i for i in interfaces if str(i.name) == picked), None) if picked else None
            )
            if interface is None:
                interface = nb.dcim.interfaces.create(
                    {
                        "device": int(device.id),
                        "name": _FALLBACK_INTERFACE_NAME,
                        "type": "other",
                    }
                )

        existing = nb.ipam.ip_addresses.get(address=address)
        if existing is None:
            body: dict[str, Any] = {
                "address": address,
                "status": "active",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": int(interface.id),
            }
            if vrf_id is not None:
                body["vrf"] = vrf_id
            ip_obj = nb.ipam.ip_addresses.create(body)
            result = "created"
        else:
            if getattr(existing, "assigned_object_id", None) != int(interface.id):
                existing.update(
                    {
                        "assigned_object_type": "dcim.interface",
                        "assigned_object_id": int(interface.id),
                    }
                )
            ip_obj = existing
            result = "exists"

        device.update({"primary_ip4": int(ip_obj.id)})
    except Exception as exc:  # pynetbox RequestError etc.
        return "error", str(exc)
    return result, str(interface.name)


def _add_tag(device: Any) -> bool | str:
    """Add the ``wireless`` tag to an existing device. ``True`` on success, else error text."""
    try:
        slugs = sorted(set(normalize_tags(getattr(device, "tags", [])) + [_TAG_SLUG]))
        device.update({"tags": [{"slug": s} for s in slugs]})
    except Exception as exc:
        return str(exc)
    return True


def _result(
    *,
    apply: bool,
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
            f"{tag_planned} need the {_TAG_SLUG!r} tag — run with --apply"
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
