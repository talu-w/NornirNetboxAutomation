"""``wireless-sync`` — create NetBox WLCs/APs from an Aruba Conductor, tag them ``wireless``.

Reads the Conductor's device inventory over its read-only REST API
(``show switches`` + ``show ap database long``), compares it to NetBox by serial
then name, and:

* creates every WLC/AP NetBox is missing — role ``wireless``, device type matched
  from the Aruba model string, site derived from the hostname prefix — each
  stamped with the ``wireless`` tag;
* adds the ``wireless`` tag to Conductor devices that already exist in NetBox but
  are not yet tagged.

It never updates or deletes an existing device, and never creates a device type
or a site. A device whose model has no matching NetBox device type, or whose
hostname maps to no site (and no ``--default-site`` was given), is reported and
skipped.

Plans by default; ``--apply`` writes. Auth is the shared device login
(``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``); TLS verification is always on unless
``--aruba-insecure`` is passed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bunnyauto.aruba.conductor import ArubaConductorClient
from bunnyauto.aruba.inventory import WirelessDevice, parse_ap_database, parse_switches
from bunnyauto.aruba.sitematch import Site, match_site
from bunnyauto.common import env_flag, normalize_tags
from bunnyauto.errors import ArubaError, ToolError
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

_TAG_SLUG = "wireless"
_ROLE_SLUG = "wireless"


@dataclass(slots=True)
class _Outcome:
    device: WirelessDevice
    action: str  # "in-sync" | "tag" | "create" | "blocked"
    site: str = ""
    device_type: str = ""
    reason: str = ""


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

        role_key = _role_key(nb)
        outcomes = [
            self._classify(d, by_serial, by_name, types_by_key, sites, default_site)
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
        created = tagged = create_planned = tag_planned = 0
        failures: list[str] = []
        blocked: list[str] = []

        for out in outcomes:
            d = out.device
            data[d.name] = {
                "kind": d.kind,
                "serial": d.serial,
                "action": out.action,
                "site": out.site,
                "device_type": out.device_type,
                "reason": out.reason,
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
                if apply:
                    err = _create_device(
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
        return _Outcome(
            d,
            "create",
            site=site.slug,
            device_type=str(getattr(device_type, "model", "")),
        )


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
) -> str | None:
    """Create one NetBox device. Returns ``None`` on success, else the error text."""
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
        nb.dcim.devices.create(body)
    except Exception as exc:  # pynetbox RequestError etc.
        return str(exc)
    return None


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
    total: int,
) -> ToolResult:
    progressed = bool(created or tagged or create_planned or tag_planned)
    if failures or blocked:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and (created or tagged):
        status = Status.CHANGED
    elif create_planned or tag_planned:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"created {created} device(s), tagged {tagged} existing device(s)"
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

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


TOOL = WirelessSync()
