"""``security subnet-check`` — is a subnet already on the firewall, and in which policies?

Connects to one FortiGate's REST API, pulls its address objects,
address groups and firewall policies — both policy CMDB endpoints, since a
FortiGate is in either profile-based NGFW mode (``firewall/policy``, GUI:
"Policy") or policy-based NGFW mode (``firewall/security-policy``, GUI:
"Security Policy" — the factory default on some higher-end models, e.g. the
900G/901G series); see :meth:`~bunnyauto.firewall.fortigate.FortiGateClient.policies` —
and reports how a user-supplied subnet relates to what is already there:

* **not present**  -> ``Status.OK``  (exit 0)  — nothing overlaps it; free to use.
* **present**      -> ``Status.DRIFT`` (exit 10) — an address object exists that is
  equal to, contains, or sits inside the queried subnet. ``data["in_use"]`` says
  whether any policy references it; an unreferenced object is still a name/space
  collision for anything that would later create it.
* **cannot check** -> ``Status.ERROR`` (exit 1) — bad input, or the firewall was
  unreachable / rejected the token.

It also checks the FortiGate's own configured interfaces (primary, secondary,
IPv6) for an address already sitting in the queried range. That is reported as
an informational note only (``data["on_interface"]`` / ``data["interfaces"]``)
and never changes ``present``/``in_use`` or the exit code — the tool's job is
the address-object/policy check above, not "is this IP alive on the box".

An address object wider than :data:`~bunnyauto.firewall.usage.MIN_MATCH_PREFIXLEN`
that merely *contains* the query (e.g. an RFC1918 supernet like ``10.0.0.0/8``)
is likewise never counted as a match — it always would be, making every check
"fail". See ``data["broad_matches"]`` / ``data["permitted_by_broad_match"]``.

All three of the above (catch-alls, broad supernets, interfaces) print as one
clean, indented "Notes" block rather than a dense run-on line.

**Free -> create it** (2026-09-24, owner request). When the check is green, the
tool offers to create an address object for the subnet on that same FortiGate:
``firewall/address`` type ``ipmask`` with the queried mask, or ``firewall/address6``
type ``ipprefix`` (:class:`~bunnyauto.firewall.fortigate.NewAddress`). It asks
"create it?", then the object's name (default: the subnet itself, e.g.
``10.20.30.0/24``; ``--name`` sets it), then — in a protected environment — for
the environment's name typed out, and creates nothing unless each answer says
so. A subnet the check found present is never offered. Where it asks:

* the hub: after every green check. The tool ``confirms_writes``, so the hub
  doesn't ask ``--apply`` up front — it asks once the result is known;
* the CLI: only with ``--apply`` (plan unless ``--apply``), on a terminal.
  ``--yes`` answers in advance (CI: ``--apply --yes``, name from ``--name``);
  ``--apply`` with neither a terminal nor ``--yes`` stops before connecting.

Created -> ``Status.CHANGED`` (exit 20). Free but not created (no ``--apply``,
or declined) stays ``OK``/0, so a pipeline that only checks keeps its 0/10/1
gate. Free but the create failed — the firewall refused it, or the name is
already an address object/group with no one there to pick another -> ``ERROR``/1.
``data["address_object"]`` (only when free) = ``name``/``subnet``/``endpoint``/
``comment``/``created``/``reason``. Nothing existing is ever updated, renamed or
deleted.

This tool touches neither devices nor NetBox, so it declares
``needs_devices = needs_netbox = False`` and runs with only its own token set.
The firewall URL and the name of the token's env var come from the environment
in ``bunnyauto.yaml`` (``fw_url`` / ``fw_token_env``), or from ``--fw-url`` /
``--fw-token-env``. Creating needs a token whose admin profile can write
firewall addresses.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from bunnyauto.common import env_flag
from bunnyauto.errors import FirewallError
from bunnyauto.firewall.fortigate import FortiGateClient, NewAddress
from bunnyauto.firewall.usage import (
    MIN_MATCH_PREFIXLEN,
    AddressMatch,
    InterfaceMatch,
    PolicyRef,
    UsageReport,
    analyze,
    parse_query,
)
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

#: The comment a new address object gets unless ``--comment`` says otherwise.
DEFAULT_COMMENT = "created by bunnyauto security subnet-check"


@dataclass(slots=True)
class FwSubnetCheck:
    name: str = "subnet-check"
    summary: str = (
        "Check whether a subnet is already on the firewall and in which policies; "
        "offer to create it if free"
    )
    writes: bool = True
    category: str = "security"
    needs_devices: bool = False
    needs_netbox: bool = False
    confirms_writes: bool = True
    apply_help: str = (
        "if the subnet is free, create an address object for it — asks first on a "
        "terminal (production: type the environment name); --yes creates it without asking"
    )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "subnet",
            help="the IPv4/IPv6 subnet or address to check, e.g. 10.20.30.0/24",
        )
        parser.add_argument(
            "--vdom",
            default="root",
            help="FortiGate VDOM to query (default: root)",
        )
        parser.add_argument(
            "--fw-url",
            dest="fw_url",
            default=None,
            help="firewall REST API base URL (default: the environment's fw_url)",
        )
        parser.add_argument(
            "--fw-token-env",
            dest="fw_token_env",
            default=None,
            help="name of the env var holding the firewall API token "
            "(default: the environment's fw_token_env)",
        )
        parser.add_argument(
            "--fw-insecure",
            dest="fw_insecure",
            action="store_true",
            default=env_flag("BUNNYAUTO_FW_INSECURE"),
            help="do not verify the firewall's TLS certificate",
        )
        parser.add_argument(
            "--name",
            default=None,
            help="name of the address object --apply creates "
            "(default: the subnet, e.g. 10.20.30.0/24; asked on a terminal)",
        )
        parser.add_argument(
            "--comment",
            default=DEFAULT_COMMENT,
            help=f"comment on the address object --apply creates (default: {DEFAULT_COMMENT!r})",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        try:
            query = parse_query(str(args.subnet))
        except ValueError as exc:
            raise FirewallError(
                f"{args.subnet!r} is not a valid IP subnet or address: {exc}",
                fix="pass something like 10.20.30.0/24 or 2001:db8:1::/64",
            ) from exc

        fw_url = (args.fw_url or ctx.environment.fw_url or "").strip().rstrip("/")
        if not fw_url:
            raise FirewallError(
                f"no firewall URL for environment {ctx.environment.name!r}",
                fix="add 'fw_url' to that environment in bunnyauto.yaml, or pass --fw-url",
            )

        token_env = (args.fw_token_env or ctx.environment.fw_token_env or "").strip()
        if not token_env:
            raise FirewallError(
                f"no firewall token env var configured for environment {ctx.environment.name!r}",
                fix="add 'fw_token_env' to that environment in bunnyauto.yaml, "
                "or pass --fw-token-env",
            )
        token = os.getenv(token_env, "").strip()
        if not token:
            raise FirewallError(
                f"{token_env} is not set — needed to authenticate to the firewall",
                fix=f"export {token_env}='<FortiGate REST API token>'",
            )

        # Fail before connecting rather than after the check: an --apply that can
        # never be confirmed would otherwise pass as "free, not created".
        if ctx.settings.apply and not (ctx.settings.assume_yes or ctx.interactive):
            raise FirewallError(
                "--apply needs --yes here: there is no terminal to confirm the new "
                "address object on",
                fix="add --yes to create it without asking (CI), or run it from a "
                "terminal or the hub",
            )

        verify = not args.fw_insecure
        where = f"{fw_url} (vdom {args.vdom})"
        ctx.reporter.step(
            f"querying {fw_url} (vdom={args.vdom}) for address objects, groups, "
            "policies and interfaces"
        )

        client = FortiGateClient(fw_url, token, vdom=args.vdom, verify=verify)
        try:
            with ctx.reporter.spinner(f"querying {fw_url}..."):
                addresses = client.addresses()
                groups = client.address_groups()
                policies = client.policies()
                interfaces = client.interfaces()

            ctx.reporter.info(
                f"fetched {len(addresses)} address object(s), {len(groups)} group(s), "
                f"{len(policies)} policy/policies, {len(interfaces)} interface(s)"
            )

            report = analyze(
                query, addresses, groups, policies, interfaces=interfaces, vdom=args.vdom
            )
            changes = [_describe(match) for match in report.matches]
            for line in changes:
                ctx.reporter.info(line)

            notes_block = _build_notes_block(report)
            if notes_block:
                ctx.reporter.info(notes_block)

            if not report.present:
                summary = f"{query} is not in use in any policies nor pre-existing IP object(s)."
            else:
                noun = "object" if len(report.matches) == 1 else "objects"
                if report.attached:
                    summary = (
                        f"{query} is IN USE — {len(report.matches)} overlapping address "
                        f"{noun}, referenced by {report.policy_count} policy/policies"
                    )
                else:
                    summary = (
                        f"{query} exists on the firewall ({len(report.matches)} overlapping "
                        f"address {noun}) but no policy references it"
                    )

            aside = _notes_aside(report)
            if aside:
                summary += f" ({aside} — see notes)"

            result = ToolResult(
                status=Status.DRIFT if report.present else Status.OK,
                summary=summary,
                changes=changes,
                data=report.as_dict(),
            )
            if not report.present:
                _offer_address(
                    ctx,
                    client,
                    query,
                    args,
                    where=where,
                    taken=_names_in_use(addresses, groups),
                    result=result,
                )
            return result
        finally:
            client.close()


# --- free -> create an address object for it ---------------------------------------


def _offer_address(
    ctx: Context,
    client: FortiGateClient,
    query: ipaddress.IPv4Network | ipaddress.IPv6Network,
    args: argparse.Namespace,
    *,
    where: str,
    taken: dict[str, str],
    result: ToolResult,
) -> None:
    """The subnet is free: create an address object for it, if the operator says so.

    Updates ``result`` in place — ``CHANGED`` once created, ``ERROR`` if it couldn't
    be, and left ``OK`` when there was no ``--apply`` or the answer was no.
    """
    address = NewAddress(
        name=(args.name or "").strip() or str(query),
        network=query,
        comment=(args.comment or "").strip(),
    )
    record = result.data["address_object"] = {
        **address.as_dict(),
        "created": False,
        "reason": None,
    }

    if not ctx.settings.apply:
        record["reason"] = "plan only (no --apply)"
        ctx.reporter.info(
            f"--apply would create address object {address.name!r} ({address.subnet}) on {where}"
        )
        return

    if ctx.interactive:  # the verdict, before the question it leads to
        ctx.reporter.success(result.summary)
    if not ctx.confirm(f"Create an address object for {query} on {where}"):
        _not_created(ctx, record, "declined")
        return

    name = address.name
    if not args.name:
        name = ctx.ask("Name for the new address object", default=name)
    while name in taken:
        clash = f"{name!r} is already the name of {taken[name]} on the firewall"
        if not ctx.interactive:
            _failed(result, record, query, f"{clash} — pass --name with an unused one")
            return
        ctx.reporter.warn(clash)
        name = ctx.ask("Another name (Enter to cancel)", default="")
        if not name:
            _not_created(ctx, record, "cancelled")
            return
    address = replace(address, name=name)
    record.update(address.as_dict())

    if not ctx.confirm_protected(f"create address object {name!r} ({address.subnet}) on {where}"):
        _not_created(ctx, record, "the environment name didn't match")
        return

    try:
        client.create_address(address)
    except FirewallError as exc:
        if exc.fix:
            ctx.reporter.warn(f"Fix: {exc.fix}")
        _failed(result, record, query, str(exc))
        return

    line = f"created address object {name!r} ({address.subnet}) on {where}"
    record.update(created=True, reason=None)
    ctx.reporter.success(line)
    result.status = Status.CHANGED
    result.summary = f"{query} was free — {line}"
    result.changes.append(line)


def _names_in_use(addresses: list[dict[str, Any]], groups: list[dict[str, Any]]) -> dict[str, str]:
    """Every address and group name on the box; a new object's name must be none of them."""
    taken = {str(group["name"]): "an address group" for group in groups if group.get("name")}
    taken.update({str(obj["name"]): "an address object" for obj in addresses if obj.get("name")})
    return taken


def _not_created(ctx: Context, record: dict[str, Any], reason: str) -> None:
    record["reason"] = reason
    ctx.reporter.info(f"no address object created ({reason})")


def _failed(
    result: ToolResult,
    record: dict[str, Any],
    query: ipaddress.IPv4Network | ipaddress.IPv6Network,
    reason: str,
) -> None:
    record["reason"] = reason
    result.status = Status.ERROR
    result.summary = f"{query} is free, but no address object was created: {reason}"


# --- plan-mode lines ----------------------------------------------------------------


def _format_policy_line(ref: PolicyRef) -> str:
    label = f"{ref.policyid}"
    if ref.name:
        label += f"/{ref.name}"
    field = ref.field
    if ref.via:
        field += f" via {ref.via}"
    tag = " (security-policy)" if ref.source == "security-policy" else ""
    return f"{label} [{field}]{tag}"


def _format_refs(refs: list[PolicyRef]) -> str:
    """Compact, comma-joined form — used in the dense plan-mode 'changes' list."""
    return ", ".join(_format_policy_line(ref) for ref in refs)


def _describe(match: AddressMatch) -> str:
    parts = [f"{match.cidr}  ({match.name})  {match.relation}"]
    if match.groups:
        parts.append(f"groups: {', '.join(match.groups)}")
    refs = _format_refs(match.policies) if match.policies else "none"
    parts.append(f"policies: {refs}")
    return "  —  ".join(parts)


# --- the Notes block: everything informational-only, never a match/policy hit --------
#
# Printed as one indented, hierarchical block (one reporter.info() call) instead of a
# long run-on line per object — a catch-all or broad supernet referenced by a dozen
# policies used to render as one dense, hard-to-read comma list.

_RELATION_PHRASE = {
    "exact": "is exactly",
    "supernet": "contains",
    "subnet": "sits inside",
    "overlap": "overlaps",
}


def _address_note_lines(matches: list[AddressMatch], indent: str) -> list[str]:
    lines: list[str] = []
    for match in matches:
        if match.policies:
            policy_ids = {ref.policyid for ref in match.policies}
            noun = "policy" if len(policy_ids) == 1 else "policy/policies"
            lines.append(
                f"{indent}- {match.name} ({match.cidr}) — referenced by {len(policy_ids)} {noun}:"
            )
            lines.extend(f"{indent}    · {_format_policy_line(ref)}" for ref in match.policies)
        else:
            lines.append(f"{indent}- {match.name} ({match.cidr}) — no policy references it")
    return lines


def _interface_note_lines(interfaces: list[InterfaceMatch], indent: str) -> list[str]:
    lines = []
    for iface in interfaces:
        where = f" (vdom {iface.vdom})" if iface.vdom else ""
        phrase = _RELATION_PHRASE.get(iface.relation, iface.relation)
        lines.append(
            f"{indent}- {iface.name}{where}: {iface.kind} address {iface.ip} — its network "
            f"{iface.network} {phrase} the queried range"
        )
    return lines


def _build_notes_block(report: UsageReport) -> str | None:
    """One clean block for catch-alls, broad supernets and interface addresses.

    All three are informational only — never present/in_use, never the exit code.
    Returns ``None`` when there's nothing to show.
    """
    indent = "    "
    sections: list[str] = []

    if report.catch_alls:
        sections.append(
            "  catch-all objects (match everything, not subnet-specific):\n"
            + "\n".join(_address_note_lines(report.catch_alls, indent))
        )

    if report.broad_matches:
        threshold = MIN_MATCH_PREFIXLEN.get(report.family)
        floor = f"/{threshold}" if threshold is not None else "the configured floor"
        sections.append(
            f"  broad address objects (wider than {floor} — e.g. RFC1918 supernets, "
            "not counted as a match):\n"
            + "\n".join(_address_note_lines(report.broad_matches, indent))
        )

    if report.interfaces:
        sections.append(
            "  interface addresses (live config, not an address object or policy):\n"
            + "\n".join(_interface_note_lines(report.interfaces, indent))
        )

    if not sections:
        return None
    return "Notes (informational — do not affect the pass/fail result):\n" + "\n".join(sections)


def _notes_aside(report: UsageReport) -> str:
    """Short summary-line clause pointing at the Notes block, or "" if there's nothing."""
    parts = []
    if report.catch_alls:
        parts.append(f"{len(report.catch_alls)} catch-all object(s)")
    if report.broad_matches:
        parts.append(f"{len(report.broad_matches)} broad supernet object(s)")
    if report.interfaces:
        parts.append(f"{len(report.interfaces)} interface address(es)")
    return ", ".join(parts)


TOOL = FwSubnetCheck()
