"""``fw-subnet-check`` — is a subnet already on the firewall, and in which policies?

Read-only. Connects to one FortiGate's REST API, pulls its address objects,
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

This tool touches neither devices nor NetBox, so it declares
``needs_devices = needs_netbox = False`` and runs with only its own token set.
The firewall URL and the name of the token's env var come from the environment
in ``bunnyauto.yaml`` (``fw_url`` / ``fw_token_env``), or from ``--fw-url`` /
``--fw-token-env``.

Longer term this is the "does it already exist?" gate in front of a
subnet-creation pipeline; for now it only reports.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from bunnyauto.common import env_flag
from bunnyauto.errors import FirewallError
from bunnyauto.firewall.fortigate import FortiGateClient
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


@dataclass(slots=True)
class FwSubnetCheck:
    name: str = "fw-subnet-check"
    summary: str = "Check whether a subnet is already on the firewall and in which policies"
    writes: bool = False
    needs_devices: bool = False
    needs_netbox: bool = False

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

        verify = not args.fw_insecure
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
        finally:
            client.close()

        ctx.reporter.info(
            f"fetched {len(addresses)} address object(s), {len(groups)} group(s), "
            f"{len(policies)} policy/policies, {len(interfaces)} interface(s)"
        )

        report = analyze(query, addresses, groups, policies, interfaces=interfaces, vdom=args.vdom)
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
                    f"{query} is IN USE — {len(report.matches)} overlapping address {noun}, "
                    f"referenced by {report.policy_count} policy/policies"
                )
            else:
                summary = (
                    f"{query} exists on the firewall ({len(report.matches)} overlapping "
                    f"address {noun}) but no policy references it"
                )

        aside = _notes_aside(report)
        if aside:
            summary += f" ({aside} — see notes)"

        return ToolResult(
            status=Status.DRIFT if report.present else Status.OK,
            summary=summary,
            changes=changes,
            data=report.as_dict(),
        )


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
