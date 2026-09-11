"""``fw-subnet-check`` — is a subnet already on the firewall, and in which policies?

Read-only. Connects to one FortiGate's REST API, pulls its address objects,
address groups and firewall policies, and reports how a user-supplied subnet
relates to what is already there:

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
    AddressMatch,
    InterfaceMatch,
    PolicyRef,
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
        for note in _catch_all_notes(report.catch_alls):
            ctx.reporter.info(note)
        for note in _interface_notes(report.interfaces):
            ctx.reporter.info(note)

        if not report.present:
            summary = f"{query} is not in use in any policies nor does it overlap/used by any already existing subnets. Please refer to notes if there are any"
            if report.permitted_by_catch_all:
                permitting = sum(1 for m in report.catch_alls if m.policies)
                summary += f" (but {permitting} catch-all object(s) permit it — see notes)"
            if report.on_interface:
                summary += (
                    f" ({len(report.interfaces)} interface address(es) in this range — see notes)"
                )
            return ToolResult(
                status=Status.OK,
                summary=summary,
                data=report.as_dict(),
            )

        noun = "object" if len(report.matches) == 1 else "objects"
        if report.attached:
            summary = (
                f"{query} is IN USE — {len(report.matches)} overlapping address {noun}, "
                f"referenced by {report.policy_count} policy/policies"
            )
        else:
            summary = (
                f"{query} exists on the firewall ({len(report.matches)} overlapping address "
                f"{noun}) but no policy references it"
            )
        return ToolResult(
            status=Status.DRIFT,
            summary=summary,
            changes=changes,
            data=report.as_dict(),
        )


def _format_refs(refs: list[PolicyRef]) -> str:
    return ", ".join(
        f"{ref.policyid}"
        + (f"/{ref.name}" if ref.name else "")
        + f" [{ref.field}"
        + (f" via {ref.via}" if ref.via else "")
        + "]"
        for ref in refs
    )


def _describe(match: AddressMatch) -> str:
    parts = [f"{match.cidr}  ({match.name})  {match.relation}"]
    if match.groups:
        parts.append(f"groups: {', '.join(match.groups)}")
    refs = _format_refs(match.policies) if match.policies else "none"
    parts.append(f"policies: {refs}")
    return "  —  ".join(parts)


def _catch_all_notes(catch_alls: list[AddressMatch]) -> list[str]:
    """Informational lines for ``0.0.0.0/0`` / ``::/0`` objects — never a match."""
    notes: list[str] = []
    for match in catch_alls:
        if match.policies:
            policy_ids = {ref.policyid for ref in match.policies}
            notes.append(
                f"note: the queried subnet is permitted by a catch-all, not a subnet-specific "
                f"object — {match.name} ({match.cidr}) is referenced by {len(policy_ids)} "
                f"policy/policies: {_format_refs(match.policies)}"
            )
        else:
            notes.append(
                f"note: address object {match.name} ({match.cidr}) matches everything "
                "but no policy references it"
            )
    return notes


_RELATION_PHRASE = {
    "exact": "is exactly",
    "supernet": "contains",
    "subnet": "sits inside",
    "overlap": "overlaps",
}


def _interface_notes(interfaces: list[InterfaceMatch]) -> list[str]:
    """Informational lines for live interface addresses — never a match/policy hit."""
    notes: list[str] = []
    for iface in interfaces:
        where = f" (vdom {iface.vdom})" if iface.vdom else ""
        phrase = _RELATION_PHRASE.get(iface.relation, iface.relation)
        notes.append(
            f"note: interface {iface.name}{where} has {iface.kind} address {iface.ip} "
            f"configured — its network {iface.network} {phrase} the queried range"
        )
    return notes


TOOL = FwSubnetCheck()
