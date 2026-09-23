"""``wired create-interfaces`` — discover device interfaces and create the missing ones in NetBox.

Ported from ``create_interfaces_netbox.py``. Plans by default; ``--apply`` writes.
It never updates or deletes an interface — only creates ones NetBox is missing.
Name matching and the NetBox type a new interface gets both come from
:mod:`bunnyauto.netbox.interfaces`, shared with every other tool.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

from bunnyauto.common import first_error
from bunnyauto.errors import ToolError
from bunnyauto.netbox.devices import get_netbox_device, select_tagged_inventory
from bunnyauto.netbox.interfaces import canonical_name, interface_type
from bunnyauto.tools.base import Status, ToolResult, add_common_arguments

if TYPE_CHECKING:
    from bunnyauto.context import Context

_DISABLED_STATES = {"administratively down", "admin down", "disabled"}


@dataclass(frozen=True)
class DiscoveredInterface:
    name: str
    description: str = ""
    enabled: bool = True


def parse_interfaces(rows: Any, include_virtual: bool) -> list[DiscoveredInterface]:
    if not isinstance(rows, list):
        raise ToolError(
            "'show interfaces' did not return structured data — check that "
            "ntc-templates supports this platform's TextFSM template"
        )

    discovered: dict[str, DiscoveredInterface] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("interface") or row.get("port") or "").strip()
        if not name:
            continue
        if interface_type(name) == "virtual" and not include_virtual:
            continue
        status = str(row.get("link_status") or row.get("status") or "").casefold()
        discovered.setdefault(
            canonical_name(name),
            DiscoveredInterface(
                name=name,
                description=str(row.get("description") or "").strip(),
                enabled=status not in _DISABLED_STATES,
            ),
        )
    return sorted(discovered.values(), key=lambda item: canonical_name(item.name))


def _collect(task: Task, include_virtual: bool) -> Result:
    collected = task.run(
        task=netmiko_send_command,
        name="show interfaces",
        command_string="show interfaces",
        use_textfsm=True,
        read_timeout=120,
    )
    return Result(
        host=task.host,
        changed=False,
        result=parse_interfaces(collected.result, include_virtual),
    )


@dataclass(slots=True)
class CreateInterfaces:
    name: str = "create-interfaces"
    summary: str = "Create NetBox interfaces that a device has but NetBox is missing"
    writes: bool = True
    category: str = "wired"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_common_arguments(parser)
        parser.add_argument(
            "--device",
            default=None,
            help="limit to one device by name (must still be in scope)",
        )
        parser.add_argument(
            "--include-virtual",
            action="store_true",
            dest="include_virtual",
            help="also create loopbacks, VLANs, and tunnels (Port-Channels are always included)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        nb = ctx.netbox()
        tagged = ctx.target_devices()
        if args.device:
            wanted = args.device.casefold()
            tagged = [d for d in tagged if str(d.name).casefold() == wanted]
            if not tagged:
                raise ToolError(
                    f"device {args.device!r} was not found in scope ({ctx.scope().describe()})"
                )
        if not tagged:
            return ToolResult(
                status=Status.OK,
                summary=f"no NetBox devices in scope ({ctx.scope().describe()})",
            )

        selected = select_tagged_inventory(ctx.nornir(), tagged)
        if not selected.inventory.hosts:
            raise ToolError("no tagged NetBox devices matched the Nornir inventory")

        ctx.reporter.step(f"discovering interfaces on {len(selected.inventory.hosts)} device(s)")
        with ctx.reporter.track(selected, description="create-interfaces: discover") as tracked:
            run_result = tracked.run(
                task=_collect,
                name="create-interfaces: discover",
                include_virtual=args.include_virtual,
            )

        changes: list[str] = []
        data: dict[str, Any] = {}
        failures: list[str] = []
        successes: list[str] = []
        created_total = 0

        for host_name, multi in run_result.items():
            discovered = _discovered(multi)
            if multi.failed or discovered is None:
                message = first_error(multi, "interface discovery failed")
                failures.append(host_name)
                data[host_name] = {"ok": False, "error": message}
                ctx.reporter.error(f"{host_name}: {message}")
                continue

            try:
                host = selected.inventory.hosts[host_name]
                device = get_netbox_device(nb, host)
                existing = {
                    canonical_name(i.name)
                    for i in nb.dcim.interfaces.filter(device_id=int(device.id))
                }
                missing = [i for i in discovered if canonical_name(i.name) not in existing]
            except Exception as exc:  # pynetbox RequestError etc.
                failures.append(host_name)
                data[host_name] = {"ok": False, "error": str(exc)}
                ctx.reporter.error(f"{host_name}: NetBox lookup failed: {exc}")
                continue

            for iface in missing:
                verb = "create" if ctx.settings.apply else "would create"
                changes.append(f"{device.name}: {verb} {iface.name} ({interface_type(iface.name)})")

            host_created = 0
            if missing and ctx.settings.apply:
                try:
                    host_created = _create(nb, int(device.id), missing)
                    created_total += host_created
                    ctx.reporter.success(f"{device.name}: created {host_created} interface(s)")
                except Exception as exc:
                    failures.append(host_name)
                    data[host_name] = {"ok": False, "error": f"create failed: {exc}"}
                    ctx.reporter.error(f"{device.name}: create failed: {exc}")
                    continue
            elif not missing:
                ctx.reporter.info(f"{device.name}: NetBox already has every interface")

            successes.append(host_name)
            data[host_name] = {
                "ok": True,
                "discovered": len(discovered),
                "missing": [i.name for i in missing],
                "created": host_created,
            }

        applied = ctx.settings.apply
        if failures and successes:
            status = Status.PARTIAL
        elif failures:
            status = Status.ERROR
        elif applied and created_total:
            status = Status.CHANGED
        elif changes:
            status = Status.DRIFT
        else:
            status = Status.OK

        if applied:
            summary = f"created {created_total} interface(s)"
        elif changes:
            summary = (
                f"{len(changes)} interface(s) missing from NetBox — run with --apply to create"
            )
        else:
            summary = "NetBox is in sync — no interfaces to create"
        if failures:
            summary += f" ({len(failures)} device(s) failed)"

        return ToolResult(status=status, summary=summary, changes=changes, data=data)


def _create(nb: Any, device_id: int, interfaces: list[DiscoveredInterface]) -> int:
    payload = [
        {
            "device": device_id,
            "name": iface.name,
            "type": interface_type(iface.name),
            "enabled": iface.enabled,
            "description": iface.description,
        }
        for iface in interfaces
    ]
    created = nb.dcim.interfaces.create(payload)
    return len(created) if isinstance(created, list) else 1


def _discovered(multi) -> list[DiscoveredInterface] | None:
    for item in multi:
        if isinstance(item.result, list) and all(
            isinstance(v, DiscoveredInterface) for v in item.result
        ):
            return item.result
    return None


TOOL = CreateInterfaces()
