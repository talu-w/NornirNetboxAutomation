#!/usr/bin/env python3

"""
Collect Cisco VLAN, access-port, trunk, and switch-stack interface data.

Commands collected:
    show vlan brief
    show interfaces trunk

Output:
    reports/vlan_trunk_inventory/<hostname>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import pynetbox
from nornir import InitNornir
from nornir.core.configuration import Config
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command
from nornir_utils.plugins.functions import print_result


REPORT_ROOT = Path("reports/vlan_trunk_inventory")

SHOW_VLAN_COMMAND = "show vlan brief"
SHOW_TRUNK_COMMAND = "show interfaces trunk"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class InterfaceIdentity:
    original_name: str
    interface_type: str
    stack_member: int | None
    slot: int | None
    port: int | None
    subinterface: int | None = None
    logical_interface: bool = False


@dataclass
class AccessInterface:
    interface: str
    interface_type: str
    stack_member: int | None
    slot: int | None
    port: int | None
    vlan_id: int
    vlan_name: str
    vlan_status: str


@dataclass
class TrunkInterface:
    interface: str
    interface_type: str
    stack_member: int | None
    slot: int | None
    port: int | None

    mode: str = ""
    encapsulation: str = ""
    status: str = ""
    native_vlan: int | None = None

    allowed_vlans: list[int] = field(default_factory=list)
    active_vlans: list[int] = field(default_factory=list)
    forwarding_vlans: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Interface-name parsing
# ---------------------------------------------------------------------------

INTERFACE_TYPE_MAP = {
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "gi": "GigabitEthernet",
    "gig": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "ten": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "tw": "TwoGigabitEthernet",
    "two": "TwoGigabitEthernet",
    "twogigabitethernet": "TwoGigabitEthernet",
    "fo": "FortyGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "hu": "HundredGigabitEthernet",
    "hundredgigabitethernet": "HundredGigabitEthernet",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    "po": "Port-channel",
    "port-channel": "Port-channel",
    "portchannel": "Port-channel",
    "vl": "Vlan",
    "vlan": "Vlan",
    "lo": "Loopback",
    "loopback": "Loopback",
}


def parse_interface_name(interface_name: str) -> InterfaceIdentity:
    """
    Parse Cisco interface names and extract stack-member information.

    Examples:
        Gi1/0/48  -> member=1, slot=0, port=48
        Tw2/0/1   -> member=2, slot=0, port=1
        Te3/1/1   -> member=3, slot=1, port=1
        Gi0/24    -> standalone interface; slot=0, port=24
        Po10      -> logical interface
    """

    cleaned_name = interface_name.strip().replace(" ", "")

    # Physical stack interface:
    # Gi1/0/48
    # Tw2/0/1
    # Te3/1/1
    stack_match = re.match(
        r"^(?P<type>[A-Za-z-]+)"
        r"(?P<member>\d+)/"
        r"(?P<slot>\d+)/"
        r"(?P<port>\d+)"
        r"(?:\.(?P<subinterface>\d+))?$",
        cleaned_name,
    )

    if stack_match:
        interface_prefix = stack_match.group("type").lower()
        interface_type = INTERFACE_TYPE_MAP.get(
            interface_prefix,
            stack_match.group("type"),
        )

        return InterfaceIdentity(
            original_name=cleaned_name,
            interface_type=interface_type,
            stack_member=int(stack_match.group("member")),
            slot=int(stack_match.group("slot")),
            port=int(stack_match.group("port")),
            subinterface=(
                int(stack_match.group("subinterface"))
                if stack_match.group("subinterface")
                else None
            ),
            logical_interface=False,
        )

    # Standalone/modular two-number interface:
    # Gi0/24
    # Te1/1
    standalone_match = re.match(
        r"^(?P<type>[A-Za-z-]+)"
        r"(?P<slot>\d+)/"
        r"(?P<port>\d+)"
        r"(?:\.(?P<subinterface>\d+))?$",
        cleaned_name,
    )

    if standalone_match:
        interface_prefix = standalone_match.group("type").lower()
        interface_type = INTERFACE_TYPE_MAP.get(
            interface_prefix,
            standalone_match.group("type"),
        )

        return InterfaceIdentity(
            original_name=cleaned_name,
            interface_type=interface_type,
            stack_member=None,
            slot=int(standalone_match.group("slot")),
            port=int(standalone_match.group("port")),
            subinterface=(
                int(standalone_match.group("subinterface"))
                if standalone_match.group("subinterface")
                else None
            ),
            logical_interface=False,
        )

    # Logical interfaces:
    # Po1
    # Vlan10
    # Lo0
    logical_match = re.match(
        r"^(?P<type>[A-Za-z-]+)(?P<number>\d+)"
        r"(?:\.(?P<subinterface>\d+))?$",
        cleaned_name,
    )

    if logical_match:
        interface_prefix = logical_match.group("type").lower()
        interface_type = INTERFACE_TYPE_MAP.get(
            interface_prefix,
            logical_match.group("type"),
        )

        return InterfaceIdentity(
            original_name=cleaned_name,
            interface_type=interface_type,
            stack_member=None,
            slot=None,
            port=int(logical_match.group("number")),
            subinterface=(
                int(logical_match.group("subinterface"))
                if logical_match.group("subinterface")
                else None
            ),
            logical_interface=True,
        )

    return InterfaceIdentity(
        original_name=cleaned_name,
        interface_type="Unknown",
        stack_member=None,
        slot=None,
        port=None,
        logical_interface=True,
    )


# ---------------------------------------------------------------------------
# VLAN-list helpers
# ---------------------------------------------------------------------------

def expand_vlan_list(vlan_text: str) -> list[int]:
    """
    Expand Cisco VLAN expressions.

    Examples:
        "1,10,20-22" -> [1, 10, 20, 21, 22]
        "none"       -> []
        "all"        -> [1 ... 4094]
    """

    normalized = vlan_text.strip().lower()

    if not normalized or normalized in {"none", "n/a", "--"}:
        return []

    if normalized == "all":
        return list(range(1, 4095))

    vlan_ids: set[int] = set()

    for item in normalized.replace(" ", "").split(","):
        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", maxsplit=1)

            if not start_text.isdigit() or not end_text.isdigit():
                continue

            start_vlan = int(start_text)
            end_vlan = int(end_text)

            if start_vlan > end_vlan:
                start_vlan, end_vlan = end_vlan, start_vlan

            vlan_ids.update(range(start_vlan, end_vlan + 1))

        elif item.isdigit():
            vlan_ids.add(int(item))

    return sorted(vlan_ids)


def compress_vlan_list(vlan_ids: Iterable[int]) -> str:
    """
    Compress VLAN IDs for readable console output.

    Example:
        [1, 10, 20, 21, 22] -> "1,10,20-22"
    """

    sorted_vlans = sorted(set(vlan_ids))

    if not sorted_vlans:
        return "none"

    ranges: list[str] = []
    range_start = sorted_vlans[0]
    previous_vlan = sorted_vlans[0]

    for vlan_id in sorted_vlans[1:]:
        if vlan_id == previous_vlan + 1:
            previous_vlan = vlan_id
            continue

        if range_start == previous_vlan:
            ranges.append(str(range_start))
        else:
            ranges.append(f"{range_start}-{previous_vlan}")

        range_start = vlan_id
        previous_vlan = vlan_id

    if range_start == previous_vlan:
        ranges.append(str(range_start))
    else:
        ranges.append(f"{range_start}-{previous_vlan}")

    return ",".join(ranges)


# ---------------------------------------------------------------------------
# show vlan brief parser
# ---------------------------------------------------------------------------

def split_interface_list(interface_text: str) -> list[str]:
    """Split the interface-list section of show vlan brief."""

    return [
        interface.strip()
        for interface in interface_text.split(",")
        if interface.strip()
    ]


def parse_show_vlan_brief(output: str) -> tuple[list[dict[str, Any]], list[AccessInterface]]:
    """
    Parse Cisco IOS/IOS-XE 'show vlan brief'.

    Handles wrapped interface lines by retaining the current VLAN.
    """

    vlans: list[dict[str, Any]] = []
    access_interfaces: list[AccessInterface] = []

    current_vlan: dict[str, Any] | None = None

    vlan_line_pattern = re.compile(
        r"^\s*(?P<vlan_id>\d+)\s+"
        r"(?P<vlan_name>\S+)\s+"
        r"(?P<status>active|act/unsup|suspended|shutdown)"
        r"(?:\s+(?P<ports>.*))?$",
        re.IGNORECASE,
    )

    continuation_pattern = re.compile(
        r"^\s+(?P<ports>"
        r"(?:Fa|Gi|Te|Tw|Fo|Hu|Eth|Po)"
        r"\S+.*)$",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        line = raw_line.rstrip()

        if not line:
            continue

        if line.lower().startswith("vlan"):
            continue

        if set(line.strip()) <= {"-", " "}:
            continue

        vlan_match = vlan_line_pattern.match(line)

        if vlan_match:
            current_vlan = {
                "vlan_id": int(vlan_match.group("vlan_id")),
                "vlan_name": vlan_match.group("vlan_name"),
                "status": vlan_match.group("status"),
                "interfaces": [],
            }

            ports = vlan_match.group("ports") or ""
            current_vlan["interfaces"].extend(split_interface_list(ports))
            vlans.append(current_vlan)
            continue

        continuation_match = continuation_pattern.match(line)

        if continuation_match and current_vlan is not None:
            current_vlan["interfaces"].extend(
                split_interface_list(
                    continuation_match.group("ports")
                )
            )

    for vlan in vlans:
        for interface_name in vlan["interfaces"]:
            identity = parse_interface_name(interface_name)

            access_interfaces.append(
                AccessInterface(
                    interface=identity.original_name,
                    interface_type=identity.interface_type,
                    stack_member=identity.stack_member,
                    slot=identity.slot,
                    port=identity.port,
                    vlan_id=vlan["vlan_id"],
                    vlan_name=vlan["vlan_name"],
                    vlan_status=vlan["status"],
                )
            )

    return vlans, access_interfaces


# ---------------------------------------------------------------------------
# show interfaces trunk parser
# ---------------------------------------------------------------------------

TRUNK_SECTION_HEADERS = {
    "allowed": "vlans allowed on trunk",
    "active": "vlans allowed and active in management domain",
    "forwarding": "vlans in spanning tree forwarding state and not pruned",
}


def parse_show_interfaces_trunk(output: str) -> list[TrunkInterface]:
    """Parse Cisco IOS/IOS-XE 'show interfaces trunk' output."""

    trunk_map: dict[str, TrunkInterface] = {}
    current_section: str | None = None

    operational_trunk_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+"
        r"(?P<mode>\S+)\s+"
        r"(?P<encapsulation>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<native_vlan>\d+|-)\s*$"
    )

    vlan_membership_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+"
        r"(?P<vlans>(?:none|all|[\d,\-\s]+))\s*$",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        lowered_line = line.strip().lower()

        if not lowered_line:
            continue

        if lowered_line.startswith("port") and "native vlan" in lowered_line:
            current_section = "operational"
            continue

        matched_section = False

        for section_name, section_header in TRUNK_SECTION_HEADERS.items():
            if section_header in lowered_line:
                current_section = section_name
                matched_section = True
                break

        if matched_section:
            continue

        if set(line.strip()) <= {"-", " "}:
            continue

        if current_section == "operational":
            match = operational_trunk_pattern.match(line)

            if not match:
                continue

            interface_name = match.group("interface")
            identity = parse_interface_name(interface_name)

            native_vlan_text = match.group("native_vlan")

            trunk_map[interface_name] = TrunkInterface(
                interface=identity.original_name,
                interface_type=identity.interface_type,
                stack_member=identity.stack_member,
                slot=identity.slot,
                port=identity.port,
                mode=match.group("mode"),
                encapsulation=match.group("encapsulation"),
                status=match.group("status"),
                native_vlan=(
                    int(native_vlan_text)
                    if native_vlan_text.isdigit()
                    else None
                ),
            )

            continue

        if current_section in {"allowed", "active", "forwarding"}:
            match = vlan_membership_pattern.match(line)

            if not match:
                continue

            interface_name = match.group("interface")
            vlan_ids = expand_vlan_list(match.group("vlans"))

            if interface_name not in trunk_map:
                identity = parse_interface_name(interface_name)

                trunk_map[interface_name] = TrunkInterface(
                    interface=identity.original_name,
                    interface_type=identity.interface_type,
                    stack_member=identity.stack_member,
                    slot=identity.slot,
                    port=identity.port,
                )

            trunk = trunk_map[interface_name]

            if current_section == "allowed":
                trunk.allowed_vlans = vlan_ids
            elif current_section == "active":
                trunk.active_vlans = vlan_ids
            elif current_section == "forwarding":
                trunk.forwarding_vlans = vlan_ids

    return list(trunk_map.values())


# ---------------------------------------------------------------------------
# Stack-member organization
# ---------------------------------------------------------------------------

def interface_sort_key(interface_name: str) -> tuple[int, int, int, str]:
    identity = parse_interface_name(interface_name)

    member = identity.stack_member if identity.stack_member is not None else 9999
    slot = identity.slot if identity.slot is not None else 9999
    port = identity.port if identity.port is not None else 9999

    return member, slot, port, interface_name


def organize_by_stack_member(
    access_interfaces: list[AccessInterface],
    trunk_interfaces: list[TrunkInterface],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """
    Group access and trunk interfaces by stack member.

    Physical three-number names are grouped as:
        stack_member_1
        stack_member_2
        stack_member_3

    Two-number standalone interfaces are grouped under:
        standalone

    Port-channels and other logical interfaces are grouped under:
        logical
    """

    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: {
            "access_interfaces": [],
            "trunk_interfaces": [],
        }
    )

    def group_name(
        stack_member: int | None,
        interface_type: str,
    ) -> str:
        if stack_member is not None:
            return f"stack_member_{stack_member}"

        if interface_type in {"Port-channel", "Vlan", "Loopback", "Unknown"}:
            return "logical"

        return "standalone"

    for interface in access_interfaces:
        key = group_name(
            interface.stack_member,
            interface.interface_type,
        )

        grouped[key]["access_interfaces"].append(asdict(interface))

    for interface in trunk_interfaces:
        key = group_name(
            interface.stack_member,
            interface.interface_type,
        )

        grouped[key]["trunk_interfaces"].append(asdict(interface))

    for member_data in grouped.values():
        member_data["access_interfaces"].sort(
            key=lambda item: interface_sort_key(item["interface"])
        )
        member_data["trunk_interfaces"].sort(
            key=lambda item: interface_sort_key(item["interface"])
        )

    return dict(
        sorted(
            grouped.items(),
            key=lambda item: stack_group_sort_key(item[0]),
        )
    )


def stack_group_sort_key(group_name: str) -> tuple[int, int]:
    if group_name.startswith("stack_member_"):
        member_number = int(group_name.rsplit("_", maxsplit=1)[1])
        return 0, member_number

    if group_name == "standalone":
        return 1, 0

    return 2, 0


# ---------------------------------------------------------------------------
# Nornir task
# ---------------------------------------------------------------------------

def collect_vlan_and_trunk_data(task: Task) -> Result:
    """Collect and parse VLAN/trunk data from one device."""

    vlan_result = task.run(
        task=netmiko_send_command,
        name="Collecting VLAN information",
        command_string=SHOW_VLAN_COMMAND,
        read_timeout=60,
    )

    trunk_result = task.run(
        task=netmiko_send_command,
        name="Collecting trunk information",
        command_string=SHOW_TRUNK_COMMAND,
        read_timeout=60,
    )

    vlan_output = str(vlan_result.result)
    trunk_output = str(trunk_result.result)

    vlans, access_interfaces = parse_show_vlan_brief(vlan_output)
    trunk_interfaces = parse_show_interfaces_trunk(trunk_output)

    stack_members = organize_by_stack_member(
        access_interfaces=access_interfaces,
        trunk_interfaces=trunk_interfaces,
    )

    detected_members = sorted(
        {
            interface.stack_member
            for interface in access_interfaces + trunk_interfaces
            if interface.stack_member is not None
        }
    )

    report = {
        "hostname": task.host.name,
        "management_address": task.host.hostname,
        "platform": task.host.platform,
        # Prefer an inventory-provided NetBox primary key when available. This
        # is the safest mapping when a Nornir inventory name is not identical
        # to the NetBox device name.
        "netbox_device_id": (
            task.host.get("netbox_device_id")
            or task.host.get("device_id")
        ),
        "netbox_device_name": task.host.get("netbox_device_name"),
        "collected_at": datetime.now().astimezone().isoformat(),
        "commands": {
            "vlan": SHOW_VLAN_COMMAND,
            "trunk": SHOW_TRUNK_COMMAND,
        },
        "summary": {
            "vlan_count": len(vlans),
            "access_interface_count": len(access_interfaces),
            "trunk_interface_count": len(trunk_interfaces),
            "detected_stack_members": detected_members,
            "detected_stack_member_count": len(detected_members),
        },
        "vlans": vlans,
        "access_interfaces": [
            asdict(interface)
            for interface in sorted(
                access_interfaces,
                key=lambda item: interface_sort_key(item.interface),
            )
        ],
        "trunk_interfaces": [
            asdict(interface)
            for interface in sorted(
                trunk_interfaces,
                key=lambda item: interface_sort_key(item.interface),
            )
        ],
        "stack_members": stack_members,
    }

    report_file = save_report(
        hostname=task.host.name,
        report=report,
    )

    report["report_file"] = str(report_file)

    return Result(
        host=task.host,
        result=report,
        changed=False,
    )


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def save_report(hostname: str, report: dict[str, Any]) -> Path:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)

    safe_hostname = re.sub(
        r"[^A-Za-z0-9_.-]",
        "_",
        hostname,
    )

    report_file = REPORT_ROOT / f"{safe_hostname}.json"

    report_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8",
    )

    return report_file


def print_device_summary(hostname: str, report: dict[str, Any]) -> None:
    summary = report["summary"]

    print()
    print("=" * 90)
    print(f"DEVICE: {hostname}")
    print("=" * 90)

    detected_members = summary["detected_stack_members"]

    if detected_members:
        print(
            "Detected stack members: "
            + ", ".join(str(member) for member in detected_members)
        )
    else:
        print("Detected stack members: none; device appears standalone")

    print(f"Configured VLANs: {summary['vlan_count']}")
    print(f"Access interfaces: {summary['access_interface_count']}")
    print(f"Operational trunks: {summary['trunk_interface_count']}")
    print(f"JSON report: {report['report_file']}")

    for member_name, member_data in report["stack_members"].items():
        print()
        print(f"[{member_name}]")

        access_interfaces = member_data["access_interfaces"]
        trunk_interfaces = member_data["trunk_interfaces"]

        if access_interfaces:
            print("  Access interfaces:")

            for interface in access_interfaces:
                print(
                    f"    {interface['interface']:<12} "
                    f"VLAN {interface['vlan_id']:<4} "
                    f"{interface['vlan_name']}"
                )

        if trunk_interfaces:
            print("  Trunk interfaces:")

            for interface in trunk_interfaces:
                print(
                    f"    {interface['interface']:<12} "
                    f"native={interface['native_vlan']} "
                    f"allowed={compress_vlan_list(interface['allowed_vlans'])} "
                    f"active={compress_vlan_list(interface['active_vlans'])} "
                    f"forwarding="
                    f"{compress_vlan_list(interface['forwarding_vlans'])}"
                )

        if not access_interfaces and not trunk_interfaces:
            print("  No interfaces discovered")


# ---------------------------------------------------------------------------
# NetBox synchronization
# ---------------------------------------------------------------------------

@dataclass
class SyncSummary:
    device: str
    dry_run: bool
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)


def related_id(value: Any) -> int | None:
    """Return an object's numeric ID from pynetbox's possible representations."""

    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        object_id = value.get("id")
    else:
        object_id = getattr(value, "id", None)
    return int(object_id) if object_id is not None else None


def related_ids(values: Any) -> list[int]:
    return sorted(
        object_id
        for object_id in (related_id(value) for value in (values or []))
        if object_id is not None
    )


def choice_value(value: Any) -> str | None:
    """Normalize pynetbox Choice/dict/string values (such as interface.mode)."""

    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("value")
    return getattr(value, "value", str(value))


def interface_signature(interface_name: str) -> tuple[str, int | None, int | None, int | None, int | None]:
    """Canonical signature used to match short and long Cisco interface names."""

    identity = parse_interface_name(interface_name)
    return (
        identity.interface_type.casefold(),
        identity.stack_member,
        identity.slot,
        identity.port,
        identity.subinterface,
    )


def build_interface_indexes(
    interfaces: Iterable[Any],
) -> tuple[dict[str, list[Any]], dict[tuple[Any, ...], list[Any]]]:
    by_name: dict[str, list[Any]] = defaultdict(list)
    by_signature: dict[tuple[Any, ...], list[Any]] = defaultdict(list)

    for interface in interfaces:
        name = str(interface.name).strip()
        by_name[name.casefold()].append(interface)
        by_signature[interface_signature(name)].append(interface)

    return dict(by_name), dict(by_signature)


def match_interface(
    discovered_name: str,
    by_name: dict[str, list[Any]],
    by_signature: dict[tuple[Any, ...], list[Any]],
) -> tuple[Any | None, str | None]:
    """Match only within the already-resolved device; never cross devices."""

    exact = by_name.get(discovered_name.strip().casefold(), [])
    if len(exact) == 1:
        return exact[0], None
    if len(exact) > 1:
        return None, f"ambiguous exact interface name {discovered_name!r}"

    signature_matches = by_signature.get(interface_signature(discovered_name), [])
    if len(signature_matches) == 1:
        return signature_matches[0], None
    if len(signature_matches) > 1:
        names = ", ".join(sorted(str(item.name) for item in signature_matches))
        return None, f"ambiguous canonical match for {discovered_name!r}: {names}"
    return None, f"interface {discovered_name!r} not found on this device"


def resolve_device(nb: Any, report: dict[str, Any]) -> Any:
    """Resolve a device by inventory PK, then by an explicit/exact name."""

    device_id = report.get("netbox_device_id")
    if device_id not in (None, ""):
        device = nb.dcim.devices.get(int(device_id))
        if device is None:
            raise LookupError(f"NetBox device ID {device_id} was not found")
        return device

    name = report.get("netbox_device_name") or report["hostname"]
    matches = list(nb.dcim.devices.filter(name=name))
    exact = [item for item in matches if str(item.name).casefold() == str(name).casefold()]
    if len(exact) != 1:
        raise LookupError(
            f"expected one exact NetBox device named {name!r}; found {len(exact)}. "
            "Set netbox_device_id in Nornir host data to disambiguate."
        )
    return exact[0]


def vlan_scope_id(vlan: Any) -> int | None:
    """Support both legacy site-scoped and current generic-scope VLAN records."""

    direct_scope = related_id(getattr(vlan, "scope", None)) or related_id(
        getattr(vlan, "site", None)
    )
    if direct_scope is not None:
        return direct_scope

    group = getattr(vlan, "group", None)
    if group is None:
        return None
    return related_id(getattr(group, "scope", None)) or related_id(
        getattr(group, "site", None)
    )


def build_vlan_cache(nb: Any) -> dict[int, list[Any]]:
    cache: dict[int, list[Any]] = defaultdict(list)
    for vlan in nb.ipam.vlans.all():
        cache[int(vlan.vid)].append(vlan)
    return dict(cache)


def resolve_vlan(
    vlan_cache: dict[int, list[Any]],
    vlan_id: int,
    device: Any,
) -> tuple[Any | None, str | None]:
    candidates = vlan_cache.get(vlan_id, [])
    if not candidates:
        return None, f"VLAN {vlan_id} does not exist in NetBox"
    if len(candidates) == 1:
        return candidates[0], None

    site_id = related_id(getattr(device, "site", None))
    if site_id is not None:
        scoped = [item for item in candidates if vlan_scope_id(item) == site_id]
        if len(scoped) == 1:
            return scoped[0], None

    candidate_ids = ", ".join(str(item.id) for item in candidates)
    return None, (
        f"VLAN {vlan_id} is ambiguous for device {device.name!r}; "
        f"candidate NetBox IDs: {candidate_ids}"
    )


def current_interface_state(interface: Any) -> dict[str, Any]:
    return {
        "mode": choice_value(getattr(interface, "mode", None)),
        "untagged_vlan": related_id(getattr(interface, "untagged_vlan", None)),
        "tagged_vlans": related_ids(getattr(interface, "tagged_vlans", [])),
    }


def sync_report_to_netbox(
    nb: Any,
    report: dict[str, Any],
    vlan_cache: dict[int, list[Any]],
    dry_run: bool,
) -> SyncSummary:
    """Synchronize one collected device report to its NetBox interfaces."""

    device = resolve_device(nb, report)
    summary = SyncSummary(device=str(device.name), dry_run=dry_run)
    interfaces = list(nb.dcim.interfaces.filter(device_id=device.id))
    by_name, by_signature = build_interface_indexes(interfaces)

    desired_interfaces: list[tuple[str, str, int | None, list[int]]] = []
    for access in report["access_interfaces"]:
        desired_interfaces.append(
            (access["interface"], "access", int(access["vlan_id"]), [])
        )
    for trunk in report["trunk_interfaces"]:
        native_vlan = (
            int(trunk["native_vlan"])
            if trunk.get("native_vlan") is not None
            else None
        )
        allowed_vlans = [int(vlan_id) for vlan_id in trunk.get("allowed_vlans", [])]
        # IOS renders an unrestricted trunk as "all" (1-4094). Assigning all
        # 4094 IDs would make the update fail for every VLAN not represented in
        # NetBox, so use the device's active VLAN set in that case.
        if len(allowed_vlans) == 4094:
            allowed_vlans = [
                int(vlan_id) for vlan_id in trunk.get("active_vlans", [])
            ]

        desired_interfaces.append(
            (
                trunk["interface"],
                "tagged",
                native_vlan,
                [
                    int(vlan_id)
                    for vlan_id in allowed_vlans
                    # NetBox represents the native VLAN only as untagged; do
                    # not also assign it to tagged_vlans.
                    if int(vlan_id) != native_vlan
                ],
            )
        )

    for discovered_name, mode, untagged_vid, tagged_vids in desired_interfaces:
        interface, match_error = match_interface(discovered_name, by_name, by_signature)
        if match_error:
            summary.skipped += 1
            summary.errors.append(match_error)
            continue

        untagged_vlan = None
        if untagged_vid is not None:
            untagged_vlan, vlan_error = resolve_vlan(vlan_cache, untagged_vid, device)
            if vlan_error:
                summary.skipped += 1
                summary.errors.append(f"{discovered_name}: {vlan_error}")
                continue

        tagged_vlan_objects: list[Any] = []
        tagged_errors: list[str] = []
        for vlan_id in sorted(set(tagged_vids)):
            vlan, vlan_error = resolve_vlan(vlan_cache, vlan_id, device)
            if vlan_error:
                tagged_errors.append(vlan_error)
            elif vlan is not None:
                tagged_vlan_objects.append(vlan)

        if tagged_errors:
            summary.skipped += 1
            summary.errors.append(
                f"{discovered_name}: refusing partial trunk update: "
                + "; ".join(tagged_errors)
            )
            continue

        desired = {
            "mode": mode,
            "untagged_vlan": related_id(untagged_vlan),
            "tagged_vlans": sorted(int(vlan.id) for vlan in tagged_vlan_objects),
        }
        current = current_interface_state(interface)
        if current == desired:
            summary.unchanged += 1
            continue

        description = (
            f"{interface.name}: {current} -> {desired}"
        )
        if dry_run:
            summary.updated += 1
            summary.changes.append(f"DRY-RUN {description}")
            continue

        try:
            interface.update(desired)
            summary.updated += 1
            summary.changes.append(description)
        except Exception as exc:  # report API validation/transport errors per interface
            summary.errors.append(f"{interface.name}: NetBox update failed: {exc}")

    return summary


def print_sync_summary(summary: SyncSummary) -> None:
    label = "DRY-RUN" if summary.dry_run else "NETBOX"
    print()
    print(
        f"[{label}] {summary.device}: updated={summary.updated} "
        f"unchanged={summary.unchanged} skipped={summary.skipped} "
        f"errors={len(summary.errors)}"
    )
    for change in summary.changes:
        print(f"  CHANGE: {change}")
    for error in summary.errors:
        print(f"  ERROR: {error}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect Cisco interface VLAN state and synchronize it to NetBox."
    )
    parser.add_argument("--config", default="config.yaml", help="Nornir config file")
    parser.add_argument(
        "--tag",
        default="nornirtest",
        help="Only process NetBox devices with this tag (default: nornirtest)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read NetBox and show changes without writing them",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Create JSON reports without connecting to NetBox",
    )
    return parser.parse_args()


def inventory_device_id(host: Any) -> int | None:
    """Return a NetBox device ID supplied by the inventory plugin, if present."""

    value = host.get("netbox_device_id") or host.get("device_id") or host.get("id")
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def select_tagged_hosts(nr: Any, tagged_devices: Iterable[Any]) -> Any:
    """Match NetBox's tagged-device result to the loaded Nornir inventory."""

    device_ids = {int(device.id) for device in tagged_devices}
    device_names = {str(device.name).casefold() for device in tagged_devices}

    def is_tagged(host: Any) -> bool:
        host_device_id = inventory_device_id(host)
        inventory_name = str(host.get("netbox_device_name") or host.name).casefold()
        return (
            host_device_id in device_ids
            if host_device_id is not None
            else inventory_name in device_names
        )

    return nr.filter(filter_func=is_tagged)


def load_netbox_inventory_options(config_file: str, netbox_token: str) -> dict[str, Any]:
    """Load inventory options without discarding nb_url or plugin settings."""

    config_path = Path(config_file).expanduser()
    try:
        inventory_options = dict(
            Config.from_file(config_file=str(config_path)).inventory.options
        )
    except Exception as exc:
        raise SystemExit(
            f"Unable to load Nornir config {config_path}: {exc}"
        ) from exc
    netbox_url = str(inventory_options.get("nb_url") or "").strip().rstrip("/")
    if not netbox_url:
        raise SystemExit(
            f"NetBox URL is missing from {config_path}. Set "
            "inventory.options.nb_url in the Nornir configuration."
        )
    if not netbox_url.startswith(("http://", "https://")):
        raise SystemExit(
            f"Invalid inventory.options.nb_url in {config_path}: {netbox_url!r}. "
            "Include http:// or https://."
        )

    inventory_options["nb_url"] = netbox_url
    inventory_options["nb_token"] = netbox_token
    return inventory_options


def configure_pynetbox_session(nb: Any, inventory_options: dict[str, Any]) -> None:
    """Apply the Nornir NetBox SSL setting to pynetbox's separate session."""

    ssl_verify = inventory_options.get("ssl_verify", True)
    if isinstance(ssl_verify, str):
        ssl_verify = ssl_verify.strip().casefold() not in {"false", "no", "0", "off"}

    nb.http_session.verify = ssl_verify
    if ssl_verify is False:
        LOGGER.warning(
            "SSL certificate verification is disabled for the pynetbox session"
        )


def main() -> int:
    args = parse_arguments()
    netbox_token = os.getenv("NB_TOKEN")
    nornir_username = os.getenv("NORNIR_USERNAME")
    nornir_password = os.getenv("NORNIR_PASSWORD")
    if not netbox_token:
        raise SystemExit(
            "NB_TOKEN is not set. Export the NetBox API token first: "
            "export NB_TOKEN='your-token'"
        )
    if not nornir_username or not nornir_password:
        raise SystemExit(
            "NORNIR_USERNAME and NORNIR_PASSWORD must both be set before "
            "connecting to network devices."
        )

    # Preserve every configured inventory option while replacing only the API
    # token. Passing just {"nb_token": ...} can replace the options mapping and
    # make NetBoxInventory2 fall back to http://localhost:8080.
    inventory_options = load_netbox_inventory_options(args.config, netbox_token)
    netbox_url = inventory_options["nb_url"]
    LOGGER.info("Using NetBox API URL from %s: %s", args.config, netbox_url)

    nr = InitNornir(
        config_file=args.config,
        inventory={"options": inventory_options},
    )
    # NetBox supplies the hosts and management addresses; device login
    # credentials come from the same environment variables used by the other
    # Nornir scripts in this project. Inventory defaults are inherited by each
    # host when Netmiko opens its Paramiko-backed SSH connection.
    nr.inventory.defaults.username = nornir_username
    nr.inventory.defaults.password = nornir_password

    exit_code = 0

    try:
        nb = pynetbox.api(netbox_url, token=netbox_token)
        configure_pynetbox_session(nb, inventory_options)
        tagged_devices = list(nb.dcim.devices.filter(tag=args.tag))
        switches = select_tagged_hosts(nr, tagged_devices)

        LOGGER.info(
            "NetBox tag %r selected %d device(s); %d matched the Nornir inventory",
            args.tag,
            len(tagged_devices),
            len(switches.inventory.hosts),
        )
        if not tagged_devices:
            LOGGER.warning("No NetBox devices have the tag %r; nothing to do", args.tag)
            return 0
        if not switches.inventory.hosts:
            LOGGER.error(
                "Devices with tag %r were found, but none matched the Nornir inventory",
                args.tag,
            )
            return 1

        results = switches.run(
            task=collect_vlan_and_trunk_data,
            name="Collecting VLAN and switch-stack information",
        )

        successful_reports: list[dict[str, Any]] = []
        for hostname, multi_result in results.items():
            if multi_result.failed:
                exit_code = 1
                print()
                print(f"[FAILED] {hostname}")
                print_result(multi_result)
                continue

            # The parent task is normally the first result.
            report = multi_result[0].result

            if not isinstance(report, dict):
                print(f"[FAILED] No structured report returned for {hostname}")
                continue

            print_device_summary(hostname, report)
            successful_reports.append(report)

        if not args.collect_only:
            vlan_cache = build_vlan_cache(nb)

            # Deliberately synchronize sequentially: a pynetbox API/session is
            # not shared among Nornir worker threads.
            for report in successful_reports:
                try:
                    sync_summary = sync_report_to_netbox(
                        nb=nb,
                        report=report,
                        vlan_cache=vlan_cache,
                        dry_run=args.dry_run,
                    )
                    report["netbox_sync"] = asdict(sync_summary)
                    save_report(report["hostname"], report)
                    print_sync_summary(sync_summary)
                    if sync_summary.errors:
                        exit_code = 1
                except Exception as exc:
                    exit_code = 1
                    LOGGER.exception(
                        "NetBox synchronization failed for %s: %s",
                        report["hostname"],
                        exc,
                    )

    finally:
        nr.close_connections()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
