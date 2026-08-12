#!/usr/bin/env python3

"""Synchronize Cisco interface VLAN assignments to NetBox.

Workflow:
    1. Load the NetBox-backed Nornir inventory.
    2. Select devices carrying the requested NetBox tag.
    3. Collect access, voice, trunk, link-state, and description data.
    4. Resolve duplicate voice VLAN IDs using each VLAN SVI address and the
       prefixes assigned to candidate VLANs in NetBox.
    5. Compare that state with each NetBox interface.
    6. Update only interfaces whose VLAN or metadata state differs.

The script does not create VLANs or interfaces. Missing or ambiguous NetBox
objects are reported and skipped so that partial assignments are never made.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import pynetbox
from nornir import InitNornir
from nornir.core.configuration import Config
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command
from nornir_utils.plugins.functions import print_result
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TAG = "nornirtest"
SHOW_VLAN = "show vlan brief"
SHOW_TRUNKS = "show interfaces trunk"
SHOW_SWITCHPORTS = "show interfaces switchport"
SHOW_INTERFACE_STATUS = "show interfaces status"
SHOW_INTERFACE_DESCRIPTIONS = "show interfaces description"

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Collected and synchronization state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InterfaceVlanState:
    """NetBox-compatible VLAN state collected for one interface."""

    name: str
    mode: str
    untagged_vlan: int | None = None
    tagged_vlans: tuple[int, ...] = ()
    voice_vlan: int | None = None


@dataclass
class SwitchportState:
    """Access and auxiliary voice VLANs reported for one switchport."""

    name: str
    administrative_mode: str = ""
    operational_mode: str = ""
    access_vlan: int | None = None
    voice_vlan: int | None = None


@dataclass(frozen=True)
class InterfaceMetadataState:
    """Operational state and configured description for one interface."""

    name: str
    enabled: bool | None = None
    description: str | None = None
    device_status: str = ""


@dataclass
class TrunkState:
    name: str
    native_vlan: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    active_vlans: list[int] = field(default_factory=list)
    allows_all: bool = False
    allowed_seen: bool = False
    active_seen: bool = False


@dataclass
class CollectedDevice:
    inventory_name: str
    netbox_device_id: int | None
    interfaces: list[InterfaceVlanState]
    interface_metadata: list[InterfaceMetadataState] = field(default_factory=list)
    vlan_svi_addresses: dict[int, tuple[str, ...]] = field(default_factory=dict)


@dataclass
class SyncSummary:
    device: str
    dry_run: bool
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class InterfaceSearchScope:
    """NetBox devices and interfaces belonging to one managed switch/stack."""

    connected_device: Any
    master_device: Any
    virtual_chassis: Any | None
    members_by_position: dict[int, Any]
    indexes_by_device_id: dict[
        int,
        tuple[dict[str, list[Any]], dict[tuple[str, str], list[Any]]],
    ]


@dataclass
class VlanCache:
    """VLANs plus their full VLAN-group records, indexed for resolution."""

    by_vid: dict[int, list[Any]]
    by_id: dict[int, Any]
    groups_by_id: dict[int, Any]
    prefixes_by_vlan_id: dict[int, list[Any]] = field(default_factory=dict)


@dataclass
class DeviceScopeContext:
    """NetBox scopes applicable to one physical device, with specificity."""

    ranks: dict[tuple[str, int], int]


# ---------------------------------------------------------------------------
# Cisco output parsing
# ---------------------------------------------------------------------------


def expand_vlan_list(value: str) -> list[int]:
    """Expand a Cisco VLAN expression such as ``1,10,20-22``."""

    value = value.strip().lower().replace(" ", "")
    if not value or value in {"none", "n/a", "--"}:
        return []
    if value == "all":
        return list(range(1, 4095))

    vlan_ids: set[int] = set()
    for item in value.split(","):
        if not item:
            continue
        if "-" not in item:
            if item.isdigit():
                vlan_ids.add(int(item))
            continue

        start_text, end_text = item.split("-", maxsplit=1)
        if not start_text.isdigit() or not end_text.isdigit():
            continue
        start, end = int(start_text), int(end_text)
        if start > end:
            start, end = end, start
        vlan_ids.update(range(start, end + 1))

    return sorted(vlan_ids)


def parse_vlan_brief(output: str) -> dict[str, int]:
    """Return access-interface to VLAN-ID mappings from ``show vlan brief``."""

    access_ports: dict[str, int] = {}
    current_vlan: int | None = None

    vlan_line = re.compile(
        r"^\s*(?P<vid>\d+)\s+\S+\s+"
        r"(?:active|act/unsup|suspended|shutdown)"
        r"(?:\s+(?P<ports>.*))?$",
        re.IGNORECASE,
    )
    continuation = re.compile(
        r"^\s+(?P<ports>"
        r"[A-Za-z][A-Za-z-]*\d\S*"
        r"(?:\s*,\s*[A-Za-z][A-Za-z-]*\d\S*)*"
        r")\s*$"
    )

    def add_ports(port_text: str, vlan_id: int) -> None:
        for port_name in port_text.split(","):
            port_name = port_name.strip()
            if port_name:
                access_ports[port_name] = vlan_id

    for raw_line in output.splitlines():
        match = vlan_line.match(raw_line.rstrip())
        if match:
            current_vlan = int(match.group("vid"))
            add_ports(match.group("ports") or "", current_vlan)
            continue

        match = continuation.match(raw_line.rstrip())
        if match and current_vlan is not None:
            add_ports(match.group("ports"), current_vlan)

    return access_ports


def parse_trunks(output: str) -> dict[str, TrunkState]:
    """Return operational trunk state from ``show interfaces trunk``."""

    trunks: dict[str, TrunkState] = {}
    section: str | None = None
    last_port_by_section: dict[str, str] = {}

    operational_line = re.compile(
        r"^\s*(?P<port>\S+)\s+\S+\s+\S+\s+\S+\s+"
        r"(?P<native>\d+|-)\s*$"
    )
    vlan_line = re.compile(
        r"^\s*(?P<port>\S+)\s+"
        r"(?P<vlans>(?:none|all|[\d,\-\s]+))\s*$",
        re.IGNORECASE,
    )
    vlan_continuation = re.compile(
        r"^\s+(?P<vlans>[\d,\-\s]+)\s*$",
        re.IGNORECASE,
    )

    def add_vlan_expression(
        trunk: TrunkState,
        current_section: str,
        expression: str,
    ) -> None:
        normalized = expression.strip().lower().replace(" ", "")
        vlan_ids = expand_vlan_list(normalized)
        if current_section == "allowed":
            trunk.allowed_seen = True
            trunk.allowed_vlans = sorted(set(trunk.allowed_vlans) | set(vlan_ids))
            trunk.allows_all = trunk.allows_all or normalized in {"all", "1-4094"}
        elif current_section == "active":
            trunk.active_seen = True
            trunk.active_vlans = sorted(set(trunk.active_vlans) | set(vlan_ids))

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        lowered = line.strip().lower()
        if not lowered:
            continue

        if lowered.startswith("port") and "native vlan" in lowered:
            section = "operational"
            continue
        if "vlans allowed on trunk" in lowered:
            section = "allowed"
            continue
        if "vlans allowed and active in management domain" in lowered:
            section = "active"
            continue
        if "vlans in spanning tree forwarding state and not pruned" in lowered:
            section = "forwarding"
            continue
        if lowered.startswith("port") or set(line.strip()) <= {"-", " "}:
            continue

        if section == "operational":
            match = operational_line.match(line)
            if not match:
                continue
            port = match.group("port")
            native = match.group("native")
            trunks[port] = TrunkState(
                name=port,
                native_vlan=int(native) if native.isdigit() else None,
            )
            continue

        if section not in {"allowed", "active", "forwarding"}:
            continue
        match = vlan_line.match(line)
        if match:
            port = match.group("port")
            last_port_by_section[section] = port
            trunk = trunks.setdefault(port, TrunkState(name=port))
            add_vlan_expression(trunk, section, match.group("vlans"))
            continue

        # Some platforms wrap long VLAN expressions onto an indented line
        # without repeating the interface name.
        continuation_match = vlan_continuation.match(line)
        previous_port = last_port_by_section.get(section)
        if continuation_match and previous_port is not None:
            trunk = trunks.setdefault(previous_port, TrunkState(name=previous_port))
            add_vlan_expression(trunk, section, continuation_match.group("vlans"))

    return trunks


def parse_switchports(output: str) -> dict[str, SwitchportState]:
    """Parse access and voice VLANs from ``show interfaces switchport``."""

    switchports: dict[str, SwitchportState] = {}
    current: SwitchportState | None = None

    name_line = re.compile(r"^\s*Name:\s*(?P<name>\S+)\s*$", re.IGNORECASE)
    mode_line = re.compile(
        r"^\s*Operational Mode:\s*(?P<mode>.+?)\s*$",
        re.IGNORECASE,
    )
    administrative_mode_line = re.compile(
        r"^\s*Administrative Mode:\s*(?P<mode>.+?)\s*$",
        re.IGNORECASE,
    )
    access_line = re.compile(
        r"^\s*Access Mode VLAN:\s*(?P<vid>\d+|\S+)",
        re.IGNORECASE,
    )
    voice_line = re.compile(
        r"^\s*Voice VLAN:\s*(?P<vid>\d+|\S+)",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        match = name_line.match(raw_line)
        if match:
            name = match.group("name")
            current = SwitchportState(name=name)
            switchports[name.casefold()] = current
            continue
        if current is None:
            continue

        match = administrative_mode_line.match(raw_line)
        if match:
            current.administrative_mode = match.group("mode").strip()
            continue
        match = mode_line.match(raw_line)
        if match:
            current.operational_mode = match.group("mode").strip()
            continue
        match = access_line.match(raw_line)
        if match:
            value = match.group("vid")
            current.access_vlan = int(value) if value.isdigit() else None
            continue
        match = voice_line.match(raw_line)
        if match:
            value = match.group("vid")
            current.voice_vlan = int(value) if value.isdigit() else None

    return switchports


def table_column_starts(
    header: str,
    column_names: tuple[str, ...],
) -> tuple[int, ...] | None:
    """Locate fixed-width Cisco table columns in their expected order."""

    lowered = header.casefold()
    starts: list[int] = []
    search_from = 0
    for column_name in column_names:
        position = lowered.find(column_name.casefold(), search_from)
        if position < 0:
            return None
        starts.append(position)
        search_from = position + len(column_name)
    return tuple(starts)


def parse_interface_status(output: str) -> dict[str, InterfaceMetadataState]:
    """Parse exact connected/notconnect state from ``show interfaces status``."""

    lines = output.splitlines()
    starts: tuple[int, ...] | None = None
    header_index = -1
    for index, line in enumerate(lines):
        starts = table_column_starts(line, ("Port", "Name", "Status", "Vlan"))
        if starts is not None:
            header_index = index
            break
    if starts is None:
        return {}

    port_start, name_start, status_start, vlan_start = starts
    metadata: dict[str, InterfaceMetadataState] = {}
    for line in lines[header_index + 1 :]:
        if len(line) <= port_start:
            continue
        port = line[port_start:name_start].strip()
        if not port or set(port) <= {"-"}:
            continue

        name = line[name_start:status_start].strip()
        status = line[status_start:vlan_start].strip().casefold()
        enabled: bool | None = None
        if status == "connected":
            enabled = True
        elif status == "notconnect":
            enabled = False

        # The Name column is Cisco's interface description, but it may be
        # truncated. It is retained only as a fallback for platforms that do
        # not return a description-table entry.
        metadata[port.casefold()] = InterfaceMetadataState(
            name=port,
            enabled=enabled,
            description=name or None,
            device_status=status,
        )
    return metadata


def parse_interface_descriptions(output: str) -> dict[str, str]:
    """Parse descriptions from ``show interfaces description``."""

    lines = output.splitlines()
    header_index = -1
    for index, line in enumerate(lines):
        starts = table_column_starts(
            line,
            ("Interface", "Status", "Protocol", "Description"),
        )
        if starts is not None:
            header_index = index
            break
    if header_index < 0:
        return {}

    row_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s{2,}"
        r"(?P<status>.*?)\s{2,}"
        r"(?P<protocol>\S+)"
        r"(?:\s{2,}(?P<description>.*))?\s*$"
    )
    descriptions: dict[str, str] = {}
    for line in lines[header_index + 1 :]:
        match = row_pattern.match(line)
        if not match:
            continue
        interface = match.group("interface")
        descriptions[interface.casefold()] = (
            match.group("description") or ""
        ).strip()
    return descriptions


def build_interface_metadata(
    status_output: str,
    description_output: str,
) -> list[InterfaceMetadataState]:
    """Merge live port status with authoritative interface descriptions."""

    status_by_name = parse_interface_status(status_output)
    descriptions = parse_interface_descriptions(description_output)
    status_by_signature = {
        interface_signature(state.name): state
        for state in status_by_name.values()
    }
    descriptions_by_signature: dict[
        tuple[str, str],
        list[tuple[str, str]],
    ] = defaultdict(list)
    for name, description in descriptions.items():
        descriptions_by_signature[interface_signature(name)].append(
            (name, description)
        )

    signatures = set(status_by_signature) | set(descriptions_by_signature)
    merged: list[InterfaceMetadataState] = []
    for signature in signatures:
        status_state = status_by_signature.get(signature)
        description_entries = descriptions_by_signature.get(signature, [])
        nonempty_descriptions = {
            description
            for _name, description in description_entries
            if description
        }
        if len(nonempty_descriptions) > 1:
            LOGGER.warning(
                "Conflicting descriptions found for interface signature %s: %s; "
                "using the longest value",
                signature,
                sorted(nonempty_descriptions),
            )
        if description_entries:
            # A blank description-table row means the device has no configured
            # description; never replace it with the potentially truncated
            # Name column from show interfaces status.
            description = max(nonempty_descriptions, key=len, default=None)
        else:
            description = status_state.description if status_state else None

        name = (
            status_state.name
            if status_state is not None
            else description_entries[0][0]
        )
        merged.append(
            InterfaceMetadataState(
                name=name,
                enabled=status_state.enabled if status_state else None,
                description=description or None,
                device_status=status_state.device_status if status_state else "",
            )
        )
    return sorted(merged, key=lambda item: interface_sort_key(item.name))


def parse_svi_addresses(output: str) -> tuple[str, ...]:
    """Return routed addresses shown for a Cisco VLAN interface."""

    address_pattern = re.compile(
        r"(?:Internet address is|Secondary address(?: is)?)\s+"
        r"(?P<address>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
        re.IGNORECASE,
    )
    addresses: set[str] = set()
    for match in address_pattern.finditer(output):
        try:
            addresses.add(str(ipaddress.ip_interface(match.group("address"))))
        except ValueError:
            LOGGER.warning("Ignoring invalid SVI address %r", match.group("address"))
    return tuple(sorted(addresses))


def build_collected_state(
    vlan_output: str,
    trunk_output: str,
    switchport_output: str,
) -> list[InterfaceVlanState]:
    """Combine command output into one desired state per discovered interface."""

    desired: dict[str, InterfaceVlanState] = {}
    for interface, vlan_id in parse_vlan_brief(vlan_output).items():
        desired[interface.casefold()] = InterfaceVlanState(
            name=interface,
            mode="access",
            untagged_vlan=vlan_id,
        )

    # show vlan brief can list a phone port under both its data and voice
    # VLANs, making a dict-based parse dependent on row order. The switchport
    # output is authoritative because it labels both roles explicitly.
    for switchport in parse_switchports(switchport_output).values():
        if "trunk" in (
            switchport.administrative_mode + " " + switchport.operational_mode
        ).casefold():
            continue
        if switchport.access_vlan is None and switchport.voice_vlan is None:
            continue

        tagged = (
            (switchport.voice_vlan,)
            if switchport.voice_vlan is not None
            and switchport.voice_vlan != switchport.access_vlan
            else ()
        )
        desired[switchport.name.casefold()] = InterfaceVlanState(
            name=switchport.name,
            # A data+voice port carries the data VLAN untagged and the voice
            # VLAN tagged, which NetBox represents with mode="tagged".
            mode="tagged" if tagged else "access",
            untagged_vlan=switchport.access_vlan,
            tagged_vlans=tagged,
            voice_vlan=switchport.voice_vlan,
        )

    for interface, trunk in parse_trunks(trunk_output).items():
        if not trunk.allowed_seen:
            LOGGER.warning(
                "%s: trunk was detected but its allowed-VLAN list was not "
                "parsed; leaving this interface unchanged",
                interface,
            )
            continue
        # An unrestricted Cisco trunk is reported as all/1-4094. Only VLANs
        # active on this device are meaningful interface assignments in NetBox.
        tagged = trunk.active_vlans if trunk.allows_all else trunk.allowed_vlans
        tagged = sorted(set(tagged) - {trunk.native_vlan})
        desired[interface.casefold()] = InterfaceVlanState(
            name=interface,
            mode="tagged",
            untagged_vlan=trunk.native_vlan,
            tagged_vlans=tuple(tagged),
            voice_vlan=None,
        )

    return sorted(desired.values(), key=lambda item: interface_sort_key(item.name))


def collect_device_state(task: Task, ambiguous_vlan_ids: set[int]) -> Result:
    """Nornir task: collect and parse VLAN state from one device."""

    vlan_result = task.run(
        task=netmiko_send_command,
        name=SHOW_VLAN,
        command_string=SHOW_VLAN,
        read_timeout=60,
    )
    trunk_result = task.run(
        task=netmiko_send_command,
        name=SHOW_TRUNKS,
        command_string=SHOW_TRUNKS,
        read_timeout=60,
    )
    switchport_result = task.run(
        task=netmiko_send_command,
        name=SHOW_SWITCHPORTS,
        command_string=SHOW_SWITCHPORTS,
        read_timeout=90,
    )
    status_result = task.run(
        task=netmiko_send_command,
        name=SHOW_INTERFACE_STATUS,
        command_string=SHOW_INTERFACE_STATUS,
        read_timeout=60,
    )
    description_result = task.run(
        task=netmiko_send_command,
        name=SHOW_INTERFACE_DESCRIPTIONS,
        command_string=SHOW_INTERFACE_DESCRIPTIONS,
        read_timeout=60,
    )

    switchport_output = str(switchport_result.result)
    voice_vlan_ids = {
        switchport.voice_vlan
        for switchport in parse_switchports(switchport_output).values()
        if switchport.voice_vlan is not None
    }
    vlan_svi_addresses: dict[int, tuple[str, ...]] = {}
    for vlan_id in sorted(voice_vlan_ids & ambiguous_vlan_ids):
        command = f"show interfaces vlan {vlan_id}"
        svi_result = task.run(
            task=netmiko_send_command,
            name=command,
            command_string=command,
            read_timeout=60,
        )
        vlan_svi_addresses[vlan_id] = parse_svi_addresses(str(svi_result.result))

    collected = CollectedDevice(
        inventory_name=task.host.name,
        netbox_device_id=inventory_device_id(task.host),
        interfaces=build_collected_state(
            str(vlan_result.result),
            str(trunk_result.result),
            switchport_output,
        ),
        interface_metadata=build_interface_metadata(
            str(status_result.result),
            str(description_result.result),
        ),
        vlan_svi_addresses=vlan_svi_addresses,
    )
    return Result(host=task.host, result=collected, changed=False)


# ---------------------------------------------------------------------------
# Nornir inventory and NetBox connection
# ---------------------------------------------------------------------------


def load_inventory_options(config_file: str, token: str) -> dict[str, Any]:
    """Load all inventory options and replace only the NetBox API token."""

    config_path = Path(config_file).expanduser()
    try:
        options = dict(Config.from_file(str(config_path)).inventory.options)
    except Exception as exc:
        raise RuntimeError(f"Unable to load Nornir config {config_path}: {exc}") from exc

    netbox_url = str(options.get("nb_url") or "").strip().rstrip("/")
    if not netbox_url.startswith(("http://", "https://")):
        raise ValueError(
            f"inventory.options.nb_url in {config_path} must start with "
            "http:// or https://"
        )

    options["nb_url"] = netbox_url
    options["nb_token"] = token
    return options


def ssl_verify_setting(value: Any) -> bool | str:
    """Normalize YAML/string SSL verification settings for Requests."""

    if not isinstance(value, str):
        return bool(value)
    normalized = value.strip().casefold()
    if normalized in {"false", "no", "0", "off"}:
        return False
    if normalized in {"true", "yes", "1", "on"}:
        return True
    return value  # A Requests-compatible CA bundle path.


def create_netbox_client(
    netbox_url: str,
    token: str,
    inventory_options: dict[str, Any],
) -> Any:
    """Create the pynetbox client using the inventory's SSL policy."""

    nb = pynetbox.api(netbox_url, token=token)
    verify = ssl_verify_setting(inventory_options.get("ssl_verify", True))
    nb.http_session.verify = verify
    if verify is False:
        LOGGER.warning("SSL certificate verification is disabled for NetBox")
    return nb


def inventory_device_id(host: Any) -> int | None:
    """Get the NetBox device ID exposed by common inventory plugin versions."""

    value = host.get("netbox_device_id") or host.get("device_id") or host.get("id")
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def match_inventory_host(host: Any, devices: Iterable[Any]) -> Any | None:
    """Match a Nornir host to exactly one tagged NetBox device."""

    device_list = list(devices)
    host_id = inventory_device_id(host)
    if host_id is not None:
        matches = [device for device in device_list if int(device.id) == host_id]
        return matches[0] if len(matches) == 1 else None

    host_name = str(host.get("netbox_device_name") or host.name).casefold()
    matches = [
        device for device in device_list if str(device.name).casefold() == host_name
    ]
    return matches[0] if len(matches) == 1 else None


def select_tagged_inventory(nr: Any, tagged_devices: list[Any]) -> Any:
    """Limit Nornir to tagged devices and attach their authoritative IDs."""

    selected = nr.filter(
        filter_func=lambda host: match_inventory_host(host, tagged_devices) is not None
    )
    for host in selected.inventory.hosts.values():
        device = match_inventory_host(host, tagged_devices)
        if device is not None:
            host.data["netbox_device_id"] = int(device.id)
            host.data["netbox_device_name"] = str(device.name)
    return selected


# ---------------------------------------------------------------------------
# NetBox object matching and comparison
# ---------------------------------------------------------------------------


INTERFACE_PREFIXES = {
    "fa": "fa",
    "fastethernet": "fa",
    "gi": "gi",
    "gig": "gi",
    "gigabitethernet": "gi",
    "te": "te",
    "ten": "te",
    "tengige": "te",
    "tengigabitethernet": "te",
    "tw": "tw",
    "two": "tw",
    "twogige": "tw",
    "twogigabitethernet": "tw",
    "twe": "twe",
    "twentyfivegige": "twe",
    "twentyfivegigabitethernet": "twe",
    "fo": "fo",
    "fortygige": "fo",
    "fortygigabitethernet": "fo",
    "hu": "hu",
    "hundredgige": "hu",
    "hundredgigabitethernet": "hu",
    "fou": "fou",
    "fourhundredgige": "fou",
    "fourhundredgigabitethernet": "fou",
    "eth": "eth",
    "ethernet": "eth",
    "po": "po",
    "port-channel": "po",
    "portchannel": "po",
    "fi":"fi",
    "fivegigabitethernet":"fi",
    "ap":"ap",
    "appgigabitethernet":"ap",
}


def interface_signature(name: str) -> tuple[str, str]:
    """Normalize short and long Cisco interface names for safe matching."""

    cleaned = name.strip().replace(" ", "")
    match = re.match(r"^(?P<prefix>[A-Za-z-]+)(?P<number>.+)$", cleaned)
    if not match:
        return "", cleaned.casefold()
    prefix = match.group("prefix").casefold()
    return INTERFACE_PREFIXES.get(prefix, prefix), match.group("number").casefold()


def interface_sort_key(name: str) -> tuple[str, tuple[int, ...], str]:
    prefix, number = interface_signature(name)
    numeric_parts = tuple(int(part) for part in re.findall(r"\d+", number))
    return prefix, numeric_parts, number


def interface_indexes(
    interfaces: Iterable[Any],
) -> tuple[dict[str, list[Any]], dict[tuple[str, str], list[Any]]]:
    by_name: dict[str, list[Any]] = defaultdict(list)
    by_signature: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for interface in interfaces:
        name = str(interface.name).strip()
        by_name[name.casefold()].append(interface)
        by_signature[interface_signature(name)].append(interface)
    return dict(by_name), dict(by_signature)


def match_interface(
    name: str,
    by_name: dict[str, list[Any]],
    by_signature: dict[tuple[str, str], list[Any]],
) -> tuple[Any | None, str | None]:
    exact = by_name.get(name.strip().casefold(), [])
    if len(exact) == 1:
        return exact[0], None
    if len(exact) > 1:
        return None, f"ambiguous exact interface name {name!r}"

    canonical = by_signature.get(interface_signature(name), [])
    if len(canonical) == 1:
        return canonical[0], None
    if len(canonical) > 1:
        names = ", ".join(sorted(str(item.name) for item in canonical))
        return None, f"ambiguous interface match for {name!r}: {names}"
    return None, f"interface {name!r} does not exist on this NetBox device"


def related_id(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        value = value.get("id")
    else:
        value = getattr(value, "id", None)
    return int(value) if value is not None else None


def related_ids(values: Any) -> list[int]:
    return sorted(
        object_id
        for object_id in (related_id(value) for value in (values or []))
        if object_id is not None
    )


def choice_value(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("value")
    return getattr(value, "value", str(value))


def object_type_value(value: Any) -> str | None:
    """Normalize a NetBox generic-relation object type to ``app.model``."""

    if value is None or isinstance(value, str):
        return value.casefold() if isinstance(value, str) else None
    if isinstance(value, dict):
        direct = value.get("value")
        app_label = value.get("app_label")
        model = value.get("model")
    else:
        direct = getattr(value, "value", None)
        app_label = getattr(value, "app_label", None)
        model = getattr(value, "model", None)
    if direct:
        return str(direct).casefold()
    if app_label and model:
        return f"{app_label}.{model}".casefold()
    return None


def build_vlan_cache(nb: Any) -> VlanCache:
    by_vid: dict[int, list[Any]] = defaultdict(list)
    by_id: dict[int, Any] = {}
    for vlan in nb.ipam.vlans.all():
        by_vid[int(vlan.vid)].append(vlan)
        by_id[int(vlan.id)] = vlan

    groups_by_id = {
        int(group.id): group for group in nb.ipam.vlan_groups.all()
    }
    return VlanCache(
        by_vid=dict(by_vid),
        by_id=by_id,
        groups_by_id=groups_by_id,
    )


def load_vlan_prefixes(
    nb: Any,
    cache: VlanCache,
    vlan_ids: Iterable[int],
) -> None:
    """Cache NetBox prefixes for duplicate VLAN candidates used by SVI matching."""

    candidate_object_ids = {
        int(vlan.id)
        for vid in set(vlan_ids)
        for vlan in cache.by_vid.get(vid, [])
        if len(cache.by_vid.get(vid, [])) > 1
    }
    for object_id in sorted(candidate_object_ids):
        if object_id in cache.prefixes_by_vlan_id:
            continue
        cache.prefixes_by_vlan_id[object_id] = list(
            nb.ipam.prefixes.filter(vlan_id=object_id)
        )


def resolve_vlan_from_svi(
    cache: VlanCache,
    vlan_id: int,
    candidates: list[Any],
    svi_addresses: tuple[str, ...],
) -> tuple[Any | None, str | None]:
    """Resolve a duplicate VID using the SVI address and VLAN-linked prefixes."""

    if not svi_addresses:
        return None, (
            f"VLAN {vlan_id} is ambiguous and show interfaces vlan {vlan_id} "
            "returned no routed IP address"
        )

    parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for value in svi_addresses:
        try:
            parsed_addresses.append(ipaddress.ip_interface(value).ip)
        except ValueError:
            continue

    matches: list[Any] = []
    candidate_details: list[str] = []
    for vlan in candidates:
        prefixes = cache.prefixes_by_vlan_id.get(int(vlan.id), [])
        prefix_values = [str(prefix.prefix) for prefix in prefixes]
        candidate_details.append(
            f"ID {vlan.id} prefixes={prefix_values or ['none']}"
        )
        matched = False
        for prefix_value in prefix_values:
            try:
                network = ipaddress.ip_network(prefix_value, strict=False)
            except ValueError:
                continue
            if any(
                address.version == network.version and address in network
                for address in parsed_addresses
            ):
                matched = True
                break
        if matched:
            matches.append(vlan)

    if len(matches) == 1:
        LOGGER.info(
            "Resolved duplicate voice VLAN %d to NetBox VLAN ID %s using SVI %s",
            vlan_id,
            matches[0].id,
            ", ".join(svi_addresses),
        )
        return matches[0], None

    outcome = "no candidates matched" if not matches else (
        "multiple candidates matched: "
        + ", ".join(str(vlan.id) for vlan in matches)
    )
    return None, (
        f"VLAN {vlan_id} remains ambiguous after SVI lookup "
        f"({', '.join(svi_addresses)}): {outcome}; "
        + "; ".join(candidate_details)
    )


def vlan_scope_key(
    vlan: Any,
    cache: VlanCache,
) -> tuple[tuple[str, int] | None, str]:
    """Return the typed scope key and a useful diagnostic label for a VLAN."""

    # Direct site assignment is retained for older/current NetBox versions,
    # although NetBox now recommends VLAN groups instead.
    site_id = related_id(getattr(vlan, "site", None))
    if site_id is not None:
        return ("dcim.site", site_id), f"site:{site_id}"

    group_id = related_id(getattr(vlan, "group", None))
    if group_id is None:
        return None, "global"
    group = cache.groups_by_id.get(group_id)
    if group is None:
        return None, f"group:{group_id} (scope unavailable)"

    scope_type = object_type_value(getattr(group, "scope_type", None))
    scope_id = related_id(getattr(group, "scope", None)) or integer_value(
        getattr(group, "scope_id", None)
    )
    if scope_type is None or scope_id is None:
        return None, f"group:{group_id} global"
    return (scope_type, scope_id), f"group:{group_id} {scope_type}:{scope_id}"


def add_scope_chain(
    endpoint: Any,
    initial: Any,
    scope_type: str,
    starting_rank: int,
    ranks: dict[tuple[str, int], int],
) -> None:
    """Add an object and its parent chain, highest specificity first."""

    object_id = related_id(initial)
    seen: set[int] = set()
    rank = starting_rank
    while object_id is not None and object_id not in seen:
        seen.add(object_id)
        key = (scope_type, object_id)
        ranks[key] = max(rank, ranks.get(key, -1))
        record = endpoint.get(object_id)
        if record is None:
            break
        object_id = related_id(getattr(record, "parent", None))
        rank -= 1


def build_device_scope_context(nb: Any, device: Any) -> DeviceScopeContext:
    """Build all VLAN-group scopes which can apply to a physical device."""

    ranks: dict[tuple[str, int], int] = {}
    site = getattr(device, "site", None)
    site_id = related_id(site)
    if site_id is not None:
        ranks[("dcim.site", site_id)] = 60
        full_site = nb.dcim.sites.get(site_id)
        if full_site is not None:
            add_scope_chain(
                nb.dcim.site_groups,
                getattr(full_site, "group", None),
                "dcim.sitegroup",
                50,
                ranks,
            )
            add_scope_chain(
                nb.dcim.regions,
                getattr(full_site, "region", None),
                "dcim.region",
                40,
                ranks,
            )

    add_scope_chain(
        nb.dcim.locations,
        getattr(device, "location", None),
        "dcim.location",
        70,
        ranks,
    )

    rack = getattr(device, "rack", None)
    rack_id = related_id(rack)
    if rack_id is not None:
        ranks[("dcim.rack", rack_id)] = 80
        full_rack = nb.dcim.racks.get(rack_id)
        rack_group = getattr(full_rack, "group", None) if full_rack else None
        rack_group_id = related_id(rack_group)
        if rack_group_id is not None:
            ranks[("dcim.rackgroup", rack_group_id)] = 75

    return DeviceScopeContext(ranks=ranks)


def resolve_vlan(
    cache: VlanCache,
    vlan_id: int,
    context: DeviceScopeContext,
    preferred_ids: set[int] | None = None,
    svi_addresses: tuple[str, ...] | None = None,
) -> tuple[Any | None, str | None]:
    candidates = cache.by_vid.get(vlan_id, [])
    if not candidates:
        return None, f"VLAN {vlan_id} does not exist in NetBox"

    # Voice VLANs with duplicate VIDs are resolved from live SVI addressing,
    # even if an existing interface assignment or broad scope could otherwise
    # hide an incorrect choice.
    if len(candidates) > 1 and svi_addresses is not None:
        return resolve_vlan_from_svi(cache, vlan_id, candidates, svi_addresses)

    preferred = [
        vlan
        for vlan in candidates
        if preferred_ids and int(vlan.id) in preferred_ids
    ]
    if len(preferred) == 1:
        return preferred[0], None
    if len(candidates) == 1:
        return candidates[0], None

    ranked: list[tuple[int, Any, str]] = []
    for vlan in candidates:
        scope_key, scope_label = vlan_scope_key(vlan, cache)
        rank = 0 if scope_key is None else context.ranks.get(scope_key, -1)
        if rank >= 0:
            ranked.append((rank, vlan, scope_label))

    if ranked:
        best_rank = max(item[0] for item in ranked)
        best = [item for item in ranked if item[0] == best_rank]
        if len(best) == 1:
            return best[0][1], None

    details = ", ".join(
        f"ID {vlan.id} ({vlan_scope_key(vlan, cache)[1]})"
        for vlan in candidates
    )
    return None, f"VLAN {vlan_id} is ambiguous or out of scope: {details}"


def resolve_device(nb: Any, collected: CollectedDevice) -> Any:
    if collected.netbox_device_id is not None:
        device = nb.dcim.devices.get(collected.netbox_device_id)
        if device is not None:
            return device
        raise LookupError(
            f"NetBox device ID {collected.netbox_device_id} was not found"
        )

    candidates = list(nb.dcim.devices.filter(name=collected.inventory_name))
    exact = [
        device
        for device in candidates
        if str(device.name).casefold() == collected.inventory_name.casefold()
    ]
    if len(exact) != 1:
        raise LookupError(
            f"expected one NetBox device named {collected.inventory_name!r}; "
            f"found {len(exact)}"
        )
    return exact[0]


def integer_value(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def stack_member_number(interface_name: str) -> int | None:
    """Return 2 for names such as Gi2/0/3; two-part names are standalone."""

    cleaned = interface_name.strip().replace(" ", "")
    match = re.match(
        r"^(?:[A-Za-z-]+)?(?P<member>\d+)/\d+/\d+(?:\.\d+)?$",
        cleaned,
    )
    return int(match.group("member")) if match else None


def resolve_virtual_chassis(
    nb: Any,
    device: Any,
    collected: CollectedDevice,
) -> Any | None:
    """Resolve the device's VC relation, then an exact VC hostname fallback."""

    virtual_chassis_id = related_id(getattr(device, "virtual_chassis", None))
    if virtual_chassis_id is not None:
        virtual_chassis = nb.dcim.virtual_chassis.get(virtual_chassis_id)
        if virtual_chassis is None:
            raise LookupError(
                f"device {device.name!r} references missing Virtual Chassis "
                f"ID {virtual_chassis_id}"
            )
        return virtual_chassis

    # This supports inventories named for the stack/VC while NetBox stores the
    # physical master device under a member-specific name.
    for name in {str(device.name), collected.inventory_name}:
        candidates = list(nb.dcim.virtual_chassis.filter(name=name))
        exact = [
            chassis
            for chassis in candidates
            if str(chassis.name).casefold() == name.casefold()
        ]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise LookupError(f"multiple Virtual Chassis records are named {name!r}")
    return None


def build_interface_search_scope(
    nb: Any,
    device: Any,
    collected: CollectedDevice,
) -> InterfaceSearchScope:
    """Load interfaces from a device and all of its Virtual Chassis members."""

    virtual_chassis = resolve_virtual_chassis(nb, device, collected)
    master_device = device
    members_by_position: dict[int, Any] = {}
    devices: dict[int, Any] = {int(device.id): device}

    if virtual_chassis is not None:
        members = list(
            nb.dcim.devices.filter(virtual_chassis_id=virtual_chassis.id)
        )
        for member in members:
            devices[int(member.id)] = member
            position = integer_value(getattr(member, "vc_position", None))
            if position is None:
                continue
            if position in members_by_position:
                raise LookupError(
                    f"Virtual Chassis {virtual_chassis.name!r} has multiple "
                    f"devices at position {position}"
                )
            members_by_position[position] = member

        master_id = related_id(getattr(virtual_chassis, "master", None))
        if master_id is not None:
            master_device = devices.get(master_id) or nb.dcim.devices.get(master_id)
            if master_device is None:
                raise LookupError(
                    f"Virtual Chassis {virtual_chassis.name!r} references "
                    f"missing master device ID {master_id}"
                )
            devices[int(master_device.id)] = master_device

        LOGGER.info(
            "%s: Virtual Chassis %r has member position(s): %s",
            collected.inventory_name,
            virtual_chassis.name,
            ", ".join(str(position) for position in sorted(members_by_position))
            or "none",
        )

    indexes_by_device_id = {
        device_id: interface_indexes(
            nb.dcim.interfaces.filter(device_id=device_id)
        )
        for device_id in devices
    }
    return InterfaceSearchScope(
        connected_device=device,
        master_device=master_device,
        virtual_chassis=virtual_chassis,
        members_by_position=members_by_position,
        indexes_by_device_id=indexes_by_device_id,
    )


def local_stack_aliases(interface_name: str) -> list[str]:
    """Return common member-local forms of a stack interface name."""

    cleaned = interface_name.strip().replace(" ", "")
    match = re.match(
        r"^(?P<prefix>[A-Za-z-]+)(?P<member>\d+)/(?P<remainder>\d+/\d+(?:\.\d+)?)$",
        cleaned,
    )
    if not match:
        return []
    prefix = match.group("prefix")
    remainder = match.group("remainder")
    return [f"{prefix}1/{remainder}", f"{prefix}{remainder}"]


def match_scoped_interface(
    discovered_name: str,
    scope: InterfaceSearchScope,
) -> tuple[Any | None, Any | None, str | None]:
    """Match a port on either a single-device stack or a Virtual Chassis.

    Some NetBox installations model a Cisco stack as one device containing
    every IOS interface name (Gi1/0/1, Gi2/0/1, and so on). Others model each
    member as a separate device in a Virtual Chassis. Always try the exact
    interface on the connected device first; only route by VC position when
    that direct match does not exist.
    """

    position = stack_member_number(discovered_name)
    connected_indexes = scope.indexes_by_device_id.get(
        int(scope.connected_device.id)
    )
    if connected_indexes is not None:
        interface, _ = match_interface(discovered_name, *connected_indexes)
        if interface is not None:
            return interface, scope.connected_device, None

    if position is not None and scope.virtual_chassis is not None:
        owner = scope.members_by_position.get(position)
        if owner is None:
            return None, None, (
                f"{discovered_name}: Virtual Chassis {scope.virtual_chassis.name!r} "
                f"has no member at position {position}"
            )
    elif position is not None:
        # A non-VC stack can still be represented by one NetBox device. The
        # direct lookup above is authoritative; do not alias member 2 to a
        # member-1 interface because that could update the wrong physical port.
        owner = scope.connected_device
    else:
        owner = scope.master_device

    indexes = scope.indexes_by_device_id.get(int(owner.id))
    if indexes is None:
        return None, owner, f"no interfaces were loaded for device {owner.name!r}"

    interface, error = match_interface(discovered_name, *indexes)
    if interface is not None:
        return interface, owner, None

    if position is not None and scope.virtual_chassis is None:
        return None, owner, (
            f"{discovered_name}: no exact/canonical interface exists on "
            f"single-device stack {owner.name!r}; a Virtual Chassis is "
            "required only when stack members are separate NetBox devices"
        )

    # Device-type templates sometimes store a VC member's ports in a
    # member-local form (Gi1/0/3 or Gi0/3), even when IOS reports Gi2/0/3.
    alias_matches: dict[int, Any] = {}
    for alias in local_stack_aliases(discovered_name):
        alias_interface, _ = match_interface(alias, *indexes)
        if alias_interface is not None:
            alias_matches[int(alias_interface.id)] = alias_interface
    if len(alias_matches) == 1:
        return next(iter(alias_matches.values())), owner, None
    if len(alias_matches) > 1:
        names = ", ".join(sorted(str(item.name) for item in alias_matches.values()))
        return None, owner, (
            f"{discovered_name}: multiple member-local interfaces match on "
            f"{owner.name!r}: {names}"
        )
    return None, owner, f"{discovered_name}: {error} on device {owner.name!r}"


def current_interface_state(interface: Any) -> dict[str, Any]:
    return {
        "mode": choice_value(getattr(interface, "mode", None)),
        "untagged_vlan": related_id(getattr(interface, "untagged_vlan", None)),
        "tagged_vlans": related_ids(getattr(interface, "tagged_vlans", [])),
    }


def current_interface_metadata(interface: Any) -> dict[str, Any]:
    """Return NetBox fields managed by live interface metadata collection."""

    return {
        "enabled": bool(getattr(interface, "enabled", False)),
        "description": str(getattr(interface, "description", "") or ""),
    }


def desired_netbox_state(
    discovered: InterfaceVlanState,
    current: dict[str, Any],
    context: DeviceScopeContext,
    vlan_cache: VlanCache,
    vlan_svi_addresses: dict[int, tuple[str, ...]],
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    """Translate collected VLAN IDs to unambiguous NetBox object IDs."""

    resolved: dict[int, Any] = {}
    preferred_ids = set(current["tagged_vlans"])
    if current["untagged_vlan"] is not None:
        preferred_ids.add(current["untagged_vlan"])

    fatal_errors: list[str] = []
    tagged_errors: list[str] = []

    if discovered.untagged_vlan is not None:
        vlan, error = resolve_vlan(
            vlan_cache,
            discovered.untagged_vlan,
            context,
            preferred_ids,
        )
        if error:
            fatal_errors.append(error)
        elif vlan is not None:
            resolved[discovered.untagged_vlan] = vlan

    for vlan_id in discovered.tagged_vlans:
        is_voice_vlan = vlan_id == discovered.voice_vlan
        vlan, error = resolve_vlan(
            vlan_cache,
            vlan_id,
            context,
            preferred_ids,
            # An empty tuple is intentional: for an ambiguous voice VID it
            # causes a hard error stating that the SVI had no routed address.
            vlan_svi_addresses.get(vlan_id, ()) if is_voice_vlan else None,
        )
        if error:
            if is_voice_vlan:
                fatal_errors.append(error)
            else:
                tagged_errors.append(error)
        elif vlan is not None:
            resolved[vlan_id] = vlan

    if fatal_errors:
        return None, "; ".join(fatal_errors), []

    untagged = (
        resolved[discovered.untagged_vlan]
        if discovered.untagged_vlan is not None
        else None
    )
    tagged_ids = {
        int(resolved[vlan_id].id)
        for vlan_id in discovered.tagged_vlans
        if vlan_id in resolved
    }
    warnings: list[str] = []
    if tagged_errors:
        # Do not reject the entire trunk because one permitted VLAN is absent
        # or ambiguous. Add every VLAN we can resolve, but preserve all current
        # tagged assignments so incomplete source data cannot remove anything.
        tagged_ids.update(current["tagged_vlans"])
        warnings.append(
            "some tagged VLANs could not be resolved; resolvable VLANs were "
            "applied and existing tagged assignments were preserved: "
            + "; ".join(tagged_errors)
        )

    return {
        "mode": discovered.mode,
        "untagged_vlan": related_id(untagged),
        "tagged_vlans": sorted(tagged_ids),
    }, None, warnings


def sync_device(
    nb: Any,
    collected: CollectedDevice,
    vlan_cache: VlanCache,
    dry_run: bool,
) -> SyncSummary:
    """Compare one device and apply only the necessary interface updates."""

    device = resolve_device(nb, collected)
    summary = SyncSummary(device=str(device.name), dry_run=dry_run)
    scope = build_interface_search_scope(nb, device, collected)
    contexts_by_device_id: dict[int, DeviceScopeContext] = {}

    for discovered in collected.interfaces:
        interface, owner, error = match_scoped_interface(discovered.name, scope)
        if error:
            summary.skipped += 1
            summary.errors.append(error)
            continue

        current = current_interface_state(interface)
        owner_id = int(owner.id)
        context = contexts_by_device_id.get(owner_id)
        if context is None:
            context = build_device_scope_context(nb, owner)
            contexts_by_device_id[owner_id] = context

        desired, error, warnings = desired_netbox_state(
            discovered,
            current,
            context,
            vlan_cache,
            collected.vlan_svi_addresses,
        )
        if error:
            summary.skipped += 1
            summary.errors.append(
                f"{owner.name}/{discovered.name}: {error}"
            )
            continue
        summary.warnings.extend(
            f"{owner.name}/{discovered.name}: {warning}"
            for warning in warnings
        )

        if current == desired:
            summary.unchanged += 1
            continue

        change = f"{owner.name}/{interface.name}: {current} -> {desired}"
        if dry_run:
            summary.updated += 1
            summary.changes.append(f"DRY-RUN {change}")
            continue

        try:
            LOGGER.info("Updating NetBox interface %s", change)
            interface.update(desired)
            refreshed = nb.dcim.interfaces.get(interface.id)
            if refreshed is None:
                raise RuntimeError(
                    "interface disappeared while verifying the update"
                )
            persisted = current_interface_state(refreshed)
            if persisted != desired:
                raise RuntimeError(
                    f"verification failed; NetBox returned {persisted}"
                )
            summary.updated += 1
            summary.changes.append(f"VERIFIED {change}")
        except Exception as exc:
            summary.errors.append(
                f"{owner.name}/{interface.name}: update failed: {exc}"
            )

    # Synchronize status and descriptions independently from VLAN state. This
    # ensures a VLAN ambiguity cannot prevent an otherwise safe metadata
    # update, and includes routed or unused ports absent from VLAN output.
    for discovered in collected.interface_metadata:
        interface, owner, error = match_scoped_interface(discovered.name, scope)
        if error:
            summary.skipped += 1
            summary.errors.append(error)
            continue

        desired_metadata: dict[str, Any] = {}
        if discovered.enabled is not None:
            desired_metadata["enabled"] = discovered.enabled
        if discovered.description is not None:
            desired_metadata["description"] = discovered.description
        if not desired_metadata:
            continue

        current_metadata = current_interface_metadata(interface)
        current_subset = {
            field_name: current_metadata[field_name]
            for field_name in desired_metadata
        }
        if current_subset == desired_metadata:
            summary.unchanged += 1
            continue

        change = (
            f"{owner.name}/{interface.name} metadata "
            f"(device_status={discovered.device_status or 'unknown'}): "
            f"{current_subset} -> {desired_metadata}"
        )
        if dry_run:
            summary.updated += 1
            summary.changes.append(f"DRY-RUN {change}")
            continue

        try:
            LOGGER.info("Updating NetBox interface %s", change)
            interface.update(desired_metadata)
            refreshed = nb.dcim.interfaces.get(interface.id)
            if refreshed is None:
                raise RuntimeError(
                    "interface disappeared while verifying the metadata update"
                )
            persisted = current_interface_metadata(refreshed)
            persisted_subset = {
                field_name: persisted[field_name]
                for field_name in desired_metadata
            }
            if persisted_subset != desired_metadata:
                raise RuntimeError(
                    f"metadata verification failed; NetBox returned "
                    f"{persisted_subset}"
                )
            summary.updated += 1
            summary.changes.append(f"VERIFIED {change}")
        except Exception as exc:
            summary.errors.append(
                f"{owner.name}/{interface.name}: metadata update failed: {exc}"
            )

    return summary


# ---------------------------------------------------------------------------
# CLI orchestration
# ---------------------------------------------------------------------------


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize Cisco interface VLAN assignments to NetBox."
    )
    parser.add_argument("--config", default="config.yaml", help="Nornir config file")
    parser.add_argument(
        "--tag",
        default=DEFAULT_TAG,
        help=f"NetBox device tag (default: {DEFAULT_TAG})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show differences without updating NetBox",
    )
    return parser.parse_args()


def required_environment() -> tuple[str, str, str]:
    names = ("NB_TOKEN", "NORNIR_USERNAME", "NORNIR_PASSWORD")
    values = tuple(os.getenv(name) or "" for name in names)
    missing = [name for name, value in zip(names, values) if not value]
    if missing:
        raise RuntimeError(
            "Required environment variable(s) are missing: " + ", ".join(missing)
        )
    return values  # type: ignore[return-value]


def find_collected_result(multi_result: Any) -> CollectedDevice | None:
    for item in multi_result:
        if isinstance(item.result, CollectedDevice):
            return item.result
    return None


def print_sync_summary(summary: SyncSummary) -> None:
    label = "DRY-RUN" if summary.dry_run else "NETBOX"
    update_label = "would_update" if summary.dry_run else "updated"
    print(
        f"\n[{label}] {summary.device}: {update_label}={summary.updated} "
        f"unchanged={summary.unchanged} skipped={summary.skipped} "
        f"warnings={len(summary.warnings)} errors={len(summary.errors)}"
    )
    for change in summary.changes:
        print(f"  CHANGE: {change}")
    for warning in summary.warnings:
        print(f"  WARNING: {warning}")
    for error in summary.errors:
        print(f"  ERROR: {error}")


def main() -> int:
    args = parse_arguments()
    try:
        token, username, password = required_environment()
        inventory_options = load_inventory_options(args.config, token)
    except (RuntimeError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1

    netbox_url = inventory_options["nb_url"]
    LOGGER.info("Using NetBox API URL: %s", netbox_url)

    try:
        nr = InitNornir(
            config_file=args.config,
            inventory={"options": inventory_options},
        )
    except Exception as exc:
        LOGGER.error("Unable to initialize Nornir inventory: %s", exc)
        return 1

    nr.inventory.defaults.username = username
    nr.inventory.defaults.password = password
    nb = create_netbox_client(netbox_url, token, inventory_options)
    exit_code = 0

    try:
        tagged_devices = list(nb.dcim.devices.filter(tag=args.tag))
        if not tagged_devices:
            LOGGER.warning("No NetBox devices have tag %r", args.tag)
            return 0

        selected = select_tagged_inventory(nr, tagged_devices)
        selected_count = len(selected.inventory.hosts)
        LOGGER.info(
            "Tag %r: %d NetBox device(s), %d Nornir inventory match(es)",
            args.tag,
            len(tagged_devices),
            selected_count,
        )
        if not selected_count:
            LOGGER.error("No tagged devices matched the Nornir inventory")
            return 1

        vlan_cache = build_vlan_cache(nb)
        ambiguous_vlan_ids = {
            vlan_id
            for vlan_id, candidates in vlan_cache.by_vid.items()
            if len(candidates) > 1
        }
        results = selected.run(
            task=collect_device_state,
            name="Collect interface VLAN state",
            ambiguous_vlan_ids=ambiguous_vlan_ids,
        )
        collected_devices: list[CollectedDevice] = []
        for host_name, multi_result in results.items():
            if multi_result.failed:
                exit_code = 1
                print(f"\n[COLLECTION FAILED] {host_name}")
                print_result(multi_result)
                continue

            collected = find_collected_result(multi_result)
            if collected is None:
                exit_code = 1
                LOGGER.error("%s returned no collected interface state", host_name)
                continue
            LOGGER.info(
                "%s: collected VLAN state for %d interface(s)",
                host_name,
                len(collected.interfaces),
            )
            collected_devices.append(collected)

        voice_vlan_ids = {
            vlan_id
            for collected in collected_devices
            for vlan_id in collected.vlan_svi_addresses
        }
        load_vlan_prefixes(nb, vlan_cache, voice_vlan_ids)
        for collected in collected_devices:
            try:
                summary = sync_device(
                    nb=nb,
                    collected=collected,
                    vlan_cache=vlan_cache,
                    dry_run=args.dry_run,
                )
                print_sync_summary(summary)
                if summary.errors:
                    exit_code = 1
            except Exception as exc:
                exit_code = 1
                LOGGER.exception(
                    "Unable to synchronize %s: %s",
                    collected.inventory_name,
                    exc,
                )

    except Exception as exc:
        LOGGER.exception("Synchronization failed: %s", exc)
        exit_code = 1
    finally:
        nr.close_connections()
        nb.http_session.close()

    return exit_code


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    raise SystemExit(main())
