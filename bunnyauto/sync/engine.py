"""VLAN/interface reconciliation engine. Ported from ``netbox_interfaces_update.py``.

Collects access/voice/trunk/link-state/description data per device, resolves
ambiguous voice VLANs via each VLAN's SVI address and NetBox prefixes, then
patches only the NetBox interfaces whose state differs. Never creates VLANs or
interfaces; missing or ambiguous objects are reported and skipped.

The NetBox client (``nb``) and the tagged Nornir inventory are supplied by the
``sync-interfaces`` tool; this module holds the parsing + reconciliation logic.

**Stacks.** One SSH session to a stack reports every member's ports, but NetBox
keeps each member as its own device. :func:`build_interface_search_scope`
resolves the members with :func:`bunnyauto.netbox.stacks.resolve_stack`, the
resolver ``create-interfaces`` uses (the device's Virtual Chassis, else the
``<host>-<member>`` names), so both tools agree on where a port lives. Only
devices in the run's scope are ever members. :func:`match_scoped_interface`
matches a member's port on that member's device only, never on a same-named
copy elsewhere in the stack.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

from bunnyauto.netbox.devices import inventory_device_id
from bunnyauto.netbox.interfaces import (
    interface_signature,
    member_local_names,
    stack_member,
)
from bunnyauto.netbox.records import choice_value, related_id
from bunnyauto.netbox.stacks import Stack, is_stack_wide, own_interfaces, resolve_stack

SHOW_VLAN = "show vlan brief"
SHOW_TRUNKS = "show interfaces trunk"
SHOW_SWITCHPORTS = "show interfaces switchport"
SHOW_ETHERCHANNEL_SUMMARY = "show etherchannel summary"
SHOW_INTERFACE_STATUS = "show interfaces status"
SHOW_INTERFACE_DESCRIPTIONS = "show interfaces description"

LOGGER = logging.getLogger("bunnyauto.sync")

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
    trunk_native_vlan: int | None = None
    trunk_allowed_vlans: list[int] = field(default_factory=list)
    trunk_allows_all: bool = False
    trunk_allowed_seen: bool = False
    native_vlan_tagged: bool | None = None


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
class BlockedMember:
    """A stack member's ports that no NetBox device this run may touch holds."""

    member: int
    reason: str
    ports: list[str] = field(default_factory=list)


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
    #: Of ``updated``: the updates that landed on another stack member's device.
    routed: int = 0
    #: Ports skipped because their stack member has no NetBox device in scope.
    blocked: list[BlockedMember] = field(default_factory=list)
    #: ``"<device>/<interface>"`` -> the stack member device that port belongs on:
    #: copies on the wrong member, left by create-interfaces runs before stacks.
    misplaced: dict[str, str] = field(default_factory=dict)


@dataclass
class InterfaceSearchScope:
    """One managed switch or stack: its in-scope NetBox devices and their interfaces."""

    stack: Stack
    devices_by_id: dict[int, Any]
    indexes_by_device_id: dict[
        int,
        tuple[dict[str, list[Any]], dict[tuple[str, str], list[Any]]],
    ]


@dataclass(frozen=True)
class ScopedMatch:
    """Where one reported port lives in NetBox (``interface`` on ``owner``), or why not."""

    interface: Any | None = None
    owner: Any | None = None
    error: str | None = None
    #: Set instead of ``error`` when the port's stack member has no NetBox device
    #: this run may touch; the caller reports those ports per member.
    blocked_member: int | None = None
    #: ``(device, interface)``: copies of this member-2+ port on other members.
    misplaced: tuple[tuple[Any, Any], ...] = ()


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

        # Cisco may render an EtherChannel as either ``Po1`` or
        # ``Port-channel1``. Match the standalone ``Port`` table heading only;
        # startswith("port") would incorrectly discard every full-name
        # Port-channel data row below.
        is_port_header = bool(re.match(r"^port(?:\s|$)", lowered))

        if is_port_header and "native vlan" in lowered:
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
        if is_port_header or set(line.strip()) <= {"-", " "}:
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
    trunk_native_line = re.compile(
        r"^\s*Trunking Native Mode VLAN:\s*(?P<vid>\d+|\S+)",
        re.IGNORECASE,
    )
    trunk_allowed_line = re.compile(
        r"^\s*Trunking VLANs Enabled:\s*(?P<vlans>.+?)\s*$",
        re.IGNORECASE,
    )
    native_tagging_line = re.compile(
        r"^\s*(?:Administrative )?Native VLAN tagging:\s*"
        r"(?P<state>enabled|disabled)\s*$",
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
            continue
        match = trunk_native_line.match(raw_line)
        if match:
            value = match.group("vid")
            current.trunk_native_vlan = int(value) if value.isdigit() else None
            continue
        match = trunk_allowed_line.match(raw_line)
        if match:
            expression = match.group("vlans").strip().lower().replace(" ", "")
            current.trunk_allowed_seen = True
            current.trunk_allows_all = expression in {"all", "1-4094"}
            current.trunk_allowed_vlans = expand_vlan_list(expression)
            continue
        match = native_tagging_line.match(raw_line)
        if match:
            current.native_vlan_tagged = match.group("state").casefold() == "enabled"

    return switchports


def parse_etherchannel_port_channels(output: str) -> list[str]:
    """Return aggregate interface names from ``show etherchannel summary``."""

    port_channels: dict[tuple[str, str], str] = {}
    row_pattern = re.compile(
        r"^\s*\d+\s+"
        r"(?P<name>(?:Po|Port-?channel)\s*\d+)"
        r"(?:\([^)]*\))?(?:\s|$)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = row_pattern.match(line)
        if not match:
            continue
        name = match.group("name").replace(" ", "")
        port_channels[interface_signature(name)] = name
    return sorted(port_channels.values(), key=interface_sort_key)


def parse_port_channel_running_config(output: str) -> dict[str, SwitchportState]:
    """Parse Layer-2 VLAN settings from Port-Channel config blocks."""

    configured: dict[str, SwitchportState] = {}
    current: SwitchportState | None = None
    interface_line = re.compile(
        r"^\s*interface\s+"
        r"(?P<name>(?:Po|Port-?channel)\s*\d+)\s*$",
        re.IGNORECASE,
    )
    mode_line = re.compile(
        r"^switchport\s+mode\s+(?P<mode>access|trunk)\s*$",
        re.IGNORECASE,
    )
    access_line = re.compile(
        r"^switchport\s+access\s+vlan\s+(?P<vid>\d+)\s*$",
        re.IGNORECASE,
    )
    voice_line = re.compile(
        r"^switchport\s+voice\s+vlan\s+(?P<vid>\d+)\s*$",
        re.IGNORECASE,
    )
    native_line = re.compile(
        r"^switchport\s+trunk\s+native\s+vlan\s+(?P<vid>\d+)\s*$",
        re.IGNORECASE,
    )
    allowed_line = re.compile(
        r"^switchport\s+trunk\s+allowed\s+vlan\s+"
        r"(?:(?P<operation>add)\s+)?(?P<vlans>.+?)\s*$",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        match = interface_line.match(stripped)
        if match:
            name = match.group("name").replace(" ", "")
            current = SwitchportState(name=name)
            configured[name.casefold()] = current
            continue
        if current is None or not stripped or stripped in {"!", "end"}:
            continue
        if stripped.casefold() == "no switchport":
            current.administrative_mode = "routed"
            current.operational_mode = "routed"
            current.access_vlan = None
            current.voice_vlan = None
            current.trunk_native_vlan = None
            current.trunk_allowed_seen = False
            current.trunk_allowed_vlans = []
            continue

        match = mode_line.match(stripped)
        if match:
            current.administrative_mode = match.group("mode").casefold()
            continue
        match = access_line.match(stripped)
        if match:
            current.access_vlan = int(match.group("vid"))
            continue
        match = voice_line.match(stripped)
        if match:
            current.voice_vlan = int(match.group("vid"))
            continue
        match = native_line.match(stripped)
        if match:
            current.trunk_native_vlan = int(match.group("vid"))
            continue
        match = allowed_line.match(stripped)
        if match:
            expression = match.group("vlans").strip().lower().replace(" ", "")
            vlan_ids = expand_vlan_list(expression)
            current.trunk_allowed_seen = True
            current.trunk_allows_all = expression in {"all", "1-4094"}
            if match.group("operation"):
                current.trunk_allowed_vlans = sorted(
                    set(current.trunk_allowed_vlans) | set(vlan_ids)
                )
            else:
                current.trunk_allowed_vlans = vlan_ids

    # Cisco's default access VLAN is VLAN 1 when mode access is explicit but
    # no switchport access VLAN line is present.
    for state in configured.values():
        if state.administrative_mode == "access" and state.access_vlan is None:
            state.access_vlan = 1
    return configured


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
        descriptions[interface.casefold()] = (match.group("description") or "").strip()
    return descriptions


def build_interface_metadata(
    status_output: str,
    description_output: str,
) -> list[InterfaceMetadataState]:
    """Merge live port status with authoritative interface descriptions."""

    status_by_name = parse_interface_status(status_output)
    descriptions = parse_interface_descriptions(description_output)
    status_by_signature = {
        interface_signature(state.name): state for state in status_by_name.values()
    }
    descriptions_by_signature: dict[
        tuple[str, str],
        list[tuple[str, str]],
    ] = defaultdict(list)
    for name, description in descriptions.items():
        descriptions_by_signature[interface_signature(name)].append((name, description))

    signatures = set(status_by_signature) | set(descriptions_by_signature)
    merged: list[InterfaceMetadataState] = []
    for signature in signatures:
        status_state = status_by_signature.get(signature)
        description_entries = descriptions_by_signature.get(signature, [])
        nonempty_descriptions = {
            description for _name, description in description_entries if description
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

        name = status_state.name if status_state is not None else description_entries[0][0]
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
    voice_vlan_model: str = "tagged",
    access_vlan_placement: str = "clear",
    port_channel_config_output: str = "",
) -> list[InterfaceVlanState]:
    """Combine Cisco output into one NetBox VLAN state per interface.

    ``voice_vlan_model=tagged`` models data+voice framing instead, using NetBox
    tagged mode. With the default ``access_vlan_placement=clear``, both the
    access/data VLAN and auxiliary voice VLAN are assigned to ``tagged_vlans``.
    This is the default because NetBox does not permit tagged VLAN assignments
    while an interface's 802.1Q mode is access. ``voice_vlan_model=access`` is
    retained as an opt-in compatibility policy which omits the voice VLAN.
    ``access_vlan_placement=clear`` explicitly removes NetBox's untagged VLAN
    from access-mode ports; ``untagged`` records Cisco's access VLAN there.
    """

    desired: dict[tuple[str, str], InterfaceVlanState] = {}
    for interface, vlan_id in parse_vlan_brief(vlan_output).items():
        desired[interface_signature(interface)] = InterfaceVlanState(
            name=interface,
            mode="access",
            untagged_vlan=(vlan_id if access_vlan_placement == "untagged" else None),
        )

    trunks = parse_trunks(trunk_output)
    trunks_by_signature = {interface_signature(trunk.name): trunk for trunk in trunks.values()}
    processed_trunks: set[tuple[str, str]] = set()

    switchports_by_signature = {
        interface_signature(switchport.name): switchport
        for switchport in parse_switchports(switchport_output).values()
    }
    for configured in parse_port_channel_running_config(port_channel_config_output).values():
        signature = interface_signature(configured.name)
        switchport = switchports_by_signature.get(signature)
        if switchport is None:
            switchports_by_signature[signature] = configured
            continue

        # The running configuration is authoritative for explicitly
        # configured administrative mode and access VLAN. Live switchport
        # output still supplies operational mode and native-tagging state.
        if configured.administrative_mode:
            switchport.administrative_mode = configured.administrative_mode
        if configured.access_vlan is not None:
            switchport.access_vlan = configured.access_vlan
        if configured.voice_vlan is not None:
            switchport.voice_vlan = configured.voice_vlan
        if configured.trunk_native_vlan is not None:
            switchport.trunk_native_vlan = configured.trunk_native_vlan
        if configured.trunk_allowed_seen and not switchport.trunk_allowed_seen:
            switchport.trunk_allowed_seen = True
            switchport.trunk_allows_all = configured.trunk_allows_all
            switchport.trunk_allowed_vlans = configured.trunk_allowed_vlans

    # show vlan brief can list a phone port under both its data and voice
    # VLANs, making a dict-based parse dependent on row order. The switchport
    # output is authoritative because it labels both roles explicitly.
    for switchport in switchports_by_signature.values():
        signature = interface_signature(switchport.name)
        trunk = trunks_by_signature.get(signature)
        is_trunk = (
            trunk is not None
            or "trunk"
            in (switchport.administrative_mode + " " + switchport.operational_mode).casefold()
        )

        if is_trunk:
            configured_native_vlan = (
                trunk.native_vlan
                if trunk is not None and trunk.native_vlan is not None
                else switchport.trunk_native_vlan
            )
            if trunk is not None and trunk.allowed_seen:
                allows_all = trunk.allows_all
                allowed_vlans = trunk.allowed_vlans
            elif switchport.trunk_allowed_seen:
                allows_all = switchport.trunk_allows_all
                allowed_vlans = switchport.trunk_allowed_vlans
            else:
                LOGGER.warning(
                    "%s: configured/operational trunk was detected but no "
                    "allowed-VLAN list was parsed; leaving it unchanged",
                    switchport.name,
                )
                continue

            if allows_all:
                mode = "tagged-all"
                tagged: list[int] = []
            else:
                mode = "tagged"
                tagged = sorted(set(allowed_vlans))

            if switchport.native_vlan_tagged is True:
                # vlan dot1q tag native: the configured native VLAN is carried
                # tagged and must never be sent as NetBox untagged_vlan.
                native_vlan = None
            else:
                native_vlan = configured_native_vlan
                tagged = sorted(set(tagged) - {native_vlan})

            desired[signature] = InterfaceVlanState(
                name=switchport.name,
                mode=mode,
                untagged_vlan=native_vlan,
                tagged_vlans=tuple(tagged),
                voice_vlan=None,
            )
            processed_trunks.add(signature)
            continue

        if switchport.access_vlan is None and switchport.voice_vlan is None:
            continue

        tagged_vlans: set[int] = set()
        if voice_vlan_model == "tagged" and switchport.voice_vlan is not None:
            tagged_vlans.add(switchport.voice_vlan)
            if access_vlan_placement == "clear" and switchport.access_vlan is not None:
                # The requested NetBox model has no untagged VLAN on hybrid
                # access/voice ports, so retain the data VLAN by assigning it
                # alongside the voice VLAN in tagged_vlans.
                tagged_vlans.add(switchport.access_vlan)

        is_port_channel = signature[0] == "po"
        untagged_vlan = (
            switchport.access_vlan
            if access_vlan_placement == "untagged"
            or (is_port_channel and switchport.voice_vlan is None)
            else None
        )
        if untagged_vlan is not None:
            # A NetBox VLAN cannot be both tagged and untagged on one port.
            tagged_vlans.discard(untagged_vlan)

        tagged = tuple(sorted(tagged_vlans))
        desired[signature] = InterfaceVlanState(
            name=switchport.name,
            # Access is the default because it matches Cisco's switchport mode.
            # NetBox cannot accept tagged_vlans while mode is access, so the
            # optional tagged policy is required to model a voice VLAN here.
            mode="tagged" if tagged else "access",
            untagged_vlan=untagged_vlan,
            tagged_vlans=tagged,
            voice_vlan=switchport.voice_vlan,
        )

    # Include operational trunks which were absent from switchport output.
    for interface, trunk in trunks.items():
        if interface_signature(interface) in processed_trunks:
            continue
        if not trunk.allowed_seen:
            LOGGER.warning(
                "%s: trunk was detected but its allowed-VLAN list was not "
                "parsed; leaving this interface unchanged",
                interface,
            )
            continue
        if trunk.allows_all:
            mode = "tagged-all"
            tagged = []
        else:
            mode = "tagged"
            tagged = sorted(set(trunk.allowed_vlans) - {trunk.native_vlan})
        desired[interface_signature(interface)] = InterfaceVlanState(
            name=interface,
            mode=mode,
            untagged_vlan=trunk.native_vlan,
            tagged_vlans=tuple(tagged),
            voice_vlan=None,
        )

    return sorted(desired.values(), key=lambda item: interface_sort_key(item.name))


def collect_device_state(
    task: Task,
    ambiguous_vlan_ids: set[int],
    voice_vlan_model: str,
    access_vlan_placement: str,
) -> Result:
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
    etherchannel_result = task.run(
        task=netmiko_send_command,
        name=SHOW_ETHERCHANNEL_SUMMARY,
        command_string=SHOW_ETHERCHANNEL_SUMMARY,
        read_timeout=60,
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
    port_channel_names = parse_etherchannel_port_channels(str(etherchannel_result.result))
    global_switchports = {
        interface_signature(switchport.name): switchport
        for switchport in parse_switchports(switchport_output).values()
    }
    targeted_switchport_outputs: list[str] = []
    port_channel_config_outputs: list[str] = []
    for port_channel_name in port_channel_names:
        _prefix, channel_number = interface_signature(port_channel_name)
        config_command = f"show running-config interface port-channel {channel_number}"
        config_result = task.run(
            task=netmiko_send_command,
            name=config_command,
            command_string=config_command,
            read_timeout=60,
        )
        port_channel_config_outputs.append(str(config_result.result))

        global_state = global_switchports.get(interface_signature(port_channel_name))
        global_mode = (
            global_state.administrative_mode + " " + global_state.operational_mode
            if global_state is not None
            else ""
        ).casefold()
        global_state_is_complete = global_state is not None and (
            global_state.trunk_allowed_seen
            or ("trunk" not in global_mode and global_state.access_vlan is not None)
        )
        if global_state_is_complete:
            continue
        command = f"show interfaces {port_channel_name} switchport"
        LOGGER.info(
            "%s: querying switchport state for Port-Channel %s because it "
            "was absent from the global switchport output",
            task.host.name,
            port_channel_name,
        )
        port_channel_result = task.run(
            task=netmiko_send_command,
            name=command,
            command_string=command,
            read_timeout=60,
        )
        targeted_switchport_outputs.append(str(port_channel_result.result))
    if targeted_switchport_outputs:
        switchport_output = "\n".join([switchport_output, *targeted_switchport_outputs])
    voice_vlan_ids = {
        switchport.voice_vlan
        for switchport in parse_switchports(switchport_output).values()
        if switchport.voice_vlan is not None
    }
    vlan_svi_addresses: dict[int, tuple[str, ...]] = {}
    svi_lookup_vlan_ids = (
        voice_vlan_ids & ambiguous_vlan_ids if voice_vlan_model == "tagged" else set()
    )
    for vlan_id in sorted(svi_lookup_vlan_ids):
        command = f"show interfaces vlan {vlan_id}"
        svi_result = task.run(
            task=netmiko_send_command,
            name=command,
            command_string=command,
            read_timeout=60,
        )
        vlan_svi_addresses[vlan_id] = parse_svi_addresses(str(svi_result.result))

    interfaces = build_collected_state(
        str(vlan_result.result),
        str(trunk_result.result),
        switchport_output,
        voice_vlan_model=voice_vlan_model,
        access_vlan_placement=access_vlan_placement,
        port_channel_config_output="\n".join(port_channel_config_outputs),
    )
    collected_by_signature = {
        interface_signature(interface.name): interface for interface in interfaces
    }
    for port_channel_name in port_channel_names:
        state = collected_by_signature.get(interface_signature(port_channel_name))
        if state is None:
            LOGGER.warning(
                "%s/%s: EtherChannel exists but no Layer-2 VLAN state was "
                "parsed; verify that the Port-Channel is a switchport",
                task.host.name,
                port_channel_name,
            )
            continue
        LOGGER.info(
            "%s/%s: collected Port-Channel VLAN state mode=%s untagged=%s tagged=%s",
            task.host.name,
            port_channel_name,
            state.mode,
            state.untagged_vlan,
            list(state.tagged_vlans),
        )

    collected = CollectedDevice(
        inventory_name=task.host.name,
        netbox_device_id=inventory_device_id(task.host),
        interfaces=interfaces,
        interface_metadata=build_interface_metadata(
            str(status_result.result),
            str(description_result.result),
        ),
        vlan_svi_addresses=vlan_svi_addresses,
    )
    return Result(host=task.host, result=collected, changed=False)


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
    """The one interface named ``name`` (exact, then canonical) as ``(interface, None)``.

    ``(None, why)`` when more than one matches (an ambiguous name is never
    guessed), and ``(None, None)`` when nothing does.
    """
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
    return None, None


def related_ids(values: Any) -> list[int]:
    return sorted(
        object_id
        for object_id in (related_id(value) for value in (values or []))
        if object_id is not None
    )


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

    groups_by_id = {int(group.id): group for group in nb.ipam.vlan_groups.all()}
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
        cache.prefixes_by_vlan_id[object_id] = list(nb.ipam.prefixes.filter(vlan_id=object_id))


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
        candidate_details.append(f"ID {vlan.id} prefixes={prefix_values or ['none']}")
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

    outcome = (
        "no candidates matched"
        if not matches
        else ("multiple candidates matched: " + ", ".join(str(vlan.id) for vlan in matches))
    )
    return None, (
        f"VLAN {vlan_id} remains ambiguous after SVI lookup "
        f"({', '.join(svi_addresses)}): {outcome}; " + "; ".join(candidate_details)
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

    preferred = [vlan for vlan in candidates if preferred_ids and int(vlan.id) in preferred_ids]
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

    details = ", ".join(f"ID {vlan.id} ({vlan_scope_key(vlan, cache)[1]})" for vlan in candidates)
    return None, f"VLAN {vlan_id} is ambiguous or out of scope: {details}"


def resolve_device(nb: Any, collected: CollectedDevice) -> Any:
    if collected.netbox_device_id is not None:
        device = nb.dcim.devices.get(collected.netbox_device_id)
        if device is not None:
            return device
        raise LookupError(f"NetBox device ID {collected.netbox_device_id} was not found")

    candidates = list(nb.dcim.devices.filter(name=collected.inventory_name))
    exact = [
        device
        for device in candidates
        if str(device.name).casefold() == collected.inventory_name.casefold()
    ]
    if len(exact) != 1:
        raise LookupError(
            f"expected one NetBox device named {collected.inventory_name!r}; found {len(exact)}"
        )
    return exact[0]


def integer_value(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def build_interface_search_scope(
    nb: Any,
    collected: CollectedDevice,
    in_scope: Iterable[Any],
    *,
    scope_label: str = "",
) -> InterfaceSearchScope:
    """Resolve the switch's stack members and load each one's own interfaces.

    Membership comes from :func:`bunnyauto.netbox.stacks.resolve_stack`: the
    device's Virtual Chassis, else the ``<host>-<member>`` names. Only
    ``in_scope`` devices (the run's tag + role branch + region/site) are ever
    members, so nothing outside the scope is loaded, matched or written.
    ``scope_label`` names that scope in the reason for a member outside it.
    """

    device = resolve_device(nb, collected)
    names = [state.name for state in collected.interfaces]
    names += [state.name for state in collected.interface_metadata]
    reported = {member for member in map(stack_member, names) if member is not None}
    stack = resolve_stack(nb, device, reported, in_scope, scope_label=scope_label)
    devices = {int(member.id): member for member in stack.devices()}
    if len(devices) > 1:
        members = ", ".join(f"member {n} = {d.name}" for n, d in sorted(stack.members.items()))
        LOGGER.info(
            "%s: stack resolved by %s: %s",
            collected.inventory_name,
            "Virtual Chassis" if stack.source == "virtual-chassis" else "<host>-<member> names",
            members,
        )
    return InterfaceSearchScope(
        stack=stack,
        devices_by_id=devices,
        indexes_by_device_id={
            device_id: interface_indexes(own_interfaces(nb, member))
            for device_id, member in devices.items()
        },
    )


def match_scoped_interface(
    discovered_name: str,
    scope: InterfaceSearchScope,
) -> ScopedMatch:
    """Find the NetBox interface for one reported port, on the device it belongs to.

    A port carrying a stack member's number (``Gi2/0/1``) belongs to that
    member's device (:meth:`~bunnyauto.netbox.stacks.Stack.owner`) and is
    matched **only there**: under the name the switch reports (exact, then
    canonical), else under the device type's member-1 name (``Gi1/0/1`` on
    ``SwitchA-2``, :func:`member_local_names`). A same-named interface on the
    connected device never wins over the member. For a member-2+ port that is
    a copy left on the wrong device, and updating it (what trying the
    connected device first used to do) would leave the member's real port
    stale. Such copies come back as ``misplaced``, for the report.

    If the member has no in-scope device, the connected device is tried only
    where it stands in for the member
    (:meth:`~bunnyauto.netbox.stacks.Stack.stand_in`: NetBox models the stack
    or chassis as that one device). Otherwise the port is ``blocked_member``.

    A port without a member number (Port-Channel, VLAN, mgmt) is tried on the
    connected device, then the Virtual Chassis master, then, for a
    Port-Channel or another stack-wide interface, exactly one other member. A
    standalone device keeps every port, matched by name only: a member-1 alias
    there could be a different physical port.
    """

    stack = scope.stack
    member = stack_member(discovered_name) if stack.is_stack else None
    if member is None:
        return _match_unnumbered(discovered_name, scope)

    owner = stack.owner(discovered_name)
    if owner is None:
        stand_in = stack.stand_in(discovered_name)
        if stand_in is not None:
            indexes = scope.indexes_by_device_id[int(stand_in.id)]
            interface, error = match_interface(discovered_name, *indexes)
            if interface is not None:
                return ScopedMatch(interface=interface, owner=stand_in)
            if error:
                return ScopedMatch(
                    owner=stand_in,
                    error=f"{discovered_name}: {error} on device {stand_in.name!r}",
                )
        return ScopedMatch(blocked_member=member)

    # Every member device carries its template's member-1 names, so only a copy
    # of a member-2+ port is unambiguously on the wrong device.
    misplaced = _copies_elsewhere(discovered_name, owner, scope) if member != 1 else ()
    indexes = scope.indexes_by_device_id[int(owner.id)]
    interface, error = match_interface(discovered_name, *indexes)
    if interface is None and error is None:
        interface, error = _match_template_name(discovered_name, indexes)
    if interface is not None:
        return ScopedMatch(interface=interface, owner=owner, misplaced=misplaced)
    if error is None:
        aliases = " / ".join(member_local_names(discovered_name))
        error = (
            f"interface does not exist on NetBox device {owner.name!r} (stack member "
            f"{member}), under that name or as {aliases}; wired create-interfaces creates it"
        )
    else:
        error = f"{error} on device {owner.name!r}"
    return ScopedMatch(owner=owner, error=f"{discovered_name}: {error}", misplaced=misplaced)


def _match_unnumbered(name: str, scope: InterfaceSearchScope) -> ScopedMatch:
    """A port with no stack member to route by: a standalone device's, or stack-wide."""

    stack = scope.stack
    tried = [stack.connected]
    if int(stack.anchor.id) != int(stack.connected.id):
        tried.append(stack.anchor)
    for device in tried:
        interface, error = match_interface(name, *scope.indexes_by_device_id[int(device.id)])
        if interface is not None:
            return ScopedMatch(interface=interface, owner=device)
        if error:
            return ScopedMatch(owner=device, error=f"{name}: {error} on device {device.name!r}")

    if stack.is_stack and is_stack_wide(name):
        # NetBox may keep a Port-Channel or VLAN on any member. Accept exactly one,
        # so it can never be attributed to the wrong device.
        skip = {int(device.id) for device in tried}
        holders: dict[int, tuple[Any, Any]] = {}
        for device_id, indexes in scope.indexes_by_device_id.items():
            if device_id in skip:
                continue
            interface, _ = match_interface(name, *indexes)
            if interface is not None:
                holders[int(interface.id)] = (interface, scope.devices_by_id[device_id])
        if len(holders) == 1:
            interface, holder = next(iter(holders.values()))
            return ScopedMatch(interface=interface, owner=holder)
        if len(holders) > 1:
            locations = ", ".join(
                sorted(f"{holder.name}/{interface.name}" for interface, holder in holders.values())
            )
            return ScopedMatch(
                owner=stack.anchor,
                error=f"{name}: more than one stack member has this interface: {locations}",
            )

    where = " or ".join(repr(str(device.name)) for device in tried)
    error = f"{name}: interface {name!r} does not exist on NetBox device {where}"
    if not stack.is_stack and (stack_member(name) or 0) > 1:
        error += (
            " — NetBox models it as one device (no Virtual Chassis or <host>-<member> "
            "stack found), so every port is looked up there"
        )
    return ScopedMatch(owner=stack.anchor, error=error)


def _match_template_name(
    name: str,
    indexes: tuple[dict[str, list[Any]], dict[tuple[str, str], list[Any]]],
) -> tuple[Any | None, str | None]:
    """A stack port under its device type's member-1 name (``Gi2/0/3`` as ``Gi1/0/3``)."""

    matches: dict[int, Any] = {}
    for alias in member_local_names(name):
        interface, _ = match_interface(alias, *indexes)
        if interface is not None:
            matches[int(interface.id)] = interface
    if len(matches) == 1:
        return next(iter(matches.values())), None
    if len(matches) > 1:
        names = ", ".join(sorted(str(item.name) for item in matches.values()))
        return None, f"multiple member-local interfaces match: {names}"
    return None, None


def _copies_elsewhere(
    name: str,
    owner: Any,
    scope: InterfaceSearchScope,
) -> tuple[tuple[Any, Any], ...]:
    """Interfaces named like ``name`` on the stack's other devices, as ``(device, interface)``."""

    signature = interface_signature(name)
    return tuple(
        (scope.devices_by_id[device_id], interface)
        for device_id, (_by_name, by_signature) in scope.indexes_by_device_id.items()
        if device_id != int(owner.id)
        for interface in by_signature.get(signature, [])
    )


def route_note(reported_name: str, interface: Any, owner: Any, stack: Stack) -> str:
    """The bracketed note that makes a stack port's routing reviewable in a change line.

    ``" [stack member 2]"`` when the update lands on another member's device
    than the switch was reached through; ``"reported as Gi2/0/1"`` joins it
    when NetBox holds the port under another name (the device type's member-1
    name). ``""`` for a port on the switch itself, under its own name.
    """

    notes: list[str] = []
    if int(owner.id) != int(stack.connected.id):
        member = stack.member_number(owner)
        notes.append(f"stack member {member}" if member is not None else "another stack member")
    if interface_signature(str(interface.name)) != interface_signature(reported_name):
        notes.append(f"reported as {reported_name}")
    return f" [{', '.join(notes)}]" if notes else ""


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

    untagged = resolved[discovered.untagged_vlan] if discovered.untagged_vlan is not None else None
    tagged_ids = {
        int(resolved[vlan_id].id) for vlan_id in discovered.tagged_vlans if vlan_id in resolved
    }
    warnings: list[str] = []
    if tagged_errors:
        # Do not reject the entire trunk because one permitted VLAN is absent
        # or ambiguous. Add every VLAN we can resolve, but preserve all current
        # tagged assignments so incomplete source data cannot remove anything.
        tagged_ids.update(current["tagged_vlans"])
        warnings.append(
            "some tagged VLANs could not be resolved; resolvable VLANs were "
            "applied and existing tagged assignments were preserved: " + "; ".join(tagged_errors)
        )

    return (
        {
            "mode": discovered.mode,
            "untagged_vlan": related_id(untagged),
            "tagged_vlans": sorted(tagged_ids),
        },
        None,
        warnings,
    )


def sync_device(
    nb: Any,
    collected: CollectedDevice,
    scope: InterfaceSearchScope,
    vlan_cache: VlanCache,
    dry_run: bool,
) -> SyncSummary:
    """Compare one switch or stack and apply only the necessary interface updates.

    ``scope`` is :func:`build_interface_search_scope`'s. Every change line names
    the device the update lands on, and a bracketed :func:`route_note` marks one
    that lands on another stack member or under a template name, so a plan
    shows where each write goes before ``--apply``.
    """

    stack = scope.stack
    summary = SyncSummary(device=str(stack.connected.name), dry_run=dry_run)
    contexts_by_device_id: dict[int, DeviceScopeContext] = {}
    blocked: dict[int, BlockedMember] = {}
    misplaced: dict[tuple[int, str], tuple[Any, Any, Any]] = {}

    for discovered in collected.interfaces:
        match = _place(discovered.name, scope, summary, blocked, misplaced)
        if match is None:
            continue
        interface, owner = match.interface, match.owner

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
            summary.errors.append(f"{owner.name}/{discovered.name}: {error}")
            continue
        summary.warnings.extend(
            f"{owner.name}/{discovered.name}: {warning}" for warning in warnings
        )

        if current == desired:
            summary.unchanged += 1
            continue

        note = route_note(discovered.name, interface, owner, stack)
        change = f"{owner.name}/{interface.name}{note}: {current} -> {desired}"
        if dry_run:
            _record_update(summary, f"DRY-RUN {change}", owner, stack)
            continue

        try:
            LOGGER.info("Updating NetBox interface %s", change)
            interface.update(desired)
            refreshed = nb.dcim.interfaces.get(interface.id)
            if refreshed is None:
                raise RuntimeError("interface disappeared while verifying the update")
            persisted = current_interface_state(refreshed)
            if persisted != desired:
                raise RuntimeError(f"verification failed; NetBox returned {persisted}")
            _record_update(summary, f"VERIFIED {change}", owner, stack)
        except Exception as exc:
            summary.errors.append(f"{owner.name}/{interface.name}: update failed: {exc}")

    # Synchronize status and descriptions independently from VLAN state. This
    # ensures a VLAN ambiguity cannot prevent an otherwise safe metadata
    # update, and includes routed or unused ports absent from VLAN output.
    for discovered in collected.interface_metadata:
        match = _place(discovered.name, scope, summary, blocked, misplaced)
        if match is None:
            continue
        interface, owner = match.interface, match.owner

        desired_metadata: dict[str, Any] = {}
        if discovered.enabled is not None:
            desired_metadata["enabled"] = discovered.enabled
        if discovered.description is not None:
            desired_metadata["description"] = discovered.description
        if not desired_metadata:
            continue

        current_metadata = current_interface_metadata(interface)
        current_subset = {
            field_name: current_metadata[field_name] for field_name in desired_metadata
        }
        if current_subset == desired_metadata:
            summary.unchanged += 1
            continue

        note = route_note(discovered.name, interface, owner, stack)
        change = (
            f"{owner.name}/{interface.name}{note} metadata "
            f"(device_status={discovered.device_status or 'unknown'}): "
            f"{current_subset} -> {desired_metadata}"
        )
        if dry_run:
            _record_update(summary, f"DRY-RUN {change}", owner, stack)
            continue

        try:
            LOGGER.info("Updating NetBox interface %s", change)
            interface.update(desired_metadata)
            refreshed = nb.dcim.interfaces.get(interface.id)
            if refreshed is None:
                raise RuntimeError("interface disappeared while verifying the metadata update")
            persisted = current_interface_metadata(refreshed)
            persisted_subset = {
                field_name: persisted[field_name] for field_name in desired_metadata
            }
            if persisted_subset != desired_metadata:
                raise RuntimeError(
                    f"metadata verification failed; NetBox returned {persisted_subset}"
                )
            _record_update(summary, f"VERIFIED {change}", owner, stack)
        except Exception as exc:
            summary.errors.append(f"{owner.name}/{interface.name}: metadata update failed: {exc}")

    _report_stack_leftovers(summary, blocked, misplaced)
    return summary


def _place(
    name: str,
    scope: InterfaceSearchScope,
    summary: SyncSummary,
    blocked: dict[int, BlockedMember],
    misplaced: dict[tuple[int, str], tuple[Any, Any, Any]],
) -> ScopedMatch | None:
    """Match one reported port, or record why it's skipped. ``None`` when skipped."""

    match = match_scoped_interface(name, scope)
    for device, copy in match.misplaced:
        misplaced.setdefault((int(device.id), str(copy.name)), (device, copy, match.owner))
    if match.blocked_member is not None:
        summary.skipped += 1
        item = blocked.get(match.blocked_member)
        if item is None:
            reason = scope.stack.unresolved.get(
                match.blocked_member, "no NetBox device for this stack member"
            )
            item = blocked[match.blocked_member] = BlockedMember(match.blocked_member, reason)
        # The VLAN and metadata passes both report most ports; list each once.
        if all(interface_signature(port) != interface_signature(name) for port in item.ports):
            item.ports.append(name)
        return None
    if match.error:
        summary.skipped += 1
        summary.errors.append(match.error)
        return None
    return match


def _record_update(summary: SyncSummary, change: str, owner: Any, stack: Stack) -> None:
    """Count one planned or verified update, and whether it was routed to another member."""
    summary.updated += 1
    summary.changes.append(change)
    if int(owner.id) != int(stack.connected.id):
        summary.routed += 1


def _report_stack_leftovers(
    summary: SyncSummary,
    blocked: dict[int, BlockedMember],
    misplaced: dict[tuple[int, str], tuple[Any, Any, Any]],
) -> None:
    """One warning per stack member whose ports were skipped, and per device holding copies."""

    for item in blocked.values():
        summary.warnings.append(
            f"{len(item.ports)} port(s) of stack member {item.member} not synced "
            f"(e.g. {item.ports[0]}) — {item.reason}"
        )
    summary.blocked = list(blocked.values())

    by_holder: dict[int, list[tuple[Any, Any, Any]]] = defaultdict(list)
    for device, copy, owner in misplaced.values():
        by_holder[int(device.id)].append((device, copy, owner))
        summary.misplaced[f"{device.name}/{copy.name}"] = str(owner.name)
    for copies in by_holder.values():
        device, copy, owner = copies[0]
        summary.warnings.append(
            f"{len(copies)} interface(s) on {device.name} belong to another stack member "
            f"(e.g. {copy.name} belongs on {owner.name}), likely left by a create-interfaces "
            "run before stacks were handled — no longer synced; nothing is deleted, remove "
            "them in NetBox once any cables or IPs are moved"
        )


def find_collected_result(multi_result: Any) -> CollectedDevice | None:
    for item in multi_result:
        if isinstance(item.result, CollectedDevice):
            return item.result
    return None
