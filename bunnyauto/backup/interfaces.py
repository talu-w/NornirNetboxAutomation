"""Parse the interface show-commands into one row per interface.

Ported verbatim from ``perform_backup.py`` (shared byte-for-byte with the safe
variant). ``build_interface_rows`` joins the five command outputs by interface
name into the rows the workbook renders.
"""

from __future__ import annotations

import re
from typing import Any

INTERFACE_COMMANDS: dict[str, str] = {
    "ip_brief": "show ip interface brief",
    "stats": "show interfaces stats",
    "interfaces": "show interfaces",
    "switchport": "show interfaces switchport",
    "trunk": "show interfaces trunk",
}


def canonical_interface_name(name: str) -> str:
    """Normalize common Cisco long and short interface names for joining."""
    compact = name.strip().replace(" ", "")
    replacements = {
        "HundredGigabitEthernet": "Hu",
        "FortyGigabitEthernet": "Fo",
        "TwentyFiveGigE": "Twe",
        "TenGigabitEthernet": "Te",
        "TwoGigabitEthernet": "Tw",
        "GigabitEthernet": "Gi",
        "FastEthernet": "Fa",
        "Ethernet": "Eth",
        "Port-channel": "Po",
        "PortChannel": "Po",
        "Loopback": "Lo",
        "Vlan": "Vl",
    }
    for long_name, short_name in replacements.items():
        if compact.casefold().startswith(long_name.casefold()):
            return short_name + compact[len(long_name) :]
    return compact


def new_interface_row(interface: str) -> dict[str, Any]:
    """Return an empty report row with a stable schema.

    Column order is load-bearing: the workbook keys off it (A:Y, numeric format
    on columns 8-15). Do not reorder without updating ``workbook.py``.
    """
    return {
        "Interface": canonical_interface_name(interface),
        "IP Address": "",
        "Admin State": "",
        "Protocol State": "",
        "Description": "",
        "Duplex": "",
        "Speed": "",
        "Input Rate (bps)": None,
        "Input Rate (pps)": None,
        "Output Rate (bps)": None,
        "Output Rate (pps)": None,
        "RX Packets": None,
        "RX Bytes": None,
        "TX Packets": None,
        "TX Bytes": None,
        "Last Received": "",
        "Last Transmitted": "",
        "Switchport": "",
        "Administrative Mode": "",
        "Operational Mode": "",
        "Access VLAN": "",
        "Native VLAN": "",
        "Allowed VLANs": "",
        "Active VLANs": "",
        "Forwarding VLANs": "",
    }


def get_interface_row(rows: dict[str, dict[str, Any]], interface: str) -> dict[str, Any]:
    key = canonical_interface_name(interface)
    return rows.setdefault(key, new_interface_row(key))


def parse_ip_interface_brief(output: str, rows: dict[str, dict[str, Any]]) -> None:
    pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+(?P<ip>\S+)\s+"
        r"\S+\s+\S+\s+(?P<status>.+?)\s+(?P<protocol>up|down)\s*$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match or match.group("interface").casefold() == "interface":
            continue
        row = get_interface_row(rows, match.group("interface"))
        row["IP Address"] = match.group("ip")
        row["Admin State"] = match.group("status")
        row["Protocol State"] = match.group("protocol")


def parse_show_interfaces(output: str, rows: dict[str, dict[str, Any]]) -> None:
    header_pattern = re.compile(
        r"^(?P<interface>\S+) is (?P<state>.+?), line protocol is (?P<protocol>\S+)",
        re.MULTILINE,
    )
    matches = list(header_pattern.finditer(output))

    for index, match in enumerate(matches):
        block_end = matches[index + 1].start() if index + 1 < len(matches) else len(output)
        block = output[match.start() : block_end]
        row = get_interface_row(rows, match.group("interface"))
        row["Admin State"] = match.group("state")
        row["Protocol State"] = match.group("protocol").rstrip(",")

        field_patterns = {
            "Description": r"^\s*Description:\s*(.+)$",
            "Last Received": r"Last input\s+([^,]+)",
            "Last Transmitted": r"Last input\s+[^,]+,\s*output\s+([^,]+)",
            "Input Rate (bps)": r"5 minute input rate\s+(\d+)\s+bits/sec",
            "Input Rate (pps)": r"5 minute input rate\s+\d+\s+bits/sec,\s+(\d+)\s+packets/sec",
            "Output Rate (bps)": r"5 minute output rate\s+(\d+)\s+bits/sec",
            "Output Rate (pps)": r"5 minute output rate\s+\d+\s+bits/sec,\s+(\d+)\s+packets/sec",
            "RX Packets": r"^\s*(\d+) packets input,",
            "RX Bytes": r"^\s*\d+ packets input,\s*(\d+) bytes",
            "TX Packets": r"^\s*(\d+) packets output,",
            "TX Bytes": r"^\s*\d+ packets output,\s*(\d+) bytes",
        }
        for field_name, pattern in field_patterns.items():
            value_match = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
            if value_match:
                value = value_match.group(1).strip()
                row[field_name] = int(value) if value.isdigit() else value

        link_match = re.search(
            r"\b(?P<duplex>(?:Full|Half|Auto)-duplex),\s*(?P<speed>[^,\n]+)",
            block,
            re.IGNORECASE,
        )
        if link_match:
            row["Duplex"] = link_match.group("duplex")
            row["Speed"] = link_match.group("speed").strip()


def parse_show_interface_stats(output: str, rows: dict[str, dict[str, Any]]) -> None:
    current_interface = ""
    for line in output.splitlines():
        interface_match = re.match(r"^\s*Interface\s+(\S+)\s*$", line, re.IGNORECASE)
        if interface_match:
            current_interface = interface_match.group(1)
            continue

        total_match = re.match(
            r"^\s*Total\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line, re.IGNORECASE
        )
        if current_interface and total_match:
            row = get_interface_row(rows, current_interface)
            row["RX Packets"] = int(total_match.group(1))
            row["RX Bytes"] = int(total_match.group(2))
            row["TX Packets"] = int(total_match.group(3))
            row["TX Bytes"] = int(total_match.group(4))


def vlan_number(value: str) -> str:
    match = re.match(r"\s*(\d+|none|unassigned)", value, re.IGNORECASE)
    return match.group(1) if match else value.strip()


def parse_show_interfaces_switchport(output: str, rows: dict[str, dict[str, Any]]) -> None:
    blocks = re.split(r"(?=^Name:\s*)", output, flags=re.MULTILINE)
    fields = {
        "Switchport": "Switchport",
        "Administrative Mode": "Administrative Mode",
        "Operational Mode": "Operational Mode",
        "Access Mode VLAN": "Access VLAN",
        "Trunking Native Mode VLAN": "Native VLAN",
        "Trunking VLANs Enabled": "Allowed VLANs",
    }
    for block in blocks:
        name_match = re.search(r"^Name:\s*(\S+)", block, re.MULTILINE)
        if not name_match:
            continue
        row = get_interface_row(rows, name_match.group(1))

        for label, field_name in fields.items():
            match = re.search(rf"^{re.escape(label)}:\s*(.+)$", block, re.MULTILINE | re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                row[field_name] = (
                    vlan_number(value) if field_name in {"Access VLAN", "Native VLAN"} else value
                )


def parse_show_interfaces_trunk(output: str, rows: dict[str, dict[str, Any]]) -> None:
    section = ""
    section_headers = {
        "vlans allowed on trunk": "Allowed VLANs",
        "vlans allowed and active in management domain": "Active VLANs",
        "vlans in spanning tree forwarding state and not pruned": "Forwarding VLANs",
    }
    for line in output.splitlines():
        lowered = line.strip().casefold()
        if "native vlan" in lowered and lowered.startswith("port"):
            section = "trunk"
            continue

        changed_section = False
        for heading, field_name in section_headers.items():
            if heading in lowered:
                section = field_name
                changed_section = True
                break
        if changed_section or not lowered or lowered.startswith("port"):
            continue

        if section == "trunk":
            match = re.match(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
            if match:
                row = get_interface_row(rows, match.group(1))
                if not row["Administrative Mode"]:
                    row["Administrative Mode"] = match.group(2)
                row["Operational Mode"] = match.group(4)
                row["Native VLAN"] = match.group(5)
        elif section in section_headers.values():
            match = re.match(r"^\s*(\S+)\s+(.+?)\s*$", line)
            if match:
                get_interface_row(rows, match.group(1))[section] = match.group(2)


def interface_sort_key(name: str) -> tuple[str, tuple[int, ...], str]:
    prefix_match = re.match(r"([A-Za-z-]+)(.*)", name)
    prefix = prefix_match.group(1) if prefix_match else name
    numbers = tuple(int(value) for value in re.findall(r"\d+", name))
    return prefix.casefold(), numbers, name.casefold()


def build_interface_rows(outputs: dict[str, str]) -> list[dict[str, Any]]:
    """Parse and join all collected command output by interface name."""
    rows: dict[str, dict[str, Any]] = {}
    parse_ip_interface_brief(outputs.get("ip_brief", ""), rows)
    parse_show_interfaces(outputs.get("interfaces", ""), rows)
    parse_show_interface_stats(outputs.get("stats", ""), rows)
    parse_show_interfaces_switchport(outputs.get("switchport", ""), rows)
    parse_show_interfaces_trunk(outputs.get("trunk", ""), rows)
    return [rows[name] for name in sorted(rows, key=interface_sort_key)]
