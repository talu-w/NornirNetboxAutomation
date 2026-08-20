"""Create an engineer-focused network-health workbook from Nornir and NetBox.

The script uses the repository's existing Nornir ``config.yaml``. NetBox devices
are loaded by that configuration, normalized, and filtered with Nornir's ``F``
filter. It collects device, interface, EtherChannel, port-security, CPU, and
environment state. No device configuration is changed.
"""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nornir import InitNornir
from nornir.core.filter import F
from nornir.core.inventory import ConnectionOptions, Host
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

try:
    from openpyxl import Workbook
    from openpyxl.comments import Comment
    from openpyxl.formatting.rule import ColorScaleRule, FormulaRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo
except ImportError as exc:
    raise SystemExit(
        "ERROR: This script requires openpyxl. Install it with: pip install openpyxl"
    ) from exc

try:
    from rich.console import Console
except ImportError as exc:
    raise SystemExit(
        "ERROR: This script requires Rich. Install it with: pip install rich"
    ) from exc


DEFAULT_CONFIG_FILE = "config.yaml"
DEFAULT_TARGET_TAG = "nornirtest"
DEFAULT_OUTPUT_FILE = (
    "Network_Elaborate_Health_Report_"
    f"{datetime.now().astimezone().strftime('%Y-%m-%d')}.xlsx"
)
DEFAULT_CONNECTION_TIMEOUT = 60.0
DEFAULT_AUTH_TIMEOUT = 120.0
DEFAULT_BANNER_TIMEOUT = 120.0
DEFAULT_READ_TIMEOUT = 180.0
DEFAULT_GLOBAL_DELAY_FACTOR = 2.0

# Internal scoring values. They are stored in hidden worksheet rows so the
# front-facing report stays clean while its formulas remain consistent.
CPU_WARNING_PCT = 75.0
CPU_CRITICAL_PCT = 90.0
MIN_DATA_COVERAGE_PCT = 60.0
WARNING_PENALTY = 10
CRITICAL_PENALTY = 25
ENVIRONMENT_ALERT_PENALTY = 10
ERR_DISABLED_PENALTY = 10
PORT_SECURITY_PENALTY = 10
DEGRADED_ETHERCHANNEL_PENALTY = 10
DOWN_ETHERCHANNEL_PENALTY = 25
MAX_COUNT_PENALTY = 30
MAX_ETHERCHANNEL_PENALTY = 50
HEALTHY_SCORE = 85
WATCH_SCORE = 70
HEALTH_COMPONENT_COUNT = 6

PHYSICAL_INTERFACE_RE = re.compile(
    r"^(?:Fa|FastEthernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|"
    r"Tw|TwoGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|"
    r"Hu|HundredGig(?:E|abitEthernet)|Eth|Ethernet|Et)\d",
    re.IGNORECASE,
)

INTERFACE_STATUS_RE = re.compile(
    r"\b(err-disabled|errdisabled|notconnect(?:ed)?|notconnec|connected|disabled|inactive|"
    r"monitoring|sfpAbsent|xcvrAbsent)\b",
    re.IGNORECASE,
)

ETHERCHANNEL_ROW_RE = re.compile(
    r"^\s*(?P<group>\d+)\s+"
    r"(?P<name>(?:Po|Port-?channel)\s*\d+)"
    r"(?:\((?P<flags>[^)]*)\))?\s*(?P<rest>.*)$",
    re.IGNORECASE,
)

ETHERCHANNEL_MEMBER_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z-]*\d[\w./:-]*)"
    r"\((?P<flags>[^)]+)\)",
)

ERRDISABLE_REASON_RE = re.compile(
    r"\b(psecure-violation|security-violation|bpduguard|bpdu-guard|"
    r"link-flap|channel-misconfig|udld|storm-control|dhcp-rate-limit|"
    r"arp-inspection|loopback|l2ptguard|sfp-config-mismatch)\b",
    re.IGNORECASE,
)

INVALID_COMMAND_MARKERS = (
    "% invalid input",
    "% incomplete command",
    "% ambiguous command",
    "invalid command",
    "unknown command",
)

console = Console()


@dataclass(slots=True)
class InterfaceSummary:
    connected: int | None = None
    not_connected: int | None = None
    total: int | None = None
    err_disabled: list[dict[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class EtherChannelState:
    name: str
    group: int
    protocol: str
    flags: str
    state: str
    members: list[str] = field(default_factory=list)
    bundled_members: list[str] = field(default_factory=list)
    problem_members: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PortSecurityIssue:
    interface: str
    violation_count: int
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeviceHealth:
    hostname: str
    location: str = ""
    site: str = ""
    role: str = ""
    model: str = ""
    platform: str = ""
    netbox_status: str = ""
    primary_ip: str = ""
    serial_number: str = ""
    firmware: str = ""
    connected_interfaces: int | None = None
    not_connected_interfaces: int | None = None
    total_interfaces: int | None = None
    cpu_pct: float | None = None
    environment_alerts: int | None = None
    err_disabled_interfaces: list[dict[str, str]] = field(default_factory=list)
    err_disabled_count: int | None = None
    port_security_issues: list[dict[str, Any]] = field(default_factory=list)
    port_security_interfaces: int | None = None
    port_security_violations: int | None = None
    etherchannels: list[dict[str, Any]] = field(default_factory=list)
    etherchannels_total: int | None = None
    etherchannels_healthy: int | None = None
    etherchannels_degraded: int | None = None
    etherchannels_down: int | None = None
    etherchannel_members_total: int | None = None
    etherchannel_members_bundled: int | None = None
    reachable: bool = False
    collected_at_utc: datetime | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def positive_float(value: str) -> float:
    """Return a positive numeric command-line value."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def environment_flag(name: str) -> bool:
    """Interpret a common true/false environment-variable value."""

    value = os.getenv(name, "").strip().casefold()
    return value in {"1", "true", "yes", "on"}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect engineer-focused health data from NetBox-tagged devices with "
            "Nornir and create an elaborate Excel report."
        )
    )
    parser.add_argument(
        "--config",
        default=os.getenv("NORNIR_CONFIG_FILE", DEFAULT_CONFIG_FILE),
        help="Existing Nornir config file (default: config.yaml)",
    )
    parser.add_argument(
        "--tag",
        default=os.getenv("NORNIR_TARGET_TAG", DEFAULT_TARGET_TAG),
        help="NetBox tag to select (default: nornirtest)",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=f"Excel output path (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--connection-timeout",
        "--conn-timeout",
        dest="connection_timeout",
        type=positive_float,
        default=os.getenv("NORNIR_CONNECTION_TIMEOUT", str(DEFAULT_CONNECTION_TIMEOUT)),
        help=(
            "Seconds allowed to establish SSH transport "
            f"(default: {DEFAULT_CONNECTION_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--auth-timeout",
        type=positive_float,
        default=os.getenv("NORNIR_AUTH_TIMEOUT", str(DEFAULT_AUTH_TIMEOUT)),
        help=(
            "Seconds allowed for SSH authentication "
            f"(default: {DEFAULT_AUTH_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--banner-timeout",
        type=positive_float,
        default=os.getenv("NORNIR_BANNER_TIMEOUT", str(DEFAULT_BANNER_TIMEOUT)),
        help=(
            "Seconds allowed for an SSH identification banner "
            f"(default: {DEFAULT_BANNER_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--read-timeout",
        type=positive_float,
        default=os.getenv("NORNIR_READ_TIMEOUT", str(DEFAULT_READ_TIMEOUT)),
        help=(
            "Seconds allowed for each show command to finish "
            f"(default: {DEFAULT_READ_TIMEOUT:g})"
        ),
    )
    parser.add_argument(
        "--global-delay-factor",
        type=positive_float,
        default=os.getenv(
            "NORNIR_GLOBAL_DELAY_FACTOR", str(DEFAULT_GLOBAL_DELAY_FACTOR)
        ),
        help=(
            "Netmiko delay multiplier for slow devices "
            f"(default: {DEFAULT_GLOBAL_DELAY_FACTOR:g})"
        ),
    )
    parser.add_argument(
        "--legacy-ssh",
        action="store_true",
        default=environment_flag("NORNIR_LEGACY_SSH"),
        help=(
            "Enable Netmiko compatibility for older SSH servers that do not "
            "advertise RSA-SHA2 support"
        ),
    )
    return parser.parse_args(argv)


def build_netmiko_extras(args: argparse.Namespace) -> dict[str, Any]:
    """Build adjustable Netmiko settings for slow or legacy devices."""

    extras: dict[str, Any] = {
        "conn_timeout": args.connection_timeout,
        "banner_timeout": args.banner_timeout,
        "auth_timeout": args.auth_timeout,
        "read_timeout_override": args.read_timeout,
        "global_delay_factor": args.global_delay_factor,
        "fast_cli": False,
    }
    if args.legacy_ssh:
        extras["disable_sha2_fix"] = True
    return extras


def normalize_tags(tags: Sequence[Any] | None) -> list[str]:
    """Convert NetBox tag strings, dictionaries, or objects to lowercase values."""

    normalized: set[str] = set()
    for tag in tags or []:
        if isinstance(tag, str):
            values = [tag]
        elif isinstance(tag, Mapping):
            values = [tag.get("slug"), tag.get("name")]
        else:
            values = [getattr(tag, "slug", None), getattr(tag, "name", None)]

        for value in values:
            if value:
                normalized.add(str(value).casefold())
    return sorted(normalized)


def _nested_value(data: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = data
        for part in path.split("."):
            if isinstance(value, Mapping):
                value = value.get(part)
            else:
                value = getattr(value, part, None)
            if value is None:
                break
        if value not in (None, ""):
            return value
    return None


def _display_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, Mapping):
        for key in ("display", "label", "name", "model", "address", "value", "slug"):
            if value.get(key) not in (None, ""):
                return str(value[key])
        return ""
    for attribute in ("display", "label", "name", "model", "address", "value", "slug"):
        candidate = getattr(value, attribute, None)
        if candidate not in (None, ""):
            return str(candidate)
    return str(value)


def netbox_metadata(host: Host) -> dict[str, str]:
    """Read useful management fields already supplied by the NetBox inventory."""

    data = host.data
    site = _display_value(_nested_value(data, "site", "site_name"))
    location = _display_value(_nested_value(data, "location", "location_name")) or site
    return {
        "location": location,
        "site": site,
        "role": _display_value(_nested_value(data, "role", "device_role")),
        "model": _display_value(_nested_value(data, "device_type.model", "device_type", "model")),
        "platform": _display_value(host.platform or _nested_value(data, "platform")),
        "netbox_status": _display_value(_nested_value(data, "status")),
        "primary_ip": _display_value(
            _nested_value(data, "primary_ip4.address", "primary_ip4", "primary_ip.address", "primary_ip")
        )
        or str(host.hostname or ""),
        "serial_number": _display_value(_nested_value(data, "serial", "serial_number")),
    }


def _is_invalid_command(output: str) -> bool:
    lowered = output.casefold()
    return any(marker in lowered for marker in INVALID_COMMAND_MARKERS)


def run_first_supported(
    task: Task,
    label: str,
    commands: Sequence[str],
    read_timeout: float = DEFAULT_READ_TIMEOUT,
) -> tuple[str, str]:
    """Run commands in order and return the first usable output and command."""

    errors: list[str] = []
    for command in commands:
        try:
            results = task.run(
                name=f"{label}: {command}",
                task=netmiko_send_command,
                command_string=command,
                read_timeout=read_timeout,
            )
            result = results[-1]
        except Exception as exc:  # noqa: BLE001 - plugins raise platform-specific errors.
            errors.append(f"{command}: {exc}")
            continue

        if result.failed:
            errors.append(f"{command}: {result.exception or result.result}")
            continue

        output = str(result.result or "")
        if output.strip() and not _is_invalid_command(output):
            return output, command
        errors.append(f"{command}: unsupported or empty output")

    raise RuntimeError("; ".join(errors) or f"No {label} command succeeded")


def command_profile(platform: str) -> dict[str, list[str]]:
    platform_name = platform.casefold()
    profile = {
        "version": ["show version"],
        "interfaces": ["show interfaces status", "show ip interface brief"],
        "cpu": ["show process cpu"],
        "environment": ["show environment all", "show environment",],
        "etherchannels": ["show etherchannel summary", "show port-channel summary"],
        "err_disabled": [
            "show interfaces status err-disabled",
            "show interface status err-disabled",
        ],
        "port_security": ["show port-security"],
    }

    if "nxos" in platform_name or "nx-os" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show system resources"],
                "environment": ["show env all"],
                "etherchannels": [
                    "show port-channel summary",
                    "show etherchannel summary",
                ],
                "err_disabled": [
                    "show interface status err-disabled",
                    "show interfaces status err-disabled",
                ],
                "port_security": ["show port-security"],
            }
        )
    elif "ios" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show process cpu"],
                "environment": ["show env all"],
                "etherchannels": [
                    "show etherchannel summary",
                    "show port-channel summary",
                ],
                "err_disabled": [
                    "show interfaces status err-disabled",
                    "show interface status err-disabled",
                ],
                "port_security": ["show port-security"],
            }
        )
    elif "eos" in platform_name or "arista" in platform_name:
        profile.update(
            {
                "interfaces": ["show interfaces status"],
                "cpu": ["show processes top once"],
                "environment": ["show system environment all"],
                "etherchannels": ["show port-channel summary"],
                "err_disabled": [
                    "show interfaces status errdisabled",
                    "show interfaces status err-disabled",
                ],
                "port_security": ["show port-security"],
            }
        )
    return profile


def parse_firmware(output: str) -> str:
    patterns = (
        r"Cisco IOS XE Software, Version\s+([^,\s]+)",
        r"Cisco IOS Software.*?Version\s+([^,\s]+)",
        r"NXOS:\s+version\s+([^\s]+)",
        r"system:\s+version\s+([^\s]+)",
        r"Software image version:\s*([^\s]+)",
        r"Arista .*? version\s+([^\s]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
    return "Unknown"


def parse_cpu_pct(output: str) -> float | None:
    match = re.search(
        r"CPU utilization for five seconds:\s*(\d+(?:\.\d+)?)%",
        output,
        re.IGNORECASE,
    )
    if match:
        return float(match.group(1))

    idle_match = re.search(
        r"(\d+(?:\.\d+)?)%\s*(?:idle|id)\b", output, re.IGNORECASE
    )
    if idle_match:
        return max(0.0, min(100.0, 100.0 - float(idle_match.group(1))))

    user_match = re.search(r"(\d+(?:\.\d+)?)%\s*user", output, re.IGNORECASE)
    kernel_match = re.search(r"(\d+(?:\.\d+)?)%\s*kernel", output, re.IGNORECASE)
    if user_match and kernel_match:
        return min(100.0, float(user_match.group(1)) + float(kernel_match.group(1)))
    return None


def parse_interface_summary(output: str) -> InterfaceSummary:
    connected = 0
    total = 0
    err_disabled: list[dict[str, str]] = []

    for line in output.splitlines():
        tokens = line.split()
        if not tokens or not PHYSICAL_INTERFACE_RE.match(tokens[0]):
            continue
        status_match = INTERFACE_STATUS_RE.search(line)
        if not status_match:
            continue
        status = status_match.group(1).casefold()
        total += 1
        connected += int(status == "connected")
        if status in {"err-disabled", "errdisabled"}:
            err_disabled.extend(parse_err_disabled_interfaces(line))

    if total:
        return InterfaceSummary(
            connected=connected,
            not_connected=total - connected,
            total=total,
            err_disabled=err_disabled,
        )

    # Router-style fallback for "show ip interface brief".
    brief_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+\S+\s+\S+\s+\S+\s+"
        r"(?P<status>administratively down|up|down)\s+(?P<protocol>up|down)\s*$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = brief_pattern.match(line)
        if not match or not PHYSICAL_INTERFACE_RE.match(match.group("interface")):
            continue
        total += 1
        connected += int(
            match.group("status").casefold() == "up"
            and match.group("protocol").casefold() == "up"
        )

    return InterfaceSummary(
        connected=connected if total else None,
        not_connected=(total - connected) if total else None,
        total=total if total else None,
        err_disabled=[],
    )


def parse_err_disabled_interfaces(output: str) -> list[dict[str, str]]:
    """Return err-disabled physical interfaces and any reported reason."""

    issues: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        tokens = line.split()
        if not tokens or not PHYSICAL_INTERFACE_RE.match(tokens[0]):
            continue
        lowered = line.casefold()
        if "err-disabled" not in lowered and "errdisabled" not in lowered:
            continue
        reason_match = ERRDISABLE_REASON_RE.search(line)
        interface = tokens[0]
        issues[interface.casefold()] = {
            "interface": interface,
            "reason": reason_match.group(1) if reason_match else "Reason not reported",
        }
    return sorted(issues.values(), key=lambda item: item["interface"].casefold())


def merge_interface_issues(
    *issue_groups: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    """Deduplicate interface issues while retaining the most useful reason."""

    merged: dict[str, dict[str, str]] = {}
    for group in issue_groups:
        for issue in group:
            interface = str(issue.get("interface", "")).strip()
            if not interface:
                continue
            reason = str(issue.get("reason", "Reason not reported")).strip()
            key = interface.casefold()
            if key not in merged or merged[key]["reason"] == "Reason not reported":
                merged[key] = {"interface": interface, "reason": reason}
    return sorted(merged.values(), key=lambda item: item["interface"].casefold())


def parse_port_security_issues(output: str) -> list[PortSecurityIssue]:
    """Parse affected interfaces from the Cisco port-security summary table."""

    issues: dict[str, PortSecurityIssue] = {}
    row_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+"
        r"(?P<maximum>\d+)\s+(?P<current>\d+)\s+"
        r"(?P<violations>\d+)\s+(?P<action>\S+)",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = row_pattern.match(line)
        if not match or not PHYSICAL_INTERFACE_RE.match(match.group("interface")):
            continue
        violations = int(match.group("violations"))
        if violations <= 0:
            continue
        issue = PortSecurityIssue(
            interface=match.group("interface"),
            violation_count=violations,
            action=match.group("action"),
        )
        issues[issue.interface.casefold()] = issue
    return sorted(issues.values(), key=lambda item: item.interface.casefold())


def parse_etherchannels(output: str) -> list[EtherChannelState]:
    """Parse channel state and member flags from EtherChannel summaries."""

    raw_channels: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in output.splitlines():
        row_match = ETHERCHANNEL_ROW_RE.match(line)
        if row_match:
            if current is not None:
                raw_channels.append(current)
            current = {
                "group": int(row_match.group("group")),
                "name": row_match.group("name").replace(" ", ""),
                "flags": row_match.group("flags") or "",
                "text": row_match.group("rest"),
            }
            continue
        if current is not None and ETHERCHANNEL_MEMBER_RE.search(line):
            current["text"] = f"{current['text']} {line.strip()}"
    if current is not None:
        raw_channels.append(current)

    channels: list[EtherChannelState] = []
    for raw in raw_channels:
        text = str(raw["text"])
        protocol = "Unknown"
        for token in re.findall(
            r"\b(?:LACP|PAgP|static|on|none)\b", text, re.IGNORECASE
        ):
            protocol = token
            break

        members: list[str] = []
        bundled: list[str] = []
        problem: list[str] = []
        seen: set[str] = set()
        for member_match in ETHERCHANNEL_MEMBER_RE.finditer(text):
            member = member_match.group("name")
            flags = member_match.group("flags")
            key = member.casefold()
            if key in seen:
                continue
            seen.add(key)
            members.append(member)
            if "P" in flags:
                bundled.append(member)
            else:
                problem.append(f"{member}({flags})")

        channel_flags = str(raw["flags"])
        channel_is_up = "U" in channel_flags or (
            not channel_flags and bool(bundled)
        )
        if not channel_is_up:
            state = "Down"
        elif problem or not members:
            state = "Degraded"
        else:
            state = "Up"

        channels.append(
            EtherChannelState(
                name=str(raw["name"]),
                group=int(raw["group"]),
                protocol=protocol,
                flags=channel_flags,
                state=state,
                members=members,
                bundled_members=bundled,
                problem_members=problem,
            )
        )
    return sorted(channels, key=lambda item: (item.group, item.name.casefold()))


def count_environment_alerts(output: str) -> int:
    alert_terms = re.compile(
        r"\b(fail(?:ed|ure)?|critical|alarm|shutdown|overtemp)\b", re.IGNORECASE
    )
    healthy_terms = re.compile(
        r"\b(no alarms?|normal|ok|good|passed|not present)\b", re.IGNORECASE
    )
    return sum(
        1
        for line in output.splitlines()
        if alert_terms.search(line) and not healthy_terms.search(line)
    )


def collect_device_health(
    task: Task, read_timeout: float = DEFAULT_READ_TIMEOUT
) -> Result:
    metadata = netbox_metadata(task.host)
    record = DeviceHealth(hostname=task.host.name, **metadata)
    profile = command_profile(record.platform)

    try:
        version_output, _ = run_first_supported(
            task, "Firmware", profile["version"], read_timeout
        )
    except Exception as exc:  # noqa: BLE001 - collection errors must remain in the report.
        record.notes.append(f"Connection or show version failed: {exc}")
        return Result(host=task.host, changed=False, result=record.to_dict())

    record.reachable = True
    record.firmware = parse_firmware(version_output)
    record.collected_at_utc = datetime.now(UTC).replace(tzinfo=None)

    try:
        interface_output, _ = run_first_supported(
            task, "Interfaces", profile["interfaces"], read_timeout
        )
        summary = parse_interface_summary(interface_output)
        record.connected_interfaces = summary.connected
        record.not_connected_interfaces = summary.not_connected
        record.total_interfaces = summary.total
        record.err_disabled_interfaces = summary.err_disabled
        if summary.total is None:
            record.notes.append(
                "Interface status output was returned but no physical ports were parsed."
            )
    except Exception as exc:  # noqa: BLE001 - collection errors must remain in the report.
        record.notes.append(f"Interface statistics unavailable: {exc}")

    try:
        errdisabled_output, _ = run_first_supported(
            task, "Err-disabled interfaces", profile["err_disabled"], read_timeout
        )
        record.err_disabled_interfaces = merge_interface_issues(
            record.err_disabled_interfaces,
            parse_err_disabled_interfaces(errdisabled_output),
        )
        record.err_disabled_count = len(record.err_disabled_interfaces)
    except Exception as exc:  # noqa: BLE001 - unsupported commands vary by platform.
        if record.total_interfaces is not None:
            record.err_disabled_count = len(record.err_disabled_interfaces)
        record.notes.append(f"Err-disabled interface detail unavailable: {exc}")

    try:
        etherchannel_output, _ = run_first_supported(
            task, "EtherChannels", profile["etherchannels"], read_timeout
        )
        channels = parse_etherchannels(etherchannel_output)
        record.etherchannels = [channel.to_dict() for channel in channels]
        record.etherchannels_total = len(channels)
        record.etherchannels_healthy = sum(
            channel.state == "Up" for channel in channels
        )
        record.etherchannels_degraded = sum(
            channel.state == "Degraded" for channel in channels
        )
        record.etherchannels_down = sum(
            channel.state == "Down" for channel in channels
        )
        record.etherchannel_members_total = sum(
            len(channel.members) for channel in channels
        )
        record.etherchannel_members_bundled = sum(
            len(channel.bundled_members) for channel in channels
        )
    except Exception as exc:  # noqa: BLE001 - unsupported commands vary by platform.
        record.notes.append(f"EtherChannel status unavailable: {exc}")

    try:
        port_security_output, _ = run_first_supported(
            task, "Port security", profile["port_security"], read_timeout
        )
        security_issues = parse_port_security_issues(port_security_output)
        record.port_security_issues = [issue.to_dict() for issue in security_issues]
        record.port_security_interfaces = len(security_issues)
        record.port_security_violations = sum(
            issue.violation_count for issue in security_issues
        )
    except Exception as exc:  # noqa: BLE001 - unsupported commands vary by platform.
        record.notes.append(f"Port-security status unavailable: {exc}")

    try:
        cpu_output, _ = run_first_supported(
            task, "CPU", profile["cpu"], read_timeout
        )
        record.cpu_pct = parse_cpu_pct(cpu_output)
        if record.cpu_pct is None:
            record.notes.append(
                "CPU output was returned but utilization could not be parsed."
            )
    except Exception as exc:  # noqa: BLE001 - collection errors must remain in the report.
        record.notes.append(f"CPU utilization unavailable: {exc}")

    try:
        environment_output, _ = run_first_supported(
            task, "Environment", profile["environment"], read_timeout
        )
        record.environment_alerts = count_environment_alerts(environment_output)
    except Exception as exc:  # noqa: BLE001 - collection errors must remain in the report.
        record.notes.append(f"Environment status unavailable: {exc}")

    return Result(host=task.host, changed=False, result=record.to_dict())


def _extract_records(results: Any, hosts: Mapping[str, Host]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for hostname, host in hosts.items():
        record: dict[str, Any] | None = None
        multi_result = results.get(hostname)
        if multi_result is not None:
            for item in multi_result:
                if isinstance(item.result, dict) and item.result.get("hostname") == hostname:
                    record = item.result
                    break
        if record is None:
            record = DeviceHealth(
                hostname=hostname,
                **netbox_metadata(host),
                notes=["Nornir did not return a collection result for this device."],
            ).to_dict()
        records.append(record)
    return sorted(records, key=lambda item: item["hostname"].casefold())


def _fill(color: str) -> PatternFill:
    return PatternFill("solid", fgColor=color)


def build_collection_notes(record: Mapping[str, Any]) -> list[str]:
    """Combine collection warnings with the conditions that reduced health."""

    notes = [str(note) for note in record.get("notes", []) if str(note).strip()]

    def add(note: str) -> None:
        if note not in notes:
            notes.append(note)

    if not record.get("reachable"):
        add(
            "Health impact: device was unreachable; live health data could not "
            "be collected."
        )
        return notes

    cpu_pct = record.get("cpu_pct")
    if isinstance(cpu_pct, (int, float)):
        if cpu_pct >= CPU_CRITICAL_PCT:
            add(
                f"Health impact: CPU utilization {cpu_pct:.1f}% met or exceeded the "
                f"critical threshold of {CPU_CRITICAL_PCT:.0f}%."
            )
        elif cpu_pct >= CPU_WARNING_PCT:
            add(
                f"Health impact: CPU utilization {cpu_pct:.1f}% met or exceeded the "
                f"warning threshold of {CPU_WARNING_PCT:.0f}%."
            )

    environment_alerts = record.get("environment_alerts")
    if isinstance(environment_alerts, (int, float)) and environment_alerts > 0:
        add(
            f"Health impact: {int(environment_alerts)} environmental alert"
            f"{'s were' if environment_alerts != 1 else ' was'} detected."
        )

    err_disabled = record.get("err_disabled_interfaces", [])
    if isinstance(err_disabled, Sequence) and err_disabled:
        details = ", ".join(
            f"{issue.get('interface', 'Unknown')} ({issue.get('reason', 'Reason not reported')})"
            for issue in err_disabled
            if isinstance(issue, Mapping)
        )
        add(
            f"Health impact: err-disabled interface details: {details}."
        )

    port_security_issues = record.get("port_security_issues", [])
    if isinstance(port_security_issues, Sequence) and port_security_issues:
        details = ", ".join(
            f"{issue.get('interface', 'Unknown')} "
            f"({issue.get('violation_count', 0)} violations, "
            f"action {issue.get('action', 'Unknown')})"
            for issue in port_security_issues
            if isinstance(issue, Mapping)
        )
        add(f"Health impact: port-security issues: {details}.")

    etherchannels = record.get("etherchannels", [])
    if isinstance(etherchannels, Sequence):
        for channel in etherchannels:
            if not isinstance(channel, Mapping) or channel.get("state") == "Up":
                continue
            members = channel.get("members", [])
            bundled = channel.get("bundled_members", [])
            problem = channel.get("problem_members", [])
            detail = (
                f"Health impact: {channel.get('name', 'Unknown channel')} is "
                f"{channel.get('state', 'Unknown')}; {len(bundled)}/{len(members)} "
                "members are bundled"
            )
            if problem:
                detail += f"; affected members: {', '.join(map(str, problem))}"
            add(f"{detail}.")

    available_components = 1 + sum(
        isinstance(record.get(field), (int, float))
        for field in (
            "cpu_pct",
            "environment_alerts",
            "err_disabled_count",
            "port_security_interfaces",
            "etherchannels_total",
        )
    )
    coverage_pct = available_components / HEALTH_COMPONENT_COUNT * 100
    if coverage_pct < MIN_DATA_COVERAGE_PCT:
        add(
            f"Health impact: only {coverage_pct:.0f}% of health inputs were available; "
            "health data is incomplete."
        )

    return notes


def _create_compact_health_workbook(
    records: Sequence[Mapping[str, Any]],
    target_tag: str,
    output_path: Path,
) -> None:
    """Retain the compact scorecard layout as an internal compatibility helper."""

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Network Health"
    sheet.sheet_view.showGridLines = False

    navy = "17365D"
    teal = "147D74"
    green = "C6EFCE"
    amber = "FFEB9C"
    red = "FFC7CE"
    pale_blue = "D9EAF7"
    white = "FFFFFF"
    thin_gray = Side(style="thin", color="D9E1F2")

    last_column = max(2, len(records) + 1)
    last_column_letter = get_column_letter(last_column)

    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=last_column)
    sheet["A1"] = "Nornir Networking Report - Networking Infrastructure Health"
    sheet["A1"].font = Font(size=18, bold=True, color=white)
    sheet["A1"].fill = _fill(navy)
    sheet["A1"].alignment = Alignment(vertical="center", wrap_text=True, shrink_to_fit=True)
    sheet.row_dimensions[1].height = 42

    sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=last_column)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    sheet["A2"] = (
        f"Scope: devices from the existing Nornir/NetBox inventory tagged "
        f"'{target_tag}' | Generated {generated}"
    )
    sheet["A2"].font = Font(italic=True, color="44546A")
    sheet["A2"].fill = _fill(pale_blue)
    sheet["A2"].alignment = Alignment(vertical="center", wrap_text=True, shrink_to_fit=True)
    sheet.row_dimensions[2].height = 32

    metric_rows = {
        "Health Status": 5,
        "Health Score": 6,
        "Data Coverage": 7,
        "Location": 8,
        "Site": 9,
        "Role": 10,
        "Model": 11,
        "Platform": 12,
        "NetBox Status": 13,
        "Primary IP": 14,
        "Serial Number": 15,
        "Current Firmware": 16,
        "Interface Usage": 17,
        "Connected Interfaces": 18,
        "Not Connected Interfaces": 19,
        "Total Interfaces": 20,
        "CPU Utilization": 21,
        "Environment Alerts": 22,
        "Err-disabled Interfaces": 23,
        "Reachable": 24,
        "Collected UTC": 25,
        "Collection Notes": 26,
    }

    sheet["A4"] = "Metric"
    for label, row in metric_rows.items():
        sheet.cell(row, 1, label)

    for row in range(4, 27):
        cell = sheet.cell(row, 1)
        cell.fill = _fill(navy)
        cell.font = Font(bold=True, color=white)
        cell.alignment = Alignment(vertical="center", wrap_text=True)

    field_map = {
        "Location": "location",
        "Site": "site",
        "Role": "role",
        "Model": "model",
        "Platform": "platform",
        "NetBox Status": "netbox_status",
        "Primary IP": "primary_ip",
        "Serial Number": "serial_number",
        "Current Firmware": "firmware",
        "Connected Interfaces": "connected_interfaces",
        "Not Connected Interfaces": "not_connected_interfaces",
        "Total Interfaces": "total_interfaces",
        "Environment Alerts": "environment_alerts",
        "Err-disabled Interfaces": "err_disabled_count",
        "Collected UTC": "collected_at_utc",
    }

    for index, record in enumerate(records, start=2):
        column = get_column_letter(index)
        sheet.cell(4, index, record.get("hostname", ""))
        for label, field_name in field_map.items():
            sheet.cell(metric_rows[label], index, record.get(field_name))

        cpu_pct = record.get("cpu_pct")
        sheet.cell(21, index, cpu_pct / 100 if isinstance(cpu_pct, (int, float)) else None)
        sheet.cell(24, index, "Yes" if record.get("reachable") else "No")
        sheet.cell(26, index, " | ".join(build_collection_notes(record)))

        sheet.cell(17, index, f'=IF({column}20=0,"",{column}18/{column}20)')
        sheet.cell(7, index, f"=(1+COUNT({column}21:{column}23))/4")
        sheet.cell(
            6,
            index,
            (
                f'=IF({column}24<>"Yes",0,MAX(0,100'
                f'-IF(ISNUMBER({column}21),IF({column}21>=$B$32,$B$35,'
                f'IF({column}21>=$B$31,$B$34,0)),0)'
                f'-IF(ISNUMBER({column}22),MIN({column}22*$B$36,$B$38),0)'
                f'-IF(ISNUMBER({column}23),MIN({column}23*$B$37,$B$38),0)))'
            ),
        )
        sheet.cell(
            5,
            index,
            (
                f'=IF({column}24<>"Yes","Unreachable",'
                f'IF({column}7<$B$33,"Insufficient Data",'
                f'IF({column}6>=$B$39,"Healthy",'
                f'IF({column}6>=$B$40,"Watch","Critical"))))'
            ),
        )

        header = sheet.cell(4, index)
        header.fill = _fill(teal)
        header.font = Font(bold=True, color=white)
        header.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        sheet.column_dimensions[column].width = 24

        for row in range(5, 27):
            cell = sheet.cell(row, index)
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = Border(bottom=thin_gray)

    sheet["A29"] = "Health scoring method"
    sheet.merge_cells("A29:B29")
    sheet["A29"].fill = _fill(navy)
    sheet["A29"].font = Font(bold=True, color=white)
    sheet["A30"] = "Parameter"
    sheet["B30"] = "Value"
    settings = [
        ("CPU warning", CPU_WARNING_PCT / 100),
        ("CPU critical", CPU_CRITICAL_PCT / 100),
        ("Minimum data coverage", MIN_DATA_COVERAGE_PCT / 100),
        ("Warning penalty", WARNING_PENALTY),
        ("Critical penalty", CRITICAL_PENALTY),
        ("Environment alert penalty", ENVIRONMENT_ALERT_PENALTY),
        ("Err-disabled penalty", ERR_DISABLED_PENALTY),
        ("Maximum count penalty", MAX_COUNT_PENALTY),
        ("Healthy score", HEALTHY_SCORE),
        ("Watch score", WATCH_SCORE),
    ]
    for row, (label, value) in enumerate(settings, start=31):
        sheet.cell(row, 1, label)
        sheet.cell(row, 2, value)
    for cell in sheet[30][:2]:
        cell.fill = _fill(teal)
        cell.font = Font(bold=True, color=white)
    for row in range(31, 34):
        sheet.cell(row, 2).number_format = "0%"

    sheet["A42"] = "Definitions"
    sheet["A42"].font = Font(bold=True)
    sheet.merge_cells(start_row=42, start_column=2, end_row=42, end_column=last_column)
    sheet.merge_cells(start_row=43, start_column=2, end_row=43, end_column=last_column)
    sheet["B42"] = (
        "Interface Usage = connected physical interfaces divided by all parsed physical "
        "interfaces. Unconnected, disabled, and err-disabled ports count as not connected."
    )
    sheet["B43"] = (
        "Health Score begins at 100 and applies visible CPU, environment, and "
        "err-disabled penalties. Missing metrics reduce Data Coverage instead of being "
        "treated as healthy or unhealthy."
    )
    sheet["B42"].alignment = Alignment(wrap_text=True, vertical="top")
    sheet["B43"].alignment = Alignment(wrap_text=True, vertical="top")
    sheet.row_dimensions[42].height = 58
    sheet.row_dimensions[43].height = 72

    sheet["A45"] = "Fleet summary"
    sheet.merge_cells("A45:B45")
    sheet["A45"].fill = _fill(navy)
    sheet["A45"].font = Font(bold=True, color=white)
    summary_labels = [
        "Devices",
        "Healthy",
        "Watch",
        "Critical",
        "Unreachable",
        "Insufficient Data",
        "Average Health Score",
        "Average Interface Usage",
    ]
    for row, label in enumerate(summary_labels, start=46):
        sheet.cell(row, 1, label)

    device_header_range = f"B4:{last_column_letter}4"
    status_range = f"B5:{last_column_letter}5"
    score_range = f"B6:{last_column_letter}6"
    usage_range = f"B17:{last_column_letter}17"
    sheet["B46"] = f"=COUNTA({device_header_range})"
    for row, status in zip(range(47, 52), summary_labels[1:6], strict=True):
        sheet.cell(row, 2, f'=COUNTIF({status_range},"{status}")')
    sheet["B52"] = f'=IFERROR(AVERAGE({score_range}),"")'
    sheet["B53"] = f'=IFERROR(AVERAGE({usage_range}),"")'
    sheet["B53"].number_format = "0%"

    sheet.column_dimensions["A"].width = 29
    sheet.column_dimensions["B"].width = max(sheet.column_dimensions["B"].width or 0, 24)
    sheet.row_dimensions[4].height = 30
    sheet.row_dimensions[26].height = 160
    sheet.freeze_panes = "A5"

    # Keep scoring mechanics available to formulas without showing them to
    # management users. Hidden rows collapse the method/definition section so
    # Fleet Summary follows the scorecard when scrolling.
    for row in range(29, 45):
        sheet.row_dimensions[row].hidden = True

    for column in range(2, last_column + 1):
        sheet.cell(6, column).number_format = "0"
        sheet.cell(7, column).number_format = "0%"
        sheet.cell(17, column).number_format = "0.0%"
        sheet.cell(21, column).number_format = "0.0%"
        sheet.cell(25, column).number_format = "yyyy-mm-dd hh:mm"

    status_cells = f"B5:{last_column_letter}5"
    for status, color in {
        "Healthy": green,
        "Watch": amber,
        "Critical": red,
        "Unreachable": red,
        "Insufficient Data": amber,
    }.items():
        sheet.conditional_formatting.add(
            status_cells,
            FormulaRule(formula=[f'B5="{status}"'], fill=_fill(color)),
        )
    sheet.conditional_formatting.add(
        f"B6:{last_column_letter}6",
        ColorScaleRule(
            start_type="num",
            start_value=0,
            start_color="F8696B",
            mid_type="num",
            mid_value=70,
            mid_color="FFEB84",
            end_type="num",
            end_value=100,
            end_color="63BE7B",
        ),
    )

    sheet["B17"].comment = Comment(
        "Connected physical interfaces divided by all parsed physical interfaces.",
        "Network Automation",
    )

    for row in range(29, 54):
        for column in range(1, min(last_column, 2) + 1):
            sheet.cell(row, column).alignment = Alignment(vertical="center", wrap_text=True)

    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_setup.orientation = "landscape"
    sheet.page_setup.fitToWidth = 1
    sheet.page_setup.fitToHeight = 1
    sheet.print_title_rows = "1:4"
    sheet.print_area = f"A1:{last_column_letter}26"

    workbook.calculation.calcMode = "auto"
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True

    output_path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output_path)


def _interface_issue_text(record: Mapping[str, Any]) -> str:
    issues = record.get("err_disabled_interfaces", [])
    if not isinstance(issues, Sequence):
        return ""
    return ", ".join(
        f"{issue.get('interface', 'Unknown')} ({issue.get('reason', 'Reason not reported')})"
        for issue in issues
        if isinstance(issue, Mapping)
    )


def _port_security_text(record: Mapping[str, Any]) -> str:
    issues = record.get("port_security_issues", [])
    if not isinstance(issues, Sequence):
        return ""
    return ", ".join(
        f"{issue.get('interface', 'Unknown')}: "
        f"{issue.get('violation_count', 0)} violations / "
        f"{issue.get('action', 'Unknown')}"
        for issue in issues
        if isinstance(issue, Mapping)
    )


def _etherchannel_issue_text(record: Mapping[str, Any]) -> str:
    channels = record.get("etherchannels", [])
    if not isinstance(channels, Sequence):
        return ""
    details: list[str] = []
    for channel in channels:
        if not isinstance(channel, Mapping) or channel.get("state") == "Up":
            continue
        members = channel.get("members", [])
        bundled = channel.get("bundled_members", [])
        problem = channel.get("problem_members", [])
        text = (
            f"{channel.get('name', 'Unknown')} {channel.get('state', 'Unknown')} "
            f"({len(bundled)}/{len(members)} bundled)"
        )
        if problem:
            text += f": {', '.join(map(str, problem))}"
        details.append(text)
    return " | ".join(details)


def build_issue_rows(records: Sequence[Mapping[str, Any]]) -> list[list[Any]]:
    """Create one engineer-actionable row for every detected issue."""

    rows: list[list[Any]] = []
    for record in records:
        hostname = str(record.get("hostname", "Unknown"))
        location = str(record.get("location", ""))
        primary_ip = str(record.get("primary_ip", ""))
        collected = record.get("collected_at_utc")

        def add(
            severity: str,
            category: str,
            object_name: str,
            state: str,
            details: str,
            *,
            _hostname: str = hostname,
            _location: str = location,
            _primary_ip: str = primary_ip,
            _collected: Any = collected,
        ) -> None:
            rows.append(
                [
                    _hostname,
                    severity,
                    category,
                    object_name,
                    state,
                    details,
                    _location,
                    _primary_ip,
                    _collected,
                ]
            )

        if not record.get("reachable"):
            add(
                "Critical",
                "Reachability",
                hostname,
                "Unreachable",
                "SSH collection did not complete.",
            )
            continue

        cpu_pct = record.get("cpu_pct")
        if isinstance(cpu_pct, (int, float)) and cpu_pct >= CPU_WARNING_PCT:
            severity = "Critical" if cpu_pct >= CPU_CRITICAL_PCT else "Warning"
            add(
                severity,
                "CPU",
                hostname,
                f"{cpu_pct:.1f}%",
                "CPU utilization exceeded the configured health threshold.",
            )

        environment_alerts = record.get("environment_alerts")
        if isinstance(environment_alerts, (int, float)) and environment_alerts > 0:
            add(
                "Warning",
                "Environment",
                hostname,
                f"{int(environment_alerts)} alerts",
                "Environmental command output contained active alert terms.",
            )

        for issue in record.get("err_disabled_interfaces", []):
            if isinstance(issue, Mapping):
                add(
                    "Critical",
                    "Err-disabled",
                    str(issue.get("interface", "Unknown")),
                    "Err-disabled",
                    f"Reason: {issue.get('reason', 'Reason not reported')}",
                )

        for issue in record.get("port_security_issues", []):
            if isinstance(issue, Mapping):
                add(
                    "Critical",
                    "Port Security",
                    str(issue.get("interface", "Unknown")),
                    str(issue.get("action", "Violation")),
                    f"Violation counter: {issue.get('violation_count', 0)}",
                )

        for channel in record.get("etherchannels", []):
            if not isinstance(channel, Mapping) or channel.get("state") == "Up":
                continue
            state = str(channel.get("state", "Unknown"))
            problem = channel.get("problem_members", [])
            bundled = channel.get("bundled_members", [])
            members = channel.get("members", [])
            details = f"{len(bundled)}/{len(members)} members bundled"
            if problem:
                details += f"; affected: {', '.join(map(str, problem))}"
            add(
                "Critical" if state == "Down" else "Warning",
                "EtherChannel",
                str(channel.get("name", "Unknown")),
                state,
                details,
            )

        for note in record.get("notes", []):
            add("Warning", "Telemetry", hostname, "Collection note", str(note))
    return rows


def create_elaborate_health_workbook(
    records: Sequence[Mapping[str, Any]],
    target_tag: str,
    output_path: Path,
) -> None:
    """Create an engineer overview plus a normalized issue-detail worksheet."""

    workbook = Workbook()
    overview = workbook.active
    overview.title = "Engineer Health"
    overview.sheet_view.showGridLines = False
    details = workbook.create_sheet("Issue Details")
    details.sheet_view.showGridLines = False
    scoring = workbook.create_sheet("Scoring")

    navy = "17365D"
    teal = "147D74"
    green = "C6EFCE"
    amber = "FFEB9C"
    red = "FFC7CE"
    pale_blue = "D9EAF7"
    pale_teal = "DDEBF7"
    white = "FFFFFF"
    gray = "44546A"
    thin_gray = Side(style="thin", color="D9E1F2")

    last_column = max(2, len(records) + 1)
    last_column_letter = get_column_letter(last_column)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    overview.merge_cells(
        start_row=1, start_column=1, end_row=1, end_column=last_column
    )
    overview["A1"] = "Nornir Engineer Report — Network Infrastructure Health"
    overview["A1"].font = Font(size=18, bold=True, color=white)
    overview["A1"].fill = _fill(navy)
    overview["A1"].alignment = Alignment(
        vertical="center", wrap_text=True, shrink_to_fit=True
    )
    overview.row_dimensions[1].height = 42

    overview.merge_cells(
        start_row=2, start_column=1, end_row=2, end_column=last_column
    )
    overview["A2"] = (
        f"Scope: Nornir/NetBox devices tagged '{target_tag}' | Generated {generated}"
    )
    overview["A2"].font = Font(italic=True, color=gray)
    overview["A2"].fill = _fill(pale_blue)
    overview["A2"].alignment = Alignment(vertical="center", wrap_text=True)
    overview.row_dimensions[2].height = 30

    metric_rows = {
        "Health Status": 5,
        "Health Score": 6,
        "Data Coverage": 7,
        "Location": 8,
        "Site": 9,
        "Role": 10,
        "Model": 11,
        "Platform": 12,
        "NetBox Status": 13,
        "Primary IP": 14,
        "Serial Number": 15,
        "Current Firmware": 16,
        "Reachable": 17,
        "Collected UTC": 18,
        "Interface Health": 20,
        "Interface Usage": 21,
        "Connected Interfaces": 22,
        "Not Connected Interfaces": 23,
        "Total Interfaces": 24,
        "Err-disabled Interfaces": 25,
        "Err-disabled Details": 26,
        "Port-security Interfaces": 27,
        "Port-security Violations": 28,
        "Port-security Details": 29,
        "EtherChannel Health": 31,
        "EtherChannels Total": 32,
        "EtherChannels Healthy": 33,
        "EtherChannels Degraded": 34,
        "EtherChannels Down": 35,
        "Member Availability": 36,
        "Bundled Members": 37,
        "Total Members": 38,
        "Degraded / Down Details": 39,
        "System and Collection Health": 41,
        "CPU Utilization": 42,
        "Environment Alerts": 43,
        "Engineering Notes": 44,
    }
    section_rows = {20, 31, 41}

    overview["A4"] = "Metric"
    for label, row in metric_rows.items():
        overview.cell(row, 1, label)

    for row in range(4, 45):
        cell = overview.cell(row, 1)
        if row in section_rows:
            cell.fill = _fill(teal)
        else:
            cell.fill = _fill(navy)
        cell.font = Font(bold=True, color=white)
        cell.alignment = Alignment(vertical="center", wrap_text=True)

    for row in section_rows:
        for column in range(2, last_column + 1):
            cell = overview.cell(row, column)
            cell.fill = _fill(pale_teal)
            cell.border = Border(bottom=thin_gray)

    field_map = {
        "Location": "location",
        "Site": "site",
        "Role": "role",
        "Model": "model",
        "Platform": "platform",
        "NetBox Status": "netbox_status",
        "Primary IP": "primary_ip",
        "Serial Number": "serial_number",
        "Current Firmware": "firmware",
        "Collected UTC": "collected_at_utc",
        "Connected Interfaces": "connected_interfaces",
        "Not Connected Interfaces": "not_connected_interfaces",
        "Total Interfaces": "total_interfaces",
        "Err-disabled Interfaces": "err_disabled_count",
        "Port-security Interfaces": "port_security_interfaces",
        "Port-security Violations": "port_security_violations",
        "EtherChannels Total": "etherchannels_total",
        "EtherChannels Healthy": "etherchannels_healthy",
        "EtherChannels Degraded": "etherchannels_degraded",
        "EtherChannels Down": "etherchannels_down",
        "Bundled Members": "etherchannel_members_bundled",
        "Total Members": "etherchannel_members_total",
        "Environment Alerts": "environment_alerts",
    }

    for index, record in enumerate(records, start=2):
        column = get_column_letter(index)
        overview.cell(4, index, record.get("hostname", ""))
        for label, field_name in field_map.items():
            overview.cell(metric_rows[label], index, record.get(field_name))

        overview.cell(17, index, "Yes" if record.get("reachable") else "No")
        overview.cell(26, index, _interface_issue_text(record))
        overview.cell(29, index, _port_security_text(record))
        overview.cell(39, index, _etherchannel_issue_text(record))
        overview.cell(44, index, " | ".join(build_collection_notes(record)))

        cpu_pct = record.get("cpu_pct")
        overview.cell(
            42,
            index,
            cpu_pct / 100 if isinstance(cpu_pct, (int, float)) else None,
        )
        overview.cell(21, index, f'=IF({column}24=0,"",{column}22/{column}24)')
        overview.cell(36, index, f'=IF({column}38=0,"",{column}37/{column}38)')
        overview.cell(
            7,
            index,
            (
                f'=(IF({column}17="Yes",1,0)+'
                f'COUNT({column}42,{column}43,{column}25,{column}27,{column}32))/6'
            ),
        )
        overview.cell(
            6,
            index,
            (
                f"=IF({column}17<>\"Yes\",0,MAX(0,100"
                f"-IF(ISNUMBER({column}42),IF({column}42>='Scoring'!$B$3,"
                f"'Scoring'!$B$6,IF({column}42>='Scoring'!$B$2,"
                f"'Scoring'!$B$5,0)),0)"
                f"-IF(ISNUMBER({column}43),MIN({column}43*'Scoring'!$B$7,"
                f"'Scoring'!$B$12),0)"
                f"-IF(ISNUMBER({column}25),MIN({column}25*'Scoring'!$B$8,"
                f"'Scoring'!$B$12),0)"
                f"-IF(ISNUMBER({column}27),MIN({column}27*'Scoring'!$B$9,"
                f"'Scoring'!$B$12),0)"
                f"-MIN(IF(ISNUMBER({column}34),{column}34*'Scoring'!$B$10,0)"
                f"+IF(ISNUMBER({column}35),{column}35*'Scoring'!$B$11,0),"
                f"'Scoring'!$B$13)))"
            ),
        )
        overview.cell(
            5,
            index,
            (
                f"=IF({column}17<>\"Yes\",\"Unreachable\","
                f"IF({column}7<'Scoring'!$B$4,\"Insufficient Data\","
                f"IF(OR({column}35>0,{column}6<'Scoring'!$B$15),\"Critical\","
                f"IF(OR({column}6<'Scoring'!$B$14,{column}34>0,"
                f"{column}25>0,{column}27>0,{column}43>0),\"Watch\",\"Healthy\"))))"
            ),
        )

        header = overview.cell(4, index)
        header.fill = _fill(teal)
        header.font = Font(bold=True, color=white)
        header.alignment = Alignment(
            horizontal="center", vertical="center", wrap_text=True
        )
        overview.column_dimensions[column].width = 29

        for row in range(5, 45):
            if row in section_rows:
                continue
            cell = overview.cell(row, index)
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = Border(bottom=thin_gray)

    overview.column_dimensions["A"].width = 31
    overview.row_dimensions[4].height = 32
    overview.row_dimensions[26].height = 72
    overview.row_dimensions[29].height = 72
    overview.row_dimensions[39].height = 96
    overview.row_dimensions[44].height = 220
    overview.freeze_panes = "A5"

    for column in range(2, last_column + 1):
        overview.cell(6, column).number_format = "0"
        overview.cell(7, column).number_format = "0%"
        overview.cell(18, column).number_format = "yyyy-mm-dd hh:mm"
        overview.cell(21, column).number_format = "0.0%"
        overview.cell(36, column).number_format = "0.0%"
        overview.cell(42, column).number_format = "0.0%"

    status_cells = f"B5:{last_column_letter}5"
    for status, color in {
        "Healthy": green,
        "Watch": amber,
        "Critical": red,
        "Unreachable": red,
        "Insufficient Data": amber,
    }.items():
        overview.conditional_formatting.add(
            status_cells,
            FormulaRule(formula=[f'B5="{status}"'], fill=_fill(color)),
        )
    overview.conditional_formatting.add(
        f"B6:{last_column_letter}6",
        ColorScaleRule(
            start_type="num",
            start_value=0,
            start_color="F8696B",
            mid_type="num",
            mid_value=70,
            mid_color="FFEB84",
            end_type="num",
            end_value=100,
            end_color="63BE7B",
        ),
    )
    for row, color in ((25, red), (27, red), (34, amber), (35, red), (43, amber)):
        overview.conditional_formatting.add(
            f"B{row}:{last_column_letter}{row}",
            FormulaRule(formula=[f"B{row}>0"], fill=_fill(color)),
        )

    overview["A21"].comment = Comment(
        "Connected physical interfaces divided by all parsed physical interfaces.",
        "Network Automation",
    )
    overview["A36"].comment = Comment(
        "Bundled EtherChannel members divided by all parsed channel members.",
        "Network Automation",
    )

    summary_start = 47
    overview[f"A{summary_start}"] = "Fleet Summary"
    overview.merge_cells(
        start_row=summary_start,
        start_column=1,
        end_row=summary_start,
        end_column=2,
    )
    overview[f"A{summary_start}"].fill = _fill(navy)
    overview[f"A{summary_start}"].font = Font(bold=True, color=white)
    summary_labels = [
        "Devices",
        "Healthy",
        "Watch",
        "Critical",
        "Unreachable",
        "Insufficient Data",
        "Average Health Score",
        "Total EtherChannels",
        "Degraded EtherChannels",
        "Down EtherChannels",
        "Err-disabled Interfaces",
        "Port-security Interfaces",
    ]
    for row, label in enumerate(summary_labels, start=summary_start + 1):
        overview.cell(row, 1, label)

    status_range = f"B5:{last_column_letter}5"
    overview.cell(summary_start + 1, 2, f"=COUNTA(B4:{last_column_letter}4)")
    for offset, status in enumerate(summary_labels[1:6], start=2):
        overview.cell(
            summary_start + offset,
            2,
            f'=COUNTIF({status_range},"{status}")',
        )
    overview.cell(
        summary_start + 7,
        2,
        f'=IFERROR(AVERAGE(B6:{last_column_letter}6),"")',
    )
    for offset, source_row in enumerate((32, 34, 35, 25, 27), start=8):
        overview.cell(
            summary_start + offset,
            2,
            f"=SUM(B{source_row}:{last_column_letter}{source_row})",
        )
    overview.cell(summary_start + 7, 2).number_format = "0"
    for row in range(summary_start + 1, summary_start + len(summary_labels) + 1):
        overview.cell(row, 1).font = Font(bold=True)
        overview.cell(row, 1).fill = _fill(pale_blue)
        overview.cell(row, 1).alignment = Alignment(wrap_text=True)
        overview.cell(row, 2).alignment = Alignment(horizontal="right")

    overview.sheet_properties.pageSetUpPr.fitToPage = True
    overview.page_setup.orientation = "landscape"
    overview.page_setup.fitToWidth = 1
    overview.page_setup.fitToHeight = 0
    overview.print_title_rows = "1:4"
    overview.print_area = (
        f"A1:{last_column_letter}{summary_start + len(summary_labels)}"
    )

    details.merge_cells("A1:I1")
    details["A1"] = "Engineer Issue Details"
    details["A1"].font = Font(size=18, bold=True, color=white)
    details["A1"].fill = _fill(navy)
    details["A1"].alignment = Alignment(vertical="center")
    details.row_dimensions[1].height = 42
    details.merge_cells("A2:I2")
    details["A2"] = (
        "One row per actionable device, interface, port-security, EtherChannel, "
        f"or telemetry issue | Generated {generated}"
    )
    details["A2"].font = Font(italic=True, color=gray)
    details["A2"].fill = _fill(pale_blue)
    details["A2"].alignment = Alignment(wrap_text=True)
    details.row_dimensions[2].height = 30

    headers = [
        "Device",
        "Severity",
        "Category",
        "Object",
        "State",
        "Details",
        "Location",
        "Primary IP",
        "Collected UTC",
    ]
    for column, header in enumerate(headers, start=1):
        details.cell(4, column, header)
    issue_rows = build_issue_rows(records)
    if not issue_rows:
        issue_rows = [
            [
                "Fleet",
                "Info",
                "Health",
                "All devices",
                "No active issues",
                "No engineer-actionable conditions were detected.",
                "",
                "",
                None,
            ]
        ]
    for row_index, row in enumerate(issue_rows, start=5):
        for column_index, value in enumerate(row, start=1):
            details.cell(row_index, column_index, value)

    detail_last_row = 4 + len(issue_rows)
    detail_table = Table(displayName="EngineerIssues", ref=f"A4:I{detail_last_row}")
    detail_table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=True,
        showColumnStripes=False,
    )
    details.add_table(detail_table)
    details.freeze_panes = "A5"
    details.column_dimensions["A"].width = 24
    details.column_dimensions["B"].width = 12
    details.column_dimensions["C"].width = 18
    details.column_dimensions["D"].width = 20
    details.column_dimensions["E"].width = 18
    details.column_dimensions["F"].width = 52
    details.column_dimensions["G"].width = 20
    details.column_dimensions["H"].width = 18
    details.column_dimensions["I"].width = 20
    for row in range(5, detail_last_row + 1):
        details.cell(row, 9).number_format = "yyyy-mm-dd hh:mm"
    for row in details.iter_rows(min_row=5, max_row=detail_last_row):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    details.conditional_formatting.add(
        f"A5:I{detail_last_row}",
        FormulaRule(formula=['$B5="Critical"'], fill=_fill(red)),
    )
    details.conditional_formatting.add(
        f"A5:I{detail_last_row}",
        FormulaRule(formula=['$B5="Warning"'], fill=_fill(amber)),
    )
    details.sheet_properties.pageSetUpPr.fitToPage = True
    details.page_setup.orientation = "landscape"
    details.page_setup.fitToWidth = 1
    details.page_setup.fitToHeight = 0
    details.print_title_rows = "1:4"
    details.print_area = f"A1:I{detail_last_row}"

    scoring_rows = [
        ("Parameter", "Value"),
        ("CPU warning", CPU_WARNING_PCT / 100),
        ("CPU critical", CPU_CRITICAL_PCT / 100),
        ("Minimum data coverage", MIN_DATA_COVERAGE_PCT / 100),
        ("Warning penalty", WARNING_PENALTY),
        ("Critical penalty", CRITICAL_PENALTY),
        ("Environment alert penalty", ENVIRONMENT_ALERT_PENALTY),
        ("Err-disabled penalty", ERR_DISABLED_PENALTY),
        ("Port-security penalty", PORT_SECURITY_PENALTY),
        ("Degraded EtherChannel penalty", DEGRADED_ETHERCHANNEL_PENALTY),
        ("Down EtherChannel penalty", DOWN_ETHERCHANNEL_PENALTY),
        ("Maximum count penalty", MAX_COUNT_PENALTY),
        ("Maximum EtherChannel penalty", MAX_ETHERCHANNEL_PENALTY),
        ("Healthy score", HEALTHY_SCORE),
        ("Watch score", WATCH_SCORE),
    ]
    for row in scoring_rows:
        scoring.append(row)
    for row in range(2, 5):
        scoring.cell(row, 2).number_format = "0%"
    scoring.sheet_state = "veryHidden"

    workbook.calculation.calcMode = "auto"
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    output_path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output_path)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    config_path = Path(args.config).expanduser()
    output_path = Path(args.output).expanduser()
    target_tag = str(args.tag).strip().casefold()

    if not config_path.is_file():
        console.print(
            f"[bold red]ERROR:[/] Existing Nornir config was not found: {config_path.resolve()}"
        )
        return 1
    if output_path.suffix.casefold() != ".xlsx":
        console.print("[bold red]ERROR:[/] --output must end in .xlsx")
        return 1
    if not target_tag:
        console.print("[bold red]ERROR:[/] --tag cannot be empty")
        return 1

    username = os.getenv("NORNIR_USERNAME")
    password = os.getenv("NORNIR_PASSWORD")
    if bool(username) != bool(password):
        console.print(
            "[bold red]ERROR:[/] Set both NORNIR_USERNAME and NORNIR_PASSWORD, or neither."
        )
        return 1

    try:
        nr = InitNornir(config_file=str(config_path))
    except Exception as exc:  # noqa: BLE001 - inventory plugins raise varied errors.
        console.print(f"[bold red]ERROR:[/] Could not initialize Nornir: {exc}")
        return 1

    if username and password:
        nr.inventory.defaults.username = username
        nr.inventory.defaults.password = password

    netmiko_extras = build_netmiko_extras(args)
    for host in nr.inventory.hosts.values():
        host.data["tag_slugs"] = normalize_tags(host.data.get("tags", []))
        if "netmiko" not in host.connection_options:
            host.connection_options["netmiko"] = ConnectionOptions(
                extras=dict(netmiko_extras)
            )
        else:
            existing_extras = host.connection_options["netmiko"].extras or {}
            existing_extras.update(netmiko_extras)
            host.connection_options["netmiko"].extras = existing_extras

    targets = nr.filter(F(tag_slugs__contains=target_tag))
    console.print(f"Target tag: [bold]{target_tag}[/]")
    console.print(f"Matched devices: [bold]{len(targets.inventory.hosts)}[/]")
    console.print(
        "SSH timing: "
        f"connect {args.connection_timeout:g}s | "
        f"authenticate {args.auth_timeout:g}s | "
        f"banner {args.banner_timeout:g}s | "
        f"command {args.read_timeout:g}s | "
        f"delay factor {args.global_delay_factor:g}"
    )
    if args.legacy_ssh:
        console.print(
            "[yellow]Legacy SSH compatibility is enabled for this run.[/]"
        )

    if not targets.inventory.hosts:
        console.print("No devices matched the requested NetBox tag. No workbook was created.")
        return 0

    console.print(
        "Collecting firmware, interface, EtherChannel, port-security, CPU, "
        "and environment health..."
    )
    results = targets.run(
        name="Collect network health",
        task=collect_device_health,
        read_timeout=args.read_timeout,
    )
    records = _extract_records(results, targets.inventory.hosts)
    create_elaborate_health_workbook(records, target_tag, output_path)

    reachable = sum(bool(record.get("reachable")) for record in records)
    console.print(f"[bold green]Created:[/] {output_path.resolve()}")
    console.print(f"Reachable devices: {reachable}/{len(records)}")
    if reachable < len(records):
        console.print(
            "Unreachable devices remain in the workbook with their NetBox information and notes."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
