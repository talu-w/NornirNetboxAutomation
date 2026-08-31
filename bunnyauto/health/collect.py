"""Per-device health collection. Ported from ``network_simple_health_report.py``.

Read-only: firmware, interface usage, CPU, environment alerts. Platform
differences are absorbed by ``run_first_supported`` (try commands in order,
take the first usable output) and ``command_profile``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command

if TYPE_CHECKING:
    from nornir.core.inventory import Host

DEFAULT_READ_TIMEOUT = 180.0

PHYSICAL_INTERFACE_RE = re.compile(
    r"^(?:Fa|FastEthernet|Gi|GigabitEthernet|Te|TenGigabitEthernet|"
    r"Tw|TwoGigabitEthernet|Twe|TwentyFiveGigE|Fo|FortyGigabitEthernet|"
    r"Hu|HundredGig(?:E|abitEthernet)|Eth|Ethernet|Et)\d",
    re.IGNORECASE,
)
INTERFACE_STATUS_RE = re.compile(
    r"\b(err-disabled|notconnect(?:ed)?|notconnec|connected|disabled|inactive|"
    r"monitoring|sfpAbsent|xcvrAbsent)\b",
    re.IGNORECASE,
)
INVALID_COMMAND_MARKERS = (
    "% invalid input",
    "% incomplete command",
    "% ambiguous command",
    "invalid command",
    "unknown command",
)


@dataclass(slots=True)
class InterfaceSummary:
    connected: int | None = None
    not_connected: int | None = None
    total: int | None = None
    err_disabled: int | None = None


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
    err_disabled_interfaces: int | None = None
    reachable: bool = False
    collected_at_utc: datetime | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _nested_value(data: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value: Any = data
        for part in path.split("."):
            value = value.get(part) if isinstance(value, Mapping) else getattr(value, part, None)
            if value is None:
                break
        if value not in (None, ""):
            return value
    return None


def _display_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    keys = ("display", "label", "name", "model", "address", "value", "slug")
    if isinstance(value, Mapping):
        for key in keys:
            if value.get(key) not in (None, ""):
                return str(value[key])
        return ""
    for attribute in keys:
        candidate = getattr(value, attribute, None)
        if candidate not in (None, ""):
            return str(candidate)
    return str(value)


def netbox_metadata(host: Host) -> dict[str, str]:
    """Management fields the NetBox inventory already supplies for a host."""
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
            _nested_value(
                data,
                "primary_ip4.address",
                "primary_ip4",
                "primary_ip.address",
                "primary_ip",
            )
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
    *,
    allow_empty: bool = False,
) -> tuple[str, str]:
    """Run commands in order; return the first usable ``(output, command)``.

    ``allow_empty=True`` accepts a command that ran cleanly but produced no
    output (e.g. ``show interfaces status err-disabled`` when nothing is
    err-disabled) — a valid "no findings" result rather than an unsupported one.
    """
    errors: list[str] = []
    for command in commands:
        try:
            result = task.run(
                name=f"{label}: {command}",
                task=netmiko_send_command,
                command_string=command,
                read_timeout=read_timeout,
            )[-1]
        except Exception as exc:
            errors.append(f"{command}: {exc}")
            continue
        if result.failed:
            errors.append(f"{command}: {result.exception or result.result}")
            continue
        output = str(result.result or "")
        if not _is_invalid_command(output) and (output.strip() or allow_empty):
            return output, command
        errors.append(f"{command}: unsupported or empty output")
    raise RuntimeError("; ".join(errors) or f"No {label} command succeeded")


def command_profile(platform: str) -> dict[str, list[str]]:
    platform_name = platform.casefold()
    profile = {
        "version": ["show version"],
        "interfaces": ["show interfaces status", "show ip interface brief"],
        "cpu": ["show process cpu"],
        "environment": ["show environment all", "show environment"],
    }
    if "nxos" in platform_name or "nx-os" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show system resources"],
                "environment": ["show env all"],
            }
        )
    elif "ios" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show process cpu"],
                "environment": ["show env all"],
            }
        )
    elif "eos" in platform_name or "arista" in platform_name:
        profile.update(
            {
                "interfaces": ["show interfaces status"],
                "cpu": ["show processes top once"],
                "environment": ["show system environment all"],
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
        r"CPU utilization for five seconds:\s*(\d+(?:\.\d+)?)%", output, re.IGNORECASE
    )
    if match:
        return float(match.group(1))
    idle_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:idle|id)\b", output, re.IGNORECASE)
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
    err_disabled = 0
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
        err_disabled += int(status == "err-disabled")

    if total:
        return InterfaceSummary(
            connected=connected,
            not_connected=total - connected,
            total=total,
            err_disabled=err_disabled,
        )

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
            match.group("status").casefold() == "up" and match.group("protocol").casefold() == "up"
        )

    return InterfaceSummary(
        connected=connected if total else None,
        not_connected=(total - connected) if total else None,
        total=total if total else None,
        err_disabled=0 if total else None,
    )


def count_environment_alerts(output: str) -> int:
    alert_terms = re.compile(
        r"\b(fail(?:ed|ure)?|critical|alarm|shutdown|overtemp)\b", re.IGNORECASE
    )
    healthy_terms = re.compile(r"\b(no alarms?|normal|ok|good|passed|not present)\b", re.IGNORECASE)
    return sum(
        1
        for line in output.splitlines()
        if alert_terms.search(line) and not healthy_terms.search(line)
    )


def collect_device_health(task: Task, read_timeout: float = DEFAULT_READ_TIMEOUT) -> Result:
    metadata = netbox_metadata(task.host)
    record = DeviceHealth(hostname=task.host.name, **metadata)
    profile = command_profile(record.platform)

    try:
        version_output, _ = run_first_supported(task, "Firmware", profile["version"], read_timeout)
    except Exception as exc:
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
    except Exception as exc:
        record.notes.append(f"Interface statistics unavailable: {exc}")

    try:
        cpu_output, _ = run_first_supported(task, "CPU", profile["cpu"], read_timeout)
        record.cpu_pct = parse_cpu_pct(cpu_output)
        if record.cpu_pct is None:
            record.notes.append("CPU output was returned but utilization could not be parsed.")
    except Exception as exc:
        record.notes.append(f"CPU utilization unavailable: {exc}")

    try:
        environment_output, _ = run_first_supported(
            task, "Environment", profile["environment"], read_timeout
        )
        record.environment_alerts = count_environment_alerts(environment_output)
    except Exception as exc:
        record.notes.append(f"Environment status unavailable: {exc}")

    return Result(host=task.host, changed=False, result=record.to_dict())


def extract_records(results: Any, hosts: Mapping[str, Host]) -> list[dict[str, Any]]:
    """Turn the AggregatedResult into one dict per host, sorted by hostname."""
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
