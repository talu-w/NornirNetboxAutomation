"""Engineer-view health collection. Ported from ``network_elaborate_health_report.py``.

Builds on :mod:`bunnyauto.health.collect` (the shared ``run_first_supported``
command-fallback, firmware/CPU/environment parsers, NetBox metadata) and adds the
interface-error, EtherChannel, port-security, and control-plane collectors.

Dropped in the port (dead in the original — flagged for the owner):
* ``_create_compact_health_workbook`` (defined, never called; CLAUDE.md issue #1).
* Spanning-tree parsing (``SpanningTreeInstance`` etc.) — defined but never wired
  into ``collect_device_health`` or the workbook.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from nornir.core.task import Result, Task

from bunnyauto.health.collect import (
    DEFAULT_READ_TIMEOUT,
    count_environment_alerts,
    netbox_metadata,
    parse_cpu_pct,
    parse_firmware,
    run_first_supported,
)

if TYPE_CHECKING:
    from nornir.core.inventory import Host

RECENT_EVENT_SECONDS = 3_600

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
    r"(?P<name>[A-Za-z][A-Za-z-]*\d[\w./:-]*)\((?P<flags>[^)]+)\)",
)

INTERFACE_COUNTER_ALIASES = {
    "alignerr": "alignment_errors",
    "fcserr": "crc_errors",
    "crc": "crc_errors",
    "xmterr": "output_errors",
    "rcverr": "input_errors",
    "inerrors": "input_errors",
    "outerrors": "output_errors",
    "undersize": "undersize",
    "outdiscards": "output_drops",
    "indiscards": "input_drops",
    "singlecol": "single_collisions",
    "multicol": "multiple_collisions",
    "latecol": "late_collisions",
    "excesscol": "excessive_collisions",
    "collisions": "collisions",
    "carrisen": "carrier_sense_errors",
    "runts": "runts",
    "runt": "runts",
    "giants": "giants",
    "frame": "frame_errors",
    "overrun": "overruns",
    "ignored": "ignored",
}
ETHERCHANNEL_MEMBER_FLAG_MEANINGS = {
    "P": "bundled",
    "H": "hot standby",
    "s": "suspended",
    "I": "stand-alone",
    "D": "down",
    "w": "waiting",
    "f": "failed aggregator allocation",
    "M": "minimum links not met",
    "m": "minimum links not met",
}
ERRDISABLE_REASON_RE = re.compile(
    r"\b(psecure-violation|security-violation|bpduguard|bpdu-guard|"
    r"link-flap|channel-misconfig|udld|storm-control|dhcp-rate-limit|"
    r"arp-inspection|loopback|l2ptguard|sfp-config-mismatch)\b",
    re.IGNORECASE,
)


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
    standby_members: list[str] = field(default_factory=list)
    problem_members: list[str] = field(default_factory=list)
    member_details: list[dict[str, str]] = field(default_factory=list)
    min_links: int | None = None
    risk_reasons: list[str] = field(default_factory=list)

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
class InterfaceQualityIssue:
    interface: str
    counters: dict[str, int] = field(default_factory=dict)
    last_link_flapped: str = ""
    recent_link_flap: bool = False
    interface_resets: int = 0
    carrier_transitions: int = 0

    @property
    def error_total(self) -> int:
        return sum(self.counters.values())

    @property
    def unstable(self) -> bool:
        return bool(
            self.recent_link_flap or self.interface_resets > 0 or self.carrier_transitions > 0
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["error_total"] = self.error_total
        data["unstable"] = self.unstable
        return data


@dataclass(slots=True)
class SecurityControlException:
    category: str
    object_name: str
    count: int
    details: str

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
    interface_quality_issues: list[dict[str, Any]] = field(default_factory=list)
    interfaces_with_errors: int | None = None
    interface_error_total: int | None = None
    interface_instability_count: int | None = None
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
    etherchannel_members_standby: int | None = None
    etherchannel_member_issues: int | None = None
    etherchannel_min_link_risks: int | None = None
    security_control_exceptions: list[dict[str, Any]] = field(default_factory=list)
    security_control_exception_count: int | None = None
    security_control_drop_count: int | None = None
    reachable: bool = False
    collected_at_utc: datetime | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# small parse helpers
# ---------------------------------------------------------------------------


def _counter_value(value: str) -> int | None:
    cleaned = value.replace(",", "").strip()
    return int(cleaned) if cleaned.isdigit() else None


def _counter_name(value: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return INTERFACE_COUNTER_ALIASES.get(normalized)


def _interface_key(value: str) -> str:
    """Normalize common long/short interface prefixes for deduplication."""
    compact = value.strip().replace(" ", "").casefold()
    prefixes = (
        ("twentyfivegige", "twe"),
        ("hundredgigabitethernet", "hu"),
        ("hundredgige", "hu"),
        ("fortygigabitethernet", "fo"),
        ("tengigabitethernet", "te"),
        ("twogigabitethernet", "tw"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("portchannel", "po"),
        ("ethernet", "eth"),
    )
    for long_name, short_name in prefixes:
        if compact.startswith(long_name):
            return short_name + compact[len(long_name) :]
    return compact


def _duration_seconds(value: str) -> int | None:
    """Convert common IOS/NX-OS elapsed-time strings to seconds."""
    text = value.strip().casefold().rstrip(".,")
    if not text or "never" in text:
        return None

    clock_match = re.fullmatch(r"(?:(\d+):)?(\d+):(\d+)", text)
    if clock_match:
        hours = int(clock_match.group(1) or 0)
        minutes = int(clock_match.group(2))
        seconds = int(clock_match.group(3))
        return hours * 3_600 + minutes * 60 + seconds

    units = {
        "w": 604_800,
        "week": 604_800,
        "weeks": 604_800,
        "d": 86_400,
        "day": 86_400,
        "days": 86_400,
        "h": 3_600,
        "hour": 3_600,
        "hours": 3_600,
        "m": 60,
        "minute": 60,
        "minutes": 60,
        "s": 1,
        "second": 1,
        "seconds": 1,
    }
    matches = re.findall(r"(\d+)\s*(weeks?|days?|hours?|minutes?|seconds?|[wdhms])", text)
    if not matches:
        return None
    return sum(int(number) * units[unit] for number, unit in matches)


# ---------------------------------------------------------------------------
# interface quality / errors
# ---------------------------------------------------------------------------


def parse_interface_quality(output: str) -> list[InterfaceQualityIssue]:
    """Parse cumulative interface errors plus reset/link-transition indicators."""
    issues: dict[str, InterfaceQualityIssue] = {}

    def get_issue(interface: str) -> InterfaceQualityIssue:
        key = _interface_key(interface)
        if key not in issues:
            issues[key] = InterfaceQualityIssue(interface=interface)
        return issues[key]

    header: list[str | None] | None = None
    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].casefold() in {"port", "interface"}:
            candidate = [_counter_name(token) for token in tokens[1:]]
            header = candidate if any(candidate) else None
            continue
        if header and PHYSICAL_INTERFACE_RE.match(tokens[0]):
            issue = get_issue(tokens[0])
            for name, raw_value in zip(header, tokens[1:], strict=False):
                value = _counter_value(raw_value)
                if name and value is not None:
                    issue.counters[name] = max(issue.counters.get(name, 0), value)

    current: InterfaceQualityIssue | None = None
    block_pattern = re.compile(
        r"^\s*(?P<interface>\S+)\s+is\s+.+?,\s*line protocol is\s+", re.IGNORECASE
    )
    metric_patterns = {
        "input_errors": r"([\d,]+)\s+input errors",
        "crc_errors": r"([\d,]+)\s+CRC",
        "frame_errors": r"([\d,]+)\s+frame",
        "overruns": r"([\d,]+)\s+overrun",
        "ignored": r"([\d,]+)\s+ignored",
        "runts": r"([\d,]+)\s+runts",
        "giants": r"([\d,]+)\s+giants",
        "output_errors": r"([\d,]+)\s+output errors",
        "collisions": r"([\d,]+)\s+collisions",
        "output_drops": r"Total output drops:\s*([\d,]+)",
    }
    for line in output.splitlines():
        block_match = block_pattern.match(line)
        if block_match:
            interface = block_match.group("interface")
            current = get_issue(interface) if PHYSICAL_INTERFACE_RE.match(interface) else None
            continue
        if current is None:
            continue
        for name, pattern in metric_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = _counter_value(match.group(1))
                if value is not None:
                    current.counters[name] = max(current.counters.get(name, 0), value)

        reset_match = re.search(r"([\d,]+)\s+interface resets", line, re.IGNORECASE)
        if reset_match:
            current.interface_resets = _counter_value(reset_match.group(1)) or 0
        transition_match = re.search(r"([\d,]+)\s+carrier transitions", line, re.IGNORECASE)
        if transition_match:
            current.carrier_transitions = _counter_value(transition_match.group(1)) or 0
        flap_match = re.search(r"Last link flapped\s+([^\s,()]+)", line, re.IGNORECASE)
        if flap_match:
            current.last_link_flapped = flap_match.group(1)
            elapsed = _duration_seconds(current.last_link_flapped)
            current.recent_link_flap = elapsed is not None and elapsed <= RECENT_EVENT_SECONDS

    return sorted(
        (issue for issue in issues.values() if issue.error_total > 0 or issue.unstable),
        key=lambda item: item.interface.casefold(),
    )


def merge_interface_quality_issues(
    *issue_groups: Sequence[InterfaceQualityIssue],
) -> list[InterfaceQualityIssue]:
    merged: dict[str, InterfaceQualityIssue] = {}
    for group in issue_groups:
        for issue in group:
            key = _interface_key(issue.interface)
            target = merged.setdefault(key, InterfaceQualityIssue(issue.interface))
            for name, value in issue.counters.items():
                target.counters[name] = max(target.counters.get(name, 0), value)
            target.interface_resets = max(target.interface_resets, issue.interface_resets)
            target.carrier_transitions = max(target.carrier_transitions, issue.carrier_transitions)
            if issue.last_link_flapped:
                target.last_link_flapped = issue.last_link_flapped
            target.recent_link_flap = target.recent_link_flap or issue.recent_link_flap
    return sorted(merged.values(), key=lambda item: item.interface.casefold())


# ---------------------------------------------------------------------------
# security / control-plane
# ---------------------------------------------------------------------------


def parse_security_control_exceptions(
    outputs: Mapping[str, str],
) -> list[SecurityControlException]:
    """Parse nonzero CoPP, Dynamic ARP Inspection, and DHCP-snooping drops."""
    exceptions: dict[tuple[str, str, str], SecurityControlException] = {}

    def add(category: str, object_name: str, count: int, details: str) -> None:
        if count <= 0:
            return
        key = (category.casefold(), object_name.casefold(), details.casefold())
        exceptions[key] = SecurityControlException(
            category=category, object_name=object_name, count=count, details=details
        )

    control_plane = outputs.get("control_plane", "")
    current_class = "Control plane"
    for line in control_plane.splitlines():
        class_match = re.search(r"Class-map:\s*([^\s(]+)", line, re.IGNORECASE)
        if class_match:
            current_class = class_match.group(1)
        drop_match = re.search(r"drop packets\s+([\d,]+)", line, re.IGNORECASE)
        if drop_match:
            add(
                "Control Plane",
                current_class,
                _counter_value(drop_match.group(1)) or 0,
                "Cumulative control-plane policy drops",
            )

    arp_output = outputs.get("arp_inspection", "")
    for line in arp_output.splitlines():
        tokens = line.split()
        if len(tokens) >= 3 and tokens[0].isdigit():
            dropped = _counter_value(tokens[2])
            if dropped is not None:
                add("Dynamic ARP Inspection", f"VLAN {tokens[0]}", dropped, "Cumulative DAI drops")

    for source, category in (
        ("arp_inspection", "Dynamic ARP Inspection"),
        ("dhcp_snooping", "DHCP Snooping"),
    ):
        for line in outputs.get(source, "").splitlines():
            match = re.search(
                r"^\s*(?P<label>[^:=]*drop[^:=]*?)\s*(?:=|:)\s*(?P<count>[\d,]+)\s*$",
                line,
                re.IGNORECASE,
            )
            if not match:
                continue
            label = " ".join(match.group("label").split())
            add(
                category,
                label or category,
                _counter_value(match.group("count")) or 0,
                "Cumulative security drop counter",
            )
    return sorted(
        exceptions.values(),
        key=lambda item: (item.category.casefold(), item.object_name.casefold()),
    )


# ---------------------------------------------------------------------------
# interface status / err-disabled / port-security
# ---------------------------------------------------------------------------


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


def merge_interface_issues(*issue_groups: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
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


# ---------------------------------------------------------------------------
# etherchannels
# ---------------------------------------------------------------------------


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
        for token in re.findall(r"\b(?:LACP|PAgP|static|on|none)\b", text, re.IGNORECASE):
            protocol = token
            break

        members: list[str] = []
        bundled: list[str] = []
        standby: list[str] = []
        problem: list[str] = []
        member_details: list[dict[str, str]] = []
        seen: set[str] = set()
        for member_match in ETHERCHANNEL_MEMBER_RE.finditer(text):
            member = member_match.group("name")
            flags = member_match.group("flags")
            key = member.casefold()
            if key in seen:
                continue
            seen.add(key)
            members.append(member)
            meanings = [
                ETHERCHANNEL_MEMBER_FLAG_MEANINGS[flag]
                for flag in flags
                if flag in ETHERCHANNEL_MEMBER_FLAG_MEANINGS
            ]
            if "P" in flags:
                bundled.append(member)
                member_state = "Bundled"
                is_problem = False
            elif "H" in flags:
                standby.append(member)
                member_state = "Hot standby"
                is_problem = False
            else:
                member_state = ", ".join(meanings) or "Not bundled"
                is_problem = True
                problem.append(f"{member} ({flags}: {member_state})")
            member_details.append(
                {
                    "interface": member,
                    "flags": flags,
                    "state": member_state,
                    "problem": "Yes" if is_problem else "No",
                }
            )

        channel_flags = str(raw["flags"])
        channel_is_up = "U" in channel_flags or (not channel_flags and bool(bundled))
        risk_reasons: list[str] = []
        if not channel_is_up:
            state = "Down"
            risk_reasons.append("port-channel is not in use")
        elif problem or not members:
            state = "Degraded"
            if problem:
                risk_reasons.append("one or more members are not bundled")
            if not members:
                risk_reasons.append("no member interfaces were parsed")
        else:
            state = "Up"
        if "M" in channel_flags or "m" in channel_flags:
            if "minimum links not met" not in risk_reasons:
                risk_reasons.append("minimum links not met")
            state = "Down"

        channels.append(
            EtherChannelState(
                name=str(raw["name"]),
                group=int(raw["group"]),
                protocol=protocol,
                flags=channel_flags,
                state=state,
                members=members,
                bundled_members=bundled,
                standby_members=standby,
                problem_members=problem,
                member_details=member_details,
                risk_reasons=risk_reasons,
            )
        )
    return sorted(channels, key=lambda item: (item.group, item.name.casefold()))


def parse_etherchannel_min_links(output: str) -> dict[int, int]:
    """Parse configured minimum-link requirements from channel detail output."""
    minimums: dict[int, int] = {}
    current_group: int | None = None
    for line in output.splitlines():
        group_match = re.search(r"\bGroup\s*:?\s*(\d+)\b", line, re.IGNORECASE)
        if group_match:
            current_group = int(group_match.group(1))
        min_match = re.search(r"\b(?:Minimum Links|Min-?links)\s*:?\s*(\d+)\b", line, re.IGNORECASE)
        if current_group is not None and min_match:
            minimums[current_group] = int(min_match.group(1))
    return minimums


def enrich_etherchannels(channels: Sequence[EtherChannelState], detail_output: str) -> None:
    """Apply minimum-link requirements to parsed EtherChannel state."""
    minimums = parse_etherchannel_min_links(detail_output)
    for channel in channels:
        channel.min_links = minimums.get(channel.group)
        if not channel.min_links:
            continue
        bundled = len(channel.bundled_members)
        if bundled < channel.min_links:
            reason = (
                f"{bundled}/{channel.min_links} required members are bundled; minimum links not met"
            )
            if reason not in channel.risk_reasons:
                channel.risk_reasons.append(reason)
            channel.state = "Down"


# ---------------------------------------------------------------------------
# command profile + the per-device task
# ---------------------------------------------------------------------------


def command_profile(platform: str) -> dict[str, list[str]]:
    platform_name = platform.casefold()
    profile = {
        "version": ["show version"],
        "interfaces": ["show interfaces status", "show ip interface brief"],
        "cpu": ["show process cpu"],
        "environment": ["show environment all", "show environment"],
        "interface_errors": [
            "show interfaces counters errors",
            "show interface counters errors",
        ],
        "interface_detail": ["show interfaces"],
        "etherchannels": ["show etherchannel summary", "show port-channel summary"],
        "etherchannel_detail": ["show etherchannel detail", "show port-channel database"],
        "err_disabled": [
            "show interfaces status err-disabled",
            "show interface status err-disabled",
        ],
        "port_security": ["show port-security"],
        "control_plane": [
            "show policy-map control-plane",
            "show policy-map interface control-plane",
        ],
        "arp_inspection": ["show ip arp inspection statistics"],
        "dhcp_snooping": ["show ip dhcp snooping statistics"],
    }
    if "nxos" in platform_name or "nx-os" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show system resources"],
                "environment": ["show env all"],
                "interface_errors": [
                    "show interface counters errors",
                    "show interfaces counters errors",
                ],
                "interface_detail": ["show interface"],
                "etherchannels": ["show port-channel summary", "show etherchannel summary"],
                "etherchannel_detail": ["show port-channel database", "show port-channel summary"],
                "err_disabled": [
                    "show interface status err-disabled",
                    "show interfaces status err-disabled",
                ],
                "port_security": ["show port-security"],
                "control_plane": [
                    "show policy-map interface control-plane",
                    "show policy-map control-plane",
                ],
            }
        )
    elif "ios" in platform_name:
        profile.update(
            {
                "interfaces": ["show interface status"],
                "cpu": ["show process cpu"],
                "environment": ["show env all"],
                "interface_errors": [
                    "show interfaces counters errors",
                    "show interface counters errors",
                ],
                "interface_detail": ["show interfaces"],
                "etherchannels": ["show etherchannel summary", "show port-channel summary"],
                "etherchannel_detail": ["show etherchannel detail", "show port-channel database"],
                "err_disabled": [
                    "show interfaces status err-disabled",
                    "show interface status err-disabled",
                ],
                "port_security": ["show port-security"],
                "control_plane": [
                    "show policy-map control-plane",
                    "show policy-map interface control-plane",
                ],
            }
        )
    elif "eos" in platform_name or "arista" in platform_name:
        profile.update(
            {
                "interfaces": ["show interfaces status"],
                "cpu": ["show processes top once"],
                "environment": ["show system environment all"],
                "interface_errors": [
                    "show interfaces counters errors",
                    "show interfaces counters discards",
                ],
                "interface_detail": ["show interfaces"],
                "etherchannels": ["show port-channel summary"],
                "etherchannel_detail": ["show lacp neighbor", "show port-channel summary"],
                "err_disabled": [
                    "show interfaces status errdisabled",
                    "show interfaces status err-disabled",
                ],
                "port_security": ["show port-security"],
                "control_plane": ["show policy-map control-plane"],
            }
        )
    return profile


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

    quality_outputs: list[str] = []
    quality_errors: list[str] = []
    for label, profile_key in (
        ("Interface error counters", "interface_errors"),
        ("Interface detail", "interface_detail"),
    ):
        try:
            output, _ = run_first_supported(task, label, profile[profile_key], read_timeout)
            quality_outputs.append(output)
        except Exception:
            quality_errors.append(label)

    if quality_outputs:
        quality_issues = merge_interface_quality_issues(
            *(parse_interface_quality(output) for output in quality_outputs)
        )
        record.interface_quality_issues = [issue.to_dict() for issue in quality_issues]
        record.interfaces_with_errors = sum(issue.error_total > 0 for issue in quality_issues)
        record.interface_error_total = sum(issue.error_total for issue in quality_issues)
        record.interface_instability_count = sum(issue.unstable for issue in quality_issues)
        if quality_errors:
            record.notes.append(
                "Some interface-quality detail was unavailable: " + ", ".join(quality_errors) + "."
            )
    else:
        record.notes.append(
            "Interface quality and instability commands were unsupported or "
            "returned no usable output."
        )

    try:
        errdisabled_output, _ = run_first_supported(
            task,
            "Err-disabled interfaces",
            profile["err_disabled"],
            read_timeout,
            allow_empty=True,
        )
        record.err_disabled_interfaces = merge_interface_issues(
            record.err_disabled_interfaces,
            parse_err_disabled_interfaces(errdisabled_output),
        )
        record.err_disabled_count = len(record.err_disabled_interfaces)
    except Exception:
        if record.total_interfaces is not None:
            record.err_disabled_count = len(record.err_disabled_interfaces)

    try:
        etherchannel_output, _ = run_first_supported(
            task, "EtherChannels", profile["etherchannels"], read_timeout
        )
        channels = parse_etherchannels(etherchannel_output)
        try:
            etherchannel_detail, _ = run_first_supported(
                task, "EtherChannel detail", profile["etherchannel_detail"], read_timeout
            )
            enrich_etherchannels(channels, etherchannel_detail)
        except Exception:
            if channels:
                record.notes.append(
                    "EtherChannel detail was unavailable; summary member flags "
                    "were still collected."
                )
        record.etherchannels = [channel.to_dict() for channel in channels]
        record.etherchannels_total = len(channels)
        record.etherchannels_healthy = sum(channel.state == "Up" for channel in channels)
        record.etherchannels_degraded = sum(channel.state == "Degraded" for channel in channels)
        record.etherchannels_down = sum(channel.state == "Down" for channel in channels)
        record.etherchannel_members_total = sum(len(channel.members) for channel in channels)
        record.etherchannel_members_bundled = sum(
            len(channel.bundled_members) for channel in channels
        )
        record.etherchannel_members_standby = sum(
            len(channel.standby_members) for channel in channels
        )
        record.etherchannel_member_issues = sum(
            len(channel.problem_members) for channel in channels
        )
        record.etherchannel_min_link_risks = sum(
            any("minimum links" in reason for reason in channel.risk_reasons)
            for channel in channels
        )
    except Exception as exc:
        record.notes.append(f"EtherChannel status unavailable: {exc}")

    try:
        port_security_output, _ = run_first_supported(
            task, "Port security", profile["port_security"], read_timeout
        )
        security_issues = parse_port_security_issues(port_security_output)
        record.port_security_issues = [issue.to_dict() for issue in security_issues]
        record.port_security_interfaces = len(security_issues)
        record.port_security_violations = sum(issue.violation_count for issue in security_issues)
    except Exception as exc:
        record.notes.append(f"Port-security status unavailable: {exc}")

    security_outputs: dict[str, str] = {}
    security_errors: list[str] = []
    for profile_key, label in (
        ("control_plane", "Control-plane policy"),
        ("arp_inspection", "Dynamic ARP Inspection"),
        ("dhcp_snooping", "DHCP snooping"),
    ):
        try:
            output, _ = run_first_supported(task, label, profile[profile_key], read_timeout)
            security_outputs[profile_key] = output
        except Exception:
            security_errors.append(label)

    if security_outputs:
        exceptions = parse_security_control_exceptions(security_outputs)
        record.security_control_exceptions = [exc.to_dict() for exc in exceptions]
        record.security_control_exception_count = len(exceptions)
        record.security_control_drop_count = sum(exc.count for exc in exceptions)
        if security_errors:
            record.notes.append(
                "Some security/control-plane views were unavailable: "
                + ", ".join(security_errors)
                + "."
            )
    else:
        record.notes.append(
            "Security/control-plane exception commands were unsupported or returned "
            "no usable output."
        )

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
