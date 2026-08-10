#!/usr/bin/env python3

"""Synchronize Cisco interface VLAN assignments to NetBox.

Workflow:
    1. Load the NetBox-backed Nornir inventory.
    2. Select devices carrying the requested NetBox tag.
    3. Collect access and trunk VLAN state from those devices.
    4. Compare that state with each NetBox interface.
    5. Update only interfaces whose VLAN state differs.

The script does not create VLANs or interfaces. Missing or ambiguous NetBox
objects are reported and skipped so that partial assignments are never made.
"""

from __future__ import annotations

import argparse
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


DEFAULT_TAG = "nornirtest"
SHOW_VLAN = "show vlan brief"
SHOW_TRUNKS = "show interfaces trunk"

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


@dataclass
class TrunkState:
    name: str
    native_vlan: int | None = None
    allowed_vlans: list[int] = field(default_factory=list)
    active_vlans: list[int] = field(default_factory=list)
    allows_all: bool = False


@dataclass
class CollectedDevice:
    inventory_name: str
    netbox_device_id: int | None
    interfaces: list[InterfaceVlanState]


@dataclass
class SyncSummary:
    device: str
    dry_run: bool
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0
    changes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


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
        r"^\s+(?P<ports>(?:Fa|Gi|Te|Tw|Fo|Hu|Eth|Po)\S+.*)$",
        re.IGNORECASE,
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

    operational_line = re.compile(
        r"^\s*(?P<port>\S+)\s+\S+\s+\S+\s+\S+\s+"
        r"(?P<native>\d+|-)\s*$"
    )
    vlan_line = re.compile(
        r"^\s*(?P<port>\S+)\s+"
        r"(?P<vlans>(?:none|all|[\d,\-\s]+))\s*$",
        re.IGNORECASE,
    )

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
        if not match:
            continue

        port = match.group("port")
        expression = match.group("vlans").strip().lower().replace(" ", "")
        trunk = trunks.setdefault(port, TrunkState(name=port))
        if section == "allowed":
            trunk.allowed_vlans = expand_vlan_list(expression)
            trunk.allows_all = expression in {"all", "1-4094"}
        elif section == "active":
            trunk.active_vlans = expand_vlan_list(expression)

    return trunks


def build_collected_state(vlan_output: str, trunk_output: str) -> list[InterfaceVlanState]:
    """Combine command output into one desired state per discovered interface."""

    desired: dict[str, InterfaceVlanState] = {}
    for interface, vlan_id in parse_vlan_brief(vlan_output).items():
        desired[interface.casefold()] = InterfaceVlanState(
            name=interface,
            mode="access",
            untagged_vlan=vlan_id,
        )

    for interface, trunk in parse_trunks(trunk_output).items():
        # An unrestricted Cisco trunk is reported as all/1-4094. Only VLANs
        # active on this device are meaningful interface assignments in NetBox.
        tagged = trunk.active_vlans if trunk.allows_all else trunk.allowed_vlans
        tagged = sorted(set(tagged) - {trunk.native_vlan})
        desired[interface.casefold()] = InterfaceVlanState(
            name=interface,
            mode="tagged",
            untagged_vlan=trunk.native_vlan,
            tagged_vlans=tuple(tagged),
        )

    return sorted(desired.values(), key=lambda item: interface_sort_key(item.name))


def collect_device_state(task: Task) -> Result:
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

    collected = CollectedDevice(
        inventory_name=task.host.name,
        netbox_device_id=inventory_device_id(task.host),
        interfaces=build_collected_state(
            str(vlan_result.result),
            str(trunk_result.result),
        ),
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
    "twogigabitethernet": "tw",
    "fo": "fo",
    "fortygige": "fo",
    "fortygigabitethernet": "fo",
    "hu": "hu",
    "hundredgige": "hu",
    "hundredgigabitethernet": "hu",
    "eth": "eth",
    "ethernet": "eth",
    "po": "po",
    "port-channel": "po",
    "portchannel": "po",
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


def vlan_scope_id(vlan: Any) -> int | None:
    """Support both site-scoped and generic-scope NetBox VLAN records."""

    scope_id = related_id(getattr(vlan, "scope", None))
    if scope_id is not None:
        return scope_id
    site_id = related_id(getattr(vlan, "site", None))
    if site_id is not None:
        return site_id

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
    cache: dict[int, list[Any]],
    vlan_id: int,
    device: Any,
) -> tuple[Any | None, str | None]:
    candidates = cache.get(vlan_id, [])
    if not candidates:
        return None, f"VLAN {vlan_id} does not exist in NetBox"
    if len(candidates) == 1:
        return candidates[0], None

    site_id = related_id(getattr(device, "site", None))
    if site_id is not None:
        site_candidates = [
            vlan for vlan in candidates if vlan_scope_id(vlan) == site_id
        ]
        if len(site_candidates) == 1:
            return site_candidates[0], None

    global_candidates = [vlan for vlan in candidates if vlan_scope_id(vlan) is None]
    if len(global_candidates) == 1:
        return global_candidates[0], None

    ids = ", ".join(str(vlan.id) for vlan in candidates)
    return None, f"VLAN {vlan_id} is ambiguous; candidate NetBox IDs: {ids}"


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


def current_interface_state(interface: Any) -> dict[str, Any]:
    return {
        "mode": choice_value(getattr(interface, "mode", None)),
        "untagged_vlan": related_id(getattr(interface, "untagged_vlan", None)),
        "tagged_vlans": related_ids(getattr(interface, "tagged_vlans", [])),
    }


def desired_netbox_state(
    discovered: InterfaceVlanState,
    device: Any,
    vlan_cache: dict[int, list[Any]],
) -> tuple[dict[str, Any] | None, str | None]:
    """Translate collected VLAN IDs to unambiguous NetBox object IDs."""

    required_vids = set(discovered.tagged_vlans)
    if discovered.untagged_vlan is not None:
        required_vids.add(discovered.untagged_vlan)

    resolved: dict[int, Any] = {}
    errors: list[str] = []
    for vlan_id in sorted(required_vids):
        vlan, error = resolve_vlan(vlan_cache, vlan_id, device)
        if error:
            errors.append(error)
        elif vlan is not None:
            resolved[vlan_id] = vlan

    if errors:
        return None, "; ".join(errors)

    untagged = (
        resolved[discovered.untagged_vlan]
        if discovered.untagged_vlan is not None
        else None
    )
    return {
        "mode": discovered.mode,
        "untagged_vlan": related_id(untagged),
        "tagged_vlans": sorted(
            int(resolved[vlan_id].id) for vlan_id in discovered.tagged_vlans
        ),
    }, None


def sync_device(
    nb: Any,
    collected: CollectedDevice,
    vlan_cache: dict[int, list[Any]],
    dry_run: bool,
) -> SyncSummary:
    """Compare one device and apply only the necessary interface updates."""

    device = resolve_device(nb, collected)
    summary = SyncSummary(device=str(device.name), dry_run=dry_run)
    interfaces = list(nb.dcim.interfaces.filter(device_id=device.id))
    by_name, by_signature = interface_indexes(interfaces)

    for discovered in collected.interfaces:
        interface, error = match_interface(discovered.name, by_name, by_signature)
        if error:
            summary.skipped += 1
            summary.errors.append(error)
            continue

        desired, error = desired_netbox_state(discovered, device, vlan_cache)
        if error:
            summary.skipped += 1
            summary.errors.append(f"{discovered.name}: {error}")
            continue

        current = current_interface_state(interface)
        if current == desired:
            summary.unchanged += 1
            continue

        change = f"{interface.name}: {current} -> {desired}"
        if dry_run:
            summary.updated += 1
            summary.changes.append(f"DRY-RUN {change}")
            continue

        try:
            interface.update(desired)
            summary.updated += 1
            summary.changes.append(change)
        except Exception as exc:
            summary.errors.append(f"{interface.name}: update failed: {exc}")

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
    print(
        f"\n[{label}] {summary.device}: updated={summary.updated} "
        f"unchanged={summary.unchanged} skipped={summary.skipped} "
        f"errors={len(summary.errors)}"
    )
    for change in summary.changes:
        print(f"  CHANGE: {change}")
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

        results = selected.run(
            task=collect_device_state,
            name="Collect interface VLAN state",
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

        vlan_cache = build_vlan_cache(nb)
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
