#!/usr/bin/env python3
"""Discover interfaces with Nornir and create missing NetBox interfaces."""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import pynetbox
from nornir import InitNornir
from nornir.core.configuration import Config
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger(__name__)
DEFAULT_CONFIG = "config.yaml"
DEFAULT_TAG = "nornirtest"

TYPE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:lo|loopback)", re.I), "virtual"),
    (re.compile(r"^(?:vlan|bdi|irb|tunnel|tun|port-channel|po)", re.I), "virtual"),
    (re.compile(r"^(?:fa|fastethernet)", re.I), "100base-tx"),
    (re.compile(r"^(?:fi|fivegigabitethernet)", re.I), "5gbase-t"),
    (re.compile(r"^(?:gi|gigabitethernet)", re.I), "1000base-t"),
    (re.compile(r"^(?:te|tengigabitethernet)", re.I), "10gbase-x-sfpp"),
    (re.compile(r"^(?:tw|twe|twentyfivegige|twentyfivegigabitethernet)", re.I), "25gbase-x-sfp28"),
    (re.compile(r"^(?:fo|fortygige|fortygigabitethernet)", re.I), "40gbase-x-qsfpp"),
    (re.compile(r"^(?:hu|hundredgige|hundredgigabitethernet)", re.I), "100gbase-x-qsfp28"),
)


@dataclass(frozen=True)
class DiscoveredInterface:
    name: str
    description: str = ""
    enabled: bool = True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Use the Nornir inventory to discover interfaces on NetBox-tagged "
            "devices and create the missing interface objects in NetBox."
        )
    )
    parser.add_argument(
        "device",
        nargs="?",
        help=(
            "Optional Nornir inventory/NetBox device name. The device must also "
            "carry the selected NetBox tag."
        ),
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="Nornir configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_TAG,
        help=f"NetBox device tag used to select targets (default: {DEFAULT_TAG})",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create missing interfaces; the default is a dry run",
    )
    parser.add_argument(
        "--include-virtual",
        action="store_true",
        help="Include loopbacks, VLANs, tunnels, and port-channels",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
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


def load_inventory_options(config_file: str, token: str) -> dict[str, Any]:
    """Read NetBox settings from the Nornir config and inject the API token."""
    config_path = Path(config_file).expanduser().resolve()
    try:
        options = dict(Config.from_file(str(config_path)).inventory.options)
    except Exception as exc:
        raise RuntimeError(f"Unable to load Nornir config {config_path}: {exc}") from exc

    netbox_url = str(options.get("nb_url") or "").strip().rstrip("/")
    if not netbox_url.startswith(("http://", "https://")):
        raise RuntimeError(
            f"inventory.options.nb_url in {config_path} must start with http:// or https://"
        )
    options["nb_url"] = netbox_url
    options["nb_token"] = token
    return options


def ssl_verify_setting(value: Any) -> bool | str:
    if not isinstance(value, str):
        return bool(value)
    normalized = value.strip().casefold()
    if normalized in {"false", "no", "0", "off"}:
        return False
    if normalized in {"true", "yes", "1", "on"}:
        return True
    return value


def create_netbox_client(options: dict[str, Any], token: str) -> Any:
    netbox = pynetbox.api(options["nb_url"], token=token)
    netbox.http_session.verify = ssl_verify_setting(options.get("ssl_verify", True))
    return netbox


def normalize_name(name: str) -> str:
    compact = re.sub(r"\s+", "", name).casefold()
    prefixes = {
        "hundredgigabitethernet": "hu",
        "hundredgige": "hu",
        "fortygigabitethernet": "fo",
        "fortygige": "fo",
        "twentyfivegigabitethernet": "twe",
        "twentyfivegige": "twe",
        "tengigabitethernet": "te",
        "tengige": "te",
        "gigabitethernet": "gi",
        "fastethernet": "fa",
        "fivegigabitethernet": "fi",
        "port-channel": "po",
        "portchannel": "po",
        "loopback": "lo",
        "ethernet": "eth",
    }
    for long_name, short_name in prefixes.items():
        if compact.startswith(long_name):
            return short_name + compact[len(long_name) :]
    return compact


def interface_type(name: str) -> str:
    for pattern, netbox_type in TYPE_RULES:
        if pattern.search(name):
            return netbox_type
    return "other"


def parse_interfaces(rows: Any, include_virtual: bool) -> list[DiscoveredInterface]:
    if not isinstance(rows, list):
        raise ValueError(
            "The command did not return structured TextFSM data. Verify that "
            "ntc-templates supports 'show interfaces' for this Netmiko platform."
        )

    discovered: dict[str, DiscoveredInterface] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("interface") or row.get("port") or "").strip()
        if not name:
            continue
        netbox_type = interface_type(name)
        if netbox_type == "virtual" and not include_virtual:
            continue
        status = str(row.get("link_status") or row.get("status") or "").casefold()
        discovered.setdefault(
            normalize_name(name),
            DiscoveredInterface(
                name=name,
                description=str(row.get("description") or "").strip(),
                enabled=status not in {"administratively down", "admin down", "disabled"},
            ),
        )
    return sorted(discovered.values(), key=lambda item: normalize_name(item.name))


def collect_interfaces(task: Task, include_virtual: bool) -> Result:
    command_result = task.run(
        task=netmiko_send_command,
        name="Discover device interfaces",
        command_string="show interfaces",
        use_textfsm=True,
        read_timeout=120,
    )
    interfaces = parse_interfaces(command_result.result, include_virtual)
    return Result(host=task.host, result=interfaces, changed=False)


def find_discovered_result(multi_result: Any) -> list[DiscoveredInterface] | None:
    for item in multi_result:
        if (
            isinstance(item.result, list)
            and all(isinstance(value, DiscoveredInterface) for value in item.result)
        ):
            return item.result
    return None


def result_error(multi_result: Any) -> str:
    for item in reversed(multi_result):
        if getattr(item, "exception", None) is not None:
            return str(item.exception)
    return "interface collection failed"


def inventory_device_id(host: Any) -> int | None:
    value = host.get("netbox_device_id") or host.get("device_id") or host.get("id")
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def match_inventory_host(host: Any, devices: Iterable[Any]) -> Any | None:
    """Match a Nornir host to exactly one authoritative NetBox device."""
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
    """Select tagged inventory hosts and attach their authoritative NetBox IDs."""
    selected = nr.filter(
        filter_func=lambda host: match_inventory_host(host, tagged_devices) is not None
    )
    for host in selected.inventory.hosts.values():
        device = match_inventory_host(host, tagged_devices)
        if device is not None:
            host.data["netbox_device_id"] = int(device.id)
            host.data["netbox_device_name"] = str(device.name)
    return selected


def get_netbox_device(netbox: Any, host: Any) -> Any:
    device_id = inventory_device_id(host)
    device = netbox.dcim.devices.get(device_id) if device_id else None
    if device is None:
        device = netbox.dcim.devices.get(name=host.name)
    if device is None:
        raise RuntimeError(f"No NetBox device object matched Nornir host {host.name!r}")
    return device


def existing_interfaces(netbox: Any, device_id: int) -> dict[str, Any]:
    return {
        normalize_name(interface.name): interface
        for interface in netbox.dcim.interfaces.filter(device_id=device_id)
    }


def create_missing(
    netbox: Any, device_id: int, interfaces: Iterable[DiscoveredInterface]
) -> int:
    payload = [
        {
            "device": device_id,
            "name": interface.name,
            "type": interface_type(interface.name),
            "enabled": interface.enabled,
            "description": interface.description,
        }
        for interface in interfaces
    ]
    if not payload:
        return 0
    created = netbox.dcim.interfaces.create(payload)
    return len(created) if isinstance(created, list) else 1


def main() -> int:
    args = parse_arguments()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    nr = None
    try:
        token, username, password = required_environment()
        options = load_inventory_options(args.config, token)
        nr = InitNornir(
            config_file=args.config,
            inventory={"options": options},
        )
        nr.inventory.defaults.username = username
        nr.inventory.defaults.password = password

        netbox = create_netbox_client(options, token)
        tagged_devices = list(netbox.dcim.devices.filter(tag=args.tag))
        if not tagged_devices:
            LOGGER.warning("No NetBox devices have tag %r", args.tag)
            return 0

        if args.device:
            requested_name = args.device.casefold()
            tagged_devices = [
                device
                for device in tagged_devices
                if str(device.name).casefold() == requested_name
            ]
            if not tagged_devices:
                raise RuntimeError(
                    f"Device {args.device!r} was not found with NetBox tag {args.tag!r}"
                )

        selected = select_tagged_inventory(nr, tagged_devices)
        selected_count = len(selected.inventory.hosts)
        LOGGER.info(
            "Tag %r: %d NetBox device(s), %d Nornir inventory match(es)",
            args.tag,
            len(tagged_devices),
            selected_count,
        )
        if not selected_count:
            raise RuntimeError("No tagged NetBox devices matched the Nornir inventory")

        for host in selected.inventory.hosts.values():
            LOGGER.info(
                "Selected %s (%s), platform=%s",
                host.name,
                host.hostname,
                host.platform,
            )

        results = selected.run(
            task=collect_interfaces,
            name="Collect interfaces for NetBox comparison",
            include_virtual=args.include_virtual,
        )
        exit_code = 0
        for host_name, host_result in results.items():
            print(f"\n========== {host_name} ==========")
            if host_result.failed:
                LOGGER.error("%s: %s", host_name, result_error(host_result))
                exit_code = 1
                continue

            discovered = find_discovered_result(host_result)
            if discovered is None:
                LOGGER.error("%s: collection returned no interface list", host_name)
                exit_code = 1
                continue

            try:
                host = selected.inventory.hosts[host_name]
                device = get_netbox_device(netbox, host)
                existing = existing_interfaces(netbox, int(device.id))
                missing = [
                    item
                    for item in discovered
                    if normalize_name(item.name) not in existing
                ]

                LOGGER.info(
                    "%s: discovered=%d already_present=%d missing=%d",
                    device.name,
                    len(discovered),
                    len(discovered) - len(missing),
                    len(missing),
                )
                for interface in missing:
                    action = "CREATE" if args.apply else "WOULD CREATE"
                    print(
                        f"{action}  {interface.name}  "
                        f"({interface_type(interface.name)})"
                    )

                if not missing:
                    print("NetBox already contains every discovered interface.")
                elif args.apply:
                    count = create_missing(netbox, int(device.id), missing)
                    print(
                        f"Created {count} interface(s) on NetBox device {device.name}."
                    )
                else:
                    print(
                        "Dry-run only; rerun with --apply to create the missing "
                        "interfaces."
                    )
            except (RuntimeError, pynetbox.core.query.RequestError) as exc:
                LOGGER.error("%s: NetBox synchronization failed: %s", host_name, exc)
                exit_code = 1

        return exit_code
    except (RuntimeError, ValueError, pynetbox.core.query.RequestError) as exc:
        LOGGER.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        LOGGER.error("Cancelled")
        return 130
    finally:
        if nr is not None:
            nr.close_connections()


if __name__ == "__main__":
    sys.exit(main())
