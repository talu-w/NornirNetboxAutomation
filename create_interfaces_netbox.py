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


LOGGER = logging.getLogger(__name__)
DEFAULT_CONFIG = Path(__file__).resolve().with_name("config.yaml")

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
            "Use the Nornir inventory to discover one device's interfaces and "
            "create the missing interface objects in NetBox."
        )
    )
    parser.add_argument("device", help="Nornir inventory/NetBox device name")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Nornir configuration file (default: config.yaml beside this script)",
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


def find_inventory_host(nr: Any, requested_name: str) -> Any:
    matches = [
        host
        for host in nr.inventory.hosts.values()
        if host.name.casefold() == requested_name.casefold()
        or str(host.get("netbox_device_name") or "").casefold()
        == requested_name.casefold()
    ]
    if not matches:
        raise RuntimeError(f"Device {requested_name!r} is not in the Nornir inventory")
    if len(matches) > 1:
        raise RuntimeError(f"Device name {requested_name!r} matched multiple inventory hosts")
    return matches[0]


def get_netbox_device(netbox: Any, host: Any) -> Any:
    device_id = host.get("netbox_device_id") or host.get("device_id") or host.get("id")
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

        host = find_inventory_host(nr, args.device)
        selected = nr.filter(filter_func=lambda candidate: candidate is host)
        LOGGER.info(
            "Collecting %s (%s), platform=%s",
            host.name,
            host.hostname,
            host.platform,
        )
        results = selected.run(
            task=collect_interfaces,
            name="Collect interfaces for NetBox comparison",
            include_virtual=args.include_virtual,
        )
        host_result = results[host.name]
        if host_result.failed:
            error = host_result.exception or "interface collection failed"
            raise RuntimeError(f"{host.name}: {error}")
        discovered = find_discovered_result(host_result)
        if discovered is None:
            raise RuntimeError(f"{host.name}: collection returned no interface list")

        netbox = create_netbox_client(options, token)
        device = get_netbox_device(netbox, host)
        existing = existing_interfaces(netbox, int(device.id))
        missing = [item for item in discovered if normalize_name(item.name) not in existing]

        LOGGER.info(
            "%s: discovered=%d already_present=%d missing=%d",
            device.name,
            len(discovered),
            len(discovered) - len(missing),
            len(missing),
        )
        for interface in missing:
            action = "CREATE" if args.apply else "WOULD CREATE"
            print(f"{action}  {interface.name}  ({interface_type(interface.name)})")

        if not missing:
            print("NetBox already contains every discovered interface.")
        elif args.apply:
            count = create_missing(netbox, int(device.id), missing)
            print(f"Created {count} interface(s) on NetBox device {device.name}.")
        else:
            print("Dry-run only; rerun with --apply to create the missing interfaces.")
        return 0
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
