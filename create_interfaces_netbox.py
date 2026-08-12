#!/usr/bin/env python3
"""Discover a device's interfaces and create missing NetBox interface objects."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable

import pynetbox
from netmiko import ConnectHandler


LOG = logging.getLogger("sync_device_interfaces")

# NetBox interface types. The mapping is intentionally conservative; unknown
# names are created as "other" rather than assigned a potentially wrong type.
TYPE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(?:lo|loopback)", re.I), "virtual"),
    (re.compile(r"^(?:vlan|bdi|irb|tunnel|tun|port-channel|po)", re.I), "virtual"),
    (re.compile(r"^(?:fa|fastethernet)", re.I), "100base-tx"),
    (re.compile(r"^(?:gi|gigabitethernet)", re.I), "1000base-t"),
    (re.compile(r"^(?:te|tengigabitethernet|ten-gigabitethernet)", re.I), "10gbase-x-sfpp"),
    (re.compile(r"^(?:tw|twentyfivegige|twentyfivegigabitethernet)", re.I), "25gbase-x-sfp28"),
    (re.compile(r"^(?:fo|fortygigabitethernet)", re.I), "40gbase-x-qsfpp"),
    (re.compile(r"^(?:hu|hundredgige|hundredgigabitethernet)", re.I), "100gbase-x-qsfp28"),
    (re.compile(r"^(?:eth|ethernet)", re.I), "other"),
)


@dataclass(frozen=True)
class DiscoveredInterface:
    name: str
    description: str = ""
    enabled: bool = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create interfaces in NetBox that exist on a network device but not in NetBox."
    )
    parser.add_argument("device", help="Existing NetBox device name")
    parser.add_argument("--apply", action="store_true", help="Create missing interfaces (default is dry-run)")
    parser.add_argument("--username", default=os.getenv("DEVICE_USERNAME"), help="SSH username")
    parser.add_argument("--password", default=os.getenv("DEVICE_PASSWORD"), help="SSH password")
    parser.add_argument("--secret", default=os.getenv("DEVICE_SECRET"), help="Optional enable secret")
    parser.add_argument("--address", help="Override the device's NetBox primary IP/DNS name")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--netmiko-type", help="Override Netmiko device_type derived from NetBox platform")
    parser.add_argument("--include-virtual", action="store_true", help="Include loopbacks, VLANs, tunnels, etc.")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable NetBox TLS certificate verification")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


def record_value(value: Any, attribute: str = "value") -> Any:
    """Read a field from pynetbox Record, dict, or primitive values."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get(attribute)
    return getattr(value, attribute, value)


def device_address(device: Any, override: str | None) -> str:
    if override:
        return override
    primary_ip = getattr(device, "primary_ip", None)
    address = record_value(primary_ip, "address")
    if address:
        return str(address).split("/", maxsplit=1)[0]
    if getattr(device, "name", None):
        return str(device.name)
    raise ValueError("The device has no primary IP or usable name; supply --address")


def netmiko_device_type(device: Any, override: str | None) -> str:
    if override:
        return override
    platform = getattr(device, "platform", None)
    slug = record_value(platform, "slug")
    if not slug:
        raise ValueError("The NetBox device has no platform; supply --netmiko-type")
    aliases = {
        "ios": "cisco_ios",
        "ios-xe": "cisco_xe",
        "iosxe": "cisco_xe",
        "nx-os": "cisco_nxos",
        "nxos": "cisco_nxos",
        "eos": "arista_eos",
        "junos": "juniper_junos",
    }
    return aliases.get(str(slug).lower(), str(slug))


def normalize_name(name: str) -> str:
    """Normalize common long/short interface prefixes for comparison."""
    compact = re.sub(r"\s+", "", name).casefold()
    prefixes = {
        "hundredgigabitethernet": "hu",
        "fortygigabitethernet": "fo",
        "twentyfivegigabitethernet": "tw",
        "tengigabitethernet": "te",
        "gigabitethernet": "gi",
        "fastethernet": "fa",
        "port-channel": "po",
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


def is_virtual(name: str) -> bool:
    return interface_type(name) == "virtual"


def parse_interfaces(rows: Any, include_virtual: bool) -> list[DiscoveredInterface]:
    if not isinstance(rows, list):
        raise ValueError(
            "Netmiko did not return structured data. Install ntc-templates and ensure "
            "the platform supports the 'show interfaces' TextFSM template."
        )

    discovered: dict[str, DiscoveredInterface] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("interface") or row.get("port") or "").strip()
        if not name or (is_virtual(name) and not include_virtual):
            continue
        description = str(row.get("description") or "").strip()
        link_status = str(row.get("link_status") or row.get("status") or "").casefold()
        enabled = link_status not in {"administratively down", "admin down", "disabled"}
        discovered.setdefault(normalize_name(name), DiscoveredInterface(name, description, enabled))
    return sorted(discovered.values(), key=lambda item: normalize_name(item.name))


def discover_interfaces(connection: dict[str, Any], include_virtual: bool) -> list[DiscoveredInterface]:
    LOG.info("Connecting to %s", connection["host"])
    with ConnectHandler(**connection) as session:
        rows = session.send_command("show interfaces", use_textfsm=True)
    return parse_interfaces(rows, include_virtual)


def existing_interfaces(netbox: Any, device_id: int) -> dict[str, Any]:
    return {
        normalize_name(interface.name): interface
        for interface in netbox.dcim.interfaces.filter(device_id=device_id)
    }


def create_missing(netbox: Any, device: Any, interfaces: Iterable[DiscoveredInterface]) -> int:
    payload = [
        {
            "device": device.id,
            "name": interface.name,
            "type": interface_type(interface.name),
            "enabled": interface.enabled,
            "description": interface.description,
        }
        for interface in interfaces
    ]
    if not payload:
        return 0

    # A single REST bulk request avoids leaving a partially-created set when
    # NetBox rejects one of the records.
    created = netbox.dcim.interfaces.create(payload)
    return len(created) if isinstance(created, list) else 1


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        netbox = pynetbox.api(required_env("NETBOX_URL"), token=required_env("NETBOX_TOKEN"))
        netbox.http_session.verify = not args.no_verify_tls
        device = netbox.dcim.devices.get(name=args.device)
        if device is None:
            raise ValueError(f"No NetBox device named {args.device!r} was found")

        username = args.username or input("Device username: ").strip()
        password = args.password or getpass.getpass("Device password: ")
        if not username or not password:
            raise ValueError("Device username and password are required")

        connection: dict[str, Any] = {
            "device_type": netmiko_device_type(device, args.netmiko_type),
            "host": device_address(device, args.address),
            "username": username,
            "password": password,
            "port": args.port,
        }
        if args.secret:
            connection["secret"] = args.secret

        discovered = discover_interfaces(connection, args.include_virtual)
        existing = existing_interfaces(netbox, device.id)
        missing = [item for item in discovered if normalize_name(item.name) not in existing]

        LOG.info(
            "%s: discovered=%d, already_in_netbox=%d, missing=%d",
            device.name,
            len(discovered),
            len(discovered) - len(missing),
            len(missing),
        )
        for interface in missing:
            print(f"{'CREATE' if args.apply else 'WOULD CREATE'}  {interface.name}  ({interface_type(interface.name)})")

        if not missing:
            print("NetBox already contains every discovered interface.")
        elif args.apply:
            count = create_missing(netbox, device, missing)
            print(f"Created {count} interface(s) on NetBox device {device.name}.")
        else:
            print("Dry-run only; rerun with --apply to create the missing interfaces.")
        return 0
    except (ValueError, pynetbox.core.query.RequestError) as exc:
        LOG.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        LOG.error("Cancelled")
        return 130


if __name__ == "__main__":
    sys.exit(main())