'''This script will go through Netbox and filter out devices based on a unique "tag/tags" object then send a command(s) to those devices while providing output'''

'''Features to be added:
   1.) Send Multiple commands
   2.) Pick devices based on unique objects
   3.) Connect to multiple devices to send commands all at once
   4.) Save the output from Multiple devices into a Dir/Repo for logging'''

import os
import sys
from typing import Any

from nornir import InitNornir
from nornir.core.filter import F
from nornir.core.task import Task
from nornir_netmiko.tasks import netmiko_send_command
from nornir_utils.plugins.functions import print_result
from nornir.core.inventory import ConnectionOptions

USERNETWORKCOMMAND = input('Please input the network command:')

def main() -> int:
    
    username = os.getenv("NORNIR_USERNAME")
    password = os.getenv("NORNIR_PASSWORD")

    if not username or not password:
        print(
            "ERROR: NORNIR_USERNAME and NORNIR_PASSWORD "
            "must be set in the environment."
        )
        return 1

    try:
        nr = InitNornir(config_file="config.yaml")
    except Exception as exc:
        print(f"ERROR: Could not initialize Nornir/NetBox inventory: {exc}")
        return 1
    
    nr.inventory.defaults.username = username
    nr.inventory.defaults.password = password

    # Prepare NetBox tag data for Nornir F filtering.
    for host in nr.inventory.hosts.values():
        host.data["tag_slugs"] = normalize_tag_slugs(
            host.data.get("tags", [])
        )

        #Connection options - Configured currently for connecting to legacy SSH/slower devices.
        #Applied to all the objects that are pulled above from nr.inventory.hosts
        host.connection_options["netmiko"] = ConnectionOptions(extras= {"conn_timeout": 30,
                                                                        "banner_timeout": 60,
                                                                        "auth_timeout": 60,
                                                                        "fast_cli": False})

    #Local Nornir inventory filtering.
    testing_devices = nr.filter(
        F(tag_slugs__contains="networking-active")
    )

    if not testing_devices.inventory.hosts:
        print("No inventory devices have the NetBox tag 'testing'.")
        return 0

    print("Matched devices:")

    for host in testing_devices.inventory.hosts.values():
        print(
            f"  {host.name}: "
            f"hostname={host.hostname}, "
            f"platform={host.platform}, "
            f"tags={host.data['tag_slugs']}"
        )
    #Calls upon the send_command function to use Netmiko
    results = testing_devices.run(task=send_command)
    print_result(results)
    return 2 if results.failed_hosts else 0

def normalize_tag_slugs(tags: list[Any]) -> list[str]:
    """Return normalized tag slugs from NetBox inventory data."""

    normalized: list[str] = []

    for tag in tags:
        if isinstance(tag, str):
            value = tag

        elif isinstance(tag, dict):
            value = tag.get("slug") or tag.get("name")

        else:
            value = (
                getattr(tag, "slug", None)
                or getattr(tag, "name", None)
            )

        if value:
            normalized.append(str(value).casefold())

    return normalized

def send_command(task: Task):
    result = task.run(
        task=netmiko_send_command,
        command_string=USERNETWORKCOMMAND,
        name=f"Sending '{USERNETWORKCOMMAND}' to {task.host.name}",
        
    )

    print(f"\n========== {task.host.name} ==========\n")
    print(result.result)

if __name__ == "__main__":
    sys.exit(main())