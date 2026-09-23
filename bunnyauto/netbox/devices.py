"""NetBox device records: match them to Nornir hosts, and tag them.

The host-matching helpers were first shared by ``create-interfaces`` and
``sync-interfaces`` (ported from the copies duplicated in
``create_interfaces_netbox.py`` and ``netbox_interfaces_update.py``).
:func:`add_tag` came out of ``wireless sync``, and is the one way any tool adds
a tag to an existing device.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from bunnyauto.common import normalize_tags
from bunnyauto.errors import NetBoxError

if TYPE_CHECKING:
    from nornir.core import Nornir


def inventory_device_id(host: Any) -> int | None:
    """The NetBox device id a Nornir host carries, if any inventory-plugin spelling has it."""
    value = host.get("netbox_device_id") or host.get("device_id") or host.get("id")
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def match_inventory_host(host: Any, devices: Iterable[Any]) -> Any | None:
    """Return the single NetBox device that matches ``host``, or ``None`` if ambiguous."""
    device_list = list(devices)
    host_id = inventory_device_id(host)
    if host_id is not None:
        matches = [device for device in device_list if int(device.id) == host_id]
        return matches[0] if len(matches) == 1 else None

    host_name = str(host.get("netbox_device_name") or host.name).casefold()
    matches = [d for d in device_list if str(d.name).casefold() == host_name]
    return matches[0] if len(matches) == 1 else None


def select_tagged_inventory(nr: Nornir, tagged_devices: list[Any]) -> Nornir:
    """Limit the inventory to hosts matching a tagged device, attaching their ids."""
    selected = nr.filter(
        filter_func=lambda host: match_inventory_host(host, tagged_devices) is not None
    )
    for host in selected.inventory.hosts.values():
        device = match_inventory_host(host, tagged_devices)
        if device is not None:
            host.data["netbox_device_id"] = int(device.id)
            host.data["netbox_device_name"] = str(device.name)
    return selected


def get_netbox_device(nb: Any, host: Any) -> Any:
    """Fetch the NetBox device object for a selected Nornir host."""
    device_id = inventory_device_id(host)
    device = nb.dcim.devices.get(device_id) if device_id else None
    if device is None:
        device = nb.dcim.devices.get(name=host.name)
    if device is None:
        raise NetBoxError(f"no NetBox device matched Nornir host {host.name!r}")
    return device


def add_tag(device: Any, slug: str) -> bool | str:
    """Add tag ``slug`` to an existing device, keeping its other tags.

    ``True`` on success, otherwise the error text (the caller reports it and
    carries on with the rest of the run).
    """
    try:
        slugs = sorted(set(normalize_tags(getattr(device, "tags", [])) + [slug.casefold()]))
        device.update({"tags": [{"slug": s} for s in slugs]})
    except Exception as exc:  # pynetbox RequestError etc.
        return str(exc)
    return True
