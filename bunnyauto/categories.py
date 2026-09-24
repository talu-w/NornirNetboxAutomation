"""The tool categories, and the NetBox role branch each one is confined to.

A category is a family of tools for one part of the network. Each device-scoped
category owns one **branch** of NetBox's device-role tree (NetBox >= 4.3 nests
roles). Its tools only ever see devices whose role is in that branch, on top of
the environment's tag (which network) and any ``--region``/``--site``
(where). With a role tree like::

    Networking
    ├── Wired Network      -> wired      Routing, Switching > Core > Distribution > Access
    ├── Wireless Network   -> wireless   Wireless Controller > Wireless Access Point
    └── Network Security   -> security   Firewalls

a wired tool can never SSH into an AP or a firewall, whatever tags they carry.

:data:`DEFAULT_ROLES` holds the role slugs bunnyauto relies on. They are
NetBox's auto-generated slugs for the names above. Override any of them under
``roles:`` in ``bunnyauto.yaml`` (see ``bunnyauto.example.yaml``).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Category:
    """One family of tools: the CLI word, its menu text, and the role branch it owns."""

    #: CLI word and hub menu key, e.g. ``"wired"``.
    key: str
    #: Menu / help heading, e.g. ``"Wired Network"``.
    title: str
    #: One line for ``--help`` and the hub menu.
    summary: str
    #: Key into the environment's role map naming this category's branch root
    #: (see :data:`DEFAULT_ROLES`); ``None`` for a category that doesn't target
    #: network devices.
    branch: str | None = None


CATEGORIES: dict[str, Category] = {
    category.key: category
    for category in (
        Category(
            key="wired",
            title="Wired Network",
            summary="routers and switches (Cisco IOS/IOS-XE over SSH)",
            branch="wired",
        ),
        Category(
            key="wireless",
            title="Wireless Network",
            summary="Aruba wireless controllers and access points",
            branch="wireless",
        ),
        Category(
            key="security",
            title="Network Security",
            summary="firewalls",
            branch="security",
        ),
        Category(
            key="netbox",
            title="NetBox",
            summary="NetBox itself: device-type catalog, targeting preview",
        ),
    )
}

#: Every NetBox device-role slug bunnyauto relies on, by the key ``roles:`` in
#: bunnyauto.yaml uses to override it. The first three are category branch
#: roots; the wireless leaves are the roles ``wireless sync`` creates WLCs and
#: APs with.
DEFAULT_ROLES: dict[str, str] = {
    "wired": "wired-network",
    "wireless": "wireless-network",
    "security": "network-security",
    "wireless-controller": "wireless-controller",
    "wireless-access-point": "wireless-access-point",
}

#: The category branch each non-root role in :data:`DEFAULT_ROLES` must sit
#: inside — a WLC or AP role outside the wireless branch would put every device
#: created with it out of reach of the wireless tools.
ROLE_HOMES: dict[str, str] = {
    "wireless-controller": "wireless",
    "wireless-access-point": "wireless",
}
