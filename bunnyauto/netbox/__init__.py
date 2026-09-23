"""Shared NetBox building blocks — one home, reused by every tool category.

Nothing here knows about a vendor or a tool category: a wired, wireless, or
security tool that needs to match, classify, or write a NetBox object calls
the same function. If two tools need the same NetBox logic, it belongs here,
not copied into both.

=================  =========================================================
``records``        read pynetbox values: related-object ids, choice fields
``roles``          the device-role tree (NetBox >= 4.3 nests roles), role lookups
``devices``        Nornir host <-> NetBox device matching, device tagging
``interfaces``     interface names (Gi1/0/1 == GigabitEthernet1/0/1), stack
                   members, NetBox interface types, picking a wired port
``hostnames``      neighbor hostname -> NetBox device (FQDN/short, stack members)
``tokens``         terse vendor strings -> device types / platforms
``ipam``           containing-prefix lookup, primary-IP assignment
``cabling``        LLDP/CDP-style neighbor -> NetBox cable plan + create
=================  =========================================================
"""
