#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto sync-interfaces``.

The VLAN/interface reconciliation engine now lives in ``bunnyauto/sync/`` and
runs as the ``sync-interfaces`` tool. It plans by default; ``--apply`` writes to
NetBox.

    python netbox_interfaces_update.py --env test
        ≡  bunnyauto --env test sync-interfaces

    python netbox_interfaces_update.py --env test --apply
        ≡  bunnyauto --env test sync-interfaces --apply

(The old ``--dry-run`` flag is gone — planning is the default; pass ``--apply``
to write. See D4 in the bunnyauto Platform Design doc.)
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("sync-interfaces", sys.argv[1:])))
