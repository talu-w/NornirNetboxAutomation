#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto create-interfaces``.

The implementation now lives in ``bunnyauto/tools/create_interfaces.py``. It
plans by default; pass ``--apply`` to create the missing NetBox interfaces.

    python create_interfaces_netbox.py --env test
        ≡  bunnyauto --env test create-interfaces

    python create_interfaces_netbox.py --env test --apply
        ≡  bunnyauto --env test create-interfaces --apply
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("create-interfaces", sys.argv[1:])))
