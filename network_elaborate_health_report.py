#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto health-elaborate``.

The engineer health workbook now lives in ``bunnyauto/tools/health_elaborate.py``
(collection in ``bunnyauto/health/elaborate_collect.py``, workbook in
``elaborate_workbook.py``). Read-only.

    python network_elaborate_health_report.py --env test
        ≡  bunnyauto --env test health-elaborate

Dropped in the port (dead in the original): the unused
``_create_compact_health_workbook`` and the never-wired spanning-tree parsing.
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("health-elaborate", sys.argv[1:])))
