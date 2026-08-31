#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto health-simple``.

The management scorecard now lives in ``bunnyauto/tools/health_simple.py`` (with
the shared collection layer in ``bunnyauto/health/``). Read-only.

    python network_simple_health_report.py --env test
        ≡  bunnyauto --env test health-simple
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("health-simple", sys.argv[1:])))
