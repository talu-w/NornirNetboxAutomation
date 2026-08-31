#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto send-command``.

The real implementation now lives in ``bunnyauto/tools/send_command.py``. This
file is kept so existing habits and any wrapper scripts keep working during the
migration (see the bunnyauto Platform Design doc); it will be removed once CI is
the primary entry path.

    python send_command.py --env test "show version"
        ≡  bunnyauto --env test send-command "show version"
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("send-command", sys.argv[1:])))
