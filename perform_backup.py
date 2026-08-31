#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto backup --raw``.

The backup pipeline now lives in ``bunnyauto/backup/`` and runs as the
``backup`` tool. This script historically wrote the running-config verbatim, so
the shim passes ``--raw`` to preserve that behaviour.

    python perform_backup.py --env test
        ≡  bunnyauto --env test backup --raw

Prefer plain ``bunnyauto --env test backup`` — it redacts secrets before
writing to disk.
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main([*forward_argv("backup", sys.argv[1:]), "--raw"]))
