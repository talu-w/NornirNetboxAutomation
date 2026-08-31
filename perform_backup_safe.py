#!/usr/bin/env python3
"""Compatibility shim — forwards to ``bunnyauto backup``.

The backup pipeline (config + environment + interface workbook, with secrets
redacted) now lives in ``bunnyauto/backup/`` and runs as the ``backup`` tool.
Redaction is the default, so this shim needs no extra flag.

    python perform_backup_safe.py --env test
        ≡  bunnyauto --env test backup
"""

from __future__ import annotations

import sys

from bunnyauto.cli import forward_argv, main

if __name__ == "__main__":
    sys.exit(main(forward_argv("backup", sys.argv[1:])))
