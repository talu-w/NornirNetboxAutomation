#!/usr/bin/env python3
"""Compatibility shim — launches the bunnyauto interactive hub.

The hub now lives in ``bunnyauto/hub.py``. This file is kept so the familiar
``python nornir_hub.py`` still opens the menu; it will be removed once CI is the
primary entry path. ``bunnyauto`` with no arguments does the same thing.
"""

from __future__ import annotations

import sys

from bunnyauto.hub import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
