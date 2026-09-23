"""bunnyauto — a NetBox-driven, Nornir-executed network automation platform.

This package holds the shared core that every tool and both entry points (the
interactive hub and the CI command line) build on:

* :mod:`bunnyauto.environments` — resolve the selected test/prod environment.
* :mod:`bunnyauto.errors`       — one typed exception tree with friendly messages.
* :mod:`bunnyauto.common`       — Nornir/NetBox bootstrap, tag and Netmiko helpers.
* :mod:`bunnyauto.preflight`    — credential and token checks.
* :mod:`bunnyauto.reporting`    — a single output sink (TTY, CI, or JSON).
* :mod:`bunnyauto.result`       — the structured result every tool returns.
* :mod:`bunnyauto.context`      — the per-invocation Context object.
* :mod:`bunnyauto.categories`   — tool categories and the NetBox role branch each owns.
* :mod:`bunnyauto.scope`        — tag + role branch + region/site: which devices a run touches.
* :mod:`bunnyauto.netbox`       — shared NetBox building blocks every category reuses.

Tools live in :mod:`bunnyauto.tools`, one package per category (``wired``,
``wireless``, ``security``, ``netbox``). Nothing here connects to a device or
to NetBox on import.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
