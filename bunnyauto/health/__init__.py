"""Read-only network-health collection shared by the two health-report tools.

``collect.py`` gathers firmware, interface, CPU, and environment state per
device (the ``run_first_supported`` command-fallback pattern absorbs platform
differences). Each report tool renders those records its own way — the
management scorecard (``health-simple``) or the engineer view
(``health-elaborate``).
"""
