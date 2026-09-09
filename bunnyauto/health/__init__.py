"""Read-only network-health collection behind the ``health`` tool.

``collect.py`` gathers firmware, interface, CPU, and environment state per
device (the ``run_first_supported`` command-fallback pattern absorbs platform
differences). The ``health`` tool renders those records one of two ways — the
management scorecard (``health simple``) or the engineer view
(``health elaborate``); ``elaborate_collect.py`` extends the collection for the
latter.
"""
