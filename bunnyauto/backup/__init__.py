"""Backup pipeline: collect running-config + environment + interface state.

Formerly the near-duplicate ``perform_backup.py`` / ``perform_backup_safe.py``
pair. Now one path with a ``sanitize`` toggle (D2): secrets are redacted by
default, ``--raw`` opts out.
"""
