#!/usr/bin/env python3

"""Create sanitized Nornir/NetBox backups of network running configurations.

This entry point reuses the collection workflow in ``perform_backup.py`` and
removes common credential, AAA, RADIUS, TACACS+, SNMP authentication, and key
statements before a configuration is written. It is intentionally conservative:
when a line appears security-sensitive, the complete line is replaced instead
of attempting to preserve part of it.

The sanitizer targets common Cisco IOS/IOS-XE/NX-OS/ASA syntax and also catches
several generic network-configuration secret forms. Always validate the rules
against sanitized lab configurations for every platform in your inventory.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path


# Universal NetBox tag used to select devices for sanitized backups.
# Change the default here or override it at runtime with NORNIR_TARGET_TAG.
DEFAULT_TARGET_TAG = "nornirtest"
NORNIR_TARGET_TAG = os.getenv("NORNIR_TARGET_TAG", DEFAULT_TARGET_TAG)

DEFAULT_SAFE_BACKUP_ROOT = "./config_backups_safe"
SANITIZED_HEADER = (
    "! SANITIZED BACKUP - NOT A COMPLETE RESTORE CONFIGURATION\n"
    "! Security-sensitive statements were removed before this file was written."
)
_SANITIZED_HEADER_LINES = frozenset(SANITIZED_HEADER.splitlines())


class SanitizationError(ValueError):
    """Raised when sanitized output still appears to contain sensitive data."""


_PRIVATE_KEY_START = re.compile(
    r"^-{4,5}BEGIN (?:SSH2 )?(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-{4,5}$",
    re.IGNORECASE,
)
_PRIVATE_KEY_END = re.compile(
    r"^-{4,5}END (?:SSH2 )?(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-{4,5}$",
    re.IGNORECASE,
)

# These commands introduce indented Cisco-style blocks whose names, endpoints,
# and child commands are all considered sensitive for a clean shared backup.
_SENSITIVE_BLOCKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^aaa\s+group\s+server\b", re.IGNORECASE),
        "centralized authentication block",
    ),
    (
        re.compile(r"^(?:radius|tacacs)\s+server\b", re.IGNORECASE),
        "centralized authentication block",
    ),
    (
        re.compile(r"^key\s+chain\b", re.IGNORECASE),
        "key-chain block",
    ),
    (
        re.compile(r"^crypto\s+ikev2\s+keyring\b", re.IGNORECASE),
        "keyring block",
    ),
    (
        re.compile(r"^crypto\s+keyring\b", re.IGNORECASE),
        "keyring block",
    ),
)

# Order matters: the first match supplies the audit-friendly redaction label.
_SENSITIVE_LINES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "local account",
        re.compile(
            r"(?:^|\s)(?:username|user-name)\b|\blogin\s+user\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AAA or centralized authentication",
        re.compile(
            r"(?:^|\s)(?:aaa(?:-server)?|radius(?:-server)?|tacacs(?:-server)?)\b"
            r"|\b(?:authentication|authorization|accounting)\b"
            r"|\bserver-private\b"
            r"|^(?:\s*)(?:dot1x|mab)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "credential",
        re.compile(
            r"\b(?:password|passwd|secret|shared-secret|client-secret)\b"
            r"|\bencrypted-password\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SNMP access",
        re.compile(
            r"(?:^|\s)snmp(?:-server)?\s+(?:community|user|host|group)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "authentication key",
        re.compile(
            r"\b(?:key-string|authentication-key|message-digest-key|pre-shared-key|"
            r"private-key|wpa-psk|psk)\b"
            r"|\bcrypto\s+isakmp\s+key\b"
            r"|^\s*key\s+(?!chain\b)(?:\d+\s+)?\S+"
            r"|\b(?:standby|vrrp|glbp)\b.*\bauthentication\b"
            r"|\bntp\s+(?:authentication-key|trusted-key)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "embedded access token",
        re.compile(
            r"\b(?:api[-_ ]?key|access[-_ ]?token|bearer[-_ ]?token)\b\s*(?:=|\s)\s*\S+",
            re.IGNORECASE,
        ),
    ),
    (
        "embedded URL credential",
        re.compile(r"://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE),
    ),
    (
        "PPP credential",
        re.compile(r"(?:^|\s)ppp\s+(?:chap|pap)\b", re.IGNORECASE),
    ),
)


def _block_category(line: str) -> str | None:
    """Return the category when a line starts a sensitive config block."""

    for pattern, category in _SENSITIVE_BLOCKS:
        if pattern.search(line):
            return category
    return None


def _line_category(line: str) -> str | None:
    """Classify a single sensitive statement without returning its contents."""

    stripped = line.strip()
    if stripped.startswith("! <redacted:") or stripped.startswith("! SANITIZED BACKUP"):
        return None

    for category, pattern in _SENSITIVE_LINES:
        if pattern.search(line):
            return category
    return None


def _append_marker(lines: list[str], category: str, indentation: str = "") -> None:
    """Append one marker and collapse adjacent identical redactions."""

    marker = f"{indentation}! <redacted: {category}>"
    if not lines or lines[-1] != marker:
        lines.append(marker)


def _remaining_sensitive_lines(lines: Iterable[str]) -> list[int]:
    """Return line numbers that fail the post-sanitization safety scan."""

    suspicious: list[int] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if _PRIVATE_KEY_START.match(stripped):
            suspicious.append(line_number)
        elif _block_category(stripped) or _line_category(line):
            suspicious.append(line_number)
    return suspicious


def sanitize_running_config(running_config: str) -> str:
    """Return a shareable configuration with security material removed.

    Sensitive statements become comments so a reviewer can see where material
    was removed without seeing names, endpoints, hashes, keys, or clear text.
    A final scan fails closed if a recognized sensitive form somehow remains.
    """

    if not running_config.strip():
        raise SanitizationError("Cannot sanitize an empty running configuration.")

    sanitized: list[str] = []
    sensitive_block: str | None = None
    private_key_block = False

    for original_line in running_config.splitlines():
        stripped = original_line.strip()

        # Avoid duplicating the notice if a previously sanitized backup is
        # processed again during testing or an offline workflow.
        if original_line in _SANITIZED_HEADER_LINES:
            continue

        if private_key_block:
            if _PRIVATE_KEY_END.match(stripped):
                private_key_block = False
            continue

        if sensitive_block is not None:
            if stripped == "!":
                sanitized.append("!")
                sensitive_block = None
                continue
            if stripped.casefold() == "exit":
                sensitive_block = None
                continue
            if not stripped or original_line[:1].isspace():
                continue

            # A non-indented command begins a new section even when the input
            # omitted the usual Cisco ``!`` separator. Process it normally.
            sensitive_block = None

        if _PRIVATE_KEY_START.match(stripped):
            _append_marker(sanitized, "private key block")
            private_key_block = True
            continue

        block_category = _block_category(stripped)
        if block_category:
            _append_marker(sanitized, block_category)
            sensitive_block = block_category
            continue

        line_category = _line_category(original_line)
        if line_category:
            indentation_match = re.match(r"^\s*", original_line)
            indentation = indentation_match.group(0) if indentation_match else ""
            _append_marker(sanitized, line_category, indentation)
            continue

        sanitized.append(original_line.rstrip())

    remaining = _remaining_sensitive_lines(sanitized)
    if remaining:
        locations = ", ".join(str(line_number) for line_number in remaining[:10])
        raise SanitizationError(
            "The safety scan found recognized sensitive syntax after sanitation "
            f"at output line(s) {locations}; no configuration was written."
        )

    return SANITIZED_HEADER + "\n" + "\n".join(sanitized).rstrip() + "\n"


def main() -> int:
    """Run the shared Nornir backup workflow with sanitation enabled."""

    import perform_backup as backup

    backup.TARGET_TAG = NORNIR_TARGET_TAG
    backup.CONFIG_SANITIZER = sanitize_running_config
    backup.BACKUP_ROOT = Path(
        os.getenv("NORNIR_SAFE_BACKUP_ROOT", DEFAULT_SAFE_BACKUP_ROOT)
    )
    backup.console.print(
        "[bold yellow]SANITIZED BACKUP MODE:[/] Security-sensitive configuration "
        "will be removed before files are written."
    )
    return backup.main()


if __name__ == "__main__":
    raise SystemExit(main())