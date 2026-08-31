"""Redact secrets from a running configuration before it is written to disk.

Ported verbatim from ``perform_backup_safe.py`` — the rules and the fail-closed
re-check are unchanged. ``sanitize_running_config`` raises
:class:`SanitizationError` rather than write a config that still contains a
recognized secret, or one with an unterminated private-key block.
"""

from __future__ import annotations

import re

SANITIZED_HEADER = (
    "! SANITIZED BACKUP - NOT A COMPLETE RESTORE CONFIGURATION\n"
    "! Sensitive values were replaced before this file was written."
)
_SANITIZED_HEADER_LINES = frozenset(SANITIZED_HEADER.splitlines())

# A value can be a normal config token, a quoted value, or one of our existing
# placeholders. Treating placeholders as one value makes sanitation idempotent.
_VALUE = r'(?:<removed [^>\r\n]+>|"[^"\r\n]*"|\'[^\'\r\n]*\'|\S+)'


class SanitizationError(ValueError):
    """Raised when safe output cannot be guaranteed."""


_PRIVATE_KEY_START = re.compile(
    r"^-{4,5}BEGIN (?:SSH2 )?(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-{4,5}$",
    re.IGNORECASE,
)
_PRIVATE_KEY_END = re.compile(
    r"^-{4,5}END (?:SSH2 )?(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-{4,5}$",
    re.IGNORECASE,
)


def _value_pattern(prefix: str) -> re.Pattern[str]:
    """Compile a case-insensitive pattern with prefix and value groups."""
    return re.compile(rf"(?P<prefix>{prefix})(?P<value>{_VALUE})", re.IGNORECASE)


_IP_HTTP_USERNAME = _value_pattern(r"\bip\s+http\s+client\s+username\s+")
_IP_HTTP_PASSWORD = _value_pattern(r"\bip\s+http\s+client\s+password(?:\s+[056789])?\s+")
_USERNAME = _value_pattern(r"\b(?:username|user-name)\s+")
_LOGIN_USER = _value_pattern(r"\blogin\s+user\s+")

_ENABLE_SECRET = _value_pattern(r"^\s*enable\s+secret(?:\s+[056789])?\s+")
_ENABLE_PASSWORD = _value_pattern(r"^\s*enable\s+password(?:\s+[056789])?\s+")
_GENERIC_CREDENTIAL = _value_pattern(
    r"\b(?:password|passwd|secret|shared-secret|client-secret)(?:\s+[056789])?\s+"
)

_SNMP_COMMUNITY = _value_pattern(r"\bsnmp(?:-server)?\s+community\s+")
_SNMP_USER = _value_pattern(r"\bsnmp(?:-server)?\s+user\s+")
_SNMP_AUTH = _value_pattern(r"\bauth\s+(?:md5|sha(?:-\d+)?)(?:\s+[056789])?\s+")
_SNMP_PRIV = _value_pattern(r"\bpriv\s+(?:des|3des|aes(?:\s+\d+)?)(?:\s+[056789])?\s+")

_SERVER_KEY = _value_pattern(r"\bserver-key(?:\s+[056789])?\s+")
_KEY_STRING = _value_pattern(r"\bkey-string(?:\s+[056789])?\s+")
_PRE_SHARED_KEY = _value_pattern(r"\bpre-shared-key(?:\s+[056789])?\s+")
_RADIUS_TACACS_KEY = _value_pattern(r"\b(?:radius-server|tacacs-server)\s+key(?:\s+[056789])?\s+")
_TYPED_KEY = _value_pattern(r"(?<![-\w])key\s+[056789]\s+")
_ISAKMP_KEY = _value_pattern(r"\bcrypto\s+isakmp\s+key\s+")
_OSPF_AUTH_KEY = _value_pattern(r"\bip\s+ospf\s+authentication-key(?:\s+[056789])?\s+")
_MESSAGE_DIGEST_KEY = _value_pattern(
    r"\bmessage-digest-key\s+\S+\s+(?:md5|sha(?:-\d+)?)(?:\s+[056789])?\s+"
)
_NTP_AUTH_KEY = _value_pattern(
    r"^\s*ntp\s+authentication-key\s+\S+\s+(?:md5|sha(?:-\d+)?)(?:\s+[056789])?\s+"
)
_WPA_PSK = _value_pattern(r"\b(?:wpa-psk|psk)(?:\s+[056789])?\s+")

_ACCESS_TOKEN = _value_pattern(
    r"\b(?:api[-_ ]?key|access[-_ ]?token|bearer[-_ ]?token)\b\s*(?:=|\s)\s*"
)
_URL_CREDENTIAL = re.compile(
    rf"(?P<prefix>://)(?P<username>{_VALUE}):(?P<password>{_VALUE})@",
    re.IGNORECASE,
)


def _is_removed(value: str) -> bool:
    return value.casefold().startswith("<removed ") and value.endswith(">")


def _replace_value(line: str, pattern: re.Pattern[str], marker: str) -> str:
    """Replace every unsanitized value matched by pattern."""

    def replace(match: re.Match[str]) -> str:
        if _is_removed(match.group("value")):
            return match.group(0)
        return match.group("prefix") + marker

    return pattern.sub(replace, line)


def _replace_url_credentials(line: str) -> str:
    """Remove usernames and passwords embedded in URLs."""

    def replace(match: re.Match[str]) -> str:
        username = match.group("username")
        password = match.group("password")
        if _is_removed(username) and _is_removed(password):
            return match.group(0)
        return "://<removed username>:<removed password>@"

    return _URL_CREDENTIAL.sub(replace, line)


def sanitize_config_line(line: str) -> str:
    """Replace recognized sensitive values while preserving command syntax."""
    cleaned = _replace_url_credentials(line)

    # Account identifiers.
    cleaned = _replace_value(cleaned, _IP_HTTP_USERNAME, "<removed IP HTTP client username>")
    cleaned = _replace_value(cleaned, _SNMP_USER, "<removed SNMP username>")
    cleaned = _replace_value(cleaned, _USERNAME, "<removed username>")
    cleaned = _replace_value(cleaned, _LOGIN_USER, "<removed username>")

    # Passwords and enable secrets. Run special cases before the generic rule.
    cleaned = _replace_value(cleaned, _IP_HTTP_PASSWORD, "<removed IP HTTP client password>")
    cleaned = _replace_value(cleaned, _ENABLE_SECRET, "<removed enable secret>")
    cleaned = _replace_value(cleaned, _ENABLE_PASSWORD, "<removed enable password>")
    cleaned = _replace_value(cleaned, _GENERIC_CREDENTIAL, "<removed password>")

    # SNMP names and authentication material.
    cleaned = _replace_value(cleaned, _SNMP_COMMUNITY, "<removed SNMP community>")
    if re.search(r"\bsnmp(?:-server)?\b", cleaned, re.IGNORECASE):
        cleaned = _replace_value(cleaned, _SNMP_AUTH, "<removed SNMP auth key>")
        cleaned = _replace_value(cleaned, _SNMP_PRIV, "<removed SNMP privacy key>")

    # Shared keys used by AAA, routing, VPN, NTP, and wireless features.
    cleaned = _replace_value(cleaned, _SERVER_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _KEY_STRING, "<removed key string>")
    cleaned = _replace_value(cleaned, _PRE_SHARED_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _RADIUS_TACACS_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _ISAKMP_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _OSPF_AUTH_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _MESSAGE_DIGEST_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _NTP_AUTH_KEY, "<removed key>")
    cleaned = _replace_value(cleaned, _WPA_PSK, "<removed key>")
    cleaned = _replace_value(cleaned, _TYPED_KEY, "<removed key>")

    cleaned = _replace_value(cleaned, _ACCESS_TOKEN, "<removed token>")
    return cleaned


def sanitize_running_config(running_config: str) -> str:
    """Return a readable configuration with sensitive values replaced inline."""
    if not running_config.strip():
        raise SanitizationError("Cannot sanitize an empty running configuration.")

    sanitized: list[str] = []
    private_key_block = False

    for original_line in running_config.splitlines():
        stripped = original_line.strip()

        if original_line in _SANITIZED_HEADER_LINES:
            continue

        if private_key_block:
            if _PRIVATE_KEY_END.match(stripped):
                private_key_block = False
            continue

        if _PRIVATE_KEY_START.match(stripped):
            sanitized.append("! <removed private key block>")
            private_key_block = True
            continue

        sanitized.append(sanitize_config_line(original_line.rstrip()))

    if private_key_block:
        raise SanitizationError(
            "An unterminated private-key block was found; no configuration was written."
        )

    # Fail closed if another sanitation pass would change anything. This keeps
    # recognized raw values from reaching disk if a replacement rule regresses.
    remaining = [
        line_number
        for line_number, line in enumerate(sanitized, start=1)
        if sanitize_config_line(line) != line
    ]
    if remaining:
        locations = ", ".join(str(line_number) for line_number in remaining[:10])
        raise SanitizationError(
            "Recognized sensitive values remain after sanitation at output line(s) "
            f"{locations}; no configuration was written."
        )

    return SANITIZED_HEADER + "\n" + "\n".join(sanitized).rstrip() + "\n"
