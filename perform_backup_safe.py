#!/usr/bin/env python3

"""Create standalone sanitized Nornir/NetBox configuration backups.

Sensitive values are replaced inline so the resulting configuration retains
its useful structure. For example, ``enable secret 9 HASH`` becomes
``enable secret 9 <removed enable secret>``. The safe backup is intentionally
not suitable as a complete restore configuration.
"""

from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


# Universal NetBox tag used to select devices for sanitized backups.
# Change the default here or override it at runtime with NORNIR_TARGET_TAG.
DEFAULT_TARGET_TAG = "nornirtest"
NORNIR_TARGET_TAG = os.getenv("NORNIR_TARGET_TAG", DEFAULT_TARGET_TAG)

DEFAULT_SAFE_BACKUP_ROOT = "./config_backups_safe"
NORNIR_CONFIG_FILE = os.getenv("NORNIR_CONFIG_FILE", "config.yaml")
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

    return re.compile(
        rf"(?P<prefix>{prefix})(?P<value>{_VALUE})",
        re.IGNORECASE,
    )


_IP_HTTP_USERNAME = _value_pattern(r"\bip\s+http\s+client\s+username\s+")
_IP_HTTP_PASSWORD = _value_pattern(
    r"\bip\s+http\s+client\s+password(?:\s+[056789])?\s+"
)
_USERNAME = _value_pattern(r"\b(?:username|user-name)\s+")
_LOGIN_USER = _value_pattern(r"\blogin\s+user\s+")

_ENABLE_SECRET = _value_pattern(r"^\s*enable\s+secret(?:\s+[056789])?\s+")
_ENABLE_PASSWORD = _value_pattern(r"^\s*enable\s+password(?:\s+[056789])?\s+")
_GENERIC_CREDENTIAL = _value_pattern(
    r"\b(?:password|passwd|secret|shared-secret|client-secret)"
    r"(?:\s+[056789])?\s+"
)

_SNMP_COMMUNITY = _value_pattern(r"\bsnmp(?:-server)?\s+community\s+")
_SNMP_USER = _value_pattern(r"\bsnmp(?:-server)?\s+user\s+")
_SNMP_AUTH = _value_pattern(
    r"\bauth\s+(?:md5|sha(?:-\d+)?)(?:\s+[056789])?\s+"
)
_SNMP_PRIV = _value_pattern(
    r"\bpriv\s+(?:des|3des|aes(?:\s+\d+)?)(?:\s+[056789])?\s+"
)

_SERVER_KEY = _value_pattern(r"\bserver-key(?:\s+[056789])?\s+")
_KEY_STRING = _value_pattern(r"\bkey-string(?:\s+[056789])?\s+")
_PRE_SHARED_KEY = _value_pattern(r"\bpre-shared-key(?:\s+[056789])?\s+")
_RADIUS_TACACS_KEY = _value_pattern(
    r"\b(?:radius-server|tacacs-server)\s+key(?:\s+[056789])?\s+"
)
_TYPED_KEY = _value_pattern(r"(?<![-\w])key\s+[056789]\s+")
_ISAKMP_KEY = _value_pattern(r"\bcrypto\s+isakmp\s+key\s+")
_OSPF_AUTH_KEY = _value_pattern(
    r"\bip\s+ospf\s+authentication-key(?:\s+[056789])?\s+"
)
_MESSAGE_DIGEST_KEY = _value_pattern(
    r"\bmessage-digest-key\s+\S+\s+(?:md5|sha(?:-\d+)?)"
    r"(?:\s+[056789])?\s+"
)
_NTP_AUTH_KEY = _value_pattern(
    r"^\s*ntp\s+authentication-key\s+\S+\s+"
    r"(?:md5|sha(?:-\d+)?)(?:\s+[056789])?\s+"
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
    cleaned = _replace_value(
        cleaned,
        _IP_HTTP_USERNAME,
        "<removed IP HTTP client username>",
    )
    cleaned = _replace_value(cleaned, _SNMP_USER, "<removed SNMP username>")
    cleaned = _replace_value(cleaned, _USERNAME, "<removed username>")
    cleaned = _replace_value(cleaned, _LOGIN_USER, "<removed username>")

    # Passwords and enable secrets. Run special cases before the generic rule.
    cleaned = _replace_value(
        cleaned,
        _IP_HTTP_PASSWORD,
        "<removed IP HTTP client password>",
    )
    cleaned = _replace_value(
        cleaned,
        _ENABLE_SECRET,
        "<removed enable secret>",
    )
    cleaned = _replace_value(
        cleaned,
        _ENABLE_PASSWORD,
        "<removed enable password>",
    )
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


def normalize_tags(tags: list[Any]) -> list[str]:
    """Return lowercase NetBox tag names and slugs."""

    normalized: set[str] = set()
    for tag in tags:
        if isinstance(tag, str):
            values = (tag,)
        elif isinstance(tag, dict):
            values = (tag.get("slug"), tag.get("name"))
        else:
            values = (getattr(tag, "slug", None), getattr(tag, "name", None))

        for value in values:
            if value:
                normalized.add(str(value).casefold())

    return sorted(normalized)


def safe_host_component(hostname: str) -> str:
    """Return a hostname that cannot escape the backup directory."""

    component = re.sub(r"[^A-Za-z0-9._-]+", "_", hostname).strip("._")
    return component or "device"


def config_output_path(output_dir: Path, hostname: str) -> Path:
    """Return the sanitized configuration path for one device."""

    safe_hostname = safe_host_component(hostname)
    return output_dir / safe_hostname / f"{safe_hostname}.cfg"


def write_private_text(output_path: Path, content: str) -> None:
    """Atomically write a UTF-8 file restricted to its owner."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.",
        suffix=".tmp",
        dir=output_path.parent,
    )
    temporary_path = Path(temporary_name)

    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content.rstrip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, output_path)
        output_path.chmod(0o600)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
        raise


def collect_and_save_safe_config(task: Any, output_dir: Path) -> Any:
    """Collect, sanitize, and save one device's running configuration."""

    from nornir.core.task import Result
    from nornir_netmiko.tasks import netmiko_send_command

    try:
        command_results = task.run(
            name="Collect running configuration (contents omitted from logs)",
            task=netmiko_send_command,
            command_string="show running-config",
            read_timeout=120,
        )
    except Exception as exc:
        return Result(
            host=task.host,
            failed=True,
            exception=exc,
            result=f"Collection failed ({type(exc).__name__}); no file was written.",
        )

    command_result = command_results[-1]
    if command_result.failed:
        failure_exception = command_result.exception
        command_result.result = "Collection failed; device output omitted from logs."
        return Result(
            host=task.host,
            failed=True,
            exception=failure_exception,
            result="Running-configuration collection failed; no file was written.",
        )

    running_config = str(command_result.result)
    command_result.result = "Running configuration collected; contents omitted from logs."

    if not running_config.strip():
        return Result(
            host=task.host,
            failed=True,
            result="The device returned an empty configuration; no file was written.",
        )

    try:
        sanitized_config = sanitize_running_config(running_config)
    except SanitizationError as exc:
        return Result(
            host=task.host,
            failed=True,
            exception=exc,
            result=f"Sanitation failed: {exc}",
        )

    output_path = config_output_path(output_dir, task.host.name)
    try:
        write_private_text(output_path, sanitized_config)
    except OSError as exc:
        return Result(
            host=task.host,
            failed=True,
            exception=exc,
            result=f"Could not write the sanitized configuration ({type(exc).__name__}).",
        )

    return Result(
        host=task.host,
        changed=False,
        result=f"Saved sanitized configuration to {output_path.resolve()}",
    )


def main() -> int:
    """Run the standalone Nornir/NetBox safe-backup workflow."""

    try:
        from nornir import InitNornir
        from nornir.core.filter import F
        from nornir.core.inventory import ConnectionOptions
        from nornir_netmiko.tasks import netmiko_send_command  # noqa: F401
    except ImportError as exc:
        print(
            "ERROR: Missing backup dependency. Install nornir and "
            f"nornir-netmiko in this environment: {exc}"
        )
        return 1

    username = os.getenv("NORNIR_USERNAME")
    password = os.getenv("NORNIR_PASSWORD")
    if not username or not password:
        print("ERROR: NORNIR_USERNAME and NORNIR_PASSWORD must be set.")
        return 1

    try:
        nr = InitNornir(config_file=NORNIR_CONFIG_FILE)
    except Exception as exc:
        print(f"ERROR: Could not initialize Nornir/NetBox inventory: {exc}")
        return 1

    nr.inventory.defaults.username = username
    nr.inventory.defaults.password = password

    if not nr.inventory.hosts:
        print(
            "No devices were loaded. Check the NetBox inventory plugin, API URL, "
            "token, permissions, and Nornir configuration."
        )
        return 1

    connection_defaults = {
        "conn_timeout": 30,
        "banner_timeout": 60,
        "auth_timeout": 60,
        "fast_cli": False,
    }

    for host in nr.inventory.hosts.values():
        host.data["tag_slugs"] = normalize_tags(host.data.get("tags") or [])
        existing = host.connection_options.get("netmiko")
        extras = dict(connection_defaults)
        if existing and existing.extras:
            extras.update(existing.extras)

        host.connection_options["netmiko"] = ConnectionOptions(
            hostname=existing.hostname if existing else None,
            port=existing.port if existing else None,
            username=existing.username if existing else None,
            password=existing.password if existing else None,
            platform=existing.platform if existing else None,
            extras=extras,
        )

    targets = nr.filter(F(tag_slugs__contains=NORNIR_TARGET_TAG.casefold()))

    print("\n--- Safe backup filter results ---")
    print(f"Target tag: {NORNIR_TARGET_TAG!r}")
    print(f"Matched devices: {len(targets.inventory.hosts)}")
    for number, hostname in enumerate(targets.inventory.hosts, start=1):
        print(f"  {number:>3}. {hostname}")

    if not targets.inventory.hosts:
        print("No devices matched the configured NetBox tag.")
        return 0

    backup_time = datetime.now()
    backup_root = Path(
        os.getenv("NORNIR_SAFE_BACKUP_ROOT", DEFAULT_SAFE_BACKUP_ROOT)
    )
    output_dir = (
        backup_root
        / backup_time.strftime("%Y")
        / backup_time.strftime("%m")
        / backup_time.strftime("%d")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir.resolve()}")
    print("Collecting and sanitizing running configurations...")

    results = targets.run(
        name="Collect and save sanitized running configurations",
        task=collect_and_save_safe_config,
        output_dir=output_dir,
    )

    log_lines = [
        "Standalone sanitized Nornir backup",
        f"Time: {backup_time.isoformat()}",
        f"Target tag: {NORNIR_TARGET_TAG}",
        f"Output directory: {output_dir.resolve()}",
        "",
    ]

    print("\n--- Safe backup summary ---")
    for hostname in targets.inventory.hosts:
        if hostname in results.failed_hosts:
            status = f"FAILED {hostname} (no sanitized configuration written)"
        else:
            output_path = config_output_path(output_dir, hostname)
            status = f"SAVED  {hostname}: {output_path.resolve()}"
        print(status)
        log_lines.append(status)

    failed_count = len(results.failed_hosts)
    successful_count = len(targets.inventory.hosts) - failed_count
    completion = f"Completed: {successful_count} successful, {failed_count} failed"
    print(completion)
    log_lines.extend(("", completion))

    log_path = output_dir / f"nornir_safe_backup_{backup_time:%Y%m%d_%H%M%S}.log"
    try:
        write_private_text(log_path, "\n".join(log_lines))
    except OSError as exc:
        print(f"ERROR: Could not write the safe backup log ({type(exc).__name__}).")
        return 1

    print(f"Run log: {log_path.resolve()}")
    return 1 if failed_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
