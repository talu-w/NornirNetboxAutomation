"""The preamble every current script re-implements, in one place.

``build_nornir()`` is the single home for: loading the NetBox-backed inventory,
pointing it at the selected environment, applying credentials, normalizing NetBox
tags onto each host, and attaching Netmiko connection options (including the
legacy-SSH profile for older gear). The rest are the small shared helpers those
steps need.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nornir import InitNornir
from nornir.core.configuration import Config
from nornir.core.filter import F
from nornir.core.inventory import ConnectionOptions

from bunnyauto.errors import ConfigError, InventoryError, NetBoxError

if TYPE_CHECKING:
    from nornir.core import Nornir

    from bunnyauto.context import Credentials, Settings

# NetBox tags (either spelling) that opt a single host into the legacy profile,
# regardless of the global --legacy-ssh flag.
LEGACY_SSH_TAGS = frozenset({"ssh-legacy", "legacy-ssh"})

# Extra Netmiko/Paramiko settings for SSH servers that advertise an RSA host key
# but cannot process rsa-sha2-256/512 signatures. Consolidated from send_command.py.
LEGACY_NETMIKO_EXTRAS: dict[str, Any] = {
    "disable_sha2_fix": True,
    "disabled_algorithms": {
        "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"],
        "keys": ["rsa-sha2-256", "rsa-sha2-512"],
        "kex": [
            "curve25519-sha256@libssh.org",
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
        ],
    },
}


# ---------------------------------------------------------------------------
# argparse helpers (shared by the CLI parent parser, added in step 2)
# ---------------------------------------------------------------------------


def positive_float(value: str) -> float:
    """argparse ``type=`` for a strictly-positive number."""
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean-ish environment variable (``1/true/yes/on``)."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# NetBox tags
# ---------------------------------------------------------------------------


def normalize_tags(tags: Sequence[Any] | None) -> list[str]:
    """Casefold NetBox tag strings, dicts, or objects to a sorted slug list.

    NetBox tags arrive as plain strings, ``{"slug": ..., "name": ...}`` dicts, or
    pynetbox record objects depending on the inventory source; this flattens all
    three so downstream code only ever deals with lowercase slugs.
    """
    normalized: set[str] = set()
    for tag in tags or []:
        if isinstance(tag, str):
            candidates: list[Any] = [tag]
        elif isinstance(tag, Mapping):
            candidates = [tag.get("slug"), tag.get("name")]
        else:
            candidates = [getattr(tag, "slug", None), getattr(tag, "name", None)]
        for candidate in candidates:
            if candidate:
                normalized.add(str(candidate).casefold())
    return sorted(normalized)


# ---------------------------------------------------------------------------
# Netmiko connection options
# ---------------------------------------------------------------------------


def build_netmiko_extras(settings: Settings, *, legacy: bool) -> dict[str, Any]:
    """Netmiko ``extras`` for one host, with the legacy profile folded in on request."""
    extras: dict[str, Any] = {
        "conn_timeout": settings.connect_timeout,
        "banner_timeout": settings.banner_timeout,
        "auth_timeout": settings.auth_timeout,
        "read_timeout_override": settings.read_timeout,
        "global_delay_factor": settings.delay_factor,
        "fast_cli": False,
    }
    if legacy:
        extras.update(LEGACY_NETMIKO_EXTRAS)
    return extras


def _apply_netmiko_extras(host: Any, extras: Mapping[str, Any]) -> None:
    existing = host.connection_options.get("netmiko")
    if existing is None:
        host.connection_options["netmiko"] = ConnectionOptions(extras=dict(extras))
        return
    merged = dict(existing.extras or {})
    merged.update(extras)
    existing.extras = merged


# ---------------------------------------------------------------------------
# Nornir + NetBox bootstrap
# ---------------------------------------------------------------------------


def load_raw_inventory_options(config_file: str | os.PathLike[str]) -> dict[str, Any]:
    """Return ``inventory.options`` from the Nornir config, unmodified."""
    path = Path(config_file).expanduser()
    try:
        return dict(Config.from_file(str(path)).inventory.options)
    except FileNotFoundError as exc:
        raise ConfigError(
            f"Nornir config not found: {path}",
            fix="copy config.example.yaml to config.yaml",
        ) from exc
    except Exception as exc:  # nornir raises assorted types for a bad config
        raise ConfigError(f"could not load Nornir config {path}: {exc}") from exc


def ssl_verify_setting(value: Any) -> bool | str:
    """Normalize a YAML/string ``ssl_verify`` value for a Requests session."""
    if not isinstance(value, str):
        return bool(value)
    normalized = value.strip().casefold()
    if normalized in {"false", "no", "0", "off"}:
        return False
    if normalized in {"true", "yes", "1", "on"}:
        return True
    return value  # treat anything else as a CA bundle path


def build_nornir(settings: Settings, creds: Credentials) -> Nornir:
    """Initialize the NetBox inventory for ``settings.environment`` and prime hosts.

    The environment's ``nb_url`` and token override whatever the Nornir config
    carries, so one ``config.yaml`` serves both test and prod.
    """
    options = load_raw_inventory_options(settings.config_file)
    options["nb_url"] = settings.nb_url
    options["nb_token"] = creds.nb_token

    try:
        nr = InitNornir(
            config_file=str(settings.config_file),
            inventory={"options": options},
        )
    except Exception as exc:
        raise InventoryError(
            f"could not initialize the NetBox inventory for {settings.environment!r}: {exc}",
            fix="check the environment's nb_url, the API token, and NetBox reachability",
        ) from exc

    nr.inventory.defaults.username = creds.username
    nr.inventory.defaults.password = creds.password

    default_extras = build_netmiko_extras(settings, legacy=False)
    legacy_extras = build_netmiko_extras(settings, legacy=True)
    for host in nr.inventory.hosts.values():
        slugs = normalize_tags(host.data.get("tags", []))
        host.data["tag_slugs"] = slugs
        is_legacy = settings.legacy_ssh or bool(LEGACY_SSH_TAGS.intersection(slugs))
        host.data["ssh_profile"] = "legacy" if is_legacy else "default"
        _apply_netmiko_extras(host, legacy_extras if is_legacy else default_extras)

    if not nr.inventory.hosts:
        raise InventoryError(
            f"the {settings.environment!r} NetBox returned no devices",
            fix="confirm devices exist in that NetBox and the API token can read them",
        )
    return nr


def filter_by_tag(nr: Nornir, tag: str) -> Nornir:
    """Return the sub-inventory whose hosts carry ``tag`` (case-insensitive)."""
    slug = tag.strip().casefold()
    return nr.filter(F(tag_slugs__contains=slug))


def build_netbox(settings: Settings, token: str) -> Any:
    """Create a direct pynetbox client for tools that write NetBox objects."""
    try:
        import pynetbox
    except ImportError as exc:  # pragma: no cover - pynetbox is a declared dep
        raise NetBoxError(
            "pynetbox is required for tools that write to NetBox",
            fix="pip install pynetbox",
        ) from exc

    nb = pynetbox.api(settings.nb_url, token=token)
    nb.http_session.verify = ssl_verify_setting(settings.ssl_verify)
    return nb
