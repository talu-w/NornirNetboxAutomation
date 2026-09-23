"""Load ``bunnyauto.yaml`` and resolve the environment a run targets.

An *environment* bundles the three things the "which network" choice has to
drive together: the NetBox URL, the name of the env var holding that instance's
API token, and the default NetBox tag. ``test`` and ``prod`` are separate NetBox
instances; picking one here is what keeps a run pointed at a single network.

The file is deliberately small and hand-editable::

    environments:
      test:
        nb_url: https://netbox-lab.example.com
        default_tag: nornirtest
        token_env: BUNNYAUTO_TEST_NB_TOKEN
      prod:
        nb_url: https://netbox.example.com
        default_tag: networking-active
        token_env: BUNNYAUTO_PROD_NB_TOKEN
        protected: true

An optional ``roles:`` mapping (top-level, and/or inside one environment to
override it there) points bunnyauto at your NetBox device-role slugs when they
differ from :data:`bunnyauto.categories.DEFAULT_ROLES`; see
:mod:`bunnyauto.categories` for what each key means.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bunnyauto.categories import DEFAULT_ROLES
from bunnyauto.errors import ConfigError, UnknownEnvironmentError

DEFAULT_ENV_FILE = "bunnyauto.yaml"
ENV_FILE_VAR = "BUNNYAUTO_ENV_FILE"

_ALLOWED_KEYS = {
    "nb_url",
    "default_tag",
    "token_env",
    "protected",
    "fw_url",
    "fw_token_env",
    "aruba_url",
    "device_username_env",
    "device_password_env",
    "roles",
}


@dataclass(slots=True, frozen=True)
class Environment:
    """One resolved target network."""

    name: str
    nb_url: str
    default_tag: str
    token_env: str
    protected: bool = False
    #: Base URL of this network's firewall (FortiGate REST API), if it has one.
    fw_url: str | None = None
    #: Name of the env var holding that firewall's API token.
    fw_token_env: str | None = None
    #: Base URL of this network's Aruba Mobility Conductor REST API, if it has one.
    #: Auth is the shared device login (NORNIR_USERNAME / NORNIR_PASSWORD), so
    #: there is no separate token-env key.
    aruba_url: str | None = None
    #: Names of the env vars holding this environment's device login, when it
    #: has its own realm distinct from the shared NORNIR_USERNAME/PASSWORD
    #: (e.g. a Cisco DevNet sandbox with its own fixed creds). Unset means
    #: "use the shared vars" — the common case for test/prod, one AAA realm.
    device_username_env: str | None = None
    device_password_env: str | None = None
    #: NetBox device-role slugs by :data:`~bunnyauto.categories.DEFAULT_ROLES`
    #: key — the defaults, overlaid with the file's ``roles:`` (top-level, then
    #: this environment's own).
    roles: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_ROLES), hash=False)

    @property
    def token(self) -> str | None:
        """The API token for this environment, read from its own env var."""
        value = os.getenv(self.token_env, "").strip()
        return value or None

    @property
    def fw_token(self) -> str | None:
        """The firewall API token for this environment, read from its own env var."""
        if not self.fw_token_env:
            return None
        value = os.getenv(self.fw_token_env, "").strip()
        return value or None


def environment_file_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Resolve which overlay file to read: ``--env-file`` > env var > default."""
    candidate = explicit or os.getenv(ENV_FILE_VAR) or DEFAULT_ENV_FILE
    return Path(candidate).expanduser()


def load_environments(
    path: str | os.PathLike[str] | None = None,
) -> dict[str, Environment]:
    """Parse the overlay file into ``{name: Environment}``.

    Raises :class:`ConfigError` if the file is missing, unparseable, or shaped
    wrong. Every environment is validated so a typo surfaces here rather than as
    a confusing NetBox error later.
    """
    file_path = environment_file_path(path)
    if not file_path.is_file():
        raise ConfigError(
            f"environment file not found: {file_path}",
            fix=f"copy bunnyauto.example.yaml to {file_path.name} and fill in your URLs",
        )

    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse {file_path}: {exc}") from exc

    if not isinstance(raw, Mapping) or "environments" not in raw:
        raise ConfigError(f"{file_path} must contain a top-level 'environments:' mapping")

    section = raw["environments"]
    if not isinstance(section, Mapping) or not section:
        raise ConfigError(f"{file_path}: 'environments:' must define at least one entry")

    shared_roles = _parse_roles(raw.get("roles"), file_path, where="top-level")

    environments: dict[str, Environment] = {}
    for name, body in section.items():
        environments[str(name)] = _build_environment(str(name), body, file_path, shared_roles)
    return environments


def resolve_environment(
    name: str,
    path: str | os.PathLike[str] | None = None,
) -> Environment:
    """Return the named environment, or raise :class:`UnknownEnvironmentError`."""
    environments = load_environments(path)
    try:
        return environments[name]
    except KeyError:
        raise UnknownEnvironmentError(name, environments) from None


def _parse_roles(value: Any, file_path: Path, *, where: str) -> dict[str, str]:
    """Validate a ``roles:`` mapping: known keys only, each a non-empty slug."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{file_path}: {where} 'roles:' must be a mapping of key: slug")
    unknown = sorted(str(key) for key in value if str(key) not in DEFAULT_ROLES)
    if unknown:
        raise ConfigError(
            f"{file_path}: {where} 'roles:' has unknown key(s): {', '.join(unknown)}",
            fix=f"use only: {', '.join(DEFAULT_ROLES)}",
        )
    roles: dict[str, str] = {}
    for key, slug in value.items():
        text = str(slug or "").strip()
        if not text:
            raise ConfigError(f"{file_path}: {where} 'roles:' {key!r} needs a role slug")
        roles[str(key)] = text
    return roles


def _build_environment(
    name: str,
    body: Any,
    file_path: Path,
    shared_roles: Mapping[str, str] | None = None,
) -> Environment:
    if not isinstance(body, Mapping):
        raise ConfigError(f"{file_path}: environment {name!r} must be a mapping")

    unknown = set(body) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(
            f"{file_path}: environment {name!r} has unknown key(s): {', '.join(sorted(unknown))}"
        )

    nb_url = str(body.get("nb_url") or "").strip().rstrip("/")
    if not nb_url.startswith(("http://", "https://")):
        raise ConfigError(
            f"{file_path}: environment {name!r} nb_url must start with http:// or https://"
        )

    default_tag = str(body.get("default_tag") or "").strip()
    if not default_tag:
        raise ConfigError(f"{file_path}: environment {name!r} is missing 'default_tag'")

    token_env = str(body.get("token_env") or "").strip()
    if not token_env:
        raise ConfigError(
            f"{file_path}: environment {name!r} is missing 'token_env' "
            f"(the name of the env var holding this instance's NetBox token)"
        )

    fw_url = str(body.get("fw_url") or "").strip().rstrip("/") or None
    if fw_url and not fw_url.startswith(("http://", "https://")):
        raise ConfigError(
            f"{file_path}: environment {name!r} fw_url must start with http:// or https://"
        )
    fw_token_env = str(body.get("fw_token_env") or "").strip() or None
    if fw_url and not fw_token_env:
        raise ConfigError(
            f"{file_path}: environment {name!r} sets 'fw_url' but is missing 'fw_token_env' "
            f"(the name of the env var holding that firewall's API token)"
        )

    aruba_url = str(body.get("aruba_url") or "").strip().rstrip("/") or None
    if aruba_url and not aruba_url.startswith(("http://", "https://")):
        raise ConfigError(
            f"{file_path}: environment {name!r} aruba_url must start with http:// or https://"
        )

    device_username_env = str(body.get("device_username_env") or "").strip() or None
    device_password_env = str(body.get("device_password_env") or "").strip() or None
    if bool(device_username_env) != bool(device_password_env):
        raise ConfigError(
            f"{file_path}: environment {name!r} sets one of 'device_username_env' / "
            f"'device_password_env' but not the other — set both, or neither to use "
            f"the shared NORNIR_USERNAME/NORNIR_PASSWORD"
        )

    roles = {
        **DEFAULT_ROLES,
        **(shared_roles or {}),
        **_parse_roles(body.get("roles"), file_path, where=f"environment {name!r}"),
    }

    return Environment(
        name=name,
        nb_url=nb_url,
        default_tag=default_tag,
        token_env=token_env,
        protected=bool(body.get("protected", False)),
        fw_url=fw_url,
        fw_token_env=fw_token_env,
        aruba_url=aruba_url,
        device_username_env=device_username_env,
        device_password_env=device_password_env,
        roles=roles,
    )
