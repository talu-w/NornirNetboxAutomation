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
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bunnyauto.errors import ConfigError, UnknownEnvironmentError

DEFAULT_ENV_FILE = "bunnyauto.yaml"
ENV_FILE_VAR = "BUNNYAUTO_ENV_FILE"

_ALLOWED_KEYS = {"nb_url", "default_tag", "token_env", "protected"}


@dataclass(slots=True, frozen=True)
class Environment:
    """One resolved target network."""

    name: str
    nb_url: str
    default_tag: str
    token_env: str
    protected: bool = False

    @property
    def token(self) -> str | None:
        """The API token for this environment, read from its own env var."""
        value = os.getenv(self.token_env, "").strip()
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

    environments: dict[str, Environment] = {}
    for name, body in section.items():
        environments[str(name)] = _build_environment(str(name), body, file_path)
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


def _build_environment(name: str, body: Any, file_path: Path) -> Environment:
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

    return Environment(
        name=name,
        nb_url=nb_url,
        default_tag=default_tag,
        token_env=token_env,
        protected=bool(body.get("protected", False)),
    )
