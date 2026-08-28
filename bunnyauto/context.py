"""The per-invocation ``Context`` and the ``build_context`` that assembles it.

Both entry points do the same thing: resolve the environment, run preflight,
fold in any overrides, and hand every tool one ``Context``. Nornir and the
direct NetBox client are built lazily and cached, so the hub can render menus
without an inventory pull until a tool actually runs.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from bunnyauto.common import (
    build_netbox,
    build_nornir,
    load_raw_inventory_options,
    ssl_verify_setting,
)
from bunnyauto.environments import Environment, resolve_environment
from bunnyauto.errors import NetBoxError, TagMismatchError
from bunnyauto.preflight import preflight

if TYPE_CHECKING:
    from nornir.core import Nornir

    from bunnyauto.reporting import Reporter

DEFAULT_CONFIG_FILE = "config.yaml"

_TIMEOUT_FIELDS = {
    "connect_timeout",
    "auth_timeout",
    "banner_timeout",
    "read_timeout",
    "delay_factor",
}


@dataclass(slots=True)
class Settings:
    """Everything a run needs that isn't a credential or a live client."""

    environment: str
    nb_url: str
    config_file: Path
    target_tag: str
    protected: bool = False
    ssl_verify: bool | str = True
    legacy_ssh: bool = False
    apply: bool = False
    assume_yes: bool = False
    force_tag: bool = False
    output_dir: Path = field(default_factory=lambda: Path("."))
    connect_timeout: float = 60.0
    auth_timeout: float = 120.0
    banner_timeout: float = 120.0
    read_timeout: float = 180.0
    delay_factor: float = 2.0


@dataclass(slots=True)
class Credentials:
    """The device login plus the selected environment's NetBox token."""

    username: str
    password: str
    nb_token: str


@dataclass(slots=True)
class Context:
    settings: Settings
    creds: Credentials
    reporter: Reporter
    environment: Environment
    _nr: Nornir | None = None
    _nb: Any = None

    def nornir(self) -> Nornir:
        """The NetBox-backed inventory for this environment. Built once, reused."""
        if self._nr is None:
            self._nr = build_nornir(self.settings, self.creds)
        return self._nr

    def netbox(self) -> Any:
        """Direct NetBox API client for tools that write objects (not inventory)."""
        if self._nb is None:
            if not self.creds.nb_token:  # pragma: no cover - preflight already guards
                raise NetBoxError(
                    f"{self.environment.token_env} is not set",
                    fix=f"export {self.environment.token_env}='<token>'",
                )
            self._nb = build_netbox(self.settings, self.creds.nb_token)
        return self._nb

    def close(self) -> None:
        """Release any open connections. Safe to call more than once."""
        if self._nr is not None:
            try:
                self._nr.close_connections()
            except Exception:  # best-effort cleanup
                pass
        if self._nb is not None:
            session = getattr(self._nb, "http_session", None)
            if session is not None:
                session.close()
        self._nr = None
        self._nb = None


def build_context(
    *,
    env: str,
    reporter: Reporter,
    creds: Credentials | None = None,
    config_file: str | os.PathLike[str] = DEFAULT_CONFIG_FILE,
    env_file: str | os.PathLike[str] | None = None,
    tag: str | None = None,
    force_tag: bool = False,
    apply: bool = False,
    assume_yes: bool = False,
    legacy_ssh: bool = False,
    output_dir: str | os.PathLike[str] = ".",
    timeouts: Mapping[str, float] | None = None,
) -> Context:
    """Resolve the environment, run preflight, and return a ready ``Context``.

    ``creds`` may be passed in when the caller (the hub) already ran preflight;
    otherwise it is run here.
    """
    environment = resolve_environment(env, env_file)

    # The cross-wiring guard runs before preflight: catching "wrong environment
    # for this tag" should not depend on credentials already being configured.
    tag_value = (tag or environment.default_tag).strip()
    if tag_value.casefold() != environment.default_tag.casefold() and not force_tag:
        raise TagMismatchError(tag_value, environment.name, environment.default_tag)

    if creds is None:
        creds = preflight(environment)

    config_path = Path(config_file).expanduser()
    raw_options = load_raw_inventory_options(config_path)
    ssl_verify = ssl_verify_setting(raw_options.get("ssl_verify", True))

    extra_timeouts = {
        key: float(value) for key, value in (timeouts or {}).items() if key in _TIMEOUT_FIELDS
    }
    settings = Settings(
        environment=environment.name,
        nb_url=environment.nb_url,
        config_file=config_path,
        target_tag=tag_value,
        protected=environment.protected,
        ssl_verify=ssl_verify,
        legacy_ssh=legacy_ssh,
        apply=apply,
        assume_yes=assume_yes,
        force_tag=force_tag,
        output_dir=Path(output_dir).expanduser(),
        **extra_timeouts,
    )
    return Context(
        settings=settings,
        creds=creds,
        reporter=reporter,
        environment=environment,
    )
