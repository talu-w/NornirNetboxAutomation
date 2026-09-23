"""The per-invocation ``Context`` and the ``build_context`` that assembles it.

Both entry points do the same thing: resolve the environment, run preflight,
fold in any overrides, and hand every tool one ``Context``. Nornir, the direct
NetBox client, the role tree and the resolved :class:`~bunnyauto.scope.Scope`
are all built lazily and cached, so the hub can render menus without touching
NetBox until a tool actually runs.

Tools get their devices from here, never by building their own queries:
:meth:`Context.target_hosts` (the Nornir inventory, for SSH tools) and
:meth:`Context.target_devices` (NetBox records, for NetBox-first tools) both
apply the same tag + role branch + region/site scope.
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
    filter_by_tag,
    load_raw_inventory_options,
    ssl_verify_setting,
)
from bunnyauto.environments import Environment, resolve_environment
from bunnyauto.errors import NetBoxError, RoleScopeError, TagMismatchError
from bunnyauto.netbox.roles import RoleTree
from bunnyauto.preflight import preflight
from bunnyauto.scope import Scope, resolve_scope

if TYPE_CHECKING:
    from nornir.core import Nornir

    from bunnyauto.categories import Category
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
    region: str | None = None
    site: str | None = None
    #: The running tool's category key (``"wired"``, ...), if it has one.
    category: str | None = None
    #: That category's role-branch root slug, from the environment's ``roles``;
    #: ``None`` when the tool isn't confined to a role branch.
    branch_role: str | None = None
    #: ``--role``: a narrower role inside the branch (validated by ``Context.scope``).
    role: str | None = None
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
    _roles: RoleTree | None = None
    _scope: Scope | None = None

    def nornir(self) -> Nornir:
        """The NetBox-backed inventory for this run's role branch + region/site.

        Built once, reused. Not yet filtered by tag — see :meth:`target_hosts`.
        """
        if self._nr is None:
            filters = self.scope().location_filters()
            with self.reporter.spinner("querying NetBox inventory..."):
                self._nr = build_nornir(self.settings, self.creds, filters=filters)
        return self._nr

    def target_hosts(self) -> Nornir:
        """The Nornir hosts this run may touch: :meth:`nornir` narrowed to the tag."""
        return filter_by_tag(self.nornir(), self.settings.target_tag)

    def target_devices(self) -> list[Any]:
        """The NetBox devices this run may touch: tag + role branch + region/site."""
        return list(self.netbox().dcim.devices.filter(**self.scope().device_filters()))

    def role_tree(self) -> RoleTree:
        """NetBox's device-role hierarchy. Fetched once, reused."""
        if self._roles is None:
            self._roles = RoleTree.load(self.netbox())
        return self._roles

    def scope(self) -> Scope:
        """This run's validated tag + role + region/site narrowing (see :mod:`bunnyauto.scope`)."""
        if self._scope is None:
            self._scope = resolve_scope(self.settings, self.role_tree)
        return self._scope

    def banner(self) -> None:
        """The environment header both entry points show before a tool runs."""
        settings = self.settings
        self.reporter.banner(
            self.environment,
            settings.target_tag,
            role=settings.role or settings.branch_role,
            region=settings.region,
            site=settings.site,
        )

    def netbox(self) -> Any:
        """Direct NetBox API client (object reads/writes, role tree, scope checks)."""
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
    region: str | None = None,
    site: str | None = None,
    apply: bool = False,
    assume_yes: bool = False,
    legacy_ssh: bool = False,
    output_dir: str | os.PathLike[str] = ".",
    timeouts: Mapping[str, float] | None = None,
    need_devices: bool = True,
    need_netbox: bool = True,
    category: Category | None = None,
    role: str | None = None,
) -> Context:
    """Resolve the environment, run preflight, and return a ready ``Context``.

    ``creds`` may be passed in when the caller (the hub) already ran preflight;
    otherwise it is run here. ``need_devices`` / ``need_netbox`` let a tool that
    uses neither (a firewall-only query) run without those variables set.

    ``category`` confines the run to that category's NetBox role branch (unless
    the tool doesn't use NetBox at all); ``role`` is ``--role``, a narrower role
    inside it. Neither touches NetBox here — :meth:`Context.scope` validates them
    against the role tree the first time a tool asks for devices.
    """
    environment = resolve_environment(env, env_file)

    # The cross-wiring guard runs before preflight: catching "wrong environment
    # for this tag" should not depend on credentials already being configured.
    tag_value = (tag or environment.default_tag).strip()
    if tag_value.casefold() != environment.default_tag.casefold() and not force_tag:
        raise TagMismatchError(tag_value, environment.name, environment.default_tag)

    if creds is None:
        creds = preflight(environment, need_devices=need_devices, need_netbox=need_netbox)

    # Silences requests/urllib3's InsecureRequestWarning for the whole process.
    # Every tool (NetBox via pynetbox, FortiGate, Aruba Conductor) funnels
    # through this one function, so this is the one place it needs to live.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config_path = Path(config_file).expanduser()
    raw_options = load_raw_inventory_options(config_path)
    ssl_verify = ssl_verify_setting(raw_options.get("ssl_verify", True))

    extra_timeouts = {
        key: float(value) for key, value in (timeouts or {}).items() if key in _TIMEOUT_FIELDS
    }
    branch_role = None
    if category is not None and category.branch is not None and need_netbox:
        branch_role = environment.roles.get(category.branch)
    role_value = (role or "").strip() or None
    if role_value and branch_role is None:
        raise RoleScopeError(
            f"--role {role_value!r} doesn't apply here: this tool isn't confined to a "
            "NetBox role branch",
            fix="drop --role",
        )

    settings = Settings(
        environment=environment.name,
        nb_url=environment.nb_url,
        config_file=config_path,
        target_tag=tag_value,
        region=(region or "").strip() or None,
        site=(site or "").strip() or None,
        category=category.key if category is not None else None,
        branch_role=branch_role,
        role=role_value,
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
