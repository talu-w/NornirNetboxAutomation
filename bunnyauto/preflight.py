"""Credential and token checks — the first thing an entry point runs.

The goal is that a missing or half-configured credential produces one clear
sentence (and the export line to fix it), never a traceback and never a failure
part-way through a device connection.

* ``NORNIR_USERNAME`` / ``NORNIR_PASSWORD`` — the device login shared by most
  environments (one AAA realm), used when an environment doesn't declare its
  own ``device_username_env`` / ``device_password_env`` override (e.g. a
  DevNet sandbox with its own fixed, unrelated creds).
* the environment's own ``token_env`` — that NetBox instance's API token. It is
  always required: every run reads inventory from that environment's NetBox.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from bunnyauto.errors import EnvVarError

if TYPE_CHECKING:
    from bunnyauto.context import Credentials
    from bunnyauto.environments import Environment

USERNAME_VAR = "NORNIR_USERNAME"
PASSWORD_VAR = "NORNIR_PASSWORD"


def preflight_device_credentials(
    username_var: str = USERNAME_VAR, password_var: str = PASSWORD_VAR
) -> tuple[str, str]:
    """Return ``(username, password)`` read from ``username_var``/``password_var``.

    Defaults to the shared ``NORNIR_USERNAME``/``NORNIR_PASSWORD``; an
    environment with its own device-credential override passes its own var
    names instead. Raises :class:`EnvVarError` if not both set.
    """
    username = os.getenv(username_var, "").strip()
    password = os.getenv(password_var, "").strip()

    if bool(username) != bool(password):
        raise EnvVarError(
            f"set both {username_var} and {password_var}, or neither — only one is currently set",
            fix=f"export {username_var}='<user>' {password_var}='<password>'",
        )
    if not username:
        raise EnvVarError(
            f"{username_var} and {password_var} are not set — needed to log in to devices",
            fix=f"export {username_var}='<user>' {password_var}='<password>'",
        )
    return username, password


def preflight(
    environment: Environment,
    *,
    need_devices: bool = True,
    need_netbox: bool = True,
) -> Credentials:
    """Check for a run against ``environment``; returns ready-to-use creds.

    A tool that touches neither devices nor NetBox (for example a firewall-only
    query) passes ``need_devices=False`` / ``need_netbox=False`` so its run is
    not blocked by unrelated, unset variables. Any token that *is* set is still
    carried through.
    """
    from bunnyauto.context import Credentials

    username, password = ("", "")
    if need_devices:
        username, password = preflight_device_credentials(
            environment.device_username_env or USERNAME_VAR,
            environment.device_password_env or PASSWORD_VAR,
        )

    token = environment.token or ""
    if need_netbox and not token:
        raise EnvVarError(
            f"{environment.token_env} is not set — needed to read the "
            f"{environment.name} NetBox inventory ({environment.nb_url})",
            fix=f"export {environment.token_env}='<your NetBox API token>'",
        )

    return Credentials(username=username, password=password, nb_token=token)
