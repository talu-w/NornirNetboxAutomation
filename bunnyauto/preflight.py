"""Credential and token checks — the first thing an entry point runs.

The goal is that a missing or half-configured credential produces one clear
sentence (and the export line to fix it), never a traceback and never a failure
part-way through a device connection.

* ``NORNIR_USERNAME`` / ``NORNIR_PASSWORD`` — the device login, shared by both
  environments (one AAA realm). Both or neither.
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


def preflight_device_credentials() -> tuple[str, str]:
    """Return ``(username, password)`` or raise :class:`EnvVarError`."""
    username = os.getenv(USERNAME_VAR, "").strip()
    password = os.getenv(PASSWORD_VAR, "").strip()

    if bool(username) != bool(password):
        raise EnvVarError(
            f"set both {USERNAME_VAR} and {PASSWORD_VAR}, or neither — only one is currently set",
            fix=f"export {USERNAME_VAR}='<user>' {PASSWORD_VAR}='<password>'",
        )
    if not username:
        raise EnvVarError(
            f"{USERNAME_VAR} and {PASSWORD_VAR} are not set — needed to log in to devices",
            fix=f"export {USERNAME_VAR}='<user>' {PASSWORD_VAR}='<password>'",
        )
    return username, password


def preflight(environment: Environment) -> Credentials:
    """Full check for a run against ``environment``; returns ready-to-use creds."""
    from bunnyauto.context import Credentials

    username, password = preflight_device_credentials()

    token = environment.token
    if not token:
        raise EnvVarError(
            f"{environment.token_env} is not set — needed to read the "
            f"{environment.name} NetBox inventory ({environment.nb_url})",
            fix=f"export {environment.token_env}='<your NetBox API token>'",
        )

    return Credentials(username=username, password=password, nb_token=token)
