"""A minimal, read-only Aruba OS 8 Mobility Conductor REST client.

The conductor's REST API is used the same way the CLI is: log in, run ``show``
commands, log out. Only that is exposed here. Every failure is turned into an
:class:`~bunnyauto.errors.ArubaError` so the entry points render one line, never
a traceback.

Auth is the shared device login (``NORNIR_USERNAME`` / ``NORNIR_PASSWORD``). The
password is sent as POST form data — never in a URL or in argv — and the session
token (``UIDARUBA``) plus cookie are held on the :class:`requests.Session`.

TLS verification is **on by default** and independent of the Nornir config's
``ssl_verify``: the conductor is expected to present a valid certificate.
"""

from __future__ import annotations

from typing import Any

from bunnyauto.errors import ArubaError

_LOGIN = "/v1/api/login"
_LOGOUT = "/v1/api/logout"
_SHOWCOMMAND = "/v1/configuration/showcommand"


class ArubaConductorClient:
    """Read-only access to one Aruba Mobility Conductor (or Controller).

    Use as a context manager so logout always runs::

        with ArubaConductorClient(url, user, pw) as c:
            aps = c.ap_database()
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify: bool | str = True,
        timeout: float = 30.0,
    ) -> None:
        import requests  # deferred: keep bunnyauto import-light

        self._base = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._timeout = timeout
        self._token: str | None = None
        self._session = requests.Session()
        self._session.verify = verify

    # -- lifecycle ----------------------------------------------------------

    def __enter__(self) -> ArubaConductorClient:
        self.login()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def login(self) -> None:
        """Authenticate and capture the session token. Idempotent."""
        import requests

        if self._token:
            return
        url = f"{self._base}{_LOGIN}"
        try:
            resp = self._session.post(
                url,
                data={"username": self._username, "password": self._password},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise ArubaError(
                f"could not reach the Aruba Conductor at {self._base}: {exc}",
                fix="check the URL (include :4343 if that is the API port), the "
                "network path to it, and that the REST API is enabled",
            ) from exc

        if resp.status_code in (401, 403):
            raise ArubaError(
                f"the Conductor rejected the login for {self._username!r} "
                f"(HTTP {resp.status_code})",
                fix="confirm NORNIR_USERNAME / NORNIR_PASSWORD are valid on the Conductor "
                "and the account is allowed REST API access",
            )
        if resp.status_code != 200:
            raise ArubaError(f"the Conductor returned HTTP {resp.status_code} for the login")

        result = _global_result(resp, "login")
        token = str(result.get("UIDARUBA") or "").strip()
        if not token or str(result.get("status", "0")) not in ("0", "Success"):
            detail = result.get("status_str") or "no UIDARUBA in the response"
            raise ArubaError(
                f"the Conductor login did not succeed: {detail}",
                fix="confirm NORNIR_USERNAME / NORNIR_PASSWORD are valid on the Conductor",
            )
        self._token = token

    def close(self) -> None:
        """Log out (best effort) and drop the session."""
        if self._token:
            try:
                self._session.post(f"{self._base}{_LOGOUT}", timeout=self._timeout)
            except Exception:  # logout is best-effort cleanup
                pass
        self._token = None
        self._session.close()

    # -- public collections ----------------------------------------------

    def ap_database(self) -> list[dict[str, Any]]:
        """Rows from ``show ap database long`` (one per access point)."""
        return _rows(self.showcommand("show ap database long"))

    def switches(self) -> list[dict[str, Any]]:
        """Rows from ``show switches`` (the controllers the Conductor manages)."""
        return _rows(self.showcommand("show switches"))

    def showcommand(self, command: str) -> dict[str, Any]:
        """Run one ``show`` command and return the parsed JSON object."""
        import requests

        if not self._token:
            self.login()
        url = f"{self._base}{_SHOWCOMMAND}"
        try:
            resp = self._session.get(
                url,
                params={"command": command, "UIDARUBA": self._token},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise ArubaError(
                f"could not run {command!r} on the Conductor at {self._base}: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise ArubaError(
                f"the Conductor rejected the session while running {command!r} "
                f"(HTTP {resp.status_code})",
                fix="the session may have expired mid-run; try again",
            )
        if resp.status_code != 200:
            raise ArubaError(f"the Conductor returned HTTP {resp.status_code} for {command!r}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ArubaError(
                f"the Conductor response for {command!r} was not JSON "
                "(is the URL the API base and not the GUI?)"
            ) from exc
        if not isinstance(payload, dict):
            raise ArubaError(f"the Conductor response for {command!r} was not a JSON object")
        return payload


def _global_result(resp: Any, what: str) -> dict[str, Any]:
    try:
        payload = resp.json()
    except ValueError as exc:
        raise ArubaError(
            f"the Conductor {what} response was not JSON (is the URL the API base and not the GUI?)"
        ) from exc
    result = payload.get("_global_result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        raise ArubaError(f"the Conductor {what} response was not in the expected shape")
    return result


def _rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the first list-of-dicts value in a showcommand payload.

    AOS wraps table output under a key whose name varies by command and version
    (``"AP Database"``, ``"All Switches"``, ...). ``_meta`` (the column list) and
    scalar fields are skipped.
    """
    for key, value in payload.items():
        if key == "_meta":
            continue
        if isinstance(value, list) and value and all(isinstance(row, dict) for row in value):
            return value
    return []
