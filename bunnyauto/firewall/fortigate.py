"""A minimal, read-only FortiGate REST API client.

Only the CMDB collections the subnet-usage check needs are exposed: address
objects, address groups, and firewall policies (IPv4 + IPv6 in each case, and
both policy CMDB endpoints — see :meth:`FortiGateClient.policies`). Every
failure is turned into a :class:`~bunnyauto.errors.FirewallError` so the entry
points render one line, never a traceback.

Auth is a FortiOS REST API token sent as ``Authorization: Bearer <token>``.
The token never appears in a URL or in argv — the tool reads it from an
environment variable named in ``bunnyauto.yaml``.
"""

from __future__ import annotations

from typing import Any

from bunnyauto.errors import FirewallError

_CMDB = "/api/v2/cmdb/"


class FortiGateClient:
    """Read-only access to one FortiGate, scoped to a single VDOM."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        vdom: str = "root",
        verify: bool | str = True,
        timeout: float = 30.0,
    ) -> None:
        import requests  # deferred: keep bunnyauto import-light

        self._base = base_url.rstrip("/")
        self._vdom = vdom
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {token}"
        self._session.verify = verify

    # -- public collections ---------------------------------------------------

    def addresses(self) -> list[dict[str, Any]]:
        """IPv4 and IPv6 firewall address objects."""
        return self._get("firewall/address") + self._get("firewall/address6", optional=True)

    def address_groups(self) -> list[dict[str, Any]]:
        """IPv4 and IPv6 firewall address groups."""
        return self._get("firewall/addrgrp") + self._get("firewall/addrgrp6", optional=True)

    def policies(self) -> list[dict[str, Any]]:
        """IPv4/IPv6 firewall policies (``policyid``, ``srcaddr``, ``dstaddr``, …).

        A FortiGate runs in either *profile-based* NGFW mode (policies under
        ``firewall/policy`` — GUI: "Policy") or *policy-based* NGFW mode
        (``firewall/security-policy`` — GUI: "Security Policy", the factory
        default on some higher-end models, e.g. the 900G/901G series). Only one
        is ever populated on a given box, so both are queried and merged;
        ``firewall/security-policy`` is tolerant of a 404 for older firmware
        that predates the endpoint entirely. Each row is tagged with which
        endpoint it came from so :func:`bunnyauto.firewall.usage.analyze` can
        report it (``PolicyRef.source``).
        """
        policy = self._get("firewall/policy")
        for row in policy:
            row["_bunnyauto_policy_source"] = "policy"
        security_policy = self._get("firewall/security-policy", optional=True)
        for row in security_policy:
            row["_bunnyauto_policy_source"] = "security-policy"
        return policy + security_policy

    def interfaces(self) -> list[dict[str, Any]]:
        """Configured interfaces — IPv4 ``ip``/``secondaryip``, IPv6 under ``ipv6``.

        Used only for the interface-conflict note in ``fw-subnet-check``: is the
        queried subnet already assigned to a live interface, not just an address
        object.
        """
        return self._get("system/interface")

    def close(self) -> None:
        self._session.close()

    # -- internals ----------------------------------------------------------

    def _get(self, path: str, *, optional: bool = False) -> list[dict[str, Any]]:
        import requests

        url = f"{self._base}{_CMDB}{path}"
        try:
            resp = self._session.get(url, params={"vdom": self._vdom}, timeout=self._timeout)
        except requests.RequestException as exc:
            raise FirewallError(
                f"could not reach the firewall at {self._base}: {exc}",
                fix="check the URL, the network path to it, and that the REST API is enabled",
            ) from exc

        if resp.status_code in (401, 403):
            raise FirewallError(
                f"the firewall rejected the API token (HTTP {resp.status_code})",
                fix="confirm the token is valid and its admin profile grants read access to "
                f"the {self._vdom!r} VDOM",
            )
        if resp.status_code == 404 and optional:
            return []
        if resp.status_code != 200:
            raise FirewallError(f"the firewall returned HTTP {resp.status_code} for {path}")

        try:
            payload = resp.json()
        except ValueError as exc:
            raise FirewallError(
                f"the firewall response for {path} was not JSON "
                "(is the URL the API base and not the GUI?)"
            ) from exc

        results = payload.get("results", []) if isinstance(payload, dict) else []
        return [row for row in results if isinstance(row, dict)]
