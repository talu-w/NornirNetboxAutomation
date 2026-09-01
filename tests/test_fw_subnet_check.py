"""Tests for the fw-subnet-check tool (fake FortiGate client, no HTTP)."""

from __future__ import annotations

import argparse

import pytest

from bunnyauto.environments import Environment
from bunnyauto.errors import FirewallError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools import fw_subnet_check
from bunnyauto.tools.fw_subnet_check import TOOL

NET_HQ = {"name": "net_hq", "type": "ipmask", "subnet": "10.1.0.0 255.255.0.0"}
VLAN2 = {"name": "vlan2", "type": "ipmask", "subnet": "10.1.2.0 255.255.255.0"}


def _environment(*, fw_url="https://fw.example.com", fw_token_env="FW_TOKEN") -> Environment:
    return Environment(
        name="prod",
        nb_url="https://nb.example.com",
        default_tag="networking-active",
        token_env="BUNNYAUTO_PROD_NB_TOKEN",
        protected=True,
        fw_url=fw_url,
        fw_token_env=fw_token_env,
    )


class _Ctx:
    def __init__(self, environment: Environment):
        self.environment = environment
        self.reporter = Reporter(json_mode=True)


def _args(subnet="10.1.2.0/24", **over) -> argparse.Namespace:
    base = dict(subnet=subnet, vdom="root", fw_url=None, fw_token_env=None, fw_insecure=False)
    base.update(over)
    return argparse.Namespace(**base)


def _fake_client(monkeypatch, *, addresses=(), groups=(), policies=(), boom=None):
    captured: dict = {}

    class FakeClient:
        def __init__(self, url, token, *, vdom="root", verify=True, timeout=30.0):
            captured.update(url=url, token=token, vdom=vdom, verify=verify)
            self.closed = False

        def addresses(self):
            if boom:
                raise boom
            return list(addresses)

        def address_groups(self):
            return list(groups)

        def policies(self):
            return list(policies)

        def close(self):
            self.closed = True
            captured["closed"] = True

    monkeypatch.setattr(fw_subnet_check, "FortiGateClient", FakeClient)
    return captured


# --- input / credential validation -----------------------------------


def test_bad_subnet_is_rejected(monkeypatch):
    _fake_client(monkeypatch)
    with pytest.raises(FirewallError, match="not a valid IP"):
        TOOL.run(_Ctx(_environment()), _args(subnet="not-an-ip"))


def test_missing_fw_url(monkeypatch):
    _fake_client(monkeypatch)
    with pytest.raises(FirewallError, match="no firewall URL"):
        TOOL.run(_Ctx(_environment(fw_url=None)), _args())


def test_missing_token_env_name(monkeypatch):
    _fake_client(monkeypatch)
    with pytest.raises(FirewallError, match="no firewall token env var"):
        TOOL.run(_Ctx(_environment(fw_token_env=None)), _args(fw_url="https://x"))


def test_token_env_not_set(monkeypatch):
    monkeypatch.delenv("FW_TOKEN", raising=False)
    _fake_client(monkeypatch)
    with pytest.raises(FirewallError, match="FW_TOKEN is not set"):
        TOOL.run(_Ctx(_environment()), _args())


def test_cli_overrides_win(monkeypatch):
    monkeypatch.setenv("OTHER_TOKEN", "sekret")
    captured = _fake_client(monkeypatch, addresses=[NET_HQ])
    TOOL.run(
        _Ctx(_environment(fw_url=None, fw_token_env=None)),
        _args(fw_url="https://override.example.com/", fw_token_env="OTHER_TOKEN"),
    )
    assert captured["url"] == "https://override.example.com"
    assert captured["token"] == "sekret"


# --- results --------------------------------------------------------


def test_subnet_not_present(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    _fake_client(monkeypatch, addresses=[NET_HQ])
    result = TOOL.run(_Ctx(_environment()), _args(subnet="192.168.5.0/24"))
    assert result.status is Status.OK
    assert result.exit_code == 0
    assert result.data["present"] is False


def test_subnet_present_and_in_use(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    groups = [{"name": "grp", "member": [{"name": "vlan2"}]}]
    policies = [{"policyid": 3, "name": "p", "srcaddr": [{"name": "grp"}]}]
    _fake_client(monkeypatch, addresses=[NET_HQ, VLAN2], groups=groups, policies=policies)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.1.2.0/24"))
    assert result.status is Status.DRIFT
    assert result.exit_code == 10
    assert result.data["in_use"] is True
    assert "IN USE" in result.summary
    assert result.changes  # human-readable lines present


def test_subnet_present_but_unreferenced(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    _fake_client(monkeypatch, addresses=[VLAN2])
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.1.2.0/24"))
    assert result.status is Status.DRIFT
    assert result.data["in_use"] is False
    assert "no policy references it" in result.summary


def test_insecure_flag_disables_verify(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch, addresses=[VLAN2])
    TOOL.run(_Ctx(_environment()), _args(fw_insecure=True))
    assert captured["verify"] is False
    assert captured["vdom"] == "root"
    assert captured.get("closed") is True


def test_firewall_error_propagates(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    _fake_client(monkeypatch, boom=FirewallError("could not reach the firewall"))
    with pytest.raises(FirewallError, match="could not reach"):
        TOOL.run(_Ctx(_environment()), _args())


# --- registration --------------------------------------------------


def test_tool_declares_no_device_or_netbox_need():
    assert TOOL.needs_devices is False
    assert TOOL.needs_netbox is False
    assert TOOL.writes is False


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["fw-subnet-check"] is TOOL
