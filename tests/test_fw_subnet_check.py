"""Tests for `security subnet-check` (fake FortiGate client, no HTTP)."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from bunnyauto.context import Context, Credentials, Settings
from bunnyauto.environments import Environment
from bunnyauto.errors import FirewallError
from bunnyauto.reporting import Reporter
from bunnyauto.result import Status
from bunnyauto.tools.security import subnet_check as fw_subnet_check
from bunnyauto.tools.security.subnet_check import TOOL

NET_HQ = {"name": "net_hq", "type": "ipmask", "subnet": "10.1.0.0 255.255.0.0"}
VLAN2 = {"name": "vlan2", "type": "ipmask", "subnet": "10.1.2.0 255.255.255.0"}


def _environment(
    *, fw_url="https://fw.example.com", fw_token_env="FW_TOKEN", protected=True
) -> Environment:
    return Environment(
        name="prod" if protected else "test",
        nb_url="https://nb.example.com",
        default_tag="networking-active",
        token_env="BUNNYAUTO_PROD_NB_TOKEN",
        protected=protected,
        fw_url=fw_url,
        fw_token_env=fw_token_env,
    )


class _Script:
    """A stand-in for input(): returns queued answers, then fails the test."""

    def __init__(self, *answers: str):
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        assert self.answers, f"unexpected question: {prompt!r}"
        return self.answers.pop(0)


def _Ctx(environment: Environment, *, apply=False, yes=False, ask=None) -> Context:
    """A real Context (so confirm/ask/confirm_protected are the real ones)."""
    settings = Settings(
        environment=environment.name,
        nb_url=environment.nb_url,
        config_file=Path("config.yaml"),
        target_tag=environment.default_tag,
        protected=environment.protected,
        apply=apply,
        assume_yes=yes,
    )
    return Context(
        settings=settings,
        creds=Credentials(username="", password="", nb_token=""),
        reporter=Reporter(json_mode=True),
        environment=environment,
        ask_fn=ask,
    )


def _args(subnet="10.1.2.0/24", **over) -> argparse.Namespace:
    base = dict(
        subnet=subnet,
        vdom="root",
        fw_url=None,
        fw_token_env=None,
        fw_insecure=False,
        name=None,
        comment=fw_subnet_check.DEFAULT_COMMENT,
    )
    base.update(over)
    return argparse.Namespace(**base)


def _fake_client(
    monkeypatch,
    *,
    addresses=(),
    groups=(),
    policies=(),
    interfaces=(),
    boom=None,
    create_boom=None,
):
    captured: dict = {"created": []}

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

        def interfaces(self):
            return list(interfaces)

        def create_address(self, address):
            if create_boom:
                raise create_boom
            captured["created"].append(address)

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


def test_catch_all_object_does_not_flip_the_exit_code(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    all_obj = {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"}
    policies = [{"policyid": 1, "name": "allow-any", "srcaddr": [{"name": "all"}]}]
    _fake_client(monkeypatch, addresses=[all_obj, NET_HQ], policies=policies)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="192.168.32.0/24"))
    assert result.status is Status.OK
    assert result.exit_code == 0
    assert result.data["present"] is False
    assert result.data["in_use"] is False
    assert result.data["permitted_by_catch_all"] is True
    assert result.data["catch_alls"][0]["name"] == "all"
    assert "catch-all" in result.summary


def test_broad_supernet_does_not_flip_the_exit_code(monkeypatch):
    """Owner feedback 2026-09-17: RFC1918 supernets must not read as a fail."""
    monkeypatch.setenv("FW_TOKEN", "t")
    rfc1918 = {"name": "rfc1918_all", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"}
    policies = [{"policyid": 5, "name": "deny_private_wan", "dstaddr": [{"name": "rfc1918_all"}]}]
    _fake_client(monkeypatch, addresses=[rfc1918], policies=policies)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.OK
    assert result.exit_code == 0
    assert result.data["present"] is False
    assert result.data["in_use"] is False
    assert result.data["permitted_by_broad_match"] is True
    assert result.data["broad_matches"][0]["name"] == "rfc1918_all"
    assert "broad supernet" in result.summary


def test_broad_supernet_and_notes_block_are_clean_and_indented(monkeypatch):
    """The redesigned Notes block: one grouped, indented section per category."""
    monkeypatch.setenv("FW_TOKEN", "t")
    addresses = [
        {"name": "rfc1918_all", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"},
        {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
    ]
    policies = [
        {"policyid": 5, "name": "deny_private_wan", "dstaddr": [{"name": "rfc1918_all"}]},
        {"policyid": 12, "name": "allow_out", "srcaddr": [{"name": "all"}]},
    ]
    interfaces = [{"name": "port10", "vdom": "root", "ip": "10.20.30.1 255.255.255.0"}]
    _fake_client(monkeypatch, addresses=addresses, policies=policies, interfaces=interfaces)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.OK
    assert result.data["permitted_by_catch_all"] is True
    assert result.data["permitted_by_broad_match"] is True
    assert result.data["on_interface"] is True
    # all three categories, and the summary points at the block rather than dumping it
    assert "catch-all object" in result.summary
    assert "broad supernet object" in result.summary
    assert "interface address" in result.summary


def test_interface_address_is_a_note_not_a_match(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    interfaces = [{"name": "port10", "vdom": "root", "ip": "192.168.32.1 255.255.255.0"}]
    _fake_client(monkeypatch, interfaces=interfaces)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="192.168.32.0/24"))
    assert result.status is Status.OK
    assert result.exit_code == 0
    assert result.data["present"] is False
    assert result.data["in_use"] is False
    assert result.data["on_interface"] is True
    assert result.data["interfaces"][0]["name"] == "port10"
    assert result.data["interfaces"][0]["ip"] == "192.168.32.1/24"
    assert "interface address" in result.summary


def test_interface_note_does_not_flip_a_real_drift(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    interfaces = [{"name": "port10", "ip": "10.1.2.1 255.255.255.0"}]
    _fake_client(monkeypatch, addresses=[VLAN2], interfaces=interfaces)
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.1.2.0/24"))
    assert result.status is Status.DRIFT
    assert result.data["on_interface"] is True
    assert result.data["in_use"] is False  # unrelated to the interface note


def test_security_policy_hit_is_detected_and_labeled(monkeypatch):
    """A 900G/901G-style box: policy-based NGFW mode, hit only via security-policy."""
    monkeypatch.setenv("FW_TOKEN", "t")
    pol = {"policyid": 12, "name": "allow-out", "dstaddr": [{"name": "vlan2"}]}
    pol["_bunnyauto_policy_source"] = "security-policy"
    _fake_client(monkeypatch, addresses=[VLAN2], policies=[pol])
    result = TOOL.run(_Ctx(_environment()), _args(subnet="10.1.2.0/24"))
    assert result.status is Status.DRIFT
    assert result.data["in_use"] is True
    assert result.data["matches"][0]["policies"][0]["source"] == "security-policy"
    assert "(security-policy)" in result.changes[0]


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


# --- free -> create an address object --------------------------------------
#
# Owner request 2026-09-24: a green check offers to create the subnet as an address
# object on the same FortiGate. Plan unless --apply; the hub runs it with --apply on
# (confirms_writes) and every write is asked about first.


def test_free_subnet_without_apply_only_says_what_apply_would_create(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    script = _Script()  # a terminal is there, but nothing may be asked without --apply
    result = TOOL.run(_Ctx(_environment(), ask=script), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.OK
    assert result.exit_code == 0
    assert captured["created"] == []
    assert script.prompts == []
    obj = result.data["address_object"]
    assert obj["created"] is False
    assert obj["reason"] == "plan only (no --apply)"
    assert obj["name"] == "10.20.30.0/24"
    assert obj["subnet"] == "10.20.30.0 255.255.255.0"


def test_yes_creates_it_with_the_default_name(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    result = TOOL.run(_Ctx(_environment(), apply=True, yes=True), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.CHANGED
    assert result.exit_code == 20
    [address] = captured["created"]
    assert address.name == "10.20.30.0/24"
    assert address.payload() == {
        "name": "10.20.30.0/24",
        "type": "ipmask",
        "subnet": "10.20.30.0 255.255.255.0",
        "comment": fw_subnet_check.DEFAULT_COMMENT,
    }
    assert address.endpoint == "firewall/address"
    assert result.data["address_object"]["created"] is True
    assert "created address object '10.20.30.0/24'" in result.summary
    assert captured["closed"] is True


def test_host_bits_are_dropped_and_the_chosen_mask_is_kept(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    TOOL.run(_Ctx(_environment(), apply=True, yes=True), _args(subnet="10.20.30.77/26"))
    [address] = captured["created"]
    assert address.payload()["subnet"] == "10.20.30.64 255.255.255.192"
    assert address.name == "10.20.30.64/26"


def test_ipv6_goes_to_address6_as_an_ipprefix(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    TOOL.run(
        _Ctx(_environment(), apply=True, yes=True),
        _args(subnet="2001:db8:1::/64", name="v6-lab", comment=""),
    )
    [address] = captured["created"]
    assert address.endpoint == "firewall/address6"
    assert address.payload() == {"name": "v6-lab", "type": "ipprefix", "ip6": "2001:db8:1::/64"}


def test_terminal_asks_create_then_name_then_nothing_else_off_production(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    script = _Script("y", "VLAN230_Printers")
    result = TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=script),
        _args(subnet="10.20.30.0/24"),
    )
    assert result.status is Status.CHANGED
    assert [a.name for a in captured["created"]] == ["VLAN230_Printers"]
    assert script.prompts[0].startswith("Create an address object for 10.20.30.0/24 on ")
    assert script.prompts[0].endswith("[y/N]: ")
    assert script.prompts[1] == "Name for the new address object [10.20.30.0/24]: "
    assert len(script.prompts) == 2  # an unprotected env has no typed-name gate
    assert result.data["address_object"]["name"] == "VLAN230_Printers"


def test_enter_at_the_name_prompt_keeps_the_default(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=_Script("y", "")),
        _args(subnet="10.20.30.0/24"),
    )
    assert [a.name for a in captured["created"]] == ["10.20.30.0/24"]


def test_name_flag_is_not_asked_again(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    script = _Script("y")
    TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=script),
        _args(subnet="10.20.30.0/24", name="  lab_net  "),
    )
    assert [a.name for a in captured["created"]] == ["lab_net"]
    assert len(script.prompts) == 1


def test_declining_creates_nothing_and_stays_ok(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    script = _Script("")  # Enter = no
    result = TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=script),
        _args(subnet="10.20.30.0/24"),
    )
    assert result.status is Status.OK
    assert captured["created"] == []
    assert result.data["address_object"]["reason"] == "declined"
    assert len(script.prompts) == 1


def test_production_needs_the_typed_environment_name(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    script = _Script("y", "", "prod")
    result = TOOL.run(_Ctx(_environment(), apply=True, ask=script), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.CHANGED
    assert len(captured["created"]) == 1
    assert script.prompts[2] == "Type the environment name (prod) to proceed: "


def test_production_wrong_typed_name_creates_nothing(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    result = TOOL.run(
        _Ctx(_environment(), apply=True, ask=_Script("y", "", "yes")),
        _args(subnet="10.20.30.0/24"),
    )
    assert result.status is Status.OK
    assert captured["created"] == []
    assert result.data["address_object"]["reason"] == "the environment name didn't match"


def test_present_subnet_is_never_offered(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch, addresses=[VLAN2])
    script = _Script()
    result = TOOL.run(_Ctx(_environment(), apply=True, ask=script), _args(subnet="10.1.2.0/24"))
    assert result.status is Status.DRIFT
    assert captured["created"] == []
    assert script.prompts == []
    assert "address_object" not in result.data


def test_a_taken_name_is_asked_again_on_a_terminal(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    fqdn = {"name": "printers", "type": "fqdn", "fqdn": "printers.example.com"}
    captured = _fake_client(monkeypatch, addresses=[fqdn], groups=[{"name": "lab", "member": []}])
    script = _Script("y", "printers", "lab", "printers_v230")
    result = TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=script),
        _args(subnet="10.20.30.0/24"),
    )
    assert result.status is Status.CHANGED
    assert [a.name for a in captured["created"]] == ["printers_v230"]
    assert script.prompts[2] == "Another name (Enter to cancel): "


def test_a_taken_name_can_be_cancelled(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch, addresses=[{"name": "10.20.30.0/24", "type": "fqdn"}])
    result = TOOL.run(
        _Ctx(_environment(protected=False), apply=True, ask=_Script("y", "", "")),
        _args(subnet="10.20.30.0/24"),
    )
    assert result.status is Status.OK
    assert captured["created"] == []
    assert result.data["address_object"]["reason"] == "cancelled"


def test_a_taken_name_with_nobody_to_ask_is_an_error(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch, groups=[{"name": "lab_net", "member": []}])
    result = TOOL.run(
        _Ctx(_environment(), apply=True, yes=True),
        _args(subnet="10.20.30.0/24", name="lab_net"),
    )
    assert result.status is Status.ERROR
    assert result.exit_code == 1
    assert captured["created"] == []
    assert "'lab_net' is already the name of an address group" in result.summary
    assert "--name" in result.data["address_object"]["reason"]


def test_apply_with_nobody_to_confirm_stops_before_connecting(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    captured = _fake_client(monkeypatch)
    with pytest.raises(FirewallError, match="--apply needs --yes"):
        TOOL.run(_Ctx(_environment(), apply=True), _args(subnet="10.20.30.0/24"))
    assert "url" not in captured  # the client was never built


def test_a_refused_create_is_an_error_that_keeps_the_check_data(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    refused = FirewallError(
        "the firewall refused the write to firewall/address (HTTP 403)", fix="read-write"
    )
    _fake_client(monkeypatch, create_boom=refused)
    result = TOOL.run(_Ctx(_environment(), apply=True, yes=True), _args(subnet="10.20.30.0/24"))
    assert result.status is Status.ERROR
    assert "HTTP 403" in result.summary
    assert result.data["present"] is False  # the check itself still reported
    assert result.data["address_object"]["created"] is False


# --- the Notes block (formatting) -----------------------------------


def test_notes_block_is_none_when_nothing_to_show(monkeypatch):
    monkeypatch.setenv("FW_TOKEN", "t")
    _fake_client(monkeypatch, addresses=[VLAN2])
    from bunnyauto.firewall.usage import analyze, parse_query
    from bunnyauto.tools.security.subnet_check import _build_notes_block, _notes_aside

    report = analyze(parse_query("10.1.2.0/24"), [VLAN2], [], [])
    assert _build_notes_block(report) is None
    assert _notes_aside(report) == ""


def test_notes_block_groups_and_indents_each_category():
    from bunnyauto.firewall.usage import analyze, parse_query
    from bunnyauto.tools.security.subnet_check import _build_notes_block, _notes_aside

    addresses = [
        {"name": "rfc1918_all", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"},
        {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
    ]
    policies = [
        {"policyid": 5, "name": "deny_private_wan", "dstaddr": [{"name": "rfc1918_all"}]},
        {"policyid": 12, "name": "allow_out", "srcaddr": [{"name": "all"}]},
    ]
    interfaces = [{"name": "port10", "vdom": "root", "ip": "10.20.30.1 255.255.255.0"}]
    report = analyze(parse_query("10.20.30.0/24"), addresses, [], policies, interfaces=interfaces)

    block = _build_notes_block(report)
    assert block.startswith("Notes (informational")
    assert "  catch-all objects" in block
    assert "  broad address objects (wider than /24" in block
    assert "  interface addresses" in block
    # each category's item is a "-" bullet, nested policy lines use "·"
    assert "    - all (0.0.0.0/0) — referenced by 1 policy:" in block
    assert "        · 12/allow_out [srcaddr]" in block
    assert "    - rfc1918_all (10.0.0.0/8) — referenced by 1 policy:" in block
    assert "        · 5/deny_private_wan [dstaddr]" in block
    assert "    - port10 (vdom root): primary address" in block

    aside = _notes_aside(report)
    assert "1 catch-all object(s)" in aside
    assert "1 broad supernet object(s)" in aside
    assert "1 interface address(es)" in aside


def test_notes_block_unreferenced_object_says_so_without_a_policy_list():
    from bunnyauto.firewall.usage import analyze, parse_query
    from bunnyauto.tools.security.subnet_check import _build_notes_block

    rfc1918 = {"name": "rfc1918_all", "type": "ipmask", "subnet": "10.0.0.0 255.0.0.0"}
    report = analyze(parse_query("10.20.30.0/24"), [rfc1918], [], [])
    block = _build_notes_block(report)
    assert "no policy references it" in block


# --- registration --------------------------------------------------


def test_tool_declares_no_device_or_netbox_need():
    assert TOOL.needs_devices is False
    assert TOOL.needs_netbox is False


def test_tool_writes_but_confirms_its_own_writes():
    assert TOOL.writes is True
    assert TOOL.confirms_writes is True


def test_tool_is_registered():
    from bunnyauto.tools import REGISTRY

    assert REGISTRY["security"]["subnet-check"] is TOOL
