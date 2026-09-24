"""Tests for the interactive hub — scripted stdin, no real Nornir."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from bunnyauto import hub
from bunnyauto.environments import Environment
from bunnyauto.errors import ToolError
from bunnyauto.result import Status, ToolResult
from bunnyauto.tools.netbox.import_device_type import TOOL as IMPORT_DEVICE_TYPE
from bunnyauto.tools.security.subnet_check import TOOL as SUBNET_CHECK
from bunnyauto.tools.wired.send_command import TOOL as SEND_COMMAND


class _Script:
    """A stand-in for input(): returns queued lines, then raises EOFError."""

    def __init__(self, *lines: str):
        self.lines = list(lines)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        if not self.lines:
            raise EOFError
        return self.lines.pop(0)


class _FakeTool:
    name = "demo"
    summary = "a fake tool"
    writes = False
    category = "wired"

    def __init__(self, result: ToolResult):
        self._result = result
        self.ran = False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("command")

    def run(self, ctx, args) -> ToolResult:
        self.ran = True
        return self._result


class _WriteTool(_FakeTool):
    name = "writer"
    writes = True


class _SelfConfirmingTool(_WriteTool):
    name = "asks-itself"
    confirms_writes = True


class _FakeCtx:
    def __init__(self, environment: Environment, *, apply: bool = False):
        self.environment = environment
        self.settings = argparse.Namespace(
            target_tag=environment.default_tag,
            region=None,
            site=None,
            apply=apply,
            protected=environment.protected,
        )
        self.closed = False

    def banner(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("NORNIR_USERNAME", "alice")
    monkeypatch.setenv("NORNIR_PASSWORD", "secret")
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_TOKEN", "t")
    monkeypatch.setenv("BUNNYAUTO_PROD_NB_TOKEN", "p")


# ---------------------------------------------------------------------------
# prompt helpers
# ---------------------------------------------------------------------------


def test_ask_uses_default_on_empty():
    assert hub._ask("name", default="core", input_fn=_Script("")) == "core"
    assert hub._ask("name", default="core", input_fn=_Script("edge")) == "edge"


@pytest.mark.parametrize(
    ("answer", "default", "expected"),
    [("", False, False), ("", True, True), ("y", False, True), ("no", True, False)],
)
def test_ask_bool(answer, default, expected):
    assert hub._ask_bool("go", default=default, input_fn=_Script(answer)) is expected


# ---------------------------------------------------------------------------
# prompt_for_args
# ---------------------------------------------------------------------------


def test_prompt_for_args_send_command():
    args = hub.prompt_for_args(SEND_COMMAND, input_fn=_Script("show version", ""))
    assert args.command == "show version"
    assert args.config_mode is False
    # common args keep their defaults, not prompted
    assert args.tag is None
    assert args.connect_timeout is None


def test_prompt_for_args_config_mode_yes():
    args = hub.prompt_for_args(SEND_COMMAND, input_fn=_Script("reload", "y"))
    assert args.config_mode is True


def test_prompt_for_args_applies_positional_type_conversion():
    # import-device-type's `file` positional is declared type=Path; the hub must
    # apply that converter itself since it builds the Namespace by hand rather
    # than going through argparse.parse_args().
    args = hub.prompt_for_args(IMPORT_DEVICE_TYPE, input_fn=_Script("devicetype.yaml", "n"))
    assert args.file == Path("devicetype.yaml")
    assert isinstance(args.file, Path)


def test_prompt_for_args_invalid_positional_type_raises_friendly_error():
    class _IntTool(_FakeTool):
        name = "needs-int"

        def add_arguments(self, parser: argparse.ArgumentParser) -> None:
            parser.add_argument("count", type=int)

    tool = _IntTool(ToolResult(status=Status.OK, summary="x"))
    with pytest.raises(ToolError):
        hub.prompt_for_args(tool, input_fn=_Script("not-a-number"))


def test_prompt_for_args_write_tool_asks_apply():
    tool = _WriteTool(ToolResult(status=Status.OK, summary="x"))
    args = hub.prompt_for_args(tool, input_fn=_Script("do it", "y"))
    assert args.command == "do it"
    assert args.apply is True
    assert args.yes is False  # never prompted


def test_prompt_for_args_tool_that_confirms_its_own_writes_is_not_asked_apply():
    script = _Script("10.20.30.0/24", "n")  # the subnet, then --fw-insecure
    args = hub.prompt_for_args(SUBNET_CHECK, input_fn=script)
    assert args.subnet == "10.20.30.0/24"
    assert args.fw_insecure is False
    assert args.apply is True  # on, so the tool may offer — and asks before writing
    assert args.yes is False
    assert args.name is None  # string options keep their defaults; the tool asks
    assert not any("apply" in prompt for prompt in script.prompts)


# ---------------------------------------------------------------------------
# environment menu
# ---------------------------------------------------------------------------


def test_choose_environment_by_number(env_file):
    from bunnyauto.environments import load_environments

    envs = load_environments(env_file)
    chosen = hub._choose_environment(envs, hub.make_reporter(), _Script("2"))
    assert chosen.name == "prod"


def test_choose_environment_quit(env_file):
    from bunnyauto.environments import load_environments

    envs = load_environments(env_file)
    assert hub._choose_environment(envs, hub.make_reporter(), _Script("q")) is None


def test_choose_environment_reprompts_on_junk(env_file):
    from bunnyauto.environments import load_environments

    envs = load_environments(env_file)
    chosen = hub._choose_environment(envs, hub.make_reporter(), _Script("9", "x", "1"))
    assert chosen.name == "test"


# ---------------------------------------------------------------------------
# main() end to end
# ---------------------------------------------------------------------------


def test_main_shows_missing_credentials_but_still_opens_the_menu(env_file, capsys):
    # No device creds set anywhere: the hub no longer hard-fails at startup
    # (creds may be per-environment now) — it shows status and still opens
    # the network menu; an actual tool run is what enforces for real.
    code = hub.main(["--env-file", str(env_file)], input_fn=_Script())
    assert code == 0
    out = capsys.readouterr().out
    assert "NORNIR_USERNAME" in out
    assert "NOT set" in out
    assert "Which network?" in out


def test_main_runs_a_tool_then_quits(env_file, creds, monkeypatch):
    fake = _FakeTool(ToolResult(status=Status.OK, summary="done"))
    monkeypatch.setattr(hub, "REGISTRY", {"wired": {"demo": fake}})

    captured = {}

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        env = resolve_environment(kwargs["env"], kwargs.get("env_file"))
        captured.update(kwargs)
        return _FakeCtx(env)

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    # network 1 (test), area 1 (wired), tool 1, its positional, quit
    script = _Script("1", "1", "1", "show version", "q")
    code = hub.main(["--env-file", str(env_file)], input_fn=script)

    assert code == 0
    assert fake.ran is True
    assert captured["env"] == "test"
    assert captured["category"].key == "wired"  # the run is confined to the wired branch
    assert captured["role"] is None


def test_main_protected_apply_requires_typed_name(env_file, creds, monkeypatch):
    fake = _WriteTool(ToolResult(status=Status.CHANGED, summary="applied"))
    monkeypatch.setattr(hub, "REGISTRY", {"wired": {"writer": fake}})

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        env = resolve_environment(kwargs["env"], kwargs.get("env_file"))
        return _FakeCtx(env, apply=kwargs.get("apply", False))

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    # env 2 (prod, protected), area 1, tool 1, command, apply=yes, wrong confirmation, quit
    script = _Script("2", "1", "1", "wr mem", "y", "nope", "q")
    code = hub.main(["--env-file", str(env_file)], input_fn=script)

    assert code == 0
    assert fake.ran is False  # confirmation failed -> tool never ran


def test_main_self_confirming_tool_is_not_gated_up_front(env_file, creds, monkeypatch):
    fake = _SelfConfirmingTool(ToolResult(status=Status.OK, summary="free"))
    monkeypatch.setattr(hub, "REGISTRY", {"security": {"asks-itself": fake}})
    captured = {}

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        env = resolve_environment(kwargs["env"], kwargs.get("env_file"))
        captured.update(kwargs)
        return _FakeCtx(env, apply=kwargs.get("apply", False))

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    # env 2 (prod, protected), area 1, tool 1, its positional, quit — no apply
    # question and no typed name before the run: the tool asks for itself.
    script = _Script("2", "1", "1", "10.20.30.0/24", "q")
    code = hub.main(["--env-file", str(env_file)], input_fn=script)

    assert code == 0
    assert fake.ran is True
    assert captured["apply"] is True
    assert captured["assume_yes"] is False
    assert captured["ask_fn"] is script


def test_main_back_then_quit(env_file, creds, monkeypatch):
    fake = _FakeTool(ToolResult(status=Status.OK, summary="x"))
    monkeypatch.setattr(hub, "REGISTRY", {"wired": {"demo": fake}})
    script = _Script("1", "b", "q")
    assert hub.main(["--env-file", str(env_file)], input_fn=script) == 0


def test_area_menu_lists_categories_with_their_role_branch(env_file, creds, capsys):
    hub.main(["--env-file", str(env_file)], input_fn=_Script("1", "q"))
    out = capsys.readouterr().out
    assert "which area?" in out
    assert "wired" in out and "(role branch: wired-network)" in out
    assert "wireless" in out and "(role branch: wireless-network)" in out
    assert "security" in out and "(role branch: network-security)" in out


def test_back_from_tools_returns_to_the_area_menu(env_file, creds, monkeypatch):
    wired = _FakeTool(ToolResult(status=Status.OK, summary="w"))
    wireless = _FakeTool(ToolResult(status=Status.OK, summary="wl"))
    wireless.category = "wireless"
    monkeypatch.setattr(hub, "REGISTRY", {"wired": {"demo": wired}, "wireless": {"demo": wireless}})
    ran = []

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        ran.append(kwargs["category"].key)
        return _FakeCtx(resolve_environment(kwargs["env"], kwargs.get("env_file")))

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    # network 1, area 1 (wired), back, area 2 (wireless), tool 1, positional, quit
    script = _Script("1", "1", "b", "2", "1", "show version", "q")
    assert hub.main(["--env-file", str(env_file)], input_fn=script) == 0
    assert ran == ["wireless"]
    assert wireless.ran is True and wired.ran is False
