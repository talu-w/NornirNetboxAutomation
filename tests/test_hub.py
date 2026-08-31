"""Tests for the interactive hub — scripted stdin, no real Nornir."""

from __future__ import annotations

import argparse

import pytest

from bunnyauto import hub
from bunnyauto.environments import Environment
from bunnyauto.result import Status, ToolResult
from bunnyauto.tools.send_command import TOOL as SEND_COMMAND


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


class _FakeCtx:
    def __init__(self, environment: Environment, *, apply: bool = False):
        self.environment = environment
        self.settings = argparse.Namespace(
            target_tag=environment.default_tag, apply=apply, protected=environment.protected
        )
        self.closed = False

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


def test_prompt_for_args_write_tool_asks_apply():
    tool = _WriteTool(ToolResult(status=Status.OK, summary="x"))
    args = hub.prompt_for_args(tool, input_fn=_Script("do it", "y"))
    assert args.command == "do it"
    assert args.apply is True
    assert args.yes is False  # never prompted


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


def test_main_missing_credentials_exits_1(env_file, capsys):
    code = hub.main(["--env-file", str(env_file)], input_fn=_Script())
    assert code == 1
    assert "NORNIR_USERNAME" in capsys.readouterr().out


def test_main_runs_a_tool_then_quits(env_file, creds, monkeypatch):
    fake = _FakeTool(ToolResult(status=Status.OK, summary="done"))
    monkeypatch.setattr(hub, "REGISTRY", {"demo": fake})

    captured = {}

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        env = resolve_environment(kwargs["env"], kwargs.get("env_file"))
        captured.update(kwargs)
        return _FakeCtx(env)

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    script = _Script("1", "1", "show version", "q")
    code = hub.main(["--env-file", str(env_file)], input_fn=script)

    assert code == 0
    assert fake.ran is True
    assert captured["env"] == "test"


def test_main_protected_apply_requires_typed_name(env_file, creds, monkeypatch):
    fake = _WriteTool(ToolResult(status=Status.CHANGED, summary="applied"))
    monkeypatch.setattr(hub, "REGISTRY", {"writer": fake})

    def _fake_build_context(**kwargs):
        from bunnyauto.environments import resolve_environment

        env = resolve_environment(kwargs["env"], kwargs.get("env_file"))
        return _FakeCtx(env, apply=kwargs.get("apply", False))

    monkeypatch.setattr(hub, "build_context", _fake_build_context)

    # env 2 (prod, protected), tool 1, command, apply=yes, wrong confirmation, quit
    script = _Script("2", "1", "wr mem", "y", "nope", "q")
    code = hub.main(["--env-file", str(env_file)], input_fn=script)

    assert code == 0
    assert fake.ran is False  # confirmation failed -> tool never ran


def test_main_back_then_quit(env_file, creds, monkeypatch):
    fake = _FakeTool(ToolResult(status=Status.OK, summary="x"))
    monkeypatch.setattr(hub, "REGISTRY", {"demo": fake})
    script = _Script("1", "b", "q")
    assert hub.main(["--env-file", str(env_file)], input_fn=script) == 0
