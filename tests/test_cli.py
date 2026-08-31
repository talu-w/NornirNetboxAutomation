"""Tests for the bunnyauto CLI wiring (parser, argv forwarding, main())."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import textwrap

import pytest

from bunnyauto import cli
from bunnyauto.errors import InventoryError
from bunnyauto.result import Status, ToolResult


def test_parser_requires_env():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["send-command", "show version"])


def test_parser_requires_a_tool():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--env", "test"])


def test_parser_happy_path():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["--env", "test", "--json", "send-command", "show version", "--tag", "core"]
    )
    assert args.env == "test"
    assert args.json is True
    assert args.tool == "send-command"
    assert args.command == "show version"
    assert args.tag == "core"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["--env", "test", "show version"], ["--env", "test", "send-command", "show version"]),
        (["--env=test", "show x"], ["--env=test", "send-command", "show x"]),
        (
            ["--env", "prod", "--json", "--debug", "show y"],
            ["--env", "prod", "--json", "--debug", "send-command", "show y"],
        ),
        (["show version"], ["send-command", "show version"]),
    ],
)
def test_forward_argv(raw, expected):
    assert cli.forward_argv("send-command", raw) == expected


class _FakeTool:
    name = "send-command"
    summary = "fake"
    writes = False

    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc
        self.ran_with = None

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("command")

    def run(self, ctx, args):
        self.ran_with = (ctx, args)
        if self._exc is not None:
            raise self._exc
        return self._result


class _FakeCtx:
    def __init__(self):
        self.environment = argparse.Namespace(name="test", nb_url="https://nb", protected=False)
        self.settings = argparse.Namespace(target_tag="nornirtest")
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def fake_registry(monkeypatch):
    def _install(tool):
        monkeypatch.setitem(cli.REGISTRY, "send-command", tool)
        return tool

    return _install


def test_main_returns_tool_exit_code(monkeypatch, fake_registry):
    ctx = _FakeCtx()
    tool = fake_registry(_FakeTool(result=ToolResult(status=Status.DRIFT, summary="2 changes")))
    monkeypatch.setattr(cli, "build_context", lambda **kw: ctx)

    code = cli.main(["--env", "test", "send-command", "show version"])

    assert code == 10  # DRIFT
    assert ctx.closed is True
    assert tool.ran_with is not None


def test_main_friendly_error(monkeypatch, fake_registry, capsys):
    fake_registry(_FakeTool())

    def _boom(**kwargs):
        raise InventoryError("NetBox unreachable", fix="check the URL")

    monkeypatch.setattr(cli, "build_context", _boom)

    code = cli.main(["--env", "test", "send-command", "show version"])

    assert code == 1
    err = capsys.readouterr().err
    assert "bunnyauto: NetBox unreachable" in err
    assert "check the URL" in err


def test_main_debug_reraises(monkeypatch, fake_registry):
    fake_registry(_FakeTool())

    def _boom(**kwargs):
        raise InventoryError("NetBox unreachable")

    monkeypatch.setattr(cli, "build_context", _boom)

    with pytest.raises(InventoryError):
        cli.main(["--env", "test", "--debug", "send-command", "show version"])


def test_json_output_is_always_valid_json_even_on_error(tmp_path):
    """Regression guard: importing the tool layer must not pollute stdout
    (nornir_utils pulls in rich, which used to wrap sys.stdout with ANSI)."""
    env_file = tmp_path / "bunnyauto.yaml"
    env_file.write_text(
        textwrap.dedent(
            """
            environments:
              test:
                nb_url: https://netbox-does-not-resolve.invalid
                default_tag: nornirtest
                token_env: BUNNYAUTO_TEST_NB_TOKEN
            """
        ).strip(),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "bunnyauto",
            "--env",
            "test",
            "--env-file",
            str(env_file),
            "--json",
            "sync-interfaces",
        ],
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "NORNIR_USERNAME": "u",
            "NORNIR_PASSWORD": "p",
            "BUNNYAUTO_TEST_NB_TOKEN": "t",
        },
        cwd=tmp_path,
        check=False,
    )
    payload = json.loads(proc.stdout)  # must not raise
    assert payload["status"] == "error"
    assert "\x1b" not in proc.stdout
