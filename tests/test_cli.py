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
        parser.parse_args(["wired", "send-command", "show version"])


def test_parser_requires_a_category():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--env", "test"])


def test_parser_requires_a_tool_within_the_category():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--env", "test", "wired"])


def test_parser_happy_path():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["--env", "test", "--json", "wired", "send-command", "show version", "--tag", "core"]
    )
    assert args.env == "test"
    assert args.json is True
    assert args.category == "wired"
    assert args.tool == "send-command"
    assert args.command == "show version"
    assert args.tag == "core"


def test_parser_accepts_role_region_and_site():
    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "--env",
            "test",
            "wired",
            "send-command",
            "show version",
            "--role",
            "access-switch",
            "--region",
            "south",
            "--site",
            "dallas-metro-it-services",
        ]
    )
    assert args.role == "access-switch"
    assert args.region == "south"
    assert args.site == "dallas-metro-it-services"


def test_every_category_has_its_tools():
    parser = cli.build_parser()
    for argv in (
        ["wired", "backup"],
        ["wired", "sync-interfaces"],
        ["wireless", "sync"],
        ["security", "subnet-check", "10.0.0.0/24"],
        ["netbox", "import-device-type", "x.yaml"],
        ["netbox", "scope"],
    ):
        args = parser.parse_args(["--env", "test", *argv])
        assert (args.category, args.tool) == (argv[0], argv[1])


def test_a_tool_is_not_reachable_from_another_category():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--env", "test", "wireless", "backup"])


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (
            ["--env", "test", "backup", "--raw"],
            "run: bunnyauto --env test wired backup --raw",
        ),
        (
            ["--env", "prod", "wireless-sync", "--apply"],
            "run: bunnyauto --env prod wireless sync --apply",
        ),
        (
            ["--env", "test", "fw-subnet-check", "10.1.0.0/24"],
            "run: bunnyauto --env test security subnet-check 10.1.0.0/24",
        ),
        (
            ["--env", "test", "wireless-enrich", "--apply"],
            "run: bunnyauto --env test wireless sync --apply",
        ),
        (
            ["--env", "test", "wireless", "enrich", "--wlc-port", "8443"],
            "'wireless enrich' is now part of 'wireless sync' — run: "
            "bunnyauto --env test wireless sync --wlc-port 8443",
        ),
    ],
)
def test_a_tool_typed_without_its_category_gets_the_corrected_command(argv, expected, capsys):
    assert cli.main(argv) == 2
    assert expected in capsys.readouterr().err


def test_unknown_word_is_left_to_argparse():
    assert cli._category_hint(["--env", "test", "nonsense"]) is None
    assert cli._category_hint(["--env", "wired", "wired", "backup"]) is None


class _FakeTool:
    name = "send-command"
    summary = "fake"
    writes = False
    category = "wired"

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
        self.settings = argparse.Namespace(target_tag="nornirtest", region=None, site=None)
        self.closed = False

    def banner(self):
        pass

    def close(self):
        self.closed = True


@pytest.fixture
def fake_registry(monkeypatch):
    def _install(tool):
        monkeypatch.setitem(cli.REGISTRY["wired"], "send-command", tool)
        return tool

    return _install


def test_main_returns_tool_exit_code(monkeypatch, fake_registry):
    ctx = _FakeCtx()
    tool = fake_registry(_FakeTool(result=ToolResult(status=Status.DRIFT, summary="2 changes")))
    monkeypatch.setattr(cli, "build_context", lambda **kw: ctx)

    code = cli.main(["--env", "test", "wired", "send-command", "show version"])

    assert code == 10  # DRIFT
    assert ctx.closed is True
    assert tool.ran_with is not None


@pytest.mark.parametrize(("json_flag", "expected"), [([], "terminal"), (["--json"], None)])
def test_main_hands_the_tool_a_terminal_but_never_in_json_mode(
    monkeypatch, fake_registry, json_flag, expected
):
    fake_registry(_FakeTool(result=ToolResult(status=Status.OK, summary="ok")))
    captured = {}

    def _fake_build_context(**kwargs):
        captured.update(kwargs)
        return _FakeCtx()

    monkeypatch.setattr(cli, "build_context", _fake_build_context)
    monkeypatch.setattr(cli, "terminal_input", lambda: "terminal")

    cli.main(["--env", "test", *json_flag, "wired", "send-command", "show version"])

    assert captured["ask_fn"] == expected


def test_subnet_check_apply_help_is_its_own():
    parser = cli.build_parser()
    security = next(
        action
        for action in parser._subparsers._group_actions[0].choices["security"]._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    subnet_check = security.choices["subnet-check"]
    options = {opt: action for action in subnet_check._actions for opt in action.option_strings}
    assert {"--apply", "--yes", "--name", "--comment"} <= set(options)
    assert "create an address object" in options["--apply"].help
    args = parser.parse_args(
        ["--env", "test", "security", "subnet-check", "10.20.30.0/24", "--apply", "--yes"]
    )
    assert args.apply is True and args.yes is True and args.name is None


def test_main_friendly_error(monkeypatch, fake_registry, capsys):
    fake_registry(_FakeTool())

    def _boom(**kwargs):
        raise InventoryError("NetBox unreachable", fix="check the URL")

    monkeypatch.setattr(cli, "build_context", _boom)

    code = cli.main(["--env", "test", "wired", "send-command", "show version"])

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
        cli.main(["--env", "test", "--debug", "wired", "send-command", "show version"])


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
            "wired",
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
