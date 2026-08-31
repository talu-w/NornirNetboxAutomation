"""Tests for the CI helper scripts."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ci_plan = _load("ci_plan")
ci_write_env_file = _load("ci_write_env_file")


# ---------------------------------------------------------------------------
# ci_write_env_file
# ---------------------------------------------------------------------------


def test_write_env_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BUNNYAUTO_TEST_NB_URL", "https://nb-lab.example.com")
    monkeypatch.setenv("BUNNYAUTO_PROD_NB_URL", "https://nb.example.com")

    assert ci_write_env_file.main() == 0
    text = (tmp_path / "bunnyauto.yaml").read_text()
    assert "https://nb-lab.example.com" in text
    assert "BUNNYAUTO_PROD_NB_TOKEN" in text
    assert "protected: true" in text


def test_write_env_file_missing_var(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BUNNYAUTO_TEST_NB_URL", raising=False)
    monkeypatch.setenv("BUNNYAUTO_PROD_NB_URL", "https://nb.example.com")

    assert ci_write_env_file.main() == 1
    assert "BUNNYAUTO_TEST_NB_URL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# ci_plan
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_tool(monkeypatch):
    calls: list[str] = []

    def _install(results: dict[str, dict]):
        def _run(env, tool):
            calls.append(tool)
            payload = results[tool]
            return payload.get("exit_code", 0), payload

        monkeypatch.setattr(ci_plan, "_run_tool", _run)
        return calls

    return _install


def test_ci_plan_in_sync(fake_tool, capsys):
    fake_tool(
        {
            "create-interfaces": {"status": "ok", "summary": "in sync", "changes": []},
            "sync-interfaces": {"status": "ok", "summary": "in sync", "changes": []},
        }
    )
    assert ci_plan.main(["--env", "test"]) == 0
    out = capsys.readouterr().out
    assert "NetBox is in sync" in out


def test_ci_plan_drift(fake_tool, capsys):
    fake_tool(
        {
            "create-interfaces": {"status": "ok", "summary": "in sync", "changes": []},
            "sync-interfaces": {
                "status": "drift",
                "summary": "3 interfaces would change",
                "changes": ["sw1: Gi1/0/1 vlan 10->20"],
            },
        }
    )
    assert ci_plan.main(["--env", "test"]) == 0  # drift is not a hard failure
    out = capsys.readouterr().out
    assert "Drift detected" in out
    assert "Gi1/0/1 vlan 10->20" in out


def test_ci_plan_hard_error(fake_tool, capsys):
    fake_tool(
        {
            "create-interfaces": {
                "status": "error",
                "summary": "NetBox unreachable",
                "exit_code": 1,
            },
            "sync-interfaces": {"status": "ok", "summary": "in sync", "changes": []},
        }
    )
    assert ci_plan.main(["--env", "test"]) == 1
    assert "could not run" in capsys.readouterr().out


def test_ci_plan_parses_bad_json(monkeypatch):
    import subprocess

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="bunnyauto: NetBox down\n")

    monkeypatch.setattr(ci_plan.subprocess, "run", _fake_run)
    code, payload = ci_plan._run_tool("test", "sync-interfaces")
    assert payload["status"] == "error"
    assert "NetBox down" in payload["summary"]


def test_json_error_shape_is_documented():
    # ci_plan relies on ToolResult.as_dict() keys; guard against drift.
    from bunnyauto.result import Status, ToolResult

    payload = json.loads(json.dumps(ToolResult(status=Status.DRIFT, summary="x").as_dict()))
    assert {"status", "summary", "changes", "exit_code"} <= set(payload)
