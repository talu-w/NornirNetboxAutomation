"""The workflows' ``run:`` steps turn exit codes into the right pass/fail.

GitHub runs a ``run:`` step as ``bash -e <script>``: the first command that exits
non-zero ends the step and fails the job. These tests run the real step scripts
from ``.github/workflows/`` the same way, with ``bunnyauto`` / ``python`` swapped
for a stub that exits with a chosen code (docs/ci.md, "Exit codes and job results").
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

_WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="runs the workflow steps' bash scripts",
)

# Logs its arguments, prints a line, then exits with the next code queued in
# $STUB_CODES (0 once the queue is empty).
_STUB = """\
#!/usr/bin/env bash
echo "$*" >> "$STUB_CALLS"
echo "stub output"
code=$(head -n 1 "$STUB_CODES")
tail -n +2 "$STUB_CODES" > "$STUB_CODES.next" && mv "$STUB_CODES.next" "$STUB_CODES"
exit "${code:-0}"
"""


def _step_script(workflow: str, job: str, name: str) -> str:
    doc = yaml.safe_load((_WORKFLOWS / workflow).read_text(encoding="utf-8"))
    for step in doc["jobs"][job]["steps"]:
        if step.get("name") == name:
            return step["run"]
    raise AssertionError(f"{workflow}: job {job!r} has no step named {name!r}")


def _run_step(
    tmp_path: Path, script: str, *, command: str, codes: list[int]
) -> tuple[int, list[str], str]:
    """Run ``script`` as GitHub does, with ``command`` stubbed to exit ``codes`` in turn.

    Returns the step's exit code, the stub's calls (one argument string each), and
    everything the step printed.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / command
    stub.write_text(_STUB)
    stub.chmod(0o755)
    (tmp_path / "codes").write_text("".join(f"{code}\n" for code in codes))
    (tmp_path / "step.sh").write_text(script)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "STUB_CALLS": str(tmp_path / "calls"),
        "STUB_CODES": str(tmp_path / "codes"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    proc = subprocess.run(
        ["bash", "-e", "step.sh"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls_file = tmp_path / "calls"
    calls = calls_file.read_text().splitlines() if calls_file.exists() else []
    return proc.returncode, calls, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# apply.yml: the apply step
# ---------------------------------------------------------------------------

_APPLY = ("apply.yml", "apply-prod", "Apply to prod NetBox")


@pytest.mark.parametrize(
    "codes",
    [
        pytest.param([0, 0], id="nothing-to-change"),
        pytest.param([20, 20], id="both-changed"),  # 20 used to fail the job here
        pytest.param([20, 0], id="created-then-in-sync"),
        pytest.param([10, 0], id="drift"),
    ],
)
def test_apply_success_codes_run_both_tools(tmp_path, codes):
    code, calls, _ = _run_step(tmp_path, _step_script(*_APPLY), command="bunnyauto", codes=codes)
    assert code == 0
    assert "wired create-interfaces --apply --yes" in calls[0]
    assert "wired sync-interfaces --apply --yes" in calls[1]


@pytest.mark.parametrize("failure", [1, 2, 127])
def test_apply_stops_when_create_interfaces_fails(tmp_path, failure):
    code, calls, output = _run_step(
        tmp_path, _step_script(*_APPLY), command="bunnyauto", codes=[failure]
    )
    assert code == failure
    assert len(calls) == 1  # sync-interfaces never ran
    assert f"failed with exit code {failure}" in output
    assert "::error::" in output


def test_apply_fails_when_sync_interfaces_fails(tmp_path):
    code, calls, output = _run_step(
        tmp_path, _step_script(*_APPLY), command="bunnyauto", codes=[20, 2]
    )
    assert code == 2
    assert len(calls) == 2
    assert "::error::" in output


def test_apply_drift_is_a_warning(tmp_path):
    _, _, output = _run_step(tmp_path, _step_script(*_APPLY), command="bunnyauto", codes=[10, 0])
    assert "::warning::" in output
    assert "exited 10 (DRIFT)" in output


# ---------------------------------------------------------------------------
# The plan steps: ci_plan.py's exit code survives `| tee plan.md`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "step",
    [
        pytest.param(("plan.yml", "plan", "Plan against test"), id="test"),
        pytest.param(("apply.yml", "plan-prod", "Plan against prod"), id="prod"),
    ],
)
@pytest.mark.parametrize("ci_plan_code", [0, 1])
def test_plan_step_keeps_the_ci_plan_exit_code(tmp_path, step, ci_plan_code):
    code, calls, _ = _run_step(
        tmp_path, _step_script(*step), command="python", codes=[ci_plan_code]
    )
    assert code == ci_plan_code  # tee used to turn 1 ("a tool could not run") into 0
    assert "scripts/ci_plan.py" in calls[0]
    # the plan is published whether or not it could run
    assert "stub output" in (tmp_path / "plan.md").read_text()
    assert "stub output" in (tmp_path / "summary.md").read_text()
