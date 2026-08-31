#!/usr/bin/env python3
"""Run bunnyauto's mutating tools in plan mode and format a Markdown report.

Used by the CI workflows to show what *would* change before anything is applied.
Runs each tool via ``bunnyauto --env <env> <tool> --json``, parses the structured
result, and prints one Markdown block to stdout.

Exit code:
  0  every tool ran (whether or not it found drift)
  1  a tool hard-errored (bad config, NetBox unreachable, ...)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

# Mutating tools, in the order the pipeline applies them.
PLAN_TOOLS = ("create-interfaces", "sync-interfaces")

_STATUS_EMOJI = {
    "ok": "✅",
    "drift": "📝",
    "changed": "🟦",
    "partial": "⚠️",
    "error": "❌",
}


def _run_tool(env: str, tool: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, "-m", "bunnyauto", "--env", env, "--json", tool],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        # bunnyauto --json always prints a JSON object, even on error; fall back
        # only if something upstream (e.g. the runner) truncated stdout.
        tail = (proc.stderr or proc.stdout or "no output").strip().splitlines()
        payload = {
            "status": "error",
            "summary": _strip_ansi(tail[-1]) if tail else "no output",
            "changes": [],
            "exit_code": proc.returncode or 1,
        }
    return proc.returncode, payload


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text).strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ci_plan")
    parser.add_argument("--env", required=True)
    args = parser.parse_args(argv)

    lines: list[str] = [f"## bunnyauto plan — `{args.env}`", ""]
    hard_error = False
    any_drift = False

    for tool in PLAN_TOOLS:
        code, payload = _run_tool(args.env, tool)
        status = str(payload.get("status", "error"))
        emoji = _STATUS_EMOJI.get(status, "❔")
        summary = payload.get("summary", "(no summary)")
        changes = payload.get("changes", []) or []

        lines.append(f"### {emoji} `{tool}` — {summary}")
        if status == "error":
            hard_error = True
        if status in {"drift", "partial"}:
            any_drift = True
        if changes:
            lines.append("")
            lines.append("<details><summary>Planned changes</summary>")
            lines.append("")
            lines.append("```")
            lines.extend(str(change) for change in changes[:200])
            if len(changes) > 200:
                lines.append(f"... and {len(changes) - 200} more")
            lines.append("```")
            lines.append("</details>")
        lines.append("")

    if hard_error:
        lines.append("> ❌ One or more tools could not run — see the job log.")
    elif any_drift:
        lines.append("> 📝 Drift detected. Review the planned changes above.")
    else:
        lines.append("> ✅ NetBox is in sync with the network.")

    print("\n".join(lines))
    return 1 if hard_error else 0


if __name__ == "__main__":
    sys.exit(main())
