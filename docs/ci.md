# bunnyauto CI/CD

Three GitHub Actions workflows drive the network as code:

| Workflow | Trigger | What it does | Writes? |
|---|---|---|---|
| [`plan.yml`](../.github/workflows/plan.yml) | every PR | ruff + pytest, then **plan** `wired create-interfaces` + `wired sync-interfaces` against **test** and post the diff as a PR comment | no |
| [`apply.yml`](../.github/workflows/apply.yml) | push to `main` | plan against **prod**, then **apply** after a required reviewer approves the `production` environment | yes (prod NetBox) |
| [`nightly.yml`](../.github/workflows/nightly.yml) | 07:00 UTC daily | `wired backup` (redacted) + both `wired health` reports for **test** and **prod**, committed to the backups repo | no (backups repo only) |

The `bunnyauto` CLI is the same one you run locally — CI just passes `--env` and `--apply --yes` explicitly instead of prompting.
Commands are `bunnyauto --env <env> <category> <tool>`: every tool lives in a category
(`wired`, `wireless`, `security`, `netbox`) and only touches devices whose NetBox role
is in that category's branch **and** that carry the environment's tag. Run
`bunnyauto --env <env> netbox scope` to see exactly what each category reaches.

## One-time setup

### 1. Runner

`plan.yml`'s `quality` job runs on `ubuntu-latest` (no network access needed).
Every job that talks to NetBox or the switches uses **`runs-on: [self-hosted]`** —
register a [self-hosted runner](https://docs.github.com/actions/hosting-your-own-runners)
on a box inside the network with Python 3.11+ and `git`.

*Alternative:* change those jobs to `runs-on: ubuntu-latest` and add a VPN
connect step (Tailscale, WireGuard, OpenVPN) as the first step of each.

### 2. Repository secrets

`Settings → Secrets and variables → Actions → Secrets`

| Secret | Value |
|---|---|
| `NORNIR_USERNAME` / `NORNIR_PASSWORD` | the device (AAA) login — shared by both environments |
| `BUNNYAUTO_TEST_NB_TOKEN` | API token for the **test** NetBox |
| `BUNNYAUTO_PROD_NB_TOKEN` | API token for the **prod** NetBox |
| `BACKUPS_DEPLOY_KEY` | SSH **deploy key** (private half) with write access to the backups repo |

### 3. Repository variables

`Settings → Secrets and variables → Actions → Variables`

| Variable | Example |
|---|---|
| `BUNNYAUTO_TEST_NB_URL` | `https://netbox-lab.example.com` |
| `BUNNYAUTO_PROD_NB_URL` | `https://netbox.example.com` |
| `BACKUPS_REPO_SLUG` | `your-org/network-backups` |

`bunnyauto.yaml` is gitignored; `scripts/ci_write_env_file.py` regenerates it from
these two URL variables at the start of each job.

### 4. The `production` environment

`Settings → Environments → New environment → production`

- Add **Required reviewers** (yourself / the network team).
- `apply.yml`'s `apply-prod` job targets this environment, so it **pauses** after
  the prod plan is published and only runs once a reviewer approves.

No environment-scoped secrets are needed — the prod token is a repo secret so the
read-only `plan-prod` and nightly jobs can use it without an approval each time.
(The `plan.yml` `plan` job uses a `test` environment purely for grouping; create
it with no protection rules, or drop the `environment: test` line.)

### 5. The backups repository

Create an empty private repo (e.g. `network-backups`), add the **public** half of
`BACKUPS_DEPLOY_KEY` as a deploy key **with write access**, and set
`BACKUPS_REPO_SLUG`. The nightly job commits:

```
<env>/<year>/<month>/<day>/<hostname>/{<hostname>.cfg, *_environment.txt, *_interfaces.xlsx}
<env>/reports/<date>/{health-simple.xlsx, health-elaborate.xlsx}
```

Config `diff`s over time in that repo are the running record of the network.

## Day-to-day flow

1. Change something in NetBox (or in a device the pipeline reconciles from).
2. Open a PR. `plan.yml` comments what `wired sync-interfaces` / `wired create-interfaces`
   would change against **test**.
3. Merge. `apply.yml` plans against **prod** and waits.
4. A reviewer reads the prod plan and approves the `production` deployment.
5. `apply.yml` applies to the prod NetBox.
6. The nightly job keeps the backups repo current regardless.

## Exit codes and job results

Every `bunnyauto` command ends with an exit code that says how the run went
(`EXIT_CODES` in `bunnyauto/result.py`; the pipeline depends on these numbers, so
don't change them):

| Code | Status | Meaning |
|---|---|---|
| `0` | OK | ran; nothing needed changing |
| `10` | DRIFT | found changes but didn't make them (plan mode, the default) |
| `20` | CHANGED | made the changes (`--apply`) |
| `2` | PARTIAL | some devices worked, some failed (a mistyped command also exits `2`) |
| `1` | ERROR | could not run (bad config, NetBox unreachable, ...) |

GitHub runs each `run:` step with `bash -e`: the step stops at the first command
that exits with anything but `0`, the step fails, and the job's later steps are
skipped. `10` and `20` are both good outcomes, but a step that ran `bunnyauto`
directly would still fail on them. Here is how each workflow handles that.

**`apply.yml` → "Apply to prod NetBox"** runs each command through `run_bunnyauto`,
a small helper defined at the top of the step:

| Exit code | Result |
|---|---|
| `0`, `20` | success; the next command runs |
| `10` | success, plus a warning on the run page (with `--apply` this means changes were found but not written, which shouldn't happen) |
| `1`, `2`, anything else | the step fails with that code; the commands after it don't run |

So `wired sync-interfaces` only runs once `wired create-interfaces` has succeeded.

**The plan steps** (`plan.yml` → "Plan against test", `apply.yml` → "Plan against
prod") run `scripts/ci_plan.py`. It runs the tools with `--json` and has only two
exit codes of its own: `0` when every tool ran (drift and partial results appear in
the plan and don't fail it) and `1` when a tool could not run. Its output is piped
through `tee` to save `plan.md`. A pipe normally reports only its last command's
code, so the step starts with `set -o pipefail` to keep `ci_plan.py`'s. It publishes
the plan either way, then exits with that code. If the test plan fails, the PR
still gets its comment (so the PR shows why) but the check goes red. If the prod
plan fails, `plan-prod` fails and `apply-prod` never asks for approval.

**`nightly.yml`** runs `wired backup` and `wired health` directly. They never exit
`10` or `20`, only `0` (every device done), `2` (some devices unreachable) or `1`,
so they need no helper. A `2` or `1` stops its step at that command and skips every
step after it, **including "Commit and push"**. Nothing is committed for that
environment that night. The other environment still runs, because the matrix sets
`fail-fast: false`.

**Adding a command to a workflow:** anything that can exit `10` or `20` goes
through `run_bunnyauto` (copy the helper from `apply.yml`). That means every
`--apply` run, and any write tool in plan mode. A plain `bunnyauto ...` line is only
safe for a tool that exits `0` on success. If a line pipes into another command
(`| tee ...`), make sure the step has `set -o pipefail`, or the pipe hides the exit
code. `tests/test_ci_workflows.py` runs the apply step and both plan steps with
stand-in commands on every PR, so the `quality` job fails if their exit-code handling
breaks.
