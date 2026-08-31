# bunnyauto CI/CD

Three GitHub Actions workflows drive the network as code:

| Workflow | Trigger | What it does | Writes? |
|---|---|---|---|
| [`plan.yml`](../.github/workflows/plan.yml) | every PR | ruff + pytest, then **plan** `create-interfaces` + `sync-interfaces` against **test** and post the diff as a PR comment | no |
| [`apply.yml`](../.github/workflows/apply.yml) | push to `main` | plan against **prod**, then **apply** after a required reviewer approves the `production` environment | yes (prod NetBox) |
| [`nightly.yml`](../.github/workflows/nightly.yml) | 07:00 UTC daily | `backup` (redacted) + both health reports for **test** and **prod**, committed to the backups repo | no (backups repo only) |

The `bunnyauto` CLI is the same one you run locally — CI just passes `--env` and `--apply --yes` explicitly instead of prompting.

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
2. Open a PR. `plan.yml` comments what `sync-interfaces` / `create-interfaces`
   would change against **test**.
3. Merge. `apply.yml` plans against **prod** and waits.
4. A reviewer reads the prod plan and approves the `production` deployment.
5. `apply.yml` applies to the prod NetBox.
6. The nightly job keeps the backups repo current regardless.
