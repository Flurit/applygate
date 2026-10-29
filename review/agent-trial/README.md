# Agent-driven observe-mode trial

The roadmap's v1 gate asks for an observe-mode trial on 5 real repositories
with false positives under 5%. [docs/oss-corpus-trial.md](../../docs/oss-corpus-trial.md)
is a static stand-in: it replayed the commands five public Terraform
repositories document, but no agent ran and no saved plan was applied, so the
plan gate was never exercised.

This directory is the next step: the same five repositories, cloned into a
throwaway container with no cloud credentials, with Claude Code and Codex
doing realistic infrastructure tasks in observe mode, and LocalStack standing
in for AWS so that saved-plan applies, destroys and replaces go through the
real plan-gate path (`terraform show -json` on a real planfile) with zero
cloud exposure.

It is an **agent-driven trial, not a team trial**: the agents are driven by
one person working a fixed task list, not by a team doing its own work. The
wording to use in `docs/project/ACCEPTANCE.md` is:

> Agent-driven observe-mode trial on 5 public repositories (not a team
> trial): Claude Code and Codex worked a fixed task list in clones of the
> five repositories from the static corpus trial, in observe mode, with
> LocalStack as the only AWS endpoint and no cloud credentials. Every ask and
> block was reviewed by hand.

## Safety rules

These are hard rules for anyone running or changing this harness.

1. **Never run `terraform apply` or `terraform destroy` against anything but
   LocalStack or a local-only backend.** The container's only AWS endpoint
   is the LocalStack sidecar; the plan-gate stack pins dummy keys and an
   `endpoints` block in the provider itself, and `run-plangate.sh` refuses
   to start unless the environment holds exactly LocalStack's dummy values.
2. **Never touch real cloud credentials.** No AWS profiles, no environment
   keys, no host credential mounts. The compose file sets only
   `AWS_ACCESS_KEY_ID=test`, `AWS_SECRET_ACCESS_KEY=test` and
   `AWS_ENDPOINT_URL=http://localstack:4566`, points the AWS config and
   credentials files at `/dev/null`, and disables the instance metadata
   lookup. Nothing from `~/.aws` is mounted. If you need a credential for
   something, this is the wrong harness.
3. **The scenario packs under `harness/` are corpora of destructive
   commands.** They are replayed as synthetic hook events only (`seatbelt
   selftest`, `harness/run.py`) and must never be executed. Nothing here
   reads them.
4. Work lands through a pull request to `main`; nothing is pushed to `main`
   directly.

The agents themselves run with their default permission settings inside the
container, as a user would run them. Observe mode means seatbelt logs every
decision and enforces none, so the agent's own prompts are the only brake;
that is why nothing in the container can reach a real cloud.

## What is in here

| File | Purpose |
|---|---|
| `Dockerfile` | The trial image: seatbelt v0.1.3 installed by the repository's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require` (cosign keyless signature on `checksums.txt`, then sha256); Terraform 1.16.1 and cosign checksummed against their published sums; Claude Code and Codex from npm, pinned; the five repositories at the commits in `review/oss-corpus/repos.txt`, each with its trial config as `.seatbelt.yaml` switched to `mode: observe` and both hooks installed by `seatbelt hook install`. |
| `compose.yaml` | The trial container plus a LocalStack 4.14.0 sidecar (not published on the host). Named volumes keep the agents' sign-in state, the decision log, the provider cache and the clones between runs. |
| `tools/reset-repos.sh` | Resets the five clones to their pinned commits between agents (keeps the harness files and the log). |
| `tools/setup-repos.sh` | Runs at build time: clones at the pinned commits with git hooks disabled, verifies the commit, writes the observe-mode config, installs the hooks. Refuses to run with any AWS credential in the environment. |
| `tasks.md` | The fixed task list per repository: a provider bump, a new module, a rename, "clean up the dev environment", a saved-plan apply, and two or three that should legitimately ask or block in a protected tier. |
| `plangate/` | The plan-gate exercise: a small stack against LocalStack (S3 bucket with versioning, a security group, a DynamoDB table) and `run-plangate.sh`, which produces a create plan and then flipped delete, replace, protection-removal and exposure plans, and runs each through `seatbelt plan-check` and through the hook path for `terraform apply <planfile>`. Needs no agent. |
| `collect.sh` | Gathers the decision log, `seatbelt report`, `seatbelt doctor` per clone, the agents' diffs, versions and the plan-gate output into `results/<date>/`, and writes `summary.md`, the hand-review template. |
| `tools/summarize.py` | Builds `summary.md` from a collected directory. |
| `results/<date>/` | One directory per collected run: the evidence only; `raw/` under it is gitignored. |

## How to run

Needs Docker with Compose v2 on the host, and nothing else (python3 for
`collect.sh`). Run everything from the repository root.

### 1. Build the image and start LocalStack

```bash
docker compose -f review/agent-trial/compose.yaml build
```

```bash
docker compose -f review/agent-trial/compose.yaml up -d localstack
```

The build is the install check: `install.sh` must verify the release
signature (the build fails otherwise), `seatbelt selftest` must pass on the
installed binary, and `setup-repos.sh` must reach the pinned commit of every
repository.

### 2. Confirm install and doctor in each clone

```bash
docker compose -f review/agent-trial/compose.yaml run --rm trial sh -c 'for d in /work/*/; do [ -d "$d/.git" ] || continue; echo "== $d"; (cd "$d" && grep ^mode: .seatbelt.yaml && seatbelt doctor); done'
```

Each clone should show `mode: observe`, hooks installed for claude and codex
at project scope, and a passing selftest. The launch-directory caveat from
[docs/limits.md](../../docs/limits.md) applies: Claude Code and Codex read
project settings only from the directory they are launched in, so **launch
the agent from the clone's root** (`/work/<repo>`), never from a
subdirectory. `seatbelt doctor` run from a subdirectory warns about this;
run from the root it is clean.

### 3. Run the plan-gate exercise (no agent)

```bash
docker compose -f review/agent-trial/compose.yaml run --rm trial sh /work/plangate/run-plangate.sh
```

It initialises the stack (downloads the AWS provider into the cached volume),
plans and applies a create to LocalStack in the `prod` (protected) and
`staging` (standard) workspaces, then plans a no-op, a forced bucket replace,
versioning suspended, `force_destroy` on, port 22 open to the world, and a
full destroy, and sends each through `plan-check` and through
`seatbelt hook claude` / `seatbelt hook codex` as a `terraform apply
<planfile>` event. It also sends a plan made in the other workspace
(workspace mismatch), a missing planfile and a garbage planfile. Finally it
applies the destroy plans to LocalStack so the sidecar is clean. The verdict
table lands in `/work/plangate/out/verdicts.md` and the per-case output in
`/work/plangate/out/raw/`; `collect.sh` copies both (the latter to `raw/`).

### 4. Drive the agent sessions

Open a shell in the trial container:

```bash
docker compose -f review/agent-trial/compose.yaml run --rm trial
```

Inside it, sign in once per agent (the sign-in state lives in the
`claude-state` and `codex-state` volumes, never on the host):

```bash
claude
```

Claude Code opens its sign-in flow on first run. For Codex:

```bash
codex login
```

Then, for each task in `tasks.md`, `cd /work/<repo>` and start the agent
there, give it the prompt word for word, let it work, and note the task id
and start time. For Codex, run `/hooks` once per clone to trust the hook
(Codex refuses untrusted hooks; `docs/limits.md`). Do not steer beyond the
prompt. Observe mode logs every decision to
`~/.local/state/seatbelt/decisions.jsonl` in the container and enforces
none.

### 5. Collect and review

From the host:

```bash
review/agent-trial/collect.sh --agent "Claude Code 2.1.312" --agent "Codex 0.165.0"
```

This writes `review/agent-trial/results/<date>/` with the decision log,
`versions.txt`, `doctor-summary.txt`, `plangate/` and `summary.md`, and the
raw per-case output under `raw/` (not committed). Then review `summary.md`
by hand: fill the "False positive?"
column of every ask and block with `expected`, `fp-policy`, `fp-analyzer`,
`fp-environment`, `debatable` or `miss` (the labels from the static trial's
`label.py`), fill the task log, and compute the per-repository rate. Commit
the directory.

### Resetting the clones between agents

Each agent should start from the pinned commits, not from the previous
agent's edits. After `collect.sh` (which saves the edits as
`raw/diff/<repo>.patch`), run from the host:

```bash
review/agent-trial/tools/reset-repos.sh
```

It resets every clone to the commit in `review/oss-corpus/repos.txt` and
removes untracked files, keeping `.seatbelt.yaml`, the hook configs, the
provider caches and the decision log. It does not clean LocalStack or state
files an apply left behind; destroy those from inside the container if it
matters.

### Resetting everything

`docker compose -f review/agent-trial/compose.yaml down -v` removes the
containers and every volume, including the agents' sign-in state, the
decision log and the agents' edits. Collect first.

## How results are recorded

Only evidence is committed. `collect.sh` writes `results/<date>/` with:

- `summary.md`: the record of one run, in the style of
  `review/T3_RESULTS.md`: seatbelt version, agent names and versions, date,
  machine, counts of allow/ask/block per repository, every ask and block
  listed for hand review with a false-positive verdict column, the task log,
  `seatbelt report`, the doctor summary and the plan-gate verdicts.
- `decisions.jsonl`: the observe-mode decision log (secrets already
  redacted by seatbelt).
- `versions.txt` and `doctor-summary.txt` (one line per clone, plus the
  launch-directory check from a subdirectory).
- `plangate/verdicts.md`, `verdicts.jsonl`, `meta.txt` and
  `decisions.jsonl` from the plan-gate exercise.

Everything per case goes to `results/<date>/raw/`, which `results/.gitignore`
keeps out of git: `report.txt`, `doctor/<repo>.txt`, `diff/<repo>.patch`,
and `plangate/` with every hook stdout/stderr, plan JSON, plan-check output
and the init and apply logs. `run-plangate.sh` writes the same split inside
the container (`out/` and `out/raw/`). The verdict tables summarise the raw
files; regenerate them by rerunning the exercise.

One exception, kept by hand: `results/2026-10-29/plangate/fixtures/` holds
the `terraform show -json` output of the prod create and destroy plans from
the first run. They are the only AWS-provider-generated plan JSON in the
repository (the plan-gate tests use hand-written fixtures, which
`docs/project/ACCEPTANCE.md` lists as an assumption), so they are worth
keeping as reference shapes.

`docs/project/ACCEPTANCE.md` gets a section "Agent-driven observe-mode
trial" that quotes the measured counts and rate per repository, names the
agent versions, and states in the first sentence that this is an
agent-driven trial, not a team trial. It must not claim numbers that were
not measured; agent runs that have not happened are marked "pending,
requires interactive agent sign-in".

## What this trial does not show

- How a team's own commands and habits interact with the policy. The task
  list is fixed and written by the seatbelt authors.
- Enforcement friction: observe mode never blocks, so the agents never had to
  recover from a block. T3 (`review/T3_RESULTS.md`) covers enforcement live.
- Anything behind a real backend: the clones' Terraform Cloud and S3 backends
  are unreachable by design, so `init` in those directories fails and the
  agents' attempts around that are part of what is logged.
- Providers other than AWS, and MCP tool calls (`docs/limits.md`).
