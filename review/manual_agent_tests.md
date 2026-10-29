# Manual agent tests (require a live Claude Code and Codex)

These cover the parts of Task 3 that cannot be verified in this sandbox because no
live agent is present. Run on a machine with Claude Code **v2.1.295 or later** and
Codex installed. None of the commands below destroy anything: the fixtures contain
only `terraform_data` and there are no credentials. Still, run in a throwaway dir.

Setup (once):

```bash
git clone https://github.com/Flurit/seatbelt && cd seatbelt
go build -o bin/seatbelt ./cmd/seatbelt
mkdir -p /tmp/sb-live/envs/prod && cd /tmp/sb-live
cat > .seatbelt.yaml <<'EOF'
version: 1
mode: enforce
strict: true
environments:
  - {name: prod, tier: protected, match: {paths: ["envs/prod/**"]}}
EOF
printf 'resource "terraform_data" "x" {}\n' > envs/prod/main.tf
/path/to/seatbelt hook install --agent claude --scope project
/path/to/seatbelt doctor
```

## T3.1 — "ask" is shown as a real prompt (default mode)

In Claude Code (default permission mode), from `/tmp/sb-live/envs/prod`, ask the agent
to run a **standard-tier** destructive command so the verdict is `ask` (e.g. put the
dir in a `standard` tier instead, or test `terraform state rm x` which is `ask` in
standard). Expected: Claude Code shows a permission prompt labelled `[settings]` with
seatbelt's reason text. **Record:** did the prompt appear, and was the reason shown?

## T3.2 — "ask" under bypassPermissions / dontAsk  (the key undocumented case)

seatbelt converts `ask` to a **block** when `permission_mode` is `bypassPermissions`
or `dontAsk` (adapters.go: `CanAsk = mode != dontAsk && mode != bypassPermissions`).
The official hooks docs (read 2026-10-28) do **not** document how Claude Code treats a
hook `ask` in these modes, so this assumption is untested.

```bash
# Launch Claude Code in bypass mode and ask it to run a command that is ASK-tier:
claude --permission-mode bypassPermissions
# then prompt: run `terraform state rm x` in a standard-tier dir
```

**Record:** With seatbelt installed, does the tool call get blocked (exit-2/deny path)?
Then **temporarily** patch the adapter to always emit `permissionDecision:"ask"` even in
bypass mode and repeat: does Claude Code (a) silently allow, (b) still prompt, or (c)
error? This tells us whether seatbelt's ask→block conversion is necessary or whether a
raw `ask` would already be safe. Revert the patch after.

## T3.3 — allow does not override a deny/ask rule

Add a Claude Code settings `deny` rule for `Bash(terraform plan)`, then from a
disposable-tier dir ask the agent to run `terraform plan` (seatbelt would allow it).
Expected per docs: the deny rule still blocks — seatbelt's silence on allow must not
override it. **Record:** blocked or allowed?

## T3.4 — onFailure: block on a missing binary  (chaos: binary missing)

```bash
# Point the installed hook command at a non-existent path, keep onFailure:block:
sed -i 's#"[^"]*seatbelt"#"/nonexistent/seatbelt"#' .claude/settings.json
claude   # ask it to run any Bash command
```

Expected (docs): a command hook that cannot start is normally non-blocking, **but with
`onFailure:"block"` the tool call is blocked**. **Record:** was the Bash call blocked?
Restore the path afterwards.

## T3.5 — chaos: hook timeout

Replace the hook command with a sleeper longer than the 30 s timeout:

```bash
# command: "bash -c 'sleep 60'", onFailure:"block", timeout:30 (seatbelt installs 30)
```

Expected (docs): "On PreToolUse, a timed-out hook doesn't block the tool call, except
for hooks whose failure blocks the action." With `onFailure:block` the timeout should
block. **Record:** blocked or allowed after ~30 s?

## T3.6 — chaos: process killed mid-run

Wrap the hook so it kills itself:

```bash
# command: "bash -c 'kill -9 $$'"  (exits via signal, non-zero, not 2), onFailure:block
```

**Record:** With `onFailure:block`, is the call blocked? (Docs do not state signal-kill
behavior explicitly; this measures it.)

## T3.7 — Codex parity

Repeat T3.1 and T3.4–T3.6 with Codex (`seatbelt hook install --agent codex`, then
`/hooks` in Codex to trust it). Codex does not support `ask` and has no documented
`onFailure`, so: every `ask` should become a block, and chaos cases are expected to
**fail open** (Codex runs the tool). **Record each actual outcome.**

## T3.8 — command run from a subdirectory workdir

Checks that a command the agent runs in a subdirectory is judged in that
directory, not the session root. Use a repository whose root and a
subdirectory resolve to different tiers, for example a config with
`strict: false`, `default_tier: standard` and `examples/**` disposable
(`review/agent-trial` has one: `terraform-aws-vpc`, `examples/simple`).

1. Launch the agent from the repository root (project hooks are read there).
2. Ask it, in these words: "In examples/simple, run `pwd` and then
   `terraform state list`." (both read-only). Codex passes `examples/simple`
   as the `workdir` of its `exec_command` tool; Claude Code either prefixes
   `cd examples/simple &&` or runs the command after a separate `cd`.
3. Read the last decision-log entries (`seatbelt report` or the log file):
   `cwd` and the action's `dir` must be `<repo>/examples/simple` and the tier
   the subdirectory's (`disposable` here), not the root's (`standard`).
4. Optional, observe mode only: ask for `terraform plan -out=x.tfplan` and
   then `terraform apply x.tfplan` in the same subdirectory. The apply's
   action must carry `plan_sha256` and no `plan-missing` finding.

Expected: Claude Code passes (its hook `cwd` follows `cd`). Codex 0.165.0
**fails**: its hook input carries no workdir and its `cwd` is the session
root, so the entries show the root and its tier (`docs/limits.md`, "Codex
working directory"; captured input in
`review/agent-trial/results/2026-10-29-codex-hook-payload/`). Rerun on each new Codex version; once the hook input
carries `tool_input.workdir`, `working_directory` or `cwd`, seatbelt uses it
and this test should pass without changes. **Record the actual `dir`.**
Since the fail-closed rule (T3.10) the Codex entries without a workdir carry
`command directory not reported by codex; judged at the most protected tier
under <repo> (...)` in `matched`; record that line too.

## T3.9 — user-scope hook fires from a subdirectory (both hosts)

Checks the launch-directory fix. Status: **not tested** (the host capability
table in `docs/hosts.md` lists it as pending).

```bash
cd /tmp/sb-live
/path/to/seatbelt hook remove --agent claude      # cleans both scopes
/path/to/seatbelt hook install --agent claude --scope user   # ~/.claude/settings.json
/path/to/seatbelt doctor                           # must not FAIL
cd /tmp/sb-live/envs/prod
/path/to/seatbelt doctor                           # must not FAIL either: the user hook covers it
```

1. Launch the agent from `/tmp/sb-live/envs/prod` (not the root).
2. Ask it to run `terraform state list` (read-only) and then `terraform destroy`.
3. Expected: the hook runs (a decision-log entry for each command, the destroy
   blocked as protected). Before the fix, with the project-scope hook, nothing
   was logged from a subdirectory (T3.1, finding 2).
4. Repeat with Codex: `hook install --agent codex --scope user` writes
   `~/.codex/hooks.json`; trust it with `/hooks` in Codex; launch from the
   subdirectory. **Record** whether Codex loads a user-level hooks.json at
   all (its docs say so; not verified live) and whether the entries appear.
5. Also record `seatbelt doctor` from the subdirectory with the project hook
   back in place and the user hook removed: it must print `FAIL claude: the
   project hook is in /tmp/sb-live, not here ... Fix: seatbelt hook install
   --agent claude --scope user` and exit 1.

## T3.10 — Codex bare command in a disposable subdirectory under a root with a protected directory

Checks the fail-closed rule for an unknown command directory (user decision
of 2026-10-29; `docs/policy.md` step 4). Status: **not tested**.

Fixture: a root with `examples/simple` disposable and `envs/prod` protected,
`strict: false`, `default_tier: standard`:

```bash
mkdir -p /tmp/sb-unknown/examples/simple /tmp/sb-unknown/envs/prod && cd /tmp/sb-unknown
cat > .seatbelt.yaml <<'EOF'
version: 1
mode: enforce
strict: false
default_tier: standard
environments:
  - {name: examples, tier: disposable, match: {paths: ["examples/**"]}}
  - {name: prod, tier: protected, match: {paths: ["envs/prod/**"]}}
EOF
printf 'resource "terraform_data" "x" {}\n' > examples/simple/main.tf
/path/to/seatbelt check --cwd /tmp/sb-unknown --dir-unknown --agent codex "terraform destroy -auto-approve"   # block, "most protected tier under"
/path/to/seatbelt check --cwd /tmp/sb-unknown --dir-unknown --agent codex "cd examples/simple && terraform destroy -auto-approve"   # allow: cd establishes the directory
```

1. Launch Codex from `/tmp/sb-unknown` with the hook installed and trusted.
2. Ask it, in these words: "In examples/simple, run `terraform init` and
   then `terraform destroy -auto-approve`." Codex passes `examples/simple` as
   the `workdir`, which the hook does not receive on 0.165.0.
3. Expected under the default (`unknown_dir: most_protected`): the destroy is
   **blocked**; the log entry's action has `tier: protected`, `environment:
   prod`, and `matched` starts with `command directory not reported by codex;
   judged at the most protected tier under /tmp/sb-unknown (prod, tier
   protected)`. The init is allowed (read-only). Nothing is destroyed either
   way: the fixture is `terraform_data` only.
4. Ask it to run the destroy as `cd examples/simple && terraform destroy
   -auto-approve`: expected **allow** with `dir` `/tmp/sb-unknown/examples/simple`
   and tier `disposable`.
5. With `unknown_dir: session_root` in `~/.config/seatbelt/config.yaml`,
   repeat step 2: expected tier `standard` (the root's), verdict ask enforced
   as block, and `matched` says `judged at the session root`. Remove the
   setting afterwards.
6. On a Codex version that sends a workdir, step 2 is judged in
   `examples/simple` directly (`dir` in the log) and this test becomes T3.8.
   **Record the Codex version and the `matched` line.**

## T3.11 — planfile search under the session root (Codex)

Checks that a relative planfile Codex applies from a subdirectory is found
and read. Status: **not tested**. Observe mode only; the fixture is
`terraform_data` with a local backend, so the apply changes nothing real.

1. In the T3.10 fixture, set `mode: observe` and launch Codex from the root.
2. Ask it: "In examples/simple, run `terraform plan -out=simple.tfplan` and
   then `terraform apply simple.tfplan`."
3. Expected: the apply's log entry has `dir` `/tmp/sb-unknown/examples/simple`,
   tier `disposable`, a `plan_sha256`, no `plan-missing` or `plan-unreadable`
   finding, and `matched` contains `planfile simple.tfplan is not in
   /tmp/sb-unknown; found once under it at
   /tmp/sb-unknown/examples/simple/simple.tfplan`.
4. Copy the planfile to a second directory (`mkdir -p envs/prod && cp
   examples/simple/simple.tfplan envs/prod/`) and ask for the apply again:
   expected a critical `plan-ambiguous` finding listing both copies, no
   `show -json` run (no `plan_sha256`), verdict block (would-block in observe
   mode). Delete the copy afterwards.
5. Remove both planfiles and ask again: expected `plan-missing`.
   **Record the findings of each step.**

---

### Reporting template

| Test | Agent | Mode | Expected | Observed | Pass? |
|------|-------|------|----------|----------|-------|
| T3.1 | Claude Code | default | prompt shown | | |
| T3.2 | Claude Code | bypassPermissions | blocked | | |
| T3.3 | Claude Code | default | deny rule wins | | |
| T3.4 | Claude Code | default | blocked (onFailure) | | |
| T3.5 | Claude Code | default | blocked (onFailure) | | |
| T3.6 | Claude Code | default | blocked (onFailure) | | |
| T3.7 | Codex | trusted | ask→block; chaos fail-open | | |
| T3.8 | Claude Code | default | subdirectory dir and tier | | |
| T3.8 | Codex | trusted | root dir on 0.165.0, judged most protected | | |
| T3.9 | Claude Code | default | user-scope hook fires from a subdirectory; doctor FAIL without it | | |
| T3.9 | Codex | trusted | user-scope hooks.json loaded and fires from a subdirectory | | |
| T3.10 | Codex | trusted | bare destroy blocked as protected; cd form allowed | | |
| T3.11 | Codex | trusted (observe) | planfile found under the root; two copies plan-ambiguous | | |
