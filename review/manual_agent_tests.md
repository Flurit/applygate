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
| T3.8 | Codex | trusted | root dir on 0.165.0 (known gap) | | |
