# Live-agent test results (T3.x)

> The project was renamed from seatbelt to applygate on 2026-10-29; the records below predate the rename and keep the old name where they describe those builds.

Date: 2026-10-28. Tester: Sumant Thakur (one run per case, one machine, Linux).
Binary: `seatbelt` built from main after PRs #1-#3 (`seatbelt_version: dev`).
Agents: Claude Code 2.1.312, Codex 0.159.2 (first T3.7 run) and 0.165.0 (chaos tests and clean re-run).
Fixture: `/tmp/sb-live`, `.seatbelt.yaml` with `envs/prod/**` protected, `envs/staging/**` standard, mode enforce, strict true. No cloud credentials in the shell. `terraform_data` resources only.

## Results

| Test | What was checked | Result |
|---|---|---|
| T3.1 | Claude Code shows an approval prompt for an `ask` verdict (staging `state rm`) | Pass, after launching Claude Code from `/tmp/sb-live`. From a subdirectory the hook never ran (see finding 2). |
| T3.2a | Unmodified binary in `bypassPermissions`: `ask` becomes a block | Pass (blocked, logged `enforced: block`). |
| T3.2b | Raw `ask` (patched binary, `CanAsk: true`) in `bypassPermissions` | Claude Code 2.1.312 still shows the approval prompt. The conversion to block is not needed there (finding 1). |
| T3.2c | `dontAsk` mode | Pass. Blocked by the ask-to-block conversion, since no prompt can be shown. |
| T3.3 | Claude `permissions.deny` rule beats a hook `allow` | Pass. The deny rule won. Ran in auto mode. |
| T3.4 | Hook binary missing, `onFailure: "block"` | Pass. Command blocked. |
| T3.5 | Hook hangs past timeout (`sleep 60`), `onFailure: "block"` | Pass. Command blocked. |
| T3.6 | Hook killed by signal (`kill -9`), `onFailure: "block"` | Pass. Command blocked. |
| T3.7 | Codex: `ask` becomes block, `block`, `allow` | Pass on 0.159.2 and again on 0.165.0 with a clean `.codex/hooks.json`. Decision log entries carry `"agent":"codex"`, and the ask entry has `enforced: block` plus the note "this agent cannot show an approval prompt here". |
| T3.8 (Codex chaos) | Missing binary | **Fails open.** "Hook failed: hook exited with code 127", command ran. |
| T3.8 (Codex chaos) | Killed by signal | **Fails open.** "Hook failed: hook exited without a status code", command ran. |
| T3.8 (Codex chaos) | Timeout | Not tested. |

## Findings

1. **`ask` in `bypassPermissions`.** On Claude Code 2.1.312 a hook `ask` is honoured even in bypass mode, so the adapter's `CanAsk: false` for `bypassPermissions` turns a prompt into a hard block unnecessarily. This behavior is undocumented, so it may change between versions. Keep the conversion for `dontAsk`.
2. **Launch directory.** Claude Code reads project settings only from the session's primary working directory. Launching from a subdirectory silently runs without the hook. `doctor` and the docs should say so.
3. **Codex fails open** when the hook is missing or killed. There is no `onFailure` equivalent. Codex shows the failure in the transcript and as a warning, but the command still runs.
4. **A failed hook does not override another hook's block** on Codex. With a broken extra hook and seatbelt both present, seatbelt's block still held and allowed commands still ran. (The merged-config explanation is likely but the file contents were not captured.)
5. **Unrelated Codex warning:** `priority` service tier not supported for the model. Not a seatbelt issue.

## Not covered

- Codex timeout behavior.
- macOS and Windows.
- Cursor and other agents.
- Claude Code versions other than 2.1.312, and the `ask`-in-bypass behavior on future versions.
- Real cloud resources (by design: replay-only and `terraform_data` fixtures).

## v0.6.0 re-test, headless part (2026-11-09 and 2026-11-11)

Binary: applygate built from main at `965797a` (`applygate dev`). macOS 26.7.1. Claude Code 2.1.314, Codex 0.166.0. Fixture: a fresh git repository copied from `harness/pack/fixtures/repo` (`envs/prod` protected, `envs/staging` standard, `envs/dev` disposable, trusted config). The hooks were installed with `applygate hook install --scope project`, with `XDG_CONFIG_HOME` and `XDG_STATE_HOME` added to the hook command so applygate's config, trust store and log stayed in a scratch directory. No cloud credentials were used. Each case asked a model (`claude -p --model haiku`, or `codex exec`) to run one exact command; the verdict was read from applygate's decision log and the tool result.

### Claude Code 2.1.314 (`claude -p`)

| Case | Command | Mode | Hook verdict (enforced) | What Claude Code did | Result |
|---|---|---|---|---|---|
| C1 | `ls envs/prod` | default | allow (allow) | ran | Pass |
| C2 | `cd envs/prod && terraform destroy -auto-approve` | default | block (block) | not run; the block reason reached the model | Pass |
| C3 | `cd envs/staging && terraform state rm aws_instance.x` | default | ask (ask) | not run: in `-p` there is no one to answer, and the ask came back to the model as an error | Pass (headless) |
| C3b | the same | acceptEdits | ask (block) | not run | Pass |
| C4 | `cd envs/dev && terraform destroy -auto-approve` | default | allow (allow) | ran ("No objects need to be destroyed") | Pass |
| C5 | `rm -rf .claude` | default | block (block), guard-tampering | not run | Pass |
| C6 | `git pull` | default | ask (ask) | not run | Pass (the fixture has state files, so state surgery asked first) |
| C7 | `git checkout HEAD -- .applygate.yaml` | default | block (block), guard-tampering | not run | Pass |
| C8 | Write `.claude/settings.local.json` | default | block (block), guard-tampering | not written | Pass |
| C9 | base64-decoded `terraform destroy` piped to `sh` in prod | default | none | the model declined to run it, so the hook was not reached | Not tested live (covered by `selftest`) |
| C10 | `cd envs/prod && git status --short` | default | allow (allow) | ran | Pass |
| T3.4 | hook binary missing | default | n/a | blocked: "failed; blocking because onFailure is block" | Pass |
| T3.5 | hook times out (5 s) | default | n/a | blocked: "timed out; blocking because onFailure is block" | Pass |
| T3.6 | hook killed by a signal | default | n/a | blocked | Pass |

### Codex 0.166.0 (`codex exec`, 2026-11-11)

On 2026-11-09 the hook never ran: Codex 0.166.0 runs a hook only after a person has reviewed it with `/hooks`, which records a `trusted_hash` per hook entry under `[hooks.state]` in `~/.codex/config.toml`, and an untrusted hook is skipped without a message in `codex exec`, at project scope and at user scope alike (finding 1). `--dangerously-bypass-hook-trust` was not used. On 2026-11-11 a person trusted the fixture's project hook with `/hooks` (fixture moved to `/private/tmp/ag-retest`), and the cases ran with `codex exec --sandbox workspace-write`. The hash Codex stored matches the one `applygate doctor` computes (a second known answer in `cmd/applygate/codextrust_test.go`).

Codex does not report a command's directory, so applygate judges a command at the most protected tier it could be in under the root; an absolute `cd` sets the directory, a relative one does not ([limits.md](../docs/limits.md), "Codex working directory"). The fixture's root is `strict: true`.

| Case | Command | Hook verdict (enforced) | What Codex did | Result |
|---|---|---|---|---|
| X1 | `ls envs/prod` | allow (allow) | ran | Pass |
| X2 | `cd envs/prod && terraform destroy -auto-approve` | block (block) | not run; the reason reached the model | Pass |
| X3 | `cd envs/staging && terraform state rm aws_instance.x` | block (block): the relative `cd` leaves the directory unknown, so state surgery is judged protected | not run | Pass (stricter than Claude Code's ask, as designed) |
| X4 | `rm -rf .claude` | block (block), guard-tampering | not run; first attempt: the model did not issue the command, so the hook was not reached; second attempt blocked | Pass |
| X5 | `git pull` | ask (block), hook-rewrite | not run | Pass |
| X6 | `git checkout HEAD -- .applygate.yaml` | block (block), guard-tampering | not run | Pass |
| X7 | `cd envs/prod && git status --short` | ask (block), complex-shape: git in an unknown directory under a strict root | not run | As designed; friction (finding 4) |
| T3.8a | hook binary missing | n/a | ran | Fails open (as documented) |
| T3.8b | hook runs past its 30 s timeout | n/a | ran, after the timeout | Fails open (first live test of the timeout) |
| T3.8c | hook killed by a signal | n/a | ran | Fails open (as documented) |
| T3.8d | hook exits 1 with no output | n/a | ran | Fails open |

The failure cases replaced the binary the trusted command runs (missing, `sleep 90`, `kill -9 $$`, `exit 1`) instead of editing `hooks.json`, since an edit changes the trusted hash and Codex would skip the hook for that reason instead. The binary was restored and its checksum checked.

### Claude Code 2.1.322, interactive (2026-11-11)

Run by a person in the same fixture. Claude Code had updated to 2.1.322, whose interactive sessions start in auto mode (the starting mode since 2.1.283, per its permission-modes docs).

| Case | Command | Mode | Hook verdict (enforced) | What Claude Code did | Result |
|---|---|---|---|---|---|
| T3.1 | `cd envs/staging && terraform state rm aws_instance.x` | default (`--permission-mode default`) | ask (ask) | permission prompt with applygate's full reason; the person chose No | Pass |
| I1 | the same | auto (the new starting mode, no flag) | ask (block) | blocked: "this agent cannot show an approval prompt here" | Finding 6, fixed |
| I2 | the same | plan, run after the plan was approved | ask (block) | blocked | Pass (ask is enforced as block in plan) |
| I3 | the same | auto (`--permission-mode auto`) | ask (block) | blocked | Finding 6, fixed |
| T3.9 | `terraform destroy -auto-approve` from `envs/prod`, user-scope hook only (`CLAUDE_CONFIG_DIR` with the fixture's hook) | auto | block (block) | blocked as a prod destroy; a read-only `ls`/`cat`/`terraform workspace show` before it was allowed | Pass |
| P1 | `touch probe-marker` in a scratch repository whose hook always asks (not applygate) | auto | ask | prompt shown with the hook's reason; the hook input's `permission_mode` was `"auto"`; the person chose No and the file was not created | Shows auto mode prompts for a hook's ask |


### Findings

1. **A Codex hook that has not been trusted with `/hooks` does not run, and nothing in applygate says so.** `hook install` prints a note, but `applygate doctor` does not check `[hooks.state]`. Every reinstall changes the hook entry (the v0.6.0 upgrade notes ask for one), and Codex then skips the hook until someone runs `/hooks` again. Until then, Codex sessions run unguarded while `doctor` reports the hook as installed. **Fixed:** `doctor` now recomputes Codex's hash for each applygate entry and says whether Codex will run it (`cmd/applygate/codextrust.go`; the hash matches two that Codex 0.166.0 stored, on 2026-10-30 and 2026-11-11).
2. **Claude Code fails closed on a missing, hung or killed hook** on 2.1.314, as on 2.1.312.
3. **An ask in headless Claude Code (`-p`) is not run:** the reason reaches the model as a tool error.
4. **In Codex, a relative `cd` makes the command protected.** `cd envs/dev && terraform destroy` and `cd envs/prod && git status` are judged at the most protected tier under the root, because Codex does not say where the command starts. This is the documented fail-closed reading; the cost is friction for models that `cd` with relative paths. `unknown_dir: session_root` in the user config trades it back. The capability table said "a cd or -chdir … establishes the directory"; it now says only an absolute one does.
5. **Codex fails open on every hook failure tried**, including a timeout (not tested before) and a plain `exit 1`. Unchanged and documented: Codex has no `onFailure` setting, so its sandbox and approval settings remain the backstop.
6. **On Claude Code 2.1.322 every ask was a block by default.** Interactive sessions now start in auto mode, and applygate let an ask reach Claude Code only in `default` and `bypassPermissions`, enforcing it as a block in every untested mode. A user who changed nothing would never see an applygate prompt: `git pull` in a configured repository, state surgery in staging and every other ask would be blocked with no way to approve. Claude Code's hooks docs say a PreToolUse ask in auto mode goes to the permission prompt and the classifier does not decide it, and P1 and T3.1 confirmed the prompt. **Fixed:** `auto` now shows the prompt like `default` (`internal/hook/adapters.go`); `acceptEdits` and `plan` still enforce ask as block.

### Not tested

- Claude Code: whether plan or acceptEdits mode would show the prompt (applygate keeps enforcing ask as block there); the `*` matcher with Monitor and PowerShell.
- Codex: a user-scope hook launched from a subdirectory (T3.9); the planfile search.
