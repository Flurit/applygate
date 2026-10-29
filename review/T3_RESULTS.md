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
