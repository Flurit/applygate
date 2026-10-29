# Host capabilities

<!-- Generated from internal/hook/capabilities.go by `go generate ./internal/hook`. Do not edit by hand; TestHostsDocCurrent fails when this file is stale. -->

What each agent host does with seatbelt's PreToolUse hook, as verified live. `seatbelt hosts` prints the same table. A cell that says "not tested" was not verified; nothing in this table is a guess. T3 numbers refer to the cases in [review/manual_agent_tests.md](../review/manual_agent_tests.md) and the results in [review/T3_RESULTS.md](../review/T3_RESULTS.md).

| Capability | Claude Code (`seatbelt hook claude`) | Codex (`seatbelt hook codex`) |
|---|---|---|
| Can ask | yes: a hook "ask" shows Claude Code's permission prompt with seatbelt's reason (T3.1) | no: Codex parses but does not support "ask" (it fails the hook and runs the tool), so seatbelt enforces every ask as a block (T3.7 on 0.159.2 and 0.165.0) |
| Hook crashes, times out or binary missing | fails closed: the installed hook carries onFailure: "block", so a crashed, timed-out (30 s) or missing hook blocks the tool call (T3.4 missing binary, T3.5 timeout, T3.6 killed by a signal); needs Claude Code 2.1.295 or later, older versions fail open | fails open: Codex has no onFailure setting; a missing hook binary (exit 127) and a hook killed by a signal both let the command run (T3.8 chaos on 0.165.0); timeout: not tested. seatbelt recovers panics inside its own process and blocks, so the remaining fail-open case is a hook that does not start; use Codex's sandbox and approval settings as the backstop and run seatbelt doctor |
| Tools the installed matcher sees | shell: Bash; file writes: Write, Edit, MultiEdit, NotebookEdit; reads: Read, Grep; MCP calls: no (not in the matcher, not inspected) | matcher "*": shell: Bash with tool_input.command (captured); file writes: apply_patch with the patch text in tool_input.command (captured); reads: no separate read tool seen, Codex reads files through shell commands (not tested); MCP calls: mcp__<server>__<tool> with the raw arguments (from the source, not captured), not inspected |
| Per-command working directory reaches the hook | yes: the top-level cwd is the shell's directory at the time of the call and follows an earlier cd (hooks docs, read 2026-10-29); not tested live | no on 0.165.0: the top-level cwd is the session root and tool_input holds only command; the workdir the model passes to exec_command is dropped (captured 2026-10-29; source: exec_command.rs pre_tool_use_payload, hook_runtime.rs tool_hook_cwd). seatbelt reads tool_input.workdir, working_directory or cwd when a version sends one; otherwise it judges the command at the most protected tier under the session root (unknown_dir: most_protected, the default) and a cd or -chdir inside the command establishes the directory |
| Where settings are read from | project: <session cwd>/.claude/settings.json and settings.local.json, read from the launch directory only, not from ancestors (T3.1: launched from a subdirectory the hook never ran); user: ~/.claude/settings.json (hook install --scope user); managed: managed-settings.json (docs; not tested) | project: <session cwd>/.codex/hooks.json (hooks docs, read 2026-10-28; launching from a subdirectory not tested); user: ~/.codex/hooks.json (hook install --scope user; docs, not tested); managed: not tested |
| Trust step | none observed for a project hook (T3.1); not tested further | yes: hooks must be reviewed and trusted with /hooks in Codex before they run (T3.7); codex exec has --dangerously-bypass-hook-trust (source, not tested) |
| Ask under permission modes | default: prompt shown (T3.1); bypassPermissions: prompt still shown on 2.1.312, which is undocumented (T3.2b); dontAsk: no prompt can be shown, so seatbelt enforces ask as block (T3.2c); acceptEdits, plan: not tested | no ask in any mode: every ask is enforced as a block (T3.7); permission_mode under codex exec arrives as bypassPermissions (captured) |
| Verified on | Claude Code 2.1.312 on Linux, 2026-10-28 | Codex 0.159.2 (T3.7) and 0.165.0 (chaos tests, clean re-run, hook input capture) on Linux, 2026-10-28 and 2026-10-29 |
| Evidence | review/T3_RESULTS.md | review/T3_RESULTS.md, review/agent-trial/results/2026-10-29-codex-hook-payload/README.md |
| Live tests pending | T3.9 user-scope hook fires from a subdirectory: not tested; T3.11 planfile search: not tested | T3.9 user-scope hook fires from a subdirectory: not tested; T3.10 bare command in a disposable subdirectory under a root with a protected directory: not tested; T3.11 planfile search: not tested; hook timeout: not tested |

## Not supported

| Host | Status |
|---|---|
| Cursor | not supported: no adapter, no hook format; nothing tested |
| Copilot CLI | not supported: no adapter, no hook format; nothing tested |
| OpenCode | not supported: no adapter, no hook format; nothing tested |

How seatbelt handles an unknown command directory is in [policy.md](policy.md) (step 4) and [config.md](config.md) (`unknown_dir`); the launch-directory and fail-open limits are in [limits.md](limits.md).
