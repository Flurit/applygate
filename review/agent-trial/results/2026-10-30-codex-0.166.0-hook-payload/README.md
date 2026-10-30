# Codex 0.166.0 PreToolUse hook input, captured 2026-10-30

Why: on macOS the decision log showed Codex 0.166.0 shell commands arriving
with `cwd` set to the command's directory, unlike 0.165.0 (see
`../2026-10-29-codex-hook-payload/README.md`, where `cwd` was always the
session root). This capture shows the exact input.

How: macOS 26.7.1, Codex 0.166.0 (`permissions: YOLO mode`, so
`permission_mode` is `bypassPermissions`), launched from
`/private/tmp/ag-capture` with a project-scope `.codex/hooks.json` whose hook
was a script that wrote its stdin to a file and exited 0 (allow). applygate was
not involved. The hook was trusted with `/hooks`. The fixture was one
`examples/simple/main.tf` with a `terraform_data` resource. The
`transcript_path` field (a path under `~/.codex/sessions`) is omitted below;
nothing else was changed and no secrets appear.

## Prompt 1: "In examples/simple, run pwd. Do nothing else and do not read any files."

```json
{"session_id":"01a18bcb-3949-7101-a944-612b55abde49","turn_id":"01a18bcb-86e4-7a02-ac2c-95797ebe16c4","cwd":"/private/tmp/ag-capture/examples/simple","hook_event_name":"PreToolUse","model":"gpt-6-luna","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"pwd"},"tool_use_id":"exec-fadbef2a-c67b-4997-841c-309f9a29e1b4"}
```

The session root was `/private/tmp/ag-capture`; the top-level `cwd` is the
directory the model ran the command in. `tool_input` has `command` only: no
`workdir`, `working_directory` or `cwd` field.

## Prompt 2: "Using the apply_patch tool, append the single line `# capture test` to the end of examples/simple/main.tf. Do not run any shell command and do not read any other file."

```json
{"session_id":"01a18bcb-3949-7101-a944-612b55abde49","turn_id":"01a18bcb-fc61-70c2-84d0-702372afa430","cwd":"/private/tmp/ag-capture","hook_event_name":"PreToolUse","model":"gpt-6-luna","permission_mode":"bypassPermissions","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: /private/tmp/ag-capture/examples/simple/main.tf\n@@\n+# capture test\n*** End Patch"},"tool_use_id":"exec-ea8b2e82-9bc9-4616-8ddf-67915da8cacc"}
```

For `apply_patch` the `cwd` is the session root, and the patch path is absolute.

## What it means for applygate

- On 0.166.0 a shell command's top-level `cwd` is its own directory; on 0.165.0
  it was the session root. The event carries no version and no workdir field,
  so applygate cannot tell the two apart and keeps treating the shell `cwd` as
  "not confirmed" (`DirKnown` false). That is still correct for both: the
  most-protected-tier search runs under `cwd`, which is the real directory on
  0.166.0 and the session root on 0.165.0. The `matched` text "command
  directory not reported by codex" is therefore accurate for what applygate can
  establish, even where the directory happened to be right.
- No adapter change is needed. A change that trusted `cwd` as the command
  directory would under-protect 0.165.0 sessions (the finding fixed in PR #33).
- Not captured: whether `cwd` follows an earlier `cd` in the same command or a
  `workdir` the model passes explicitly beyond the one case above.
