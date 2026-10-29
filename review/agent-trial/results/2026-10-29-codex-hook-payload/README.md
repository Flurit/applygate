# Codex 0.165.0 PreToolUse hook input, captured 2026-10-29

Why: the agent-driven trial showed every Codex decision resolved against the
session root although Codex ran the commands in `examples/simple`. This
capture confirms what the Codex source says (openai/codex at `rust-v0.165.0`,
`codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs`
`pre_tool_use_payload`, `codex-rs/core/src/hook_runtime.rs` `tool_hook_cwd`):
the hook input carries only `tool_input.command` and the session's `cwd`; the
`workdir` the model passed to `exec_command` is not in it.

How: in the trial container (`review/agent-trial/compose.yaml`, Codex signed
in via the `codex-state` volume, hook already trusted for the clone), a tee
wrapper was bind-mounted over `/usr/local/bin/seatbelt` and the real binary
at `/usr/local/bin/seatbelt-real`, so the clone's `.codex/hooks.json` and
Codex's trust hash of it stayed unchanged:

    #!/bin/sh
    d=/home/trial/.local/state/seatbelt/capture
    mkdir -p "$d"
    f="$d/$(date +%Y%m%dT%H%M%S.%N)-$$.json"
    tee "$f" | /usr/local/bin/seatbelt-real "$@"

Two `codex exec` prompts from `/work/terraform-aws-vpc` (two tiny prompts,
about 9k tokens in all). The container's sandbox (bubblewrap) could not create
a namespace on this host, so neither tool ran to completion; the hooks fired
before that, which is all the capture needs. Nothing in the clone changed
(`git status` clean, `seatbelt doctor` clean afterwards). The capture
directory was removed from the log volume after copying the files out. No
secrets appear in the payloads; nothing was redacted.

## Prompt 1: "In examples/simple, run pwd. Do nothing else and do not read any files."

Codex's own output: `/bin/bash -lc pwd in /work/terraform-aws-vpc/examples/simple`.
The hook received (file `20261029T103810.483697879-130.json`):

```json
{"session_id":"01a1873c-fd9c-7173-9d08-b8c1db18e1c7","turn_id":"01a1873d-03c9-7e43-a054-b0a393cc8a42","transcript_path":"/home/trial/.codex/sessions/2026/10/29/rollout-2026-10-29T10-38-03-01a1873c-fd9c-7173-9d08-b8c1db18e1c7.jsonl","cwd":"/work/terraform-aws-vpc","hook_event_name":"PreToolUse","model":"gpt-6-luna","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"pwd"},"tool_use_id":"exec-a8568b09-b9f1-454d-8ecc-04301322d9af"}
```

`cwd` is the session root; `tool_input` has `command` only; there is no
`workdir`, `working_directory` or other directory field at either level.
`permission_mode` is `bypassPermissions` under `codex exec` (approval policy
never).

## Prompt 2: "Using the apply_patch tool, append the single line `# capture test` to the end of examples/simple/main.tf. Do not run any shell command and do not read any other file."

Codex tried twice (the sandboxed write failed both times). The hook received
(files `20261029T103844.183470815-120.json` and `20261029T103847.035345158-134.json`):

```json
{"session_id":"01a1873d-8ca1-7a23-a25c-26df1a5e53d4","turn_id":"01a1873d-8e81-7ec1-9b8c-72bde015fab3","transcript_path":"/home/trial/.codex/sessions/2026/10/29/rollout-2026-10-29T10-38-40-01a1873d-8ca1-7a23-a25c-26df1a5e53d4.jsonl","cwd":"/work/terraform-aws-vpc","hook_event_name":"PreToolUse","model":"gpt-6-luna","permission_mode":"bypassPermissions","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: /work/terraform-aws-vpc/examples/simple/main.tf\n@@\n+# capture test\n*** End Patch"},"tool_use_id":"exec-d495fe39-772f-40c4-b320-21afa6bc3801"}
```

```json
{"session_id":"01a1873d-8ca1-7a23-a25c-26df1a5e53d4","turn_id":"01a1873d-8e81-7ec1-9b8c-72bde015fab3","transcript_path":"/home/trial/.codex/sessions/2026/10/29/rollout-2026-10-29T10-38-40-01a1873d-8ca1-7a23-a25c-26df1a5e53d4.jsonl","cwd":"/work/terraform-aws-vpc","hook_event_name":"PreToolUse","model":"gpt-6-luna","permission_mode":"bypassPermissions","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: examples/simple/main.tf\n@@\n+# capture test\n*** End Patch"},"tool_use_id":"exec-f5e24a01-a2b2-49d4-b2b6-b8516ba87393"}
```

`tool_name` is `apply_patch` and `tool_input.command` is the raw patch text;
the model wrote the path absolute once and relative once, and Codex resolves
a relative patch path against the session `cwd`, which is what seatbelt does
too (`classify.PatchPaths` with the event's cwd).

## MCP tools

Not captured: the trial container has no MCP server configured. From the
source (`codex-rs/core/src/tools/handlers/mcp.rs`): `tool_name` is
`mcp__<server>__<tool>` and `tool_input` is the tool's raw JSON arguments
(or the raw string when they are not JSON). seatbelt does not inspect MCP
tool inputs (`docs/limits.md`, S13).

## Side effects on the trial volumes

The two sessions added two rollout files to the `codex-state` volume and
three `allow` entries (one `pwd`, two `apply_patch`) to the trial's
`decisions.jsonl`, all after the 2026-10-29 collection; nothing else changed.
