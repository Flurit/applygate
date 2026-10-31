# Hook contracts of other agent hosts (documentation research, 2026-10-31)

Read from each host's own documentation and, where the host is open source, its
source code, on 2026-10-30/31. Nothing here was tested live. It is the basis for
the adapters marked "from docs, not tested live" in docs/hosts.md; a cell moves
to verified only with a live test recorded in review/T3_RESULTS.md.

Cross-loading finding that affects existing installs: **Cursor, GitHub Copilot
CLI and Devin (ex-Windsurf) all read hooks from `.claude/settings.json`** (and
Cursor/Devin from `~/.claude/settings.json`). An `applygate hook claude` entry
may therefore run inside those hosts with their payload shape and tool names
(Cursor maps Bash→Shell; Devin's shell tool is `exec`; Copilot's PascalCase
form keeps Claude names). The Claude adapter must recognise those shell tool
names so a cross-loaded hook never silently allows a shell command.

## Cursor (editor and cursor-agent CLI)

Sources: https://cursor.com/docs/hooks (also /docs/hooks.md),
https://cursor.com/docs/reference/third-party-hooks.md,
https://cursor.com/docs/cli/changelog.md, https://cursor.com/changelog/1-7.

- Config: `{"version": 1, "hooks": {"<event>": [{"command", "type"?, "timeout"? (s), "matcher"? (regex), "failClosed"? (bool, default false)}]}}`.
  Locations, all merged (deny > ask > allow): enterprise
  (`/Library/Application Support/Cursor/hooks.json`, `/etc/cursor/hooks.json`,
  `C:\ProgramData\Cursor\hooks.json`), team (dashboard), project
  `<root>/.cursor/hooks.json` (runs from the project root), user
  `~/.cursor/hooks.json` (runs from `~/.cursor/`), then Claude Code settings
  files when third-party configs are on (default on).
- Blocking events: `beforeShellExecution` (allow/deny/ask), `beforeMCPExecution`
  (allow/deny/ask), `preToolUse` (allow/deny; "ask is accepted by the schema
  but not enforced for preToolUse today"; tools Shell, Read, Write, Grep,
  Delete, Task, `MCP:<tool>`), `beforeReadFile` (allow/deny). No
  `beforeFileEdit`; block edits with `preToolUse` matcher `Write`.
- Input, common: `conversation_id`, `generation_id`, `model`,
  `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`,
  `transcript_path`. `beforeShellExecution`: `command`, `cwd` ("current
  working directory"; whether per-command is not documented), `sandbox`.
  `preToolUse` (example only): `tool_name`, `tool_input` {`command`,
  `working_directory`} for Shell, `tool_use_id`, `cwd`. `beforeReadFile`:
  `file_path` (absolute), `content`. Write/Delete/Read/Grep `tool_input`
  fields: not documented.
- Output: `{"permission": "allow"|"deny"|"ask", "user_message", "agent_message"}`.
  Exit 0 uses the JSON ("invalid JSON or a response that doesn't match the
  hook's schema blocks the action" for permission hooks); exit 2 blocks;
  other exits fail open. Crashes and timeouts fail open unless
  `failClosed: true` ("crash, timeout, non-zero exit code, no output" then
  block). Default timeout: "platform default" (not documented).
- Ask: unreliable. Cursor staff on the forum (2026-03-26, 2026-10-05): ask is
  ignored in run-everything / auto-review modes; deny "still enforced in every
  mode". applygate treats Cursor as unable to ask.
- Trust: project hooks run only in a trusted workspace. Cloud agents run
  project hooks only (no user hooks, no beforeMCPExecution).
- Known open bugs (forum): hooks failing silently in cursor-agent on Linux
  2026.08.11; on Windows with Git Bash the hook never runs and becomes a hard
  deny.

## GitHub Copilot CLI

Sources: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference,
https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks,
https://docs.github.com/en/copilot/tutorials/copilot-cli-hooks,
https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/use-hooks,
https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference,
https://github.com/github/copilot-cli/blob/main/changelog.md (latest 1.0.105, 2026-10-27).

- Config: `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash", "powershell", "command"?, "cwd"?, "env"?, "timeoutSec"? (default 30), "matcher"? (regex anchored ^(?:…)$ on toolName)}]}}`.
  Locations, all run: policy `/etc/github-copilot/policy.d/*.json`; repo
  `.github/hooks/*.json` (also used by the cloud agent, from the default
  branch); user `~/.copilot/hooks/*.json` (or `$COPILOT_HOME/hooks/`); inline
  `hooks` in `.github/copilot/settings*.json`, `.claude/settings*.json`,
  `~/.copilot/settings.json`. Hook commands run in the project root.
- Input (camelCase `preToolUse`): `sessionId`, `timestamp` (ms), `cwd`,
  `toolName`, `toolArgs` (a JSON string in the CLI examples; typed unknown in
  the reference). PascalCase `PreToolUse` gives snake_case `tool_name`,
  `tool_input` with Claude tool names. Tools: `bash`, `powershell`, `create`,
  `edit`, `apply_patch`, `str_replace_editor`, `view`, `glob`, `grep`/`rg`,
  `task`, `web_fetch`. bash args: only `command` documented; meaning of `cwd`
  (session or command directory): not documented.
- Output: `{"permissionDecision": "allow"|"deny"|"ask", "permissionDecisionReason"}`;
  empty output = default flow. Exit 2 = deny; any other non-zero exit or a
  crash = deny ("fail-closed on errors", since 1.0.57). Timeouts always fail
  open. Ask works in the interactive CLI (1.0.4+); autopilot and the cloud
  agent turn ask into deny.
- Trust: repo hooks load only after folder trust (1.0.8+);
  `disableAllHooks` in repo settings disables non-policy hooks.

## Gemini CLI

Sources: google-gemini/gemini-cli at a60946692b11 (main, 2026-10-30), same
contracts as tag v0.66.0: docs/hooks/{index,reference,best-practices}.md,
packages/core/src/hooks/{types,hookRunner,hookRegistry,hookPlanner,hookEventHandler}.ts,
packages/core/src/tools/shell.ts, packages/core/src/scheduler/scheduler.ts.

- Config in settings.json (user `~/.gemini/settings.json`, project
  `.gemini/settings.json`, system `/etc/gemini-cli/settings.json` or
  `/Library/Application Support/GeminiCli/settings.json`), concatenated:
  `{"hooks": {"BeforeTool": [{"matcher": "<regex, unanchored>", "hooks": [{"name", "type": "command", "command", "timeout" (ms, default 60000)}]}]}}`.
  Enabled by default since v0.27.0 (`hooksConfig.enabled`).
- Input: `session_id`, `transcript_path`, `cwd` (the session working
  directory, normally the project root), `hook_event_name` "BeforeTool",
  `timestamp`, `tool_name`, `tool_input`, `mcp_context` for MCP tools. Tools:
  `run_shell_command` {`command`, `description`, `dir_path` (relative to the
  project root or absolute; default the project root), `is_background`},
  `write_file`, `replace` (`file_path`), `read_file`, `read_many_files`,
  `list_directory`, `glob`, `grep_search`, MCP `mcp_<server>_<tool>`.
- Output: exit 0 + `{"decision": "allow"|"deny"|"block"|"ask", "reason"}`.
  If stdout (or else stderr) is JSON it governs regardless of exit code;
  plain text with exit 0 or 1 allows; plain text with any other exit (2
  included) denies; exit 2 with no output allows. `ask` is implemented in
  source (forces a prompt even in YOLO) but not documented; applygate does
  not use it.
- Failure: timeouts, exit 1, signals, spawn errors and internal errors fail
  open; a missing command (bash exit 127 with stderr) denies.
- Trust: settings hooks (user scope included) run only in trusted folders
  (`security.folderTrust.enabled` defaults to true); new hooks get a one-time
  warning, then run.

## Windsurf / Devin Desktop

Windsurf is now Devin Desktop; docs.windsurf.com/windsurf/cascade/hooks
redirects to docs.devin.ai. Cascade is "the legacy agent". Sources: archived
https://web.archive.org/web/20260516140338/https://docs.windsurf.com/windsurf/cascade/hooks.md,
https://docs.devin.ai/cli/extensibility/hooks/overview.md,
https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks.md,
https://docs.devin.ai/desktop/controls, https://docs.devin.ai/desktop/changelog.md.

Legacy Cascade format (Windsurf, JetBrains plugin):
- Config `{"hooks": {"pre_run_command": [{"command", "show_output"?, "working_directory"?, "powershell"?}]}}`
  in `.windsurf/hooks.json` (workspace), `~/.codeium/windsurf/hooks.json`
  (user), `~/.codeium/hooks.json` (JetBrains), system
  `/etc/windsurf/hooks.json` etc.; merged.
- Input: `agent_action_name`, `trajectory_id`, `execution_id`, `timestamp`,
  `model_name`, `tool_info` (`pre_run_command`: `command_line`, `cwd`;
  `pre_write_code`: `file_path`, `edits`; `pre_read_code`: `file_path`;
  `pre_mcp_tool_use`: server, tool, arguments). Whether `cwd` is
  per-command: not documented.
- Output: exit 2 blocks with stderr shown to the agent; any other exit
  proceeds (fails open). No JSON output, no ask, no documented timeout.

Devin Local / Devin CLI format:
- Config `.devin/hooks.v1.json` (the file is the hooks object), or `hooks` in
  `.devin/config.json`, `~/.config/devin/config.json`, `.claude/settings*.json`:
  `{"PreToolUse": [{"matcher": "^exec$", "hooks": [{"type": "command", "command", "timeout"?}]}]}`.
- Input: `hook_event_name`, `tool_name` (`exec` for shell), `tool_input`
  {`command`, `shell_id`?}, `session_id`, `prompt_id`; no cwd documented
  (`DEVIN_PROJECT_DIR` env is set).
- Output: `{"decision": "block"|"approve", "reason"}` or exit 2; other exits,
  timeouts and unreadable output are logged and do not block. No ask.
  Hooks do not load in Restricted Mode (untrusted workspace).

## OpenCode

Sources: sst/opencode tags v2.2.4 (2026-10-30) and v1.19.5 (2026-10-28):
packages/plugin/src/index.ts, packages/opencode/src/plugin/index.ts,
packages/opencode/src/session/tools.ts, packages/opencode/src/tool/shell*.ts,
packages/plugin/src/promise/{tool,adapter}.ts, packages/core/src/tool/plugin/shell.ts,
docs under packages/web/src/content/docs and services/www/src/docs/content.

- No JSON command hooks; interception is a JS/TS plugin. V1 and V2 plugin APIs
  differ ("V1 plugin implementations do not run in V2"); a module whose
  default export carries both `id`/`setup` (V2) and `server()` (V1 object
  entrypoint, OpenCode 1.18.29+) serves both.
- Locations: `.opencode/plugins/` (project), `~/.config/opencode/plugins/`
  (user); loaded automatically at startup, no trust prompt documented.
- V1 `tool.execute.before(input {tool, sessionID, callID}, output {args})`;
  V2 `ctx.tool.hook("execute.before", event {tool, sessionID, id, input})`.
  Throwing blocks that tool call; the model sees the error message and the
  turn continues. Fires for every tool, MCP included.
- Shell tool: V1 `bash`, V2 `shell`; args `command`, `workdir`? (relative to
  the instance directory), `timeout`?. File tools: V1 `read`/`edit`/`write`
  with `filePath`, `apply_patch` with `patchText`; V2 `read`/`edit`/`write`
  with `path`, `patch` with `patchText`.
- Failure: a plugin that fails to load is logged and skipped (fail open). A
  missing applygate binary is fail-closed only if the plugin turns the spawn
  error into a throw (applygate's plugin does).

## Cline

Sources: cline/cline at tag v4.1.26 (2026-10-26) and cli-v3.0.74 (hooks code
identical), legacy-extension branch at 7761370 (4.0.12):
apps/vscode/src/sdk/hooks-adapter.ts, apps/vscode/src/core/hooks/hook-factory.ts,
apps/vscode/src/core/storage/disk.ts, apps/vscode/proto/cline/hooks.proto,
sdk/packages/core/src/hooks/{hook-file-config,hook-file-hooks}.ts,
sdk/packages/shared/src/storage/paths.ts, sdk/packages/core/src/extensions/tools/constants.ts,
.clinerules/hooks/README.md, CHANGELOG.md; docs.cline.bot.

- Three hook hosts, two payload shapes: the VS Code "next" (SDK) extension,
  the VS Code legacy extension (still shipped through the A/B loader), and the
  CLI. Hooks were introduced in 3.36.0.
- Registration is an executable file, no JSON: `<workspace>/.clinerules/hooks/PreToolUse`
  and `~/Documents/Cline/Hooks/PreToolUse` (VS Code: exact name, no
  extension, executable bit; Windows `PreToolUse.ps1`). The CLI also scans
  `~/.cline/hooks` and `<ws>/.cline/hooks` and accepts extensions. One
  executable `.clinerules/hooks/PreToolUse` with a shebang serves all three.
  `hooksEnabled` defaults to true. No trust step found.
- Input (VS Code): `clineVersion`, `hookName` "PreToolUse", `timestamp`,
  `taskId`, `workspaceRoots`, `userId`, `model`, `preToolUse` {`toolName`,
  `parameters` (string→string; non-strings JSON-encoded)}. CLI: `hookName`
  "tool_call", `tool_call` {`id`, `name`, `input` (raw)}, plus the same
  `preToolUse`.
- Tools: next/CLI `run_commands` {`commands`: (string | {command, args})[]},
  but the hook sees the raw model input (may be `command`, `cmd`, a string or
  an array; a bare string or array gives `parameters` `{}` outside the CLI),
  `editor`, `apply_patch`, `read_files`, `search_codebase`, MCP
  `<server>__<tool>`. Legacy: `execute_command` {`command` (may start with
  `@workspace:`), `requires_approval`}, `write_to_file`, `replace_in_file`,
  `read_file`, `list_files`, `search_files`, `use_mcp_tool`.
- Directory: no per-command directory; commands run in the session cwd (the
  primary workspace root). Legacy multi-root commands can target another root.
- Output: `{"cancel": bool, "contextModification"?, "errorMessage"?}`. Cancel
  aborts the whole task/run, not just the tool call. VS Code honours JSON
  whatever the exit code; the CLI ignores exit codes and needs pure JSON on
  stdout.
- Failure: everything fails open — non-zero exit without JSON, invalid JSON,
  timeout (30 s VS Code, 120 s CLI), missing or non-executable script.
  applygate must always print `{"cancel": …}` and exit 0, and fail closed on
  its own errors by printing cancel. If the tool is a shell tool and no command
  can be extracted, cancel.
- Auto-approve: the hook runs in both bundles whether or not the call is
  auto-approved. No ask.

## Implementation plan (branch feat/more-agent-hosts)

- internal/hook/adapters.go: one shared payload normaliser that understands
  every shape above (Claude/Codex/Gemini/Devin snake_case, Copilot camelCase
  with string `toolArgs`, Cursor native, Windsurf `tool_info`, applygate's own
  OpenCode plugin payload) and one shell-tool name set (Bash, Shell, exec,
  bash, powershell, run_shell_command, shell, execute_command, …), so a hook
  cross-loaded by another host never allows a shell command as "other".
  Adapters then differ only in Render/Fail and CanAsk/DirKnown:
  - cursor: always print `{"permission": …}` (no output counts as failure under
    failClosed); deny with user_message/agent_message; Fail(block) exit 2;
    CanAsk false; DirKnown only from `tool_input.working_directory`.
  - copilot: deny JSON; allow = empty; Fail(block) exit 2; CanAsk true
    (autopilot/cloud turn ask into deny); DirKnown false (cwd meaning not
    documented).
  - gemini: exit 0 + `{"decision":"deny","reason"}`; allow `{}`; Fail(block)
    exit 2 with stderr text only (stdout empty); CanAsk false; cwd + dir_path,
    DirKnown true.
  - windsurf (legacy Cascade): exit 2 + stderr; CanAsk false; DirKnown false.
  - devin: `{"decision":"block","reason"}`; Fail(block) exit 2; CanAsk false;
    DirKnown false.
  - opencode: exit 2 + stderr from the plugin's spawn; CanAsk false; DirKnown
    from workdir (V1 relative to the instance directory).
- cmd/applygate: per-host install table (project/user paths, entry shape,
  detection dirs and binaries); Copilot and OpenCode get their own file
  (`.github/hooks/applygate.json`, `~/.copilot/hooks/applygate.json`,
  `.opencode/plugins/applygate.js`); Cursor entries carry `failClosed: true`.
- internal/config DefaultProtectedPaths and the shell guardText /
  isGuardMention lists: add `.cursor/hooks.json` (present), `.gemini/settings.json`,
  `.github/hooks/`, `.github/copilot/settings*.json`, `.copilot/`,
  `.windsurf/hooks.json`, `.codeium/`, `.devin/`, `.opencode/plugins/`,
  `.config/opencode/`, Cline hook directories.
- internal/hook/capabilities.go: a host row per adapter whose cells cite this
  file and say "from docs, not tested live"; regenerate docs/hosts.md.
- harness/run.py: event builders and parsers per new format; replay the pack
  in each format.
