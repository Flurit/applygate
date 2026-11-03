# v0.6.0 round-2 fix plan

This plan fixes the findings of [red-team round 2](2026-11-03-red-team-round-2.md). The user chose option (c) on 2026-11-03:
- **(a) Default-deny near guard files:** in the analyzer, a command whose words name a guard path, or a directory that holds one, is tampering unless it is a known read-only use.
- **(b) Move the guard out of the agent's reach:** managed settings, root-owned files, and a repository config that takes effect only once the user has approved it.

The work runs milestone by milestone, as the first plan did. Each milestone turns its findings' failing tests green.

## Design

### A. Default-deny near guard files (S1 to S7, S15, S19)

The classifier stops asking "which programs write files?" and asks "does this command name a guard file?".

- **What counts as naming one.** These are compared after canonicalization:
  - every word of every invocation;
  - every redirect target, including redirections on compound commands, bare redirections and `exec` redirections;
  - the literal prefix and suffix of words it cannot resolve.
- **What a match means.** A command that names a guard file, or a directory that holds one, is tampering unless it is on a short read-only list: `cat`, `head`, `tail`, `less`, `ls`, `stat`, `file`, `wc`, `grep`/`rg` (not `--pre`), `diff`, `jq` without `-i`, `test`/`[`, `git status`/`log`/`diff`/`show`, and `applygate doctor`/`report`/`hosts`. Being on the list only lets a program read; any write option on it (`-o`, `-i`, `--output`) still counts.
- **What it cannot resolve:**
  - a word with an unresolved part whose literal text ends in a guard file name or path (`${HOME:-x}/.claude/settings.json`, `"$(git rev-parse --show-toplevel)/.applygate.yaml"`);
  - a glob that could match a guard file (`setting*.json`, `.clau?e`);
  - a variable applygate itself reads (`XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME`), which is resolved from the hook's environment.
- **Canonicalization:** case folding plus the code points that file systems fold onto ASCII (U+017F ſ, U+212A K), NFC normalization, symlink resolution, and `..` resolved before any prefix test.
- **MCP tools** outside the table (`write_file`, `move_file`, `edit_file` and the rest) go through the same check on every string argument.
- **The cost:** some ordinary reads of guard files outside the list become asks or blocks. They are measured on the agent-trial and OSS-corpus traffic before merging.

### B. The guard out of the agent's reach (S8 to S13, S16, S17)

- **`applygate install --managed`** (run once with `sudo`) installs a guard the agent's user cannot change:
  - the binary at a root-owned path (`/usr/local/libexec/applygate/applygate`);
  - a root-owned system config (`/etc/applygate/config.yaml`), read as a layer above the user config, so it can pin `mode: enforce` and turn approvals off;
  - the hooks in each host's managed settings:
    - **Claude Code** (from the Claude Code docs, read 2026-11-03; to be tested live):
      - **Where:** a drop-in file `applygate.json` in `managed-settings.d/` next to `managed-settings.json`, so an organisation's own file is left alone. The directories are `/Library/Application Support/ClaudeCode/` on macOS, `/etc/claude-code/` on Linux and WSL, and `C:\Program Files\ClaudeCode\` on Windows.
      - **What it holds:** the PreToolUse hook, `allowManagedHooksOnly: true` and `permissions.disableBypassPermissionsMode: "disable"`.
      - **Why it holds:** the docs say user, project and `--settings` values cannot override a managed key, managed hooks merge rather than being replaced, and only a managed `disableAllHooks` turns them off.
      - **Not documented:** whether `--bare` and `CLAUDE_CODE_SIMPLE` skip managed hooks. This is tested live with a managed `SessionStart` marker hook before it is relied on.
    - **Codex** (from the Codex docs, read 2026-11-03, partly as a summary; to be confirmed from the source and live):
      - **Where:** `/etc/codex/requirements.toml` (`%ProgramData%\OpenAI\Codex\requirements.toml` on Windows).
      - **What it holds:** the hook under `[hooks]`, `allow_managed_hooks_only = true`, `[features] hooks = true`, and the allowed sandbox modes and approval policies.
      - **Not documented:** whether `--disable hooks`, `-c` and `-p` can turn hooks off despite the pinned feature.
- **Repository config trust.** A repository `.applygate.yaml` takes effect only when its hash matches one the user approved with `applygate trust`. Approved hashes are kept in the system config under managed mode, else in the user config.
  - An unapproved or changed config is not read. Every directory is then judged as protected, and the message tells the person to run `applygate trust`.
  - This closes every route that rewrites or plants it (git checkout, plumbing, an extraction, a clone, an unknown writer, a nested `wrappers:` list) in one place, instead of recognizing each route.
  - `applygate trust` is guard tampering when an agent runs it, like `approve`.
- **Integrity at hook start** (not built in R2-2; see [limits](../../docs/limits.md)). Without managed mode, `init` and `hook install` record a hash of the hook entries and the user config. At every hook start, applygate checks them and blocks with "applygate's configuration changed outside applygate; run `applygate doctor`". This is defence in depth: an agent that can write the record can rewrite it too, which the docs say.
- **Nested agents (S12).** Starting an agent CLI from an agent is tampering when the command:
  - turns hooks off: `--bare`, `--disable hooks`, `features.hooks=false`, profiles, `CLAUDE_CODE_SIMPLE`;
  - points the agent at another config: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `HOME=`;
  - uses `npx`/`bunx`/`pipx` to run an agent package with bypass flags.

  Under managed mode these are blocked by the host's managed settings too (to confirm per host).
- **Package managers and the binary (S8, S9).**
  - `brew`, `go install`, `go clean -i`, `pip`, `npm -g`, `cargo install`, `pipx` with an `applygate` or `seatbelt` argument are tampering.
  - The plugin launcher resolves the binary once and records its path and hash in the plugin data directory; `PATH` and `APPLYGATE_BIN` are read only by `init`.
  - Writing an executable named `applygate` or `seatbelt` into any directory on `PATH`, and writing shell start-up files, is tampering.
- **Renamed copies (S10).** A copy of the running binary is recognized by its content, a hash compared at hook start, not its name. `init`, `hook install|remove`, `approve`, `trust` and `telemetry on|off` through a copy are tampering.

### C. The hook does not trust the environment it shares (S13, S18, C8, M17)

- **Subprocesses.** Every program the hook starts (`git`, `terraform`/`tofu`, `cosign` in doctor) runs:
  - by absolute path, resolved once from a fixed list of system directories;
  - with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `-c core.fsmonitor= -c core.hooksPath=/dev/null --no-textconv --no-ext-diff`;
  - with a minimal environment.
- **Files.** The log, approvals and judge cache are opened with `O_NONBLOCK` and refused unless they are regular files. The verdict is written to stdout before the log.
- **Limits.**
  - Analysis depth is capped, so a deep nesting is unresolved, not a crash.
  - Decoder output that hits its cap is unknown.
  - The shipped judge adapters print an unjudgeable answer on a refusal instead of exiting non-zero.

### D. Concrete bypasses (the rest)

- **Analyzer (C1 to C7, C9):**
  - a `trap` body judged anywhere under the root;
  - `aws` and `helm` positionals with generic valued-flag skipping;
  - `.ONESHELL`, and `make -C` into a written path;
  - the git exec options: `grep -O`, a glued `-x`, `GIT_CONFIG_*`, `difftool -x`;
  - gzip cap;
  - PowerShell bodies analyzed as PowerShell (unresolved unless trivially known).
- **Tiers and the plan gate (T1 to T21):**
  - a backend that cannot be fully read is unknown, so protected;
  - a saved plan's own backend, workspace and directory join the tier;
  - same-command plan writes with `-chdir`, `TF_CLI_ARGS_plan` and case folding;
  - a symlink to an unmatched directory gets the strict or default rule;
  - `-invoke` and action invocations;
  - Terragrunt `--config` and external dependencies;
  - HCP workspaces, provider-block profiles, `AWS_DEFAULT_PROFILE` and friends;
  - retargeting earlier in the same command;
  - the config of the repository a `cd` or `-chdir` enters;
  - `plan-check` judged exactly like the hook, with the tier validated;
  - exposure equivalents.
- **Judge and MCP (M1 to M23):**
  - unmodelled arguments of a known tool make the call unresolved (`stdin`, `shell`, `send_ascii`, a `workdir` the server does not have);
  - a tool name matches one server only when every argument fits that server's schema;
  - `program` checks for `call_kubectl`, `call_helm` and `call_az`;
  - known shell tool names from any server are judged as shell;
  - redaction is applied after the filter and prompt are built, and to the judge's copy only;
  - the judge's tier follows `cd`;
  - write content over the cap is unjudgeable.
- **Data, the supply chain and docs (D1 to D16):**
  - redaction gaps, notes, the log line cap, case-sensitive key decoding;
  - the Action uses its own `install.sh` and validates `version`;
  - `mktemp` in `ci-plan-check.sh`;
  - `on_error` for config errors;
  - observe-mode wording;
  - install paths following `CLAUDE_CONFIG_DIR` and `CODEX_HOME`;
  - version pins at the tag;
  - release environment protection;
  - CI hardening; docs.

## Milestones

| Milestone | Covers | Done when |
|---|---|---|
| R2-0 | A failing test for every finding that can be expressed as a pack scenario or a Go test; `reviewgap` lists them | the open list equals the reproduced findings |
| R2-1 | Design A and C (default-deny, the subprocess and file hardening, the depth and decode limits) | S1 to S7, S13, S15, S18, S19, C4 and C8 pass; benign asks measured |
| R2-2 | Design B (managed install, config trust, integrity check, nested agents, package managers, the launcher, copies) | S8 to S12, S14, S16 and S17 pass; managed install tested live on macOS with Claude Code and Codex |
| R2-3 | Design D, the analyzer and tiers (C, T) | the C and T findings pass |
| R2-4 | Design D, the judge and MCP (M) | the M findings pass |
| R2-5 | Design D, data, the supply chain and docs (D); docs restated for A and B | the D findings pass; docs match |
| Round 3 | A blind red-team round, briefed the same way, on the fixed build | no critical finding |

## Decisions this plan takes, to confirm

1. **Repository configs must be trusted** before they take effect (B). This is a new step for users after every config change, like `direnv allow`. The alternative is to recognize each rewriting route, which round 2 shows does not converge.
2. **Default-deny reads** of guard files outside the read-only list become asks or blocks (A). The cost is measured in R2-1.
3. **Managed mode is the documented guarantee**, and the in-hook checks are defence in depth. Without managed mode, an agent with the user's shell can, in the end, change what the user can change; the docs say so plainly.
