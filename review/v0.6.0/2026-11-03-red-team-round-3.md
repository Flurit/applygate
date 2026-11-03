# v0.6.0 red-team round 3

**Release verdict: not releasable.** The round found 4 critical issues (36 after merging duplicates) against main at 794b904, after the round-2 fix milestones R2-1 to R2-5. The exit criterion is no critical finding, so v0.6.0 stays on hold.

Round 2 found 31 critical and 22 high issues. Round 3 found 4 critical and 10 high, and most attacks of every kind were caught. What remains are implicit shell behaviours, holes in how trust is tied to a file, a managed mode that leaves the user config in charge, and guard paths that are still listed one by one.

## Method

- **What was reviewed:** main at 794b904 (the tree of 6e5d8ce, R2-5), as a blind copy.
  - **Removed:** git history, `review/` (except the agent-trial log, real plans, host research and T3 results the tests read), the attack pack, `internal/reviewgap` and every test that uses it, and the changelog's list of fixes.
  - **Scrubbed:** finding IDs and references to earlier rounds in comments, docs and test names.
  - **Copies:** the original was read-only; each reviewer had its own copy with the fixture's repository config pre-trusted in a scratch home.
- **Who reviewed it:** six independent AI reviewer agents, one area each, briefed like round 2. The briefs named the newer documented surfaces (repository-config trust, the managed install, the plugin's binary pin) but not the fixes.
  - R1: the shell analyzer and classifier;
  - R2: self-protection and the host adapters;
  - R3: config, tiers and the plan gate;
  - R4: the model judge and the MCP mapping;
  - R5: secrets, the supply chain and failure handling;
  - R6: the docs checked against the code.
- **How:** each reviewer built its own binary and attacked it with `applygate check`, `explain`, `plan-check` and raw hook JSON, with a scratch `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME`.
  - The managed install was exercised only through Go tests that point its paths at the reviewer's own directory. No reviewer used `sudo` or wrote to a system directory.
  - R3 ran Terraform 1.14.6 `init` against an unreachable endpoint (`127.0.0.1:9`) to confirm which backend Terraform reads.
- **Effort:**
  - R1 tried about 95 attack ideas, R2 about 90, R3 about 60, R4 about 60 and R5 62.
  - R6 checked about 110 documented claims.
  - Most attacks were caught.
- **Verification:** the coordinator built main and reproduced findings in its own scratch directory, and ran the reviewers' evidence tests for the findings that need a managed install or a swapped file.
  - **V:** reproduced by the coordinator.
  - **R:** reported by the reviewer only. These are mostly docs mismatches, timing and redaction findings.
- **Side effects:**
  - **Network:** one reviewer's `go test` fetched a Go module from proxy.golang.org before it set `GOPROXY=off`. That was read-only network use.
  - **Temporary files:** one fake `install.sh` run made a temporary directory in the system temp directory, which the script removed.
  - **Coordinator error:** while writing the briefs, the coordinator ran an unquoted shell heredoc, so backtick-quoted text in it ran as commands.
    - The `applygate` on `PATH` (0.3.0) rejected `trust` and `install` as unknown commands.
    - A `go build` wrote a binary into the repository root, which was removed.
  - **Checked afterwards:** the real home directory's applygate files, the system paths of the managed install and the repository are unchanged.
- **Severity:** the same scale as rounds 1 and 2.
  - **critical:** a destructive call allowed in a protected tier, or the agent can disable applygate or approve its own call.
  - **high:** the same with an unusual setup, or real damage potential.
  - **medium:** limited impact, or a missing safeguard.
  - **low:** cosmetic, or hardening.

| | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Reported (with duplicates) | 4 | 11 | 12 | 13 | 40 |
| After merging duplicates | 4 | 10 | 10 | 12 | 36 |

## Root causes

1. **The shell runs code and resolves names in ways the analyzer does not model.**
   - **Start-up files:** `BASH_ENV`, `ENV` and `ZDOTDIR`.
   - **Hooks:** `command_not_found_handle`.
   - **Lookup tables:** `hash -p`, `CDPATH` and `cdable_vars`.
   - **Other paths:** tilde forms such as `~-`, and zsh glob qualifiers.

   Each one changes which program runs, or where it runs, without naming it. Round 2 moved guard files to default-deny; directory and program resolution still enumerate.
2. **Trust is tied to a path, not to the bytes that were approved and read.** A symlinked config is checked against its target's hash. `applygate trust` re-reads the file after the person confirms it. A config that cannot be read takes the error path, which follows the user config's `on_error` (an R2-5 change) and can allow everything.
3. **The managed install does not constrain the user config.** The system config wins only for the settings it sets (`mode`, `approvals`). The agent's user still owns `~/.config/applygate/config.yaml`, which can set `strict: false`, a disposable `default_tier`, a catch-all environment or an alias. That file is guarded only by the same default-deny check the unmanaged install uses, and a Python body that builds the path at run time gets past that check.
4. **Guard coverage is still per path and per name.**
   - **Paths:** the plugin's data directory under `XDG_CACHE_HOME`, a `--plugin-dir` checkout and the managed Claude Code directory are not guard targets.
   - **Environment variables:** `APPLYGATE_BIN`, `CLAUDE_PLUGIN_DATA` and `XDG_CACHE_HOME` on a nested `claude` are not tampering.
   - **Tool names:** an MCP edit tool named `search_and_replace` passes as a search, and camelCase shell tools are not recognized.
5. **HCL is read with regular expressions.** A trailing comment, an escape, parentheses, a `/* */` or heredoc decoy, or a dot-prefixed override file changes the backend applygate reads but not the one Terraform reads.

## Findings

Each row gives the merged ID, the reviewer IDs, the severity, the finding, and a minimal reproduction (fixture `envs/prod` protected and `envs/dev` disposable, unless it says otherwise).

### Self-protection and trust

| ID | Reviewers | Sev | Finding | Reproduction | |
|---|---|---|---|---|---|
| 3S1 | R3-1 | critical | A `.applygate.yaml` that is a symlink to a config trusted elsewhere is read as trusted, with its environments rooted at the link | a cloned repository whose `.applygate.yaml` links to the fixture's trusted config: `terraform destroy -auto-approve` in its `envs/dev`: allow (block without the config). `git clone`, `checkout` and `pull` bring the link in; `ln -s` is blocked | V |
| 3S2 | R6-1 | critical | Under a managed install the user config still loosens everything but `mode` and `approvals` | managed install into temporary roots, then a user config with `strict: false` and `default_tier: disposable`, a `**` disposable environment, or `aliases: {terraform: ls}`: destroy allowed (block without it) | V |
| 3S3 | R6-2 | high | `applygate trust` trusts the file as it is when the person types "trust", not as it was shown | the config swapped between display and confirmation: the swapped config is trusted and a destroy in its protected path is allowed. A delayed `git checkout` in the background is allowed by the hook | V |
| 3S4 | R2-1, R6-5, R5-6 | high | The plugin's binary pin can be replaced: `APPLYGATE_BIN`, `CLAUDE_PLUGIN_DATA` and `XDG_CACHE_HOME` on a nested `claude` are not tampering, and the data directory under `XDG_CACHE_HOME` is not a guard path | `CLAUDE_PLUGIN_DATA=/tmp/f APPLYGATE_BIN=/bin/true claude -p …`: allow (`CLAUDE_CONFIG_DIR=` blocks). Reviewer, end to end: the launcher pinned and ran an allow-all stub | V |
| 3S5 | R5-1 | high | A repository config that cannot be read follows the user config's `on_error`, so with `strict: false` every call is allowed without analysis | config at mode 000 in a directory its environment marks protected, user config `strict: false`: the hook allows a destroy (exit 0); trusted it denies, deleted it asks | V |
| 3S6 | R2-2 | medium | An MCP edit tool whose name reads as a search skips the guard-file check | `mcp__srv__search_and_replace` on `.applygate.yaml`: allow (`write_file` on the same file: deny) | V |
| 3S7 | R2-3 | medium | The managed Claude Code settings directory is not a guard target | `rm -rf "/Library/Application Support/ClaudeCode"`: allow (`rm -rf /etc/applygate`: block) | V |
| 3S8 | R5-2 | medium | The split-literal guard check misses `'.'` joins, implicit concatenation and `os.path.join` | `python3 -c "import os; os.chmod('.'+'applygate.yaml',0)"`: allow | V |
| 3S9 | R6-4 | medium | A `--plugin-dir` checkout's launcher and `hooks.json` are not guard paths | `echo exit 0 > <clone>/plugin/claude-code/scripts/applygate-hook`: allow | R |
| 3S10 | R5-7 | low | The managed install keeps existing directories' owner and mode | a pre-existing 0777 `managed-settings.d` stays 0777 | R |

### Shell analyzer and classifier

| ID | Reviewers | Sev | Finding | Reproduction | |
|---|---|---|---|---|---|
| 3C1 | R1-1 | critical | `BASH_ENV`, `ENV` and `ZDOTDIR` make a shell run a file the analyzer never reads | `echo "terraform destroy -auto-approve" > hook.sh; BASH_ENV=hook.sh bash -c true`: allow; `BASH_ENV=../../scripts/teardown.sh bash -c "echo building"`: allow | V |
| 3C2 | R3-3, R1-6 | critical | `cd` is resolved without `CDPATH` or `cdable_vars` | from dev: `CDPATH=..; cd staging && terraform destroy -auto-approve`: allow (`cd ../staging`: ask); `shopt -s cdable_vars; t=../prod; cd t && terraform destroy -auto-approve`: allow | V |
| 3C3 | R1-2 | high | `hash -p PATH NAME` makes a later `NAME` run another program | `hash -p /opt/homebrew/bin/terraform ls; ls destroy -auto-approve`: allow | V |
| 3C4 | R1-3 | high | A `command_not_found_handle` body runs for any unknown command but is never analyzed | `command_not_found_handle() { terraform destroy -auto-approve; }; nosuchcmd`: allow | V |
| 3C5 | R1-4 | high | `cd ~-` (and `~+`, `~user`) is taken as a literal directory | from dev: `cd ../prod; cd ../dev; cd ~-; terraform destroy -auto-approve`: allow; bash enters `envs/prod` | V |
| 3C6 | R1-5 | high | A script written earlier in the same command is unresolved but judged at the current directory's tier, though it can `cd` anywhere | from dev: `printf "cd ../prod\nterraform destroy -auto-approve\n" > r.sh; bash r.sh`: allow | V |
| 3C7 | R1-7 | medium | zsh glob qualifiers run code | `ls *(e:"terraform destroy":)`: allow | V |
| 3C8 | R3-4 | low | A declared wrapper's `skip` can swallow the engine name | `company-run terraform destroy -auto-approve` with `skip: 1`: allow | R |

### Tiers and the plan gate

| ID | Reviewers | Sev | Finding | Reproduction | |
|---|---|---|---|---|---|
| 3T1 | R3-2 | high | The declared-backend reader drops or misreads backends Terraform uses: trailing comments, escapes, parentheses, `/* */` and heredoc decoys, dot-prefixed override files, and OpenTofu's `.tofu` files | a dev directory whose `bucket = "acme-tf-state-prod" # shared`: `terraform init && terraform destroy`: allow (block without the comment). Reviewer confirmed with Terraform 1.14.6 that it reads the prod bucket in each case; `.tofu` not confirmed | V |
| 3T2 | R6-3, R5-8 | medium | In CI the repository config is never trusted, so `plan-check` and the Terragrunt hook judge everything protected and drop the config's environments and `protected_resources`, without saying so | an untrusted copy: `plan-check` on `protected_resource.json` gives "tier protected: block" with no protected-resource finding | R |
| 3T3 | R3-5 | low | Action lists Terraform never writes (`["Delete"]`, `["update","delete"]`) count as no delete | hand-fed plan JSON at tier protected: allow | R |

### Model judge and MCP

| ID | Reviewers | Sev | Finding | Reproduction | |
|---|---|---|---|---|---|
| 3M1 | R4-2 | high | tfmcp `destroy_terraform` without `plan_id` is not recognized and is allowed | `mcp__tfmcp__destroy_terraform {}` in prod: allow (with `plan_id`: deny) | V |
| 3M2 | R4-1 | medium | camelCase shell tool names are not recognized | `mcp__x__executeCommand` with `aws s3 rb … --force` in prod: allow (`execute_command`: deny) | V |
| 3M3 | R4-3 | medium | `git apply --directory=<outside> --unsafe-paths` is local git to the judge filter | with the judge on: not sent to the judge, while `patch -d /outside` is | R |

### Data, failures, supply chain and docs

| ID | Reviewers | Sev | Finding | Reproduction | |
|---|---|---|---|---|---|
| 3D1 | R5-3 | high | Redacting and writing the log runs after the decision deadline, so a 6 to 8 MB command takes over 30 s and a host that fails open on timeout runs it | a 6 MB Copilot-format destroy: 32.8 s, no verdict when killed at 30 s | R |
| 3D2 | R5-4 | medium | MCP arguments are cut to 4 KB before redaction, so a private key whose END line falls past the cut is logged | | R |
| 3D3 | R5-5 | medium | Redaction misses `aws ssm put-parameter --value`, `kubectl create secret --from-literal`, `vault kv put`, `gh secret set --body`, `docker secret create`, `az login -p`, Cookie headers and Slack webhooks; some also reach the judge | | R |
| 3D4 | R5-9 | low | The documented signature identity does not bind the calling repository (not exploitable while `release.yml` has no `workflow_call`) | | R |
| 3D5 | R5-10 | low | The decision log has no size limit or rotation; one call can add about 14 MB | | R |
| 3D6 | R6-6 | low | `install.md` says `init` writes the repository config in observe mode | | R |
| 3D7 | R6-7 | low | The plugin README and `install.md` leave out the binary pin and the block after an upgrade | | R |
| 3D8 | R6-8 | low | `telemetry.md` says only a person at a terminal turns telemetry on; there is no terminal check, and `APPLYGATE_TELEMETRY_ENDPOINT` is not in the threat model | | R |
| 3D9 | R6-9 | low | `limits.md` still describes the `mcp__.*` matcher | | R |
| 3D10 | R6-10 | low | `trust` prints the config with its newlines escaped, on one line | | R |
| 3D11 | R6-11 | low | The README's agents table says Cline and OpenCode block when applygate cannot run; `hosts.md` lists their fail-open cases | | R |
| 3D12 | R6-12 | low | `managed.md` understates what stays after `uninstall --managed` without `--purge`: the system config keeps overriding the user's settings | | R |

## What held up

- **Shell analyzer:** about 88 of 95 attacks were caught.
  - Every engine and cloud CLI destroy form tried, and wrappers, `eval` and `bash -c`.
  - Encodings, `xargs`, `make`, `trap`, coprocesses, namerefs and `IFS` splitting.
  - Interpreters, `CDPATH`-free directory changes and `TF_DATA_DIR`.
- **Self-protection:** every shell, archive, git and interpreter route into the guard files that names them.
  - Nested-agent switches and environment relocation, and package managers.
  - `PATH` and rc planting, and renamed copies recognised by content.
  - Every route to `approve`, `trust`, `install` and `telemetry`.
  - Write, Edit, `apply_patch`, Monitor, PowerShell, `write_stdin` and `js_repl`, and case-clashing keys.
- **Tiers:** about 55 workspace, path-spelling, symlink, planting, wrapper and plan-gate attacks were caught.
- **Judge and MCP:**
  - A judge answer cannot lower a block.
  - Unreadable, oversized and redaction-hidden answers ask.
  - The cache stores only escalations, and `check` does not reach the judge from a script.
  - Every destructive translation probed across the AWS, Terraform, Kubernetes, Helm, Azure and gcloud servers was caught.
- **Docs:** about 110 claims held, including the verdict table, the numbers, the time and size limits, and the self-protection examples.

## Recommendation

Fix in milestones as in round 2, then a fourth blind round. Three choices are yours to make:

1. **Managed mode and the user config (3S2).** Recommended: under a managed install, the user config may only tighten, like a repository config. That means `strict: false`, a looser `default_tier`, `aliases`, `on_error: allow`, `unknown_dir: session_root` and the judge's command come from the system config only. The alternative is to keep the user config free and document that managed mode protects only the hook and binary; that does not meet what `managed.md` promises.
2. **Reading HCL (3T1).** Recommended: parse backend blocks with HashiCorp's `hcl/v2` parser (a new dependency, already in Terraform's own module graph) and treat any parse failure as an unknown backend. The alternative is to keep the regular expressions and add comment and string handling, which keeps the same class of gap.
3. **Shell start-up and lookup state (3C1 to 3C5).** Recommended, as with guard files:
   - A shell started with `BASH_ENV`, `ENV` or `ZDOTDIR` sources that file or is unresolved.
   - Any `CDPATH`, `cdable_vars`, `hash -p` or `command_not_found_handle` makes later directory or program resolution unknown, and so judged at the most protected tier under the root.
   - A tilde form other than `~` and `~/` makes the directory unknown.

   The alternative is to model each feature exactly, which round 3 shows keeps missing the next one.

The other fixes follow from the findings:
- **Trust:** check that each config is a regular file with `Lstat`; trust the bytes that were shown; an unreadable config is untrusted and so protected.
- **Guard paths:** derive them from the paths the hook and launcher actually use; tamper-check every variable either of them reads on a nested agent.
- **MCP tool names:** a recognizer that splits on case and underscores.
- **Scripts:** a script written in the same command is unresolved anywhere under the root.
- **The log:** write it within the deadline, with size caps.
- **Redaction:** the missing forms.
- **CI:** a trust step for runners, with `plan-check` saying when a config was not read.
- **Docs:** the fixes listed above.
