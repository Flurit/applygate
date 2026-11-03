# v0.6.0 round-6 fix plan

Round 6 ([report](2026-11-03-red-team-round-6.md)) found 17 critical issues on main at 2ea60a1. The user's decision on 2026-11-03: release timing is secondary, and the promise is not narrowed. applygate keeps the promise against an agent that sets out to get round it, and the fixes have to make that hold.

## Milestones

### R6-1: fixes every option needs (this PR)

Done, with reproductions in `harness/pack_attack` (Y6*):

| Finding | Fix |
|---|---|
| 6C17, 6H5 | Watchdog at the 29 s budget; config reads capped at 1 MiB (`safefile.ReadFileMax`); brace sequences counted before expansion; words and variable values past 64 KiB of expansion are unresolved |
| 6C3 | The judge cache reads back only `ask` and `block`; under a managed install it is not used |
| 6C4, R2-11 | Under a managed install a `command` judge must be absolute and root-owned with root-owned scripts (`config.SystemProgram`), runs with a fixed `PATH` and an allowlisted environment, and a judge error makes the call unjudgeable; `SSL_CERT_FILE` and `SSL_CERT_DIR` are cleared |
| 6C1, 6C2, 6H1, R2-12 | Guard paths: shell snapshots, `session-env`, `~/.ssh/config*`, Docker CLI plugins, `~/.curlrc`, Azure CLI extensions, launch agents, fish, `environment.d`, systemd user units, oh-my-zsh custom |
| 6C5 | Nested-agent flags that start MCP servers, plugins or agents are tampering |
| 6C13 | Unresolved program names, `eval` and `source` leave the directory unknown; `find -execdir`; runner directory options (`movesDir`); `env --chdir` abbreviations |
| 6C14 | Terraform containers are judged in the mounted directory under `-w`, else unknown |
| 6C15 | Plans are resolved physically; `/dev` and `/proc` plans, and plans written in the command by anything but `plan -out`, are protected; a `plan -out` elsewhere and a plan in an environment's path bring their tier |
| 6H6, 6H9, 6H12 | Unmatched state-file directories take the unknown-directory tier; `workspace new -state` carries its state's tier; `terragrunt --all` walks its units |

**Verification:**
- `go test ./...` passes, including the attack pack (393 scenarios).
- Selftest: 163/163 exact.
- Replays: Claude 163/163, Codex 161/161.
- Agent trial: no verdict changes in prod, staging or dev, compared with main.

### R6-2: strict shapes that see what programs read

**Decided on 2026-11-03: C. Built** on branch fix/round-6-shapes:
- `internal/shell/gitstate.go` holds git's discovery, config parsing and the safe list.
- `internal/policy/engine_state.go` checks terraform's providers, upstream lock and data sources.
- Measured on the agent trial: 51 of 162 calls in a protected directory are asked about or blocked, against 47 for R6-1. Of the 4 new asks, 2 are `terragrunt` and 2 are terraform in trial directories that do not exist on this machine.
- The replay fixture has no installed providers, so the provider check is covered by unit tests, not the trial.

The analysis that led to the decision:

The remaining criticals (6C6 to 6C12, 6C16) and 6H21 share one cause: a plain command reads state an earlier allowed call can write. Exact shapes check a program's arguments, not that state. Two ways to close it inside the hook are measured below. Both keep the adversarial promise.

**Measured on the agent trial in a protected directory** (162 real calls; about 8 of the asks today come from trial paths that do not exist on this machine):

| Variant | Not allowed | Share |
|---|---|---|
| Today (main and this branch) | 47 | 29% |
| A. Tight: git, and every terraform command that runs providers or external programs (`plan`, `validate`, `console`, `show`, `state`), ask | 101 | 62% |
| B. Verified: git stays plain only when its whole configuration is verified; terraform as in A | 75 | 46% |
| C. Verified, terraform too: `plan` and `validate` stay plain when every provider under `.terraform/providers` matches the committed lock file and the configuration has no `data "external"` | about 47 to 55 (estimate, to be measured on the prototype) | about 30 to 34% |

What "verified" means, per program:
- **git:**
  - The repository is found the way git finds it: `GIT_DIR`, `-C`, a bare repository, `commondir` and worktrees.
  - Every config file git reads is checked: system, global (`~/.gitconfig`, `$XDG_CONFIG_HOME/git/config`), repository, `config.worktree`, every `include` and `includeIf`, and each submodule's `modules/*/config`.
  - Every key must be on a safe list (`core.bare`, `core.filemode`, `remote.*.url`, `branch.*.*`, `user.*` and the like); an unknown key is not plain.
  - `.gitattributes` and `info/attributes` must not name a filter, `diff` or textconv driver.
  - Hooks are checked in every git directory found.
  - Network subcommands (`fetch`, `pull`, `push`, `ls-remote`, `clone`) also need `~/.ssh/config` (now guarded) and a remote that is not a local path.
- **terraform:** providers match the lock file's hashes for this platform, the lock file is the committed one, and no `data "external"` is in the configuration or its local modules.
- **Everything plain:**
  - The program is resolved to a system directory (`/bin`, `/usr/bin`, `/usr/sbin`, `/sbin`, or a root-owned Homebrew prefix), not by basename.
  - zsh's `functions`, `commands`, `path`, `aliases` and `builtins` arrays, `hash name=path`, the hook function names (`chpwd`, `precmd`, `preexec`, `zshexit`, `TRAP*`, `periodic`), and a `cd` as the last element of a pipeline are not plain.
  - `alias`, `hash`, `enable` and `shopt expand_aliases` are not plain through persistent-shell MCP tools.
  - A Makefile or `terragrunt.hcl` written in the same command is unresolved; `make SHELL=`, `$(shell …)` and implicit rules are not plain; `terragrunt` with `run_cmd` or hooks is not plain.

Recommendation: **C**. It costs about what strict shapes cost today, if the prototype confirms the estimate. It turns the open-ended class into checks of named files, each of them an allowlist: an unknown key or provider asks.

### R6-3: OS-level enforcement (later, not instead)

The class that a text-judging hook cannot close by checks is real: code the agent can run in a disposable directory still has the user's credentials. The structural backstop is to keep production credentials out of the agent's processes:
- a credential broker that hands a short-lived role only to the commands applygate allowed in a protected tier;
- or a sandbox profile (macOS sandbox, Linux Landlock) for the agent's processes.

This is a design document after R6-2, not part of v0.6.0's fixes.

### R6-4: the rest of the highs and mediums

Every remaining high and medium in the round-6 report, in the order of the report. They are not blocked on R6-2:
- 6H2, 6H3, 6H4, 6H7, 6H8, 6H10, 6H11, 6H13 to 6H20;
- the mediums.

## Exit

Red-team round 7, briefed on the same promise, with no critical finding.
