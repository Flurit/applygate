# Upgrading

What to do when you upgrade from an earlier release. Every change is in [CHANGELOG.md](../CHANGELOG.md).

## To v0.7.0

One verdict changes. Nothing needs doing unless you relied on the prompt it removes. Hooks, configs and trust carry over as they are, and the plugin exception under v0.6.1 below holds here too.

- **In a standard tier, a saved plan whose only deletes and replaces are routine replaces is allowed.** It was asked about before. A replace is routine for a short list of types that hold no data, such as a launch template, a task definition or a policy attachment; [policy.md](policy.md) (step 6) has the list and the conditions. A protected tier blocks every replace as before, and a delete, a stateful replace and a replace of any other type still ask.
- **To keep the prompt for some resources,** list their addresses under `protected_resources`: `["aws_launch_template.*"]` for the root module, `["*aws_launch_template.*"]` to reach inside modules ([config.md](config.md)).
- **In CI,** `applygate plan-check` exits 0 for such a plan in a standard tier, where it exited 4. A job with `fail-on: ask` that judges a standard tier passes where it failed. A runner without `--trust-config` (the Action's `trust-config`) judges every directory as protected and is not affected.
- **The pull-request comment** lists routine replaces under what was found, and no longer gives "any destroy or replace" as the reason for an ask that something else caused.

## To v0.6.3

Nothing to do when you come from v0.6.0, v0.6.1 or v0.6.2. v0.6.3 reorganises the documentation and tidies the code; it changes no rule, verdict or default, and hooks, configs and trust carry over as they are. The plugin exception under v0.6.1 below holds here too.

- **Links into the docs may need updating.** `docs/migration.md` is now the last section of this page, the corpus trial is `review/oss-corpus/trial.md`, and the records that were under `docs/project/` are in `review/`. [limits.md](limits.md) has new headings, by topic.

## To v0.6.2

Nothing to do when you come from v0.6.0 or v0.6.1. v0.6.2 adds the Action's pull-request comment ([ci.md](ci.md#a-comment-on-the-pull-request)) and changes no rule, verdict or default; hooks, configs and trust carry over as they are. The plugin exception under v0.6.1 below holds here too.

- **The Action at the v0.6.2 tag installs v0.6.2.** At earlier tags it installed the release before the tag. If your workflow sets `version` itself, nothing changes.
- **`scripts/ci-plan-check.sh` exits 2, not 1, for a working directory that does not exist or an unset `PLAN`.** This matters only if a script of yours tells the two codes apart; the Action fails the job either way.

## To v0.6.1

Nothing to do when you come from v0.6.0. v0.6.1 adds `applygate scan` ([scan.md](scan.md)) and changes no rule, verdict or default; hooks, configs and trust carry over as they are.

One exception, which holds for every upgrade: the Claude Code plugin pins the binary it first found by path and sha256, so after upgrading remove `pinned-binary` from the plugin's data directory, or every call is blocked with a message that says so.

From a release before v0.6.0, follow the steps below.

## To v0.6.0

v0.6.0 fixes the findings of a pre-release security review ([review/v0.6.0](../review/v0.6.0)). Several fixes change behaviour:

- **Reinstall the hooks:** run `applygate hook install --agent claude` (and `--agent codex`) with the `--scope` you used. After reinstalling the Codex hook, open Codex and run `/hooks` to trust it again: Codex skips a changed hook without saying so, and `applygate doctor` reports whether it will run. The Claude Code matcher is now `*`, so every tool reaches the hook, and the `seatbelt` compatibility binary is gone: a hook entry that still calls it fails. `applygate doctor` flags both.
- **Trust your repository configs:** run `applygate trust` in each repository and after every change to its `.applygate.yaml`. Until then the config is not read and every directory is protected; `applygate doctor` lists the configs that need it.
- **The Claude Code plugin pins its binary** the first time it finds one. After upgrading applygate, remove `pinned-binary` from the plugin's data directory, or every call is blocked with a message that says so.
- **For a guard the agent cannot change,** use `install --managed --exclusive`, run with `/usr/bin/sudo` and a verified binary by its full path ([managed.md](managed.md)). Without it, self-protection is best-effort. Under it, the plan gate runs only a root-owned `terraform`; name one in the system config's `plan_gate.engines` if yours is a Homebrew or user install.
- **Strict shapes are on.** In a protected environment, a shell command that is not a plain list or pipeline of known programs, each called in a shape that runs no other program, is asked about: a loop, `bash -c`, `python3 -c`, `export`, `xargs`, `npx`, `man`, a pager or editor variable, git with `-c` or in a repository with hooks. `strict_shapes: false` in the user config turns it off.
- **Move loosening settings to your user config.** A repository `.applygate.yaml` can now only add protection: `mode: observe`, `strict: false`, a looser `default_tier`, `name_hints` or `on_error`, and `aliases` there are ignored, and `doctor` says so.
- **One-time approvals are off by default.** Turn them on in the user config (`approvals: true`) if you accept that an agent on the same machine can reach your terminal.
- **`applygate apply` has no `--yes` and no `--plan-json`.** In CI, gate with `applygate plan-check` or the Action and run the engine yourself.
- **The plan gate needs a committed `.terraform.lock.hcl`** wherever `.terraform/providers` holds providers. Before running `terraform show` it checks the providers against it, and without one a saved plan in a protected environment is blocked. Terragrunt's own `show` is no longer run.
- **Hook files are guarded where the agent's host loads them:** at the git root of a repository with no `.applygate.yaml`, and in the directory a Claude Code, Gemini CLI or Devin session was started in. Removing, moving, copying or extracting into a directory there that holds hook settings is blocked.
- **Git rewrites ask:** `git checkout BRANCH`, `pull`, `merge`, `rebase`, `stash` and the like ask in a repository or session directory that holds hook settings, rather than being blocked; on agents that cannot ask they are blocked. Restoring a hook or config file by name is still blocked.
- **Removing a directory** counts only guard files under it that exist and whose loss weakens the guard, so `rm -rf .terraform`, `.git` or `.vscode` at a repository root is no longer blocked as tampering.
- **Stricter verdicts:**
  - replacing a resource in a saved plan is judged like destroying it;
  - a file a command writes and then runs, a glob in a program name, and a command whose directory cannot be followed are asked about in protected environments;
  - an internal error under `on_error: auto` blocks when the repository has a protected environment.
- **`install.sh` requires cosign** to verify the release signature; `APPLYGATE_VERIFY_SIGNATURE=auto` installs without it.

## To v0.5.0

- **Approvals:** on agents that cannot show you an ask prompt, the block now names an approval ID that you can allow once with `applygate approve ID`. Nothing to reinstall; `approvals: false` turns it off.
- **Behaviour change:** commands run through `script` (for example `script -q /dev/null terraform destroy`) or `expect -c` used to go unchecked; they are now judged, so some will be blocked.

From v0.3 or earlier, also:

- **To log MCP tool calls from Claude Code,** reinstall its hook: re-run `applygate init`, or `applygate hook install --agent claude` with the `--scope` you used. `applygate doctor` flags a hook that needs this. MCP calls are logged, never blocked.
- **Behaviour change:** Cursor, Copilot CLI and Devin also run the Claude Code hook from `.claude/settings.json`. Their shell commands through that hook used to be allowed unchecked; they are now judged, so some will be blocked.
- **Protected paths:** agents can no longer edit the hook files of the newly supported agents.

## From seatbelt

This project was called seatbelt until 2026-10-29. The word already names Apple's macOS sandbox in the Claude Code and Codex documentation, and other agent-guardrail products use it, so the name was confusing for exactly the people this tool is for. v0.2.0 was the first release as applygate. For an existing install:

- the repository config is `.applygate.yaml` (a `.seatbelt.yaml` is still read, with a note from `doctor`; rename it);
- hook entries become `applygate hook claude` / `applygate hook codex` (`applygate hook install` rewrites them; the `seatbelt` compatibility binary shipped with v0.2 to v0.5 and is gone in v0.6.0, so run `applygate hook install` before upgrading; `applygate doctor` flags a hook entry that still calls it);
- the user config and the decision log move to `~/.config/applygate/` and `~/.local/state/applygate/` (existing files at the old paths are used until a new one exists);
- installer variables are `APPLYGATE_VERSION`, `APPLYGATE_INSTALL_DIR` and `APPLYGATE_VERIFY_SIGNATURE` (the `SEATBELT_*` names were honoured until v0.5; v0.6.0 reads only the `APPLYGATE_*` names).

Release tags v0.1.0 to v0.1.4 and the records under `review/` keep the old name where they describe those builds.
