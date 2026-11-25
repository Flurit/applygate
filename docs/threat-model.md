# Threat model

## Defends against

A **mistaken or manipulated agent** running with the developer's privileges. For example, an agent that:

- runs `terraform destroy`, `apply -auto-approve`, state surgery or cloud CLI deletes against the wrong or a protected environment;
- applies a saved plan in a different workspace from the one it was made in, or with a production profile set in the environment;
- works next to stale or archived state, or after the backend or lock file changed;
- hides a destructive command behind variables, functions, `eval`, `bash -c`, here-documents, base64, `xargs`, git aliases, interpreter options, Makefiles or scripts. This is often because injected instructions told it to. The analyzer follows these, and what it cannot reproduce exactly (a computed program name, a file the same command writes, a glob, a directory it loses track of) is asked about in protected environments. A program it does not know that wraps another cloud CLI is a known gap ([limits](limits.md));
- tries to turn off its own guardrails: skip-permissions flags, edits to hook settings, applygate's config, log, approvals or judge cache, a renamed or reinstalled copy of applygate, or the agent CLI's own switches (`claude plugin disable`, `claude config set`, a nested `claude --settings`, `codex -c` hook overrides);
- plants a configuration: a nested or cloned `.applygate.yaml`, which can only add protection, never remove it;
- swaps what will run: a planfile or `.terraform` rewritten earlier in the same command, or a provider binary replaced in `.terraform/providers`;
- reads cloud credential files: the AWS credential and SSO cache paths and Terraform's credentials file, with the common readers (cat, head, grep, cp, curl and the like; the list is in [limits](limits.md)); other credential files and other readers are not covered by the hook.

## Does not defend against

- A malicious insider, or an attacker with the developer's shell outside the agent.
- An agent that reaches cloud credentials by a path the hook does not see (see [limits](limits.md)).
- Compromise of the applygate binary, the agent, or the toolchain. Without a managed install ([managed.md](managed.md)) that includes a `terraform` the agent puts on `PATH` by a route the hook does not see; writing `terraform`, `tofu` or `terragrunt` into a `PATH` directory is blocked as tampering.
- Writes by routes the hook does not inspect: code in another language that writes a guard file ([Self-protection](#self-protection)) without naming it, or a process the agent started earlier. This includes a program placed in a `PATH` directory that way: strict shapes ([policy.md](policy.md)) trusts programs by name, so a plant there runs as the program it replaces.

## Self-protection

A **guard file** is a file the protection depends on: an agent's hook settings, applygate's own config, log and binary, and the other files listed below. An agent that changes one can switch the guard off, so the hook treats a write to a guard file as tampering.

How far that holds depends on how applygate is installed.

- **A managed install is the only guarantee.** With `sudo applygate install --managed`, root owns the binary, a system config that is read first, the trust store, and the hook in Claude Code's managed settings with bypass mode off. The user config may then only tighten, the judge included. The agent's user cannot change any of it. [managed.md](managed.md) has the parts, the setup and what it does not cover.
  - Two parts stay in the agent's user's reach and are hardened instead: the state directory (the decision log, and the approval store, which the install turns off), and the programs the hook runs. The plan gate runs `terraform`, `tofu` or `terragrunt` only from a root-owned path; otherwise the saved plan is unverifiable ([managed.md](managed.md) names the paths).
  - The Claude Code keys are from its docs and not yet tested live. The Codex snippet is printed, not written, and not tested live.
- **Without a managed install, self-protection is best-effort.** The hook blocks the routes it knows, and a route it does not see can still change a guard file: an agent with the user's shell can, in the end, change anything the user can. Listing every program that can write a file does not converge. Treat it as a guard against mistakes, not against an agent that is trying to get around it.
  - In a repository with no config, strict shapes ask only about a command that names an infrastructure tool or a guard file ([policy.md](policy.md), "Strict shapes"). A route the analysis does not follow is asked about there only when it names one; [limits.md](limits.md#a-repository-with-no-config) gives the measured cost. A managed install keeps the full rule in every repository.
  - `applygate init` installs at user scope (`~/.claude/settings.json`, `~/.codex/hooks.json`) so the hook fires whichever directory the session starts in. That is still a file the developer owns.
- **Observe mode turns self-protection off**, as it turns every block off. It is for a trial, not for an environment an agent should not be able to change.

The rest of this section is what the best-effort checks cover.

### Guard files

A write to any of these is blocked in every tier and in every mode except observe:

- **Agent hook settings:**
  - Claude Code and Codex: `.claude/settings*.json`, managed settings, `.codex/hooks.json` and `config.toml`;
  - the other hosts: `.cursor/hooks.json`, `.gemini/settings.json`, `.github/hooks/`, `~/.copilot/hooks/` and `settings.json`, `.windsurf/hooks.json`, `~/.codeium/windsurf/hooks.json`, `.devin/config.json`, `~/.config/devin/config.json`, `.opencode/plugins/`, `~/.config/opencode/plugins/`, `.clinerules/hooks/`, `~/Documents/Cline/Hooks/`.
- **applygate's own files:** `.applygate.yaml`, the user config, the decision log, the approval store, the judge cache, the telemetry settings and the applygate binary.
- **Claude Code extensions:** the applygate plugin's installed copy, marketplace clone, data directory and download cache (its launcher script and the binary it fetched); every Claude Code plugin's files; Claude Code skills, subagents and commands, project and user (their frontmatter can declare hooks).
- **MCP server lists of every host:** `.mcp.json`, `~/.claude.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `~/.copilot/mcp-config.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/extensions/`, `opencode.json`.
- **Config files in which a trusted program names a command to run.** Strict shapes ([policy.md](policy.md)) trusts some programs by name, and these files can make them run something else: `~/.gitconfig`, `~/.config/git/`, `~/.aws/config`, `~/.aws/cli/`, `~/.kube/config`, `~/.config/gh/`, `~/.docker/config.json`, `~/.terraformrc`, `~/.terraform.d/`, `~/.tflint.d/`, `~/.wgetrc`, helm's plugins.
- **Programs planted on `PATH`:** any program strict shapes trusts by name, or that the hook and its plugin run (`sh`, `sudo`, `sha256sum`, `aws`, `git`, …), placed in a `PATH` directory the user can write.

How the paths are matched:

- They follow `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.
- They are compared after resolving symlinks and, on macOS and Windows, case.
- A pattern such as `**/.claude/settings.json` stands for that file under home, the repository config's directory, the nearest git root and the session directory the hook's environment names (`CLAUDE_PROJECT_DIR`, `GEMINI_PROJECT_DIR`, `DEVIN_PROJECT_DIR`).

### What counts as tampering

- **Tools and routes covered:** the Write and Edit tools, `apply_patch`, MCP tools outside the known-tool table, shell redirection (on compound commands too), and code in other languages that names a guard file.
- **Shell commands are judged by default-deny.** A program that names a guard file, or a guarded directory, is tampering unless it is on a short read-only list (`cat`, `head`, `ls`, `grep`, `diff`, `git status`/`log`/`diff`/`add`/`commit`, …). This does not depend on knowing how a program writes.
  - Words applygate cannot resolve count when their literal text names a guard file (`${HOME:-x}/.claude/settings.json`) or when they are a glob that could match one.
  - The cost: some reads outside the list are blocked too, such as `cp ~/.claude/settings.json /tmp` or `sed -n 1p .applygate.yaml`.
- **Directories that hold a guard file count too.**
  - A program that writes, removes or extracts may not name such a directory. Moving, copying or extracting into it is blocked.
  - Removing it is blocked when a guard file under it exists and its loss can weaken the guard. Removing a directory that holds only Terraform providers, git hooks, MCP server lists, skills or other files that matter only for what is placed in them is not ([limits.md](limits.md)).
- **Git rewrites at a repository or session root ask rather than block.** `git checkout`, `pull` and the other work-tree rewrites there are the person's call: a commit may bring in a hook file, and a rewritten `.applygate.yaml` is not read until trusted again.

### Repository configs

- **A repository config can only add protection.** Every `.applygate.yaml` from the repository root down applies. Observe mode, `strict: false`, looser tiers and error handling, aliases, moving the log and network access (the model judge included) come from the user config only. A repository config may turn the judge off.
- **Repository configs must be trusted.** A `.applygate.yaml` is read only when a person approved its exact content with `applygate trust`, which shows the file and needs a terminal.
  - A config that is new, or changed by any route (a git checkout, an extraction, a clone, a program applygate does not know), is not read, and every directory is judged as protected until a person trusts it.
  - An agent that runs `applygate trust` is blocked as guard tampering.

### Nested agents, package managers and the plugin

- **Nested agents.** Starting an agent CLI from an agent is tampering when it:
  - turns hooks or permission checks off (`claude --bare`, `CLAUDE_CODE_SIMPLE`, `codex --disable hooks`, `codex -p`, `gemini --yolo`, `copilot --allow-all-tools`);
  - points the agent at other settings (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `HOME=`).

  `npx`, `bunx` and `pnpx` of an agent package are judged the same way.
- **Package managers** that install, remove or replace `applygate` or `seatbelt` are tampering. So is writing an executable of that name into a directory on `PATH`, or editing a shell start-up file. A copy of the running binary is recognized by its content, whatever its name.
- **The Claude Code plugin pins its binary.** The first `applygate` the launcher finds is pinned by path and sha256 in the plugin's data directory. Later calls run only that file, and only while its hash is unchanged.

### Model judge and telemetry

- **The model judge reads text the agent wrote,** which an attacker may have shaped to talk it into "allow". Its verdict is merged as the stricter of the two, and it only sees calls the rules allow, so a judge that is fooled gives the verdict the rules would have given without it ([judge.md](judge.md)).
  - Its cache reads back only escalations (`ask`, `block`), so a planted cache entry cannot make it skip a call.
  - A call that breaks the judge (too large, refused, unreadable answer) is asked about outside disposable environments.
  - Under a managed install the cache is not used, the judge program must be root's, and a judge that fails is treated like one the call broke.
- **Telemetry** is off by default and carries only anonymous verdict counts ([telemetry.md](telemetry.md)). Its settings file is a guard path, and `applygate telemetry on|off` run by an agent is blocked as guard tampering in every tier. `APPLYGATE_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment forces it off whatever the file says.

### An unreported command directory

When a host does not report the directory a command runs in (Codex 0.165.0), applygate judges the command at the most protected tier it could be in under the session root rather than trusting the root's tier ([limits.md](limits.md), [hosts.md](hosts.md)).

## Recommended pairing

The hook judges calls before they run, and a judgment can be wrong. What a wrong judgment can reach is set by the agent's credentials, so the boundary that holds whatever the hook decides is there ([credentials.md](credentials.md)):

- plan-only credentials for the agent;
- apply credentials only for a person (behind MFA) or a CI runner;
- the person's own sessions (SSO tokens, cached role credentials) kept out of the agent's OS user;
- an isolated runner for anything protected.

`applygate doctor --creds` asks AWS and the clusters whether the credentials on the machine can change production without MFA.
