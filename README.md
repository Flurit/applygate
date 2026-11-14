# applygate

**Stop coding agents from running `terraform destroy` in production.**

[![Release](https://img.shields.io/github/v/release/Flurit/applygate)](https://github.com/Flurit/applygate/releases)
[![CI](https://github.com/Flurit/applygate/actions/workflows/ci.yml/badge.svg)](https://github.com/Flurit/applygate/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Flurit/applygate)](LICENSE)

- **What it does:** before an AI coding agent runs a command, applygate checks it and answers **allow**, **ask** or **block**, with a reason the agent can act on. It covers Terraform, OpenTofu and Terragrunt, and the aws, gcloud, az, kubectl and helm CLIs.
- **Who it is for:** teams that let Claude Code, Codex or another coding agent work in infrastructure repositories.
- **How:** it runs on your machine as the agent's pre-tool-call hook. Fixed rules decide, with no model involved by default, and nothing leaves your machine.
- **What it is not:** a sandbox. It catches mistakes and most injected instructions, but an agent that is set on getting around it and holds credentials that can write can still do damage. [What it does not protect against](#what-it-does-not-protect-against).

applygate is pre-1.0, for macOS and Linux.

<p align="center">
  <img src="docs/assets/demo.svg" alt="applygate blocking terraform destroy in prod, also when it is hidden in base64, while allowing a commit message that mentions it" width="820">
</p>

## Quick start

```bash
brew install Flurit/tap/applygate     # other ways to install: docs/install.md
applygate scan                        # optional: look before you install a hook (below)
cd your-infra-repo
applygate init                        # .applygate.yaml for this repository, hooks for Claude Code and Codex, a user config if you have none
applygate check "terraform -chdir=envs/prod destroy"
```

- **Look first.** `applygate scan` needs no hook and no config. It reads the sessions Claude Code and Codex already recorded on your machine and shows what your agents can reach and what applygate would have decided on the calls they made. Nothing is run, and nothing leaves your machine ([docs/scan.md](docs/scan.md)).
- **Using Codex?** Open it and run `/hooks` once to trust the new hook. Until you do, Codex skips it without saying so. `applygate doctor` tells you whether it will run.
- **Two config files.** `.applygate.yaml` lists the repository's environments; commit it so your team shares it. It can only add protection, and after every edit a person runs `applygate trust`, so an agent cannot quietly relabel production. Your own settings, such as observe or enforce, live in `~/.config/applygate/config.yaml`.
- **It starts in observe mode.** It logs what it would block and blocks nothing. That includes an agent editing or removing applygate itself, so try it where that is acceptable.
- **Then turn it on.** After a few days, `applygate report` shows what it would have stopped and `applygate suggest` proposes environments and tiers. Set `mode: enforce` in your user config and run `applygate doctor`.

## What it decides

Every command is judged by the environment it targets. You map directories, workspaces, backends, AWS profiles, Kubernetes contexts, GCP projects and Azure subscriptions to a tier in `.applygate.yaml` ([config](docs/config.md)): **protected** for production, **standard** or **disposable**. Anything applygate cannot place counts as protected.

| Command | Protected | Standard | Disposable |
|---|---|---|---|
| Read-only: `plan`, `show`, `validate`, `state list` | allow | allow | allow |
| Apply a saved plan: `terraform apply tfplan` | plan check | plan check | allow |
| Apply without a saved plan: `apply -auto-approve` | block | ask | allow |
| Destroy: `destroy`, `apply -destroy`, `-replace`, a plan that deletes | block | ask | allow |
| State changes: `state rm/mv/push`, `force-unlock`, `taint` | block | ask | ask |
| Cloud deletes: `aws … delete-*`, `s3 rb`, `kubectl delete`, `helm uninstall` | block | ask | ask |
| Turning applygate off: skip-permission flags, editing hooks or applygate's files | block | block | block |
| Git commands that rewrite files in a repository holding agent hook files (such as `.claude/settings.json`): `checkout BRANCH`, `pull`, `merge` | ask | ask | ask |
| Commands it cannot resolve: `curl … \| bash`, `eval "$(curl …)"` | ask | ask | allow |
| Anything else that is not a plain, known command: loops, `bash -c`, `npx`, unknown programs | ask | allow | allow |

- **Plan check:** for `apply <planfile>` it reads the plan and rates what it finds as critical or high: destroyed or replaced stateful resources, removed deletion protection, internet exposure, IAM wildcards, state-backend changes. In a protected environment critical findings block and high ones ask; in a standard one critical findings ask. You can mark your own resources as critical ([policy](docs/policy.md)).
- **Turning applygate off** is blocked in every tier, but only a managed install makes that a guarantee ([below](#what-it-does-not-protect-against)).
- **Outside protected environments,** applygate still asks about a command that can run code it cannot follow if the same repository holds a protected environment.

### Why not a pattern matcher?

applygate reads commands the way the shell does. It follows `cd`, variables, `bash -c`, `eval`, `sudo`, `xargs`, Makefiles, scripts and base64 payloads to find what actually runs, so `grep "terraform destroy"` is just a grep and a destroy hidden in base64 is still a destroy. In a protected environment it also asks about anything that is not a plain command, because only plain commands are fully understood.

On 17 dangerous Terraform scenarios (our own set, so a demonstration, not a measure of coverage):

| Guard | Caught |
|---|---|
| Best existing open-source guard we tried (default config) | 5 / 17 |
| A competent hand-written Rego/regex policy | 14 / 17 |
| **applygate** (protected tier) | **17 / 17** |

The hand-written policy also blocked harmless text like `git commit -m "never run terraform destroy"`. The scenarios are in [harness/](harness), and `applygate selftest` runs all 163 scenarios against your binary.

## Supported agents

| Agent | Status | Can show you an ask prompt | If applygate cannot run |
|---|---|---|---|
| Claude Code | Tested live | yes (except in `acceptEdits`, `plan` and `dontAsk` modes) | the call is blocked (Claude Code 2.1.295 or later) |
| Codex | Tested live | no: an ask is a block | the call runs |
| GitHub Copilot CLI | Preview | yes | blocked; runs on a timeout |
| Cursor | Preview | no: an ask is a block | blocked |
| Gemini CLI | Preview | no: an ask is a block | the call runs |
| Windsurf (Cascade) | Preview | no: an ask is a block | the call runs |
| Devin (shell commands only) | Preview | no: an ask is a block | the call runs |
| OpenCode | Preview | no: an ask is a block | blocked; runs if the plugin fails to load |
| Cline | Preview | no: an ask is a block (it cancels the task) | blocked; runs on a timeout or a missing hook script |

- **`applygate init`** installs the hooks for Claude Code and Codex.
- **Preview** hooks follow each agent's documentation but have not been tested inside the agent. Install one with `applygate hook install --agent NAME`. To check it works, ask the agent to run `terraform destroy -auto-approve` in an empty directory: it should be blocked.
- **On agents that cannot ask,** a person can allow one stopped call with `applygate approve ID`. This is off by default, because an agent on the same machine can reach your terminal too ([policy](docs/policy.md)).
- **On agents where the call runs if applygate cannot start,** keep the agent's own sandbox and approval settings on as a second line.
- **MCP tools:** in Claude Code and Codex, calls to known infrastructure MCP servers (AWS, HCP Terraform, Kubernetes, gcloud, az, shell servers) are judged like the equivalent command. This has not yet been tested against the running servers ([mcp](docs/mcp.md)).

Per-agent details: [docs/hosts.md](docs/hosts.md), or `applygate hosts`.

## When something goes wrong

- **A check that fails** (a bad config, unreadable input, an internal error) blocks, unless every directory in the repository is configured as standard or disposable. `on_error` in your user config changes this.
- **A decision that takes longer than 25 seconds** is blocked.
- **If applygate cannot start at all,** the agent decides: see the table above. `applygate doctor` checks that the hook is in place.
- **To stop it blocking,** set `mode: observe` in your user config. **To remove it,** run `applygate hook remove --agent NAME` for each agent, then `brew uninstall applygate`.

## What it does not protect against

A hook cannot promise that a command is never allowed. What protects you when it is wrong is a boundary around the agent: credentials that can only plan, writes behind MFA, a versioned and locked state bucket, a host sandbox and a reviewed apply path.

- `applygate doctor --boundary` checks the ones it can and reports an assurance level from L0 (the hook only) to L3 (all of these in place) ([boundary](docs/boundary.md)).
- `applygate doctor --creds` asks your cloud accounts whether the credentials on this machine can change production without a person ([credentials](docs/credentials.md)).
- Stopping an agent from turning applygate off is guaranteed only with a managed, root-owned install ([managed](docs/managed.md)); without one it is best-effort.

Known gaps are in [docs/limits.md](docs/limits.md), and what has been tested live is in [docs/capabilities.md](docs/capabilities.md).

## Beyond agents

**From your terminal,** `applygate apply tfplan` judges a saved plan the way the hooks do, then runs `terraform apply` (or `tofu`). On an ask you confirm by typing the environment's name.

**In CI,** the same plan check runs between `plan -out` and `apply`, as a GitHub Action or a Terragrunt `before_hook` ([docs/ci.md](docs/ci.md)):

```yaml
- uses: Flurit/applygate@v0.6.0
  with:
    plan: tfplan
    working-directory: envs/prod
```

## Model judge (optional)

No model is needed. If you want a second opinion on calls the rules do not recognize (Pulumi, database clients, unknown scripts), turn on `judge:` in your user config with a model you choose. It can only make a verdict stricter, never looser ([docs/judge.md](docs/judge.md)).

## Privacy

applygate makes no network calls by default, and logs decisions locally with secrets redacted. Three opt-in features do make network calls: the model judge, anonymous usage counts ([telemetry](docs/telemetry.md)), and live checks of your AWS identity and remote state. Three commands you run yourself also ask the cloud, read-only, what the credentials on your machine can do: `doctor --creds`, `doctor --boundary` and `scan --boundary`.

## Docs

- [Install](docs/install.md): installer, Homebrew, Go, signature checks, the Claude Code plugin
- [Configuration](docs/config.md) and [policy rules](docs/policy.md)
- [Commands](docs/commands.md), [scan](docs/scan.md)
- [Agents](docs/hosts.md), [MCP servers](docs/mcp.md), [CI](docs/ci.md)
- [Limits](docs/limits.md), [threat model](docs/threat-model.md), [what has been tested](docs/capabilities.md)
- [Upgrading from an earlier release](docs/upgrading.md), [changelog](CHANGELOG.md), [roadmap](docs/roadmap.md)

## Contributing

The easiest way in is a scenario: a command or plan that applygate gets wrong, added to the pack with the verdict it should get ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go in [Discussions](https://github.com/Flurit/applygate/discussions). If you find a way around the guard, report it privately as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE). Maintained by Flurit.
