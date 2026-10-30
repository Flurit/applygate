# applygate

**Stop coding agents from running `terraform destroy` in production.**

[![Release](https://img.shields.io/github/v/release/Flurit/applygate)](https://github.com/Flurit/applygate/releases)
[![CI](https://github.com/Flurit/applygate/actions/workflows/ci.yml/badge.svg)](https://github.com/Flurit/applygate/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Flurit/applygate)](LICENSE)

A deterministic, local pre-execution check for coding agents (Claude Code, Codex, Cursor, Copilot CLI, Gemini CLI, Windsurf, Devin, OpenCode, Cline) that touch Terraform or OpenTofu infrastructure. Before the agent runs a tool call, applygate returns **allow**, **ask** or **block**, with a reason and a next step the agent can act on.

<p align="center">
  <img src="docs/assets/demo.svg" alt="applygate blocking terraform destroy in prod, also when it is hidden in base64, while allowing a commit message that mentions it" width="820">
</p>

Status: pre-1.0 (v0.3.1), tested live with Claude Code and Codex. Adapters for Cursor, GitHub Copilot CLI, Gemini CLI, Windsurf (Cascade), Devin, OpenCode and Cline are written from each host's documentation and source and are **not yet tested live** ([docs/hosts.md](docs/hosts.md)). What is and is not verified: [docs/project/ACCEPTANCE.md](docs/project/ACCEPTANCE.md). Upgrading from seatbelt, the project's old name: [docs/migration.md](docs/migration.md).

## Try it in a minute

```bash
brew install Flurit/tap/applygate         # other installs and signature checks: see Install below
cd your-infra-repo
applygate init                            # writes .applygate.yaml in observe mode and hooks Claude Code / Codex
applygate check "terraform -chdir=envs/prod destroy"
```

Observe mode logs what it would have blocked and blocks nothing, so `check` prints `allow` followed by the block that enforce mode would give. After a few days, `applygate report` shows what it caught and `applygate suggest` proposes a config; then set `mode: enforce`.

## Why another guard

Command-pattern matching is table stakes. We replayed the same 17 dangerous and 13 harmless Terraform scenarios through each guard:

| Guard | Dangerous scenarios caught |
|---|---|
| Best existing open-source guard we tried, default config | 5 / 17 |
| A competent hand-written Rego/regex policy | 14 / 17 |
| **applygate**, protected tier | **17 / 17** |

The hand-written policy still missed base64, variable and `eval` obfuscation, and it blocked harmless text such as `git commit -m "never run terraform destroy"`. A matcher cannot do better than that, because it reads text, not commands, and it cannot see what a change will do. applygate asked on 1 of the 13 harmless scenarios (an apply of a planfile that does not exist yet). Reproduce its row with `python3 -I harness/replay_pack.py --guard bin/applygate --pack harness/pack_v0_original/scenarios.json --fixture harness/pack_v0_original/fixtures/protected`; the pack and runner are in [harness/](harness), and the larger v1 pack, with a scorecard of its dangerous and harmless scenarios, runs with `applygate selftest`.

applygate does two things a matcher cannot:

1. **Shell-aware command analysis.** It parses commands the way bash does ([mvdan/sh](https://github.com/mvdan/sh)), tracks `cd`, variables, `export`, loops and functions, unwraps `bash -c`, `eval`, here-documents, `sudo`/`env`/`timeout`/`xargs`/`script`/`chroot`/`parallel`/`find -exec`, reads Makefile recipes and shell scripts, and decodes `echo … | base64 -d | sh`. It tells commands apart from text: `grep "terraform destroy"` is a grep. Anything it cannot resolve statically, such as fetched text piped into a shell, it **refuses** (ask) instead of guessing.
2. **Preflight and plan-level checks.** It maps the working directory, workspace, backend and AWS profile to an environment tier. It flags a saved plan made in another workspace (read from the planfile itself), a backend block changed since `init`, stale or archived state files (optionally compared with the remote state's lineage and serial), and lock-file or module-source drift. For `apply <planfile>` it reads `show -json` and checks for destroyed or replaced stateful resources, removed protection (deletion protection, final snapshots, force-destroy, versioning), internet exposure, IAM wildcards, and changes to the state backend itself.

It is not a sandbox and not an AI reviewer. No model is in the decision path, it makes no network calls by default, and telemetry is off unless you turn it on ([docs/telemetry.md](docs/telemetry.md): anonymous verdict counts, nothing else).

## Install

### Install and set up

```bash
# Installer from a release tag, never from main. It verifies the cosign signature on checksums.txt
# when cosign is installed and warns when it is not; APPLYGATE_VERIFY_SIGNATURE=require makes cosign
# mandatory. Without cosign only the sha256 is checked, which does not detect a tampered release.
curl -fsSL https://raw.githubusercontent.com/Flurit/applygate/v0.3.1/install.sh | APPLYGATE_VERIFY_SIGNATURE=require sh
# or: go install github.com/Flurit/applygate/cmd/applygate@v0.3.1
# or: brew install Flurit/tap/applygate   (Homebrew checks the sha256 only, not the cosign signature)
# or: go build -o bin/applygate ./cmd/applygate
cd your-infra-repo
applygate init                            # writes .applygate.yaml (observe mode), detects Claude Code / Codex, installs their hooks at user scope
$EDITOR .applygate.yaml                   # map paths/workspaces/profiles to tiers
applygate doctor
applygate check "terraform -chdir=envs/prod destroy"
```

`applygate init --no-hooks` writes the config only; `applygate init --scope project` keeps the hook inside this repository; `applygate hook install --agent AGENT [--scope user]` adds a hook by hand (project scope by default), and `applygate hook remove --agent AGENT` cleans both scopes. What each host can and cannot do with the hook is in [docs/hosts.md](docs/hosts.md) (`applygate hosts`). Releases are built by `.github/workflows/release.yml` from a tag: builds are reproducible, `checksums.txt` is signed with cosign (keyless; the Sigstore bundle is `checksums.txt.sigstore.json`), every archive carries a build-provenance attestation, and tags of published releases are never moved. A Claude Code plugin manifest lives in [plugin/claude-code](plugin/claude-code) (`claude --plugin-dir plugin/claude-code` to try it); the binary itself still comes from a release or `go install`.

Security issues: see [SECURITY.md](SECURITY.md).

After a few days in observe mode, run `applygate report` to see what would have been blocked, then `applygate suggest` to turn the log into a proposed `.applygate.yaml`: environments from the directories, workspaces, backends and AWS profiles the engine was seen with, tiers guessed from their names, directories whose names say nothing left commented out (strict mode keeps them protected until you choose), and every ask or block listed with a note on what would change it. Review the tiers, then set `mode: enforce`.

### Other agents

applygate has adapters for Cursor, GitHub Copilot CLI, Gemini CLI, Windsurf (Cascade), Devin, OpenCode and Cline. They were written from each host's documentation and, where the host is open source, its code, and **none has been run inside its host yet**, so `applygate init` names them when it detects them but does not install them on its own. Install one by hand and check it once (ask the agent to run `terraform destroy -auto-approve` in an empty directory; applygate should block it):

| Agent | Install | Hook file (project scope) | If the hook crashes or is missing |
|---|---|---|---|
| Cursor | `applygate hook install --agent cursor` | `.cursor/hooks.json` (`preToolUse`, `failClosed: true`) | blocks (failClosed) |
| GitHub Copilot CLI | `applygate hook install --agent copilot` | `.github/hooks/applygate.json` | blocks; a timeout lets the call run |
| Gemini CLI | `applygate hook install --agent gemini` | `.gemini/settings.json` (`BeforeTool`) | lets the call run |
| Windsurf (Cascade) | `applygate hook install --agent windsurf` | `.windsurf/hooks.json` | lets the call run |
| Devin | `applygate hook install --agent devin` | `.devin/config.json` (shell tool `exec` only) | lets the call run |
| OpenCode | `applygate hook install --agent opencode` | `.opencode/plugins/applygate.js` (a plugin) | blocks while the plugin is loaded |
| Cline | `applygate hook install --agent cline` | `.clinerules/hooks/PreToolUse` (a script) | blocks; a timeout lets the call run; a block cancels the whole task |

Only Copilot CLI can show an approval prompt for an ask; on the other hosts an ask is enforced as a block. Copilot CLI, Windsurf and Devin do not tell the hook which directory a command runs in, so there applygate judges a command at the most protected tier under the directory it has, as it does for Codex. Cursor, Copilot CLI and Devin also load hooks from `.claude/settings.json`; applygate's Claude Code hook then judges their shell tool calls too, but install the host's own hook for coverage you can check. Every cell, with its source, is in [docs/hosts.md](docs/hosts.md); a live test result that contradicts it is a welcome issue.

**Launch directory.** Claude Code and Codex load project settings only from the directory the session starts in, so a hook at `<repo>/.claude/settings.json` does not run if you launch the agent from a subdirectory. `applygate init` therefore installs the hook at user scope (`~/.claude/settings.json`, `~/.codex/hooks.json`), where it fires from any directory of any repository; repositories without a `.applygate.yaml` are then judged by your user config or the defaults. If you keep a project-scope hook, `applygate doctor` fails with the fix when you run it from a subdirectory the hook does not cover.

**Codex and the command directory.** Codex 0.165.0 does not tell the hook which directory a command runs in, only the session root. applygate then judges the command at the most protected tier it could be in under that root (so a destroy under a repository with a protected directory is blocked wherever Codex ran it), a `cd` in the command establishes the directory, and a relative planfile is looked up under the root. Details and the opt-out (`unknown_dir`) are in [docs/limits.md](docs/limits.md) and [docs/config.md](docs/config.md).

### Verify a download

Download a release and check its signature before running anything. Replace `v0.3.1` with the release you want and `linux_amd64` with your platform (`linux|darwin` × `amd64|arm64`):

```bash
tag=v0.3.1
base=https://github.com/Flurit/applygate/releases/download/$tag
curl -fsSLO "$base/checksums.txt" -O "$base/checksums.txt.sigstore.json" -O "$base/applygate_${tag#v}_linux_amd64.tar.gz"
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Flurit/applygate/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf "applygate_${tag#v}_linux_amd64.tar.gz" applygate && install -m 755 applygate ~/.local/bin/
```

The signature ties `checksums.txt` to this repository's release workflow for that exact tag, and the checksums tie each archive to `checksums.txt`. Each archive also carries a GitHub build-provenance attestation: `gh attestation verify <archive> --repo Flurit/applygate`.


### Apply from your own terminal

The same gate works without an agent. Make a plan, then apply it through applygate: it judges the saved plan for the directory's tier, refuses a block, asks you to type the environment's name on an ask, and only then runs the engine.

```bash
terraform plan -out=tfplan
applygate apply tfplan            # add --engine tofu for OpenTofu; extra arguments go to the engine
```

Outside a terminal an ask is refused unless `--yes` is given, and `--yes` never approves an apply in a protected tier. Every decision lands in the decision log with agent `human`.

### In CI and Terragrunt

The same plan gate runs in a pipeline between `plan -out` and `apply`, as a GitHub Action or a shell step, and as a Terragrunt `before_hook`; exit codes 0/4/3 are allow/ask/block. See [docs/ci.md](docs/ci.md).

```yaml
- uses: Flurit/applygate@v0.3.1
  with:
    plan: tfplan
    working-directory: envs/prod
```

## Verdicts

| Class | Examples | Protected | Standard | Disposable |
|---|---|---|---|---|
| Read-only | plan, show, output, validate, fmt, state list, describe/list | allow | allow | allow |
| Apply of a saved plan | `terraform apply tfplan` | plan gate | plan gate | allow |
| Unreviewed apply | `apply -auto-approve` with no plan | block | ask | allow |
| Destroy | destroy, `apply -destroy`, `-replace`, a plan that deletes | block | ask | allow |
| State surgery | state rm/mv/push, force-unlock, taint, bare init -reconfigure, -migrate-state | block | ask | ask |
| Cloud CLI destructive | `aws … delete-*`, `s3 rb`, terminate, `kubectl delete` | block | ask | ask |
| Guard tampering | skip-permissions flags, edits to hook config, applygate config or log | block | block | block |
| Dynamic / unresolvable | `eval "$(curl …)"`, `sh -c "$X"`, `curl … \| bash` | ask | ask | allow |

Plan gate: in protected tiers critical findings block and high findings ask; in standard tiers critical findings ask; in disposable tiers findings are logged. Addresses listed in `protected_resources` are critical whatever their type, and a plan whose configuration runs code (provisioners, `external` data sources) is a high finding. Unknown environments count as protected in strict mode, which is the default. The full table, including the classes applygate adds beyond the spec, is in [docs/policy.md](docs/policy.md).

## Commands

| Command | Purpose |
|---|---|
| `applygate hook claude\|codex` | Hook entry point; reads one PreToolUse event on stdin |
| `applygate check "<cmd>"` | Dry-run a command (exit 0 allow, 4 ask, 3 block) |
| `applygate explain "<cmd>"` | Parse → classify → decide trace |
| `applygate plan-check plan.json` | Evaluate `terraform show -json` output |
| `applygate apply tfplan [args]` | Judge a saved plan as the hooks would, confirm an ask by typing the environment name, then run the engine (`--engine tofu`; `--yes` outside protected tiers) |
| `applygate report` | Summarize the decision log |
| `applygate suggest [--root DIR] [--out FILE]` | Propose a `.applygate.yaml` from the observe-mode log: environments, signals and the asks and blocks to review |
| `applygate selftest` | Run the embedded scenario pack against this binary |
| `applygate init [--no-hooks] [--scope user\|project]` | Write a starter config, detect installed agents, install their hooks (user scope by default) |
| `applygate doctor`, `hook install/remove` | Setup checks (exit 1 on a problem) and manual hook management |
| `applygate hosts` | What each agent host can do with the hook; the same table as [docs/hosts.md](docs/hosts.md) |
| `applygate telemetry status\|on\|off\|send` | Anonymous usage counts, off by default; `status --payload` shows exactly what a report holds ([docs/telemetry.md](docs/telemetry.md)) |

## What happens when applygate fails

Hooks fail open by default in most agents, so this matters:

- **Internal errors it can catch** (malformed event, config error, panic): with `on_error: auto` (the default) it **blocks** in protected or unknown tiers and allows elsewhere. Blocking uses exit code 2, which Claude Code and Codex both treat as a block (Cline gets a cancel instead, since it ignores exit codes).
- **The internal 25 s deadline**: if a decision does not finish in time (for example a slow `terraform show`), applygate cancels the in-flight work — including the `show` subprocess — and **blocks in every tier**, protected or not, regardless of `on_error`. A command that cannot be checked is not allowed through. Observe mode is the only exception.
- **Crashes it cannot catch, or the agent's hook timeout** (process killed, binary missing): the agent decides. Claude Code proceeds unless the hook has `"onFailure": "block"`, which `applygate hook install` sets (it needs Claude Code v2.1.295 or later; older versions fail open).

  **Codex has no `onFailure` equivalent and fails open here.** A missing, killed or crashed Codex hook lets the tool call run (observed: exit 127 and a no-status-code exit both proceed). applygate now recovers panics inside its own process and turns them into a block, so the *only* remaining Codex fail-open case is the binary not starting at all. applygate cannot close that gap from inside the hook, so with Codex also rely on its sandbox and approval settings (`--sandbox workspace-write` or `read-only`, `approval_policy`/`--full-auto` off for infra work) as the backstop, keep plan-only credentials, and run `applygate doctor` to confirm the hook binary exists and is executable.
- **The other hosts** differ: Cursor (with the `failClosed` applygate sets), Copilot CLI, OpenCode and Cline block when applygate is missing or crashes; Gemini CLI, Windsurf and Devin let the call run, like Codex. This is from their documentation and not tested live; the per-host cells are in [docs/hosts.md](docs/hosts.md).
- **Observe mode** never blocks, including on errors.

See [docs/hosts.md](docs/hosts.md) for the per-host behaviour, [docs/limits.md](docs/limits.md) and [docs/threat-model.md](docs/threat-model.md).

## Telemetry

Off by default and off in every release. `applygate telemetry on --endpoint https://…` sends, at most once a day and after the verdict is already written, one report with the applygate version, OS and architecture, and decision counts per agent, mode and verdict. No commands, paths, names or identifiers of any kind; `applygate telemetry status --payload` prints the exact next report. `APPLYGATE_TELEMETRY=0` or `DO_NOT_TRACK=1` forces it off, and an agent that tries to flip the switch is blocked as guard tampering. Details in [docs/telemetry.md](docs/telemetry.md).

## Roadmap

[docs/roadmap.md](docs/roadmap.md) describes the stages (v1 core now; recovery checks and plan-hash approval next) and what is still open for v1. Project records (acceptance results, an independent review, requirement-by-requirement status) live in [docs/project/](docs/project).

## Contributing

The easiest way in is a scenario: a command or plan that an agent could run and applygate gets wrong, added to the pack with the verdict it should get ([CONTRIBUTING.md](CONTRIBUTING.md#adding-a-scenario)). Issues labelled [good first issue](https://github.com/Flurit/applygate/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are scoped to be done in an afternoon. Questions, setups and near-misses you have seen go in [Discussions](https://github.com/Flurit/applygate/discussions); a way around the guard goes to [SECURITY.md](SECURITY.md), not a public issue.

## Repository layout

```
cmd/applygate/         CLI
internal/shell/       shell-aware analyzer (parse, resolve, unwrap; refuses what it cannot resolve)
internal/classify/    command classes for terraform/tofu/terragrunt, aws, kubectl, agents, guard files
internal/config/      .applygate.yaml and tier resolution
internal/preflight/   workspace, backend, stale state, lock-file drift, planfile workspace
internal/plangate/    plan JSON rules; AWS resource lists in rules/aws.json (data, not code)
internal/policy/      verdict table and Decide()
internal/hook/        host adapters (Claude Code and Codex verified live; seven more from docs), error behavior
internal/decisionlog/ JSONL log with redaction, report
harness/              scenario pack, fixtures, Go regression test, run.py replay runner
docs/                 policy, config, limits, hosts (generated), threat model, roadmap; docs/project/ for project records
review/               live-agent test write-ups and the open-source corpus trial (tools, configs, summaries)
plugin/claude-code/   Claude Code plugin manifest (hooks only; the binary comes from a release)
site/                 project page, published to https://flurit.github.io/applygate/ by .github/workflows/pages.yml
.goreleaser.yaml      release builds: reproducible archives, checksums, cosign signature, SBOMs
install.sh            installer: verifies the cosign signature (when cosign is installed) and the sha256
SECURITY.md           how to report a vulnerability privately
CONTRIBUTING.md       ground rules, adding scenarios and guards
```

## License

Apache-2.0. See [LICENSE](LICENSE). Maintained by Flurit.
