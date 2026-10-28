# seatbelt

A deterministic, local pre-execution check for coding agents (Claude Code, Codex, and others with pre-tool hooks) that touch Terraform or OpenTofu infrastructure. Before the agent runs a tool call, seatbelt returns **allow**, **ask** or **block**, with a reason and a next step the agent can act on.

> Working name. Status: v1 core, pre-release. Live-tested with Claude Code 2.1.312 and Codex 0.159.2/0.165.0 (the T3 suite); see [ACCEPTANCE.md](ACCEPTANCE.md) for what has and has not been verified.
>
> An independent review ([REVIEW.md](REVIEW.md)) stress-tested this build; all eleven findings it raised are addressed (F1–F4 analyzer bypasses, F5–F7 pathological-input robustness, F8 a dependency advisory, F9 base32/gzip/tee decoder chains now decoded to a block, and the F10/F11 policy nuances). Details in [REVIEW.md](REVIEW.md).

## Why another guard

Command-pattern matching is table stakes. In our v0 test slice, existing guards on default configs caught few Terraform scenarios: cc-safety-net 1 of 17 and Vectimus 5 of 17. A competent hand-written Rego/regex policy reached 14 of 17, but it still missed base64, variable and `eval` obfuscation, and it blocked harmless text such as `git commit -m "never run terraform destroy"`. A matcher cannot do better than that, because it reads text, not commands, and it cannot see what a change will do.

seatbelt does two things a matcher cannot:

1. **Shell-aware command analysis.** It parses commands the way bash does ([mvdan/sh](https://github.com/mvdan/sh)), tracks `cd`, variables, `export`, loops and functions, unwraps `bash -c`, `eval`, here-documents, `sudo`/`env`/`timeout`/`xargs`/`script`/`chroot`/`parallel`/`find -exec`, reads Makefile recipes and shell scripts, and decodes `echo … | base64 -d | sh`. It tells commands apart from text: `grep "terraform destroy"` is a grep. Anything it cannot resolve statically, such as fetched text piped into a shell, it **refuses** (ask) instead of guessing.
2. **Preflight and plan-level checks.** It maps the working directory, workspace, backend and AWS profile to an environment tier. It flags a saved plan made in another workspace (read from the planfile itself), a backend block changed since `init`, stale or archived state files (optionally compared with the remote state's lineage and serial), and lock-file or module-source drift. For `apply <planfile>` it reads `show -json` and checks for destroyed or replaced stateful resources, removed protection (deletion protection, final snapshots, force-destroy, versioning), internet exposure, IAM wildcards, and changes to the state backend itself.

It is not a sandbox and not an AI reviewer. No model is in the decision path, there is no telemetry, and it makes no network calls by default.

## Quickstart

### Verify a download

Download a release and check its signature before running anything. Replace `v0.1.1` with the release you want and `linux_amd64` with your platform (`linux|darwin` × `amd64|arm64`):

```bash
tag=v0.1.1
base=https://github.com/Flurit/seatbelt/releases/download/$tag
curl -fsSLO "$base/checksums.txt" -O "$base/checksums.txt.sigstore.json" -O "$base/seatbelt_${tag#v}_linux_amd64.tar.gz"
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Flurit/seatbelt/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf "seatbelt_${tag#v}_linux_amd64.tar.gz" seatbelt && install -m 755 seatbelt ~/.local/bin/
```

The signature ties `checksums.txt` to this repository's release workflow for that exact tag, and the checksums tie each archive to `checksums.txt`. Each archive also carries a GitHub build-provenance attestation: `gh attestation verify <archive> --repo Flurit/seatbelt`.

### Install and set up

```bash
# Installer from a release tag, never from main. It verifies the cosign signature on checksums.txt
# when cosign is installed and warns when it is not; SEATBELT_VERIFY_SIGNATURE=require makes cosign
# mandatory. Without cosign only the sha256 is checked, which does not detect a tampered release.
curl -fsSL https://raw.githubusercontent.com/Flurit/seatbelt/v0.1.1/install.sh | SEATBELT_VERIFY_SIGNATURE=require sh
# or: go install github.com/Flurit/seatbelt/cmd/seatbelt@v0.1.1
# or: go build -o bin/seatbelt ./cmd/seatbelt
cd your-infra-repo
seatbelt init                            # writes .seatbelt.yaml (observe mode), detects Claude Code / Codex, installs their hooks
$EDITOR .seatbelt.yaml                   # map paths/workspaces/profiles to tiers
seatbelt doctor
seatbelt check "terraform -chdir=envs/prod destroy"
```

`seatbelt init --no-hooks` writes the config only; `seatbelt hook install --agent claude|codex [--scope user]` adds a hook by hand. Releases are built by `.github/workflows/release.yml` from a tag: builds are reproducible, `checksums.txt` is signed with cosign (keyless; the Sigstore bundle is `checksums.txt.sigstore.json`), every archive carries a build-provenance attestation, and tags of published releases are never moved. A Claude Code plugin manifest lives in [plugin/claude-code](plugin/claude-code) (`claude --plugin-dir plugin/claude-code` to try it); the binary itself still comes from a release or `go install`.

Security issues: see [SECURITY.md](SECURITY.md).

After a few days in observe mode, run `seatbelt report` to see what would have been blocked, review any likely false positives, then set `mode: enforce`.

**Launch from the repo root.** With a project-scope install, Claude Code and Codex load project settings only from the directory the session starts in. A hook at `<repo>/.claude/settings.json` will not run if you launch the agent from a subdirectory. `seatbelt doctor` warns when this is the case; launch from the directory holding the hook, or install at user scope with `hook install --scope user`.

## Verdicts

| Class | Examples | Protected | Standard | Disposable |
|---|---|---|---|---|
| Read-only | plan, show, output, validate, fmt, state list, describe/list | allow | allow | allow |
| Apply of a saved plan | `terraform apply tfplan` | plan gate | plan gate | allow |
| Unreviewed apply | `apply -auto-approve` with no plan | block | ask | allow |
| Destroy | destroy, `apply -destroy`, `-replace`, a plan that deletes | block | ask | allow |
| State surgery | state rm/mv/push, force-unlock, taint, init -reconfigure | block | ask | ask |
| Cloud CLI destructive | `aws … delete-*`, `s3 rb`, terminate, `kubectl delete` | block | ask | ask |
| Guard tampering | skip-permissions flags, edits to hook config, seatbelt config or log | block | block | block |
| Dynamic / unresolvable | `eval "$(curl …)"`, `sh -c "$X"`, `curl … \| bash` | ask | ask | allow |

Plan gate: in protected tiers critical findings block and high findings ask; in standard tiers critical findings ask; in disposable tiers findings are logged. Addresses listed in `protected_resources` are critical whatever their type, and a plan whose configuration runs code (provisioners, `external` data sources) is a high finding. Unknown environments count as protected in strict mode, which is the default. The full table, including the classes seatbelt adds beyond the spec, is in [docs/policy.md](docs/policy.md).

## Commands

| Command | Purpose |
|---|---|
| `seatbelt hook claude\|codex` | Hook entry point; reads one PreToolUse event on stdin |
| `seatbelt check "<cmd>"` | Dry-run a command (exit 0 allow, 4 ask, 3 block) |
| `seatbelt explain "<cmd>"` | Parse → classify → decide trace |
| `seatbelt plan-check plan.json` | Evaluate `terraform show -json` output |
| `seatbelt report` | Summarize the decision log |
| `seatbelt selftest` | Run the embedded scenario pack against this binary |
| `seatbelt init [--no-hooks]` | Write a starter config, detect installed agents, install their hooks |
| `seatbelt doctor`, `hook install/remove` | Setup checks and manual hook management |

## What happens when seatbelt fails

Hooks fail open by default in most agents, so this matters:

- **Internal errors it can catch** (malformed event, config error, panic): with `on_error: auto` (the default) it **blocks** in protected or unknown tiers and allows elsewhere. Blocking uses exit code 2, which Claude Code and Codex both treat as a block.
- **The internal 25 s deadline**: if a decision does not finish in time (for example a slow `terraform show`), seatbelt cancels the in-flight work — including the `show` subprocess — and **blocks in every tier**, protected or not, regardless of `on_error`. A command that cannot be checked is not allowed through. Observe mode is the only exception.
- **Crashes it cannot catch, or the agent's hook timeout** (process killed, binary missing): the agent decides. Claude Code proceeds unless the hook has `"onFailure": "block"`, which `seatbelt hook install` sets (it needs Claude Code v2.1.295 or later; older versions fail open).

  **Codex has no `onFailure` equivalent and fails open here.** A missing, killed or crashed Codex hook lets the tool call run (observed: exit 127 and a no-status-code exit both proceed). seatbelt now recovers panics inside its own process and turns them into a block, so the *only* remaining Codex fail-open case is the binary not starting at all. seatbelt cannot close that gap from inside the hook, so with Codex also rely on its sandbox and approval settings (`--sandbox workspace-write` or `read-only`, `approval_policy`/`--full-auto` off for infra work) as the backstop, keep plan-only credentials, and run `seatbelt doctor` to confirm the hook binary exists and is executable.
- **Observe mode** never blocks, including on errors.

See [docs/limits.md](docs/limits.md) and [docs/threat-model.md](docs/threat-model.md).

## Status against the spec

[docs/spec-alignment.md](docs/spec-alignment.md) maps every requirement of the roadmap and v0/v1 spec to where it is implemented, what deviates, and what is still open (a trial on real repositories, a first signed release, Homebrew and package-manager wrappers). [ACCEPTANCE.md](ACCEPTANCE.md) holds the measured results.

## Repository layout

```
cmd/seatbelt/         CLI
internal/shell/       shell-aware analyzer (parse, resolve, unwrap; refuses what it cannot resolve)
internal/classify/    command classes for terraform/tofu/terragrunt, aws, kubectl, agents, guard files
internal/config/      .seatbelt.yaml and tier resolution
internal/preflight/   workspace, backend, stale state, lock-file drift, planfile workspace
internal/plangate/    plan JSON rules; AWS resource lists in rules/aws.json (data, not code)
internal/policy/      verdict table and Decide()
internal/hook/        Claude Code and Codex adapters, error behavior
internal/decisionlog/ JSONL log with redaction, report
harness/              scenario pack, fixtures, Go regression test, run.py replay runner
plugin/claude-code/   Claude Code plugin manifest (hooks only; the binary comes from a release)
.goreleaser.yaml      release builds: reproducible archives, checksums, cosign signature, SBOMs
install.sh            installer: verifies the cosign signature (when cosign is installed) and the sha256
SECURITY.md           how to report a vulnerability privately
```

## License

Apache-2.0. See [LICENSE](LICENSE). Maintained by Flurit.
