# Alignment with the roadmap and v0/v1 spec

> "The spec" in this record is the project's internal planning document; its public summary is [docs/roadmap.md](../roadmap.md).

Source: the plan document "Infra Agent Seatbelt: Roadmap and v0/v1 Spec" (2026-10-27). This page maps each requirement to the repository as of 2026-10-28. Status words: **done** (implemented and tested), **partial** (implemented with a stated gap), **deviates** (implemented differently, on purpose), **open** (not done; needs something outside the repository or a decision).

The spec's own gate thresholds (catch rate, false-positive budget, install time) are proposals that were never formally agreed; measured numbers are in [ACCEPTANCE.md](ACCEPTANCE.md).

## Product definition and principles

| Spec | Status | Where |
|---|---|---|
| Single local binary with hook adapters, shell-aware analyzer, preflight, plan gate, local log | done | `cmd/seatbelt`, `internal/*` |
| Engine-neutral (Terraform and OpenTofu share plan JSON) | done | `internal/classify/engines.go`; the planfile workspace parser was verified on Terraform 1.16.1 only ([limits](../limits.md)) |
| Agent-neutral with per-agent limits documented | partial | Claude Code and Codex adapters (`internal/hook/adapters.go`); Cursor and others are v2. `harness/run.py --format cursor` can replay the pack against a Cursor-format guard |
| Deterministic rules, no model in the decision path | done | no model call anywhere; `docs/threat-model.md` |
| Parse commands the way the shell does | done | `internal/shell` on mvdan/sh; property and fuzz tests |
| Judge plans, not only commands | done | `internal/plangate` on `show -json` |
| Fail closed in protected environments, explicit fail-open | done | `on_error` (`docs/config.md`), deadline fails closed in every tier, `onFailure: block` for Claude Code; Codex fail-open on a non-starting binary is documented ([limits](../limits.md)) |
| Observe mode first, count would-have-blocked | done | `mode: observe`, `seatbelt report` |
| Local only: no telemetry, no network by default, redacted log | done | `internal/decisionlog`; the two network checks are opt-in and user-config-only |
| State limits plainly | done | `docs/limits.md`, `docs/threat-model.md` |
| Non-goals: sandboxing, MCP governance, Kubernetes, Pulumi, GCP/Azure, drift, cost, review | done | not built; `kubectl delete` is classified as cloud-destructive as a courtesy, nothing more |

## v0: guardrail test harness

| Spec | Status | Where |
|---|---|---|
| Ten dangerous scenarios S1–S10, replayed, never run | done | `harness/pack/scenarios.json` (D01–D36 plus added cases); replay only, `run.py` uses an empty PATH and no shell |
| Stretch S11 (database and backups in one plan) | done | D37 |
| Stretch S12 (plan runs code via provisioner or external data source) | done | D51, B30; `code-execution` finding |
| Stretch S13 (destructive call through a Terraform MCP tool) | open | MCP tool inputs are not inspected; documented in [limits](../limits.md) |
| Stretch S14 (instruction hidden in a README) | open | needs an end-to-end agent run; the T3 suite exercised live agents but not this case |
| Ten benign controls | done | B01–B12 cover the spec list; B13–B30 add text-mention, cleanup and S6/S12 controls |
| Adapters per agent format (Claude Code, Cursor, Codex) | done | `run.py --format claude|codex|cursor` |
| Safe fixtures, no credentials | done | `harness/pack/fixtures/repo`, `terraform_data`-only planfile |
| Two configurations per guard (default, hardened) | partial | `--config-label` records which configuration ran; no second guard has been run on this pack yet (the v0 comparison numbers come from the original pack, see [harness/README.md](../../harness/README.md)) |
| Break each guard: malformed event, slow response, crash | partial | `run.py --probes` sends malformed JSON, empty input, missing tool name, missing cwd and a 2 MB command and records whether the action would proceed; Go chaos tests cover timeout, panic and config errors. A deliberately slow guard is not simulated |
| v0.1: confirm wiring with a real agent in a throwaway VM | done | T3 suite on Claude Code 2.1.312 and Codex 0.159.2/0.165.0 (`review/T3_RESULTS.md`) |
| Scoring: catch rate, false-positive rate, bypass count by class, fail-open count, coverage type, latency p50/p95 | done | `run.py` scorecard; S3 scenarios carry `bypass_class` |
| Every result records guard version, configuration, agent format, date; one-command reproduction | done | `run.py` summary; `python3 -I harness/run.py --guard bin/seatbelt` |
| Versioned pack, runner, raw JSON, Markdown report | done | `pack_version` in the pack, `--json`, `--md` |
| Open source from day one, Apache-2.0 | done | `LICENSE`, `NOTICE` |
| Monthly CI re-run | done | `.github/workflows/ci.yml` schedule |
| Disclosure and ethics (private first, 30 days, hand-checked, scope-fair) | done | `CONTRIBUTING.md`, `harness/README.md` |
| 5 or more guards tested; gate decision | open | only seatbelt has been run on the reconstructed pack; the original v0 figures (cc-safety-net 1/17, Vectimus 5/17, Rego 14/17) predate this repository |

## v1: seatbelt core

### Scope and decision flow

| Spec | Status | Where |
|---|---|---|
| Hook adapters for Claude Code and one more agent (Codex chosen) | done | `internal/hook/adapters.go`; Codex edits may name `file_path` as well as `apply_patch` |
| Shell-aware analyzer and classifier | done | `internal/shell`, `internal/classify` |
| Preflight: environment identity, workspace/backend consistency, stale state, lockfile | done | `internal/preflight`; optional STS identity and state pull are opt-in |
| Plan gate for saved plans, AWS-first | done | `internal/plangate`, rules in `rules/aws.json` |
| Observe and enforce modes, local log, selftest | done | `mode`, `decisionlog`, `seatbelt selftest` |
| Decision flow (normalize, parse, classify, preflight, plan gate, policy, log, error behavior) | done | `docs/policy.md` "Decision flow" |
| Where a host cannot ask, fall back to block with guidance | done | `CanAsk` on the event; Codex and Claude `dontAsk` |

### Command classes and default verdicts

| Spec | Status | Where |
|---|---|---|
| The eight spec classes and their protected/standard/disposable verdicts | done | `policy.Table`; `docs/policy.md` verdict table, column "spec" |
| Unknown wrapper commands: "ask in protected tiers" (open decision) | done | class `unknown-wrapper` |
| Classes the spec does not list | deviates | `mutating`, `cloud-write`, `credential-access` added and documented in `docs/policy.md` |
| `init -reconfigure` as state surgery | deviates | read-only when it only re-points (`-backend-config` resolved, no `-migrate-state`/`-force-copy`); later commands in the same command line use the new backend ([policy.md](../policy.md), [oss-corpus-trial.md](../oss-corpus-trial.md)) |
| Pure-delete saved plan treated as destroy | deviates | documented in `docs/project/ACCEPTANCE.md` "Deviations" |

### Preflight and plan gate

| Spec | Status | Where |
|---|---|---|
| Environment identity from directory, workspace, backend, AWS profile; unknown is protected in strict mode; optional STS | done | `config.Resolve`, `preflight.live_identity` |
| Planfile workspace vs selected workspace; backend changed since init | done | `workspace-mismatch`, `backend-changed` |
| Stale or foreign state files and archives; optional read-only state pull comparing lineage and serial | done | `stale-state`; `preflight.live_state` adds `state-lineage` (user config only) |
| Lockfile and module/provider source drift | done | `lockfile-drift` via `git diff HEAD` |
| Plan gate reads `show -json`, never runs `plan` | done | `hook.ShowPlan`; `run_show: false` disables it and then blocks saved-plan applies in protected tiers |
| Rules: destroy/replace count, stateful destroyed/replaced, protection removed, exposure, state infrastructure changed, out of declared scope, with the spec severities | done | `docs/policy.md` findings table |
| Severity by tier (protected: critical blocks, high asks; standard: critical asks; disposable: log) | done | `policy.FindingVerdict` |
| Plan SHA-256 printed for v2 approval to bind to | done | `plan sha256:` line in every plan-gate message |
| Resource lists as data files | done | `internal/plangate/rules/aws.json` |
| IAM "wildcard actions or resources" | deviates | `Resource: "*"` alone is not flagged (too common); wildcard actions are |

### Configuration, messages and commands

| Spec | Status | Where |
|---|---|---|
| One small file per repository plus a user-level file | done | `.seatbelt.yaml`, `~/.config/seatbelt/config.yaml` |
| `environments` with tier and match (dirs, workspaces, aws_profiles) | deviates | key is `paths` (globs relative to the config file) and environments are a list, not a map; `backends` and `aws_accounts` added |
| `max_destroy` | done | `plan_gate.max_destroy` per tier |
| `protected_resources` | done | address globs; `protected-resource` critical finding |
| `wrappers` (commands that hide Terraform) | deviates | not a config key: Makefile recipes and readable scripts are analyzed, and an unreadable wrapper asks in protected tiers |
| Messages carry reason, evidence and next step | done | `policy.message`; agent-facing text on block, human-facing text on ask |
| `init`: starter config, detect installed agents, install hooks | done | `seatbelt init [--no-hooks]` |
| `doctor`: hooks wired, config parses, versions | done | `seatbelt doctor` also runs the selftest and warns about launch-directory mismatches |
| `check`, `explain`, `plan-check`, `report`, `selftest`, `hook install/remove` | done | `cmd/seatbelt/main.go` |

### Quality bar, security, distribution

| Spec | Status | Where |
|---|---|---|
| Test corpus: v0 pack, bypass classes, golden tests, property tests for shell parsing | done | `harness`, `internal/shell/*_test.go`, fuzz corpus |
| Speed: command decision under 50 ms p95, plan under 1 s for 1,000 resources | done | measured p95 2.9 ms in process, 1,000-resource plan 17 ms ([ACCEPTANCE.md](ACCEPTANCE.md)); `show -json` cost excluded |
| False positives under 5% of benign controls | done | 0/42 on the pack; 0.48% on 1,259 commands from 5 public repositories ([oss-corpus-trial.md](../oss-corpus-trial.md)) |
| Failure behavior: crash, timeout, malformed event end in configured behavior | done | `hook_test.go`, `run.py --probes` |
| Self-protection: config, hook entries, log | done | `guard-tampering` class, `DefaultProtectedPaths` |
| Managed-settings deployment for organizations | done (documented) | `docs/threat-model.md` |
| Supply chain: signed releases, provenance, trusted publishing, pinned dependencies | done | v0.1.0 released by `release.yml`: cosign keyless bundle on `checksums.txt`, SBOMs, SLSA v1 build-provenance attestations; SHA-pinned actions, `go.sum`, `govulncheck` in CI ([ACCEPTANCE.md](ACCEPTANCE.md) item 7) |
| Privacy: no telemetry, no network by default, redacted log outside the repo | done | `decisionlog` |
| Honest limits in docs | done | `docs/limits.md` |
| Language: Go with mvdan/sh and terraform-json | done | `go.mod` |
| Distribution: install script, Homebrew, npm/pip wrapper, Claude Code plugin | partial | `install.sh` installs the real v0.1.0 release in 3 s on Linux; after v0.1.0 it also verifies the cosign signature on `checksums.txt` when cosign is installed (`SEATBELT_VERIFY_SIGNATURE=require` makes it mandatory), and the README pins the installer URL to a tag; `plugin/claude-code` exists; the Homebrew tap (`brews:` in `.goreleaser.yaml`) is commented out until a tap repository exists; npm and pip wrappers are not started |
| Five-minute quickstart, threat model, limits | done | `README.md`, `docs/threat-model.md`, `docs/limits.md` |
| Apache-2.0 | done | `LICENSE` |

### v1 acceptance checklist

| Item | Status |
|---|---|
| Passes the v0 pack at the agreed threshold | partial: passes the reconstructed pack 122/122; no threshold agreed, original pack unavailable |
| Observe-mode trial on 5 real repositories | partial: static stand-in on 5 public repositories ([oss-corpus-trial.md](../oss-corpus-trial.md)), 0.48% false positives on 1,259 runnable commands; no agent sessions yet |
| Installs in under 5 minutes on macOS and Linux | partial: 3 s on Linux against v0.1.0; not exercised on a Mac |
| Works with Claude Code and one more agent | done: Claude Code and Codex, live-tested (T3) |
| Fail-closed behavior verified by chaos tests | done |
| Docs: quickstart, threat model, limits | done |
| Signed release with provenance | done: v0.1.0 |

## Open decisions from the spec

| Decision | Spec recommendation | Repository |
|---|---|---|
| License | Apache-2.0 | Apache-2.0 |
| Language | Go | Go |
| Who builds and maintains | undecided | Flurit (NOTICE); contributor rules in `CONTRIBUTING.md` |
| Name | placeholder; check trademarks | still "seatbelt (working name)"; not checked |
| Second agent for v1 | from v0 results and demand | Codex |
| Telemetry | none by default | none at all |
| Unknown wrapper commands | ask in protected tiers | ask in protected tiers |
| Auto-running plan in the hook | never in v1 | never; `show -json` only |
| Business model | after v1 usage | undecided |

## Not in scope of this alignment (v2 and v3)

Backup-isolation checks, plan-hash approval with typed confirmation, more agents (Cursor, Copilot CLI, OpenCode), CI mode as a GitHub Action, signed receipts, session capture, CloudTrail stamping and `seatbelt who`. The plan SHA-256 in every plan-gate message is the hook for v2 approval.
