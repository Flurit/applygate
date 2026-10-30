# Roadmap

applygate is a deterministic, local check that runs before a coding agent's infrastructure command executes and returns allow, ask or block. It is not a sandbox and not an AI reviewer. This page is the public summary of the project's planning document; "the spec" in older project notes refers to that document.

## Principles

- Deterministic rules decide. No model is in the decision path.
- Parse commands the way the shell does, not as text.
- Judge plans, not only commands: `terraform apply` says little, the plan says what will be destroyed.
- Fail closed in protected environments, and say so.
- Roll out in observe mode first and count what would have been blocked.
- Stay local: no network calls by default, secrets redacted from logs. Telemetry exists only as an opt-in of anonymous verdict counts ([telemetry.md](telemetry.md)), off in every release.
- State limits plainly. Never claim protection the design cannot give.

**Not goals:** sandboxing, credential brokering or network isolation (pair applygate with plan-only credentials and an isolated runner); general MCP governance; drift detection, cost control or code review.

## Stages

Each stage ships on its own and must pass its gate before the next starts.

| Stage | Goal | Scope | Gate to the next stage |
|---|---|---|---|
| **v0** harness | Find where existing guards fail on infrastructure | Scenario pack, replay runner, comparison of existing guards | Enough dangerous scenarios missed by existing guards to justify v1 |
| **v1** core (current) | Block the most damaging infrastructure actions with low friction | Shell-aware analyzer, environment tiers, preflight (workspace, backend, stale state, lock file), plan gate (AWS first), observe mode, local log, Claude Code and Codex | Passes the scenario pack; false positives under 5% in an observe-mode trial on 5 real repositories; installs in under 5 minutes on macOS and Linux |
| **v2** recovery and approval | Make destructive changes recoverable and approvals exact | Backup-isolation check, plan-hash approval with typed confirmation, more agents, CI mode as a GitHub Action | Blocks unrecoverable destroys in fixtures; approval refuses a changed plan |
| **v3** receipts and attribution | Tie each cloud change to an agent session and an approved plan | Signed receipts, session capture, AWS session tagging, lookup from a CloudTrail event | A CloudTrail event resolves to its session, plan and approver |

GCP, Azure, Kubernetes and Pulumi rules, platform integrations and hosted features come later, and only if v1 and v2 see real use.

## Where v1 stands

Done:
- the analyzer, tiers, preflight and plan gate;
- Claude Code and Codex adapters, tested live;
- observe mode and the decision log;
- signed releases with provenance (v0.1.0 to v0.1.4 as seatbelt, v0.2.0, v0.3.0, v0.3.1 and v0.3.2 as applygate);
- a static false-positive trial on 5 public repositories: 0.48% ([oss-corpus-trial.md](oss-corpus-trial.md)), then an agent-driven trial ([project/ACCEPTANCE.md](project/ACCEPTANCE.md));
- a plan-gate false-positive study on 212 routine plans from public Terraform against LocalStack: standard tier 0%, protected 8.0% false positives with v0.3.0, all from two analyzer rules, and 0 with the fix in v0.3.2 ([project/ACCEPTANCE.md](project/ACCEPTANCE.md));
- the plan gate in CI (GitHub Action, any runner) and as a Terragrunt `before_hook` ([ci.md](ci.md)), pulled forward from v2;
- `applygate apply <planfile>`: the same verdict for a human at a terminal, with a typed confirmation on an ask;
- `applygate suggest`: a proposed config from the observe-mode log, tiers guessed from names and nothing decided for a directory whose name says nothing.
- opt-in telemetry ([telemetry.md](telemetry.md)): anonymous counts per version, agent, mode and verdict, off by default, the switch guarded against agents;
- an install check on macOS (v0.3.0 on macOS 26.7.1, Intel: installer with signature verification in 7 s, selftest 133/133), recorded in [project/ACCEPTANCE.md](project/ACCEPTANCE.md).

Open:
- an observe-mode trial with real teams;
- Homebrew and package-manager wrappers.

[project/ACCEPTANCE.md](project/ACCEPTANCE.md) has the measured detail, and [project/spec-alignment.md](project/spec-alignment.md) maps each planned requirement to the code.
