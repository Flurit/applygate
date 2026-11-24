# Roadmap

applygate is a deterministic, local check that runs before a coding agent's infrastructure command executes and returns allow, ask or block. It is not a sandbox and not an AI reviewer: an opt-in [model judge](judge.md) can add a prompt for calls the rules do not recognize, never remove one.

## Principles

- Deterministic rules decide. A model enters only when the user turns on the model judge, only for calls the rules let through without recognizing anything, and only to make the verdict stricter ([judge.md](judge.md)).
- Parse commands the way the shell does, not as text.
- Judge plans, not only commands: `terraform apply` says little, the plan says what will be destroyed.
- Fail closed in protected environments, and say so.
- Roll out in observe mode first and count what would have been blocked.
- Stay local: no network calls by default, secrets redacted from logs. The model judge sends calls to an endpoint the user configures, only when turned on in the user config. Telemetry exists only as an opt-in of anonymous verdict counts ([telemetry.md](telemetry.md)), off in every release.
- State limits plainly. Never claim protection the design cannot give.

**Not goals:** sandboxing, credential brokering or network isolation (pair applygate with plan-only credentials and an isolated runner); general MCP governance; drift detection, cost control or code review.

## Direction

The setup to aim for is one where agents hold no credentials that can change production: plan-only credentials for agents, a managed install, and applies that a person or a pipeline reviews. applygate is for the time before a team is there, and for the steps that setup leaves open ([where-it-fits.md](where-it-fits.md)):

- the **hook** checks each call in the moment, on the laptop or runner where the agent works;
- the **plan check** is the gate in the pipeline;
- the **boundary report** says how far the setup is from the one above, and what to change.

## What exists (v0.6)

- **The hook:** shell-aware analysis, environment tiers, preflight checks and the plan gate, with AWS plan rules first ([policy.md](policy.md)). Claude Code and Codex are tested live. Cursor, Copilot CLI, Gemini CLI, Windsurf, Devin, OpenCode and Cline have adapters written from each host's documentation and not yet run inside the host ([hosts.md](hosts.md)).
- **The plan check in CI:** a GitHub Action with an optional comment on the pull request, a script for any runner, and a Terragrunt `before_hook` ([ci.md](ci.md)).
- **The boundary report:** `applygate doctor --boundary` and the credential audit ([boundary.md](boundary.md), [credentials.md](credentials.md)), and the managed install that agents cannot remove ([managed.md](managed.md)).
- **`applygate scan`:** what applygate would have decided on the calls your agents already made, with no hook installed ([scan.md](scan.md)).
- **Rolling out:** observe mode, the decision log and `applygate suggest`, which proposes a config from the log.
- **For a person at a terminal:** `applygate apply <planfile>`, and one-time approvals for agents that cannot ask (off by default).
- **Releases:** signed, with provenance; each one's verification is in [project/release-log.md](project/release-log.md).

What applygate does not see or cover is in [limits.md](limits.md).

## Next

In this order:

1. **Fewer prompts on ordinary work** in Claude Code and Codex: one-line scripts, loops and commands a project declares as its own.
2. **A path to the safer setup:** the boundary report shows the steps from one level to the next, with plan-only IAM and RBAC examples and a workflow for reviewed applies.
3. **Review from outside:** an independent security review, and a public page of reported ways past the check.
4. **An observe-mode trial with real teams.** The trials so far were run by the project on public repositories ([review/oss-corpus/trial.md](../review/oss-corpus/trial.md), [review/2026-10-28-v1-acceptance.md](../review/2026-10-28-v1-acceptance.md)).

## On hold

- Live tests of the adapters written from documentation, and new agent integrations, until prompts on Claude Code and Codex are down.
- More work on the model judge.
- npm and pip wrappers for installing.

## Later, if the core sees real use

- Plan rules for Google Cloud, Azure and Kubernetes resources, and Pulumi.
- A check that backups are isolated from what a destroy can reach.
- Receipts and attribution: tying a cloud change to the agent session and the approved plan behind it.
