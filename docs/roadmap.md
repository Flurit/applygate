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

## What exists (v0.8, and what is on main since)

- **The hook:** shell-aware analysis, environment tiers, preflight checks and the plan gate, with AWS plan rules first ([policy.md](policy.md)). Claude Code and Codex are tested live. Cursor, Copilot CLI, Gemini CLI, Windsurf, Devin, OpenCode and Cline have adapters written from each host's documentation and not yet run inside the host ([hosts.md](hosts.md)).
- **Fewer prompts where nobody asked for strictness:** in a repository with no config, a command that is not plain is asked about only when it names an infrastructure tool or a guard file (v0.8.0). A repository config, a managed install or `strict_shapes: true` keeps the full rule. What this gives up is in [limits.md](limits.md#a-repository-with-no-config).
- **Routine replaces:** in a standard tier, a saved plan whose only replaces are of listed types that hold no data is allowed without a prompt (v0.7.0, [policy.md](policy.md)). A protected tier blocks every replace as before.
- **The plan check in CI:** a GitHub Action with an optional comment on the pull request, a script for any runner, and a Terragrunt `before_hook` ([ci.md](ci.md)).
- **The boundary report:** `applygate doctor --boundary` and the credential audit ([boundary.md](boundary.md), [credentials.md](credentials.md)), and the managed install that agents cannot remove ([managed.md](managed.md)).
- **A path to the safer setup (on main, not yet in a release):** below the level, the boundary report lists the steps to the level you require, from the checks that are not met ([boundary.md](boundary.md#steps-between-levels)). [examples/boundary](../examples/boundary) holds a read-only AWS role, trust policies for a person with MFA and for a GitHub Actions job, a Kubernetes `view` binding and Google Cloud and Azure read-only grants, and [examples/github-actions/reviewed-apply.yml](../examples/github-actions/reviewed-apply.yml) is a pipeline whose apply waits for a reviewer ([ci.md](ci.md#a-reviewed-apply)). How far each file has been checked is in [limits.md](limits.md#the-boundary-examples): the Kubernetes one has run on a local cluster, the workflow has been through `actionlint`, and the AWS, Google Cloud, Azure and GitHub parts have not been run against a real account or repository. The steps do not make anyone read a plan, and applygate cannot see the reviewer rule or the trust policies.
- **`applygate scan`:** what applygate would have decided on the calls your agents already made, with no hook installed ([scan.md](scan.md)).
- **Rolling out:** observe mode, the decision log and `applygate suggest`, which proposes a config from the log.
- **For a person at a terminal:** `applygate apply <planfile>`, and one-time approvals for agents that cannot ask (off by default).
- **Releases:** signed, with provenance; each one's verification is in [project/release-log.md](project/release-log.md).

What applygate does not see or cover is in [limits.md](limits.md).

## Next

In this order. The order changed on 2026-11-25: hearing from teams that use agents near real infrastructure now comes before more features, because every figure for how often applygate asks is still from the project's own machine and trials.

1. **Real teams.** Ask teams whose agents hold real credentials to run `applygate scan` on the sessions they already have, then an observe-mode trial with those who agree. The trials so far were run by the project on public repositories ([review/oss-corpus/trial.md](../review/oss-corpus/trial.md), [review/2026-10-28-v1-acceptance.md](../review/2026-10-28-v1-acceptance.md)).
2. **Review from outside:** a public page of reported ways past the check first, then an independent security review.
3. **Fewer prompts where a config asks for strictness:** one-line scripts, loops and commands a project declares as its own, in protected directories. This was first on the list; since v0.8.0 it matters only where a config or a managed install keeps the full rule.
4. **A live test of the Cursor adapter,** the first of the adapters written from documentation.

## On hold

- Live tests of the other adapters written from documentation, and new agent integrations.
- More work on the model judge.
- npm and pip wrappers for installing.

## Later, if the core sees real use

- Plan rules for Google Cloud, Azure and Kubernetes resources, and Pulumi.
- A check that backups are isolated from what a destroy can reach.
- Receipts and attribution: tying a cloud change to the agent session and the approved plan behind it.
