# Where applygate fits

The right way to protect infrastructure is a pipeline that applies changes after review, credentials for agents that can only read and plan, and a policy check on the plan. applygate replaces none of these. It is a deterministic check for the step they do not see: a coding agent running commands directly, on a developer's machine or in a job you gave it, with credentials that can change real infrastructure.

**If your agents never hold credentials that can change production, you do not need the hook.** The plan check for a pipeline may still be useful to you ([below](#in-the-pipeline-the-plan-check)).

## Do you need it?

| Your setup | What applies |
|---|---|
| Agents work with credentials that can only read and plan, and every apply runs in a reviewed pipeline | You do not need the hook to protect production. `applygate scan --boundary` asks your cloud accounts, read-only, whether that is really so ([scan.md](scan.md)). |
| An agent runs in a terminal where your own cloud profile, a kubeconfig or a deploy role is in reach | This is the gap the hook is for. It checks each command until the credentials are narrowed; [credentials.md](credentials.md) shows how to narrow them. |
| You are not sure what the agents on your machines can reach | `applygate scan` reads the sessions Claude Code and Codex already recorded and reports it. It installs no hook and runs nothing. |

The second row is the one to check for. An agent that helps write Terraform is started in the same shell the engineer uses, and if that shell has a working profile, so does the agent.

## Who sees which step

A change reaches infrastructure by one of two paths: a command someone runs, or a pull request that a pipeline applies. Most guards sit on the second path.

| Step | Guards that see it | What applygate does there |
|---|---|---|
| An agent runs a command in a shell: `terraform apply`, `terraform state rm`, `aws s3 rb`, `kubectl delete` | The agent's own permission rules and sandbox | **The hook** judges the command before it runs, by the environment it targets |
| The change is proposed as a pull request | Branch protection, required reviews, code scanners | Nothing |
| The pipeline plans, then applies | Approvals on the apply; Sentinel, OPA or Terraform policy on the plan | **The plan check** reads the plan between the two steps |
| The cloud receives the call | IAM, MFA conditions, organization policies, deletion protection, versioned state | **The audit** reports whether these stand between the agent's credentials and production. It cannot enforce them |

## On the agent's machine: the hook

A command an agent runs in a terminal passes no pipeline, no policy engine and no reviewer. Many of the commands that do the most damage also leave no saved plan to check: `terraform state rm`, `terraform apply -auto-approve`, `aws rds delete-db-instance`, `kubectl delete namespace`, `helm uninstall`.

The hook runs as the agent's pre-tool-call hook and answers allow, ask or block for each call. Fixed rules decide, with no model in the decision.

- **It judges by environment.** The same `terraform destroy` is blocked in a directory you mapped to production and allowed in a disposable one. Anything it cannot place counts as protected.
- **It reads a command the way the shell does.** A destroy behind `bash -c`, `eval`, a Makefile target or base64 is still a destroy, and `grep "terraform destroy"` is only a grep.
- **It tells the agent why.** The reason comes back to the agent, which can then change course instead of trying variations.

It is not a sandbox, and it can be wrong. What a wrong verdict can reach is decided by the credentials the agent holds, which is why the audit below matters more than the hook ([boundary.md](boundary.md), [limits.md](limits.md)).

### Next to the agent's own permissions and sandbox

Keep them on. An agent's permission rules match the text of a command, so they cannot tell production from a scratch directory or see what a script will run. A sandbox limits files and network, but an agent that must reach the cloud API to plan can reach it to delete. The hook adds the part they lack: which environment a command targets and what it does there. On agents that run the call when a hook fails to start, the agent's sandbox and approvals are the second line ([hosts.md](hosts.md)).

## In the pipeline: the plan check

`applygate plan-check` reads the JSON of a saved plan and applies the plan rules the hook uses for `terraform apply tfplan`. It runs as a step between `plan` and `apply`, in GitHub Actions or any other CI, and nothing in it runs Terraform's apply ([ci.md](ci.md)). From the release after v0.6.1 the Action can also write the verdict on the pull request, beside what your policy check reports.

### Next to Sentinel, OPA, conftest and Terraform policy

They and the plan check read the same plan and answer different questions.

| | A policy engine | The applygate plan check |
|---|---|---|
| Question | Does this plan follow the policies our organization wrote? | Does this plan destroy data, remove a protection or open something to the internet? |
| Rules | Yours, in a policy language, as many as you need | A fixed set that ships with the tool, plus the resources you list as protected |
| To start | A policy set to write, test and keep current | One step, and tiers from `.applygate.yaml` |
| What it cannot do | See a command that has no plan | Express your own policy: tags, regions, instance sizes, naming, cost |

- **If you have a policy engine, keep it.** You can write every plan-check rule in Sentinel, Rego or Terraform policy, and if you already have, the plan check adds little. What it saves is writing and maintaining them.
- **If you have none,** the plan check is a start for the destructive cases, not a substitute for policy.
- **Its resource rules are for AWS today.** A Google Cloud or Azure plan gets the generic rules (how much is destroyed or replaced, your protected resources) and not the rules about stateful types or exposure ([capabilities.md](capabilities.md)).

### Next to approvals, Atlantis and HCP Terraform

An approval on the apply step is the control that matters most, and the plan check does not replace it. It gives the approver a short answer to "what does this plan destroy?" before they approve, and it can fail the job when the answer is a production database.

### Next to code scanners and branch protection

Checkov, Trivy and similar scanners read the configuration for misconfigurations; branch protection and required reviews decide what is merged. Both act on a pull request. Neither sees a command that is run without one.

## At the cloud: the audit

IAM policies, MFA on the role that applies, organization policies, deletion protection and a versioned, locked state bucket are the guards that hold whatever any check upstream decides. applygate cannot enforce them. It can tell you whether they are there:

```bash
applygate doctor --creds      # can the credentials on this machine change production without a person?
applygate doctor --boundary   # the same, plus the install and the sandbox, as a level from L0 to L3
```

Both ask AWS, Google Cloud, Azure and your clusters read-only questions with the credentials they audit ([credentials.md](credentials.md), [boundary.md](boundary.md)). `applygate scan --boundary` puts the same audit at the top of its report, and when no audited credential can change production it says that you do not need the hook to protect it.

## Where a team ends up

The hook is the check for the time before the boundary is in place, not the destination.

1. **Look.** `applygate scan --boundary` shows what your agents can reach and what they have run.
2. **Check each command** with the hook while agents still hold credentials that can change production.
3. **Narrow the credentials** until agents can read and plan only, and changing production needs a person.
4. **Apply through a reviewed pipeline,** with a policy engine or the plan check on the plan.

At step 4 the hook has little left to protect in production. It still checks the environments where agents do apply, such as development and staging.

## What applygate is not

- **Not a policy engine.** Its plan rules are fixed; it has no policy language.
- **Not a sandbox** and not a credential broker. It does not isolate the agent or issue credentials.
- **Not a pipeline.** It runs nothing for you except `applygate apply`, which judges a plan and then calls Terraform from your own terminal.
- **Not an AI reviewer.** Rules decide. An optional model judge can only make a verdict stricter ([judge.md](judge.md)).
