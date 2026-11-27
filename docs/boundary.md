# The boundary: what holds when the hook is wrong

applygate is a pre-execution reviewer for coding-agent shell, file and MCP calls. In a protected environment it allows only commands it recognizes in a narrow, fully understood form and asks or blocks everything else. It catches mistakes and most injected instructions. It cannot promise that a command is *never* allowed: the shell model is bash's and incomplete, an agent can write code and run it, and programs it allows (`terraform plan`, `make`, `pytest`) run code with the agent's credentials. Eleven rounds of adversarial review found about 15 critical bypasses a round; the design review concluded that the parser cannot carry the guarantee alone ([review/v0.6.0](../review/v0.6.0)).

What does hold whatever the parser misses are boundaries the agent cannot reach. applygate cannot enforce them, but it can check some of them.

## Assurance levels

| Level | Adds | How it is known |
|---|---|---|
| **L0** | The hook only | nothing to check |
| **L1** | A managed, exclusive install: root-owned config, binary and Claude Code settings, no other hooks | `doctor --boundary` checks ownership and settings ([managed.md](managed.md)) |
| **L2** | Credentials the agent holds cannot change production without a person | `doctor --boundary` audits every AWS profile, kube context, gcloud account and Azure subscription ([credentials.md](credentials.md)) |
| **L3** | A host sandbox set by managed settings, and a reviewed apply path with guarded remote state | the sandbox is checked in Claude Code's managed settings; the apply path and state guards are **attested** by you |

A level needs every check of its own and the levels below to hold. `not verified` means doctor could not show the control; it never counts. `attested` counts only toward L3 and only for controls you name in the **user** (or system) config; a repository config cannot set it:

```yaml
boundary:
  require: L2                      # applygate doctor --boundary exits 1 below this
  attest: [ci_apply, state_guards] # also oidc_pinned, branch_protection (optional)
```

- `ci_apply`: applies to protected environments run only in a reviewed pipeline, with a role the agent cannot assume.
- `state_guards`: the state bucket is versioned and object-locked, with a deny policy for deleting versions or changing the policy.

```bash
applygate doctor --boundary             # the report
applygate doctor --boundary --require L2   # exit 1 below L2, for a script or CI
```

`applygate scan --boundary` makes the same checks and puts them at the top of its report, above what the agents did in their recorded sessions ([scan.md](scan.md)).

## What the check does and does not cover

- **L1** is exactly `doctor`'s managed checks. Without `install --managed --exclusive` you are at L0. At L0, in a repository with no config, strict shapes ask only about a command that names an infrastructure tool or a guard file; a managed install asks about every command that is not plain ([policy.md](policy.md), "Strict shapes").
- **L2** asks the policy simulator about 19 destructive actions with MFA absent, including three on the state bucket (`s3:DeleteObjectVersion`, `s3:PutBucketVersioning`, `s3:DeleteBucketPolicy`), kubectl `auth can-i` for four verbs, Google Cloud's `testIamPermissions` for 17 destructive permissions on each project a gcloud configuration names, and the roles assigned to the signed-in principal on each Azure subscription. gcloud and az have no MFA-absent test: any destructive permission or role counts. Azure PIM roles that are eligible but not active are not seen. The AWS audit has been run against two real IAM users (2026-11-14 and 15): one has no destructive path; the other was first refused the simulator call and reported as not checked, then, once granted it, found to have five destructive actions and failed L2 when a config named its account protected. The Google Cloud audit has been run against one real user account and project (2026-11-15), which held 14 of the 17 permissions. For an AWS assumed role or SSO profile, the root user, a Google Cloud service account, and Azure, the audits are tested with stubs only; the Kubernetes audit has run against one local kind cluster (2026-11-26), not a managed cluster. Each audited credential has its own line in the report, the harmless ones too. A profile that could not be checked (expired SSO, no simulator permission) is `not verified`, not ok. Each credential file the agent's user can read (`~/.aws/credentials`, `~/.kube/config`, gcloud's application default credentials, `~/.azure/accessTokens.json`) is a `not verified` check: any agent that runs as you can use it, and the audit says what it can do, not who can read it. L2 is therefore not reached while one exists.
- **L3**'s sandbox check reads Claude Code's managed settings for `sandbox.enabled` and `allowUnsandboxedCommands: false`. Those keys have not been tested live. Codex sandbox modes are not checked. A sandbox set in a file your user can change counts as not verified.
- **Not covered at any level:** a swap between the hook's verdict and the execution, Codex failing open when the hook does not start, MCP servers with their own credentials, and anything that never passes through the hook.

## Steps between levels

Below the level you ask for, `applygate doctor --boundary` and `applygate scan --boundary` print what a person does next, after the level and the checks. The level asked for is `boundary.require` in the user config, `--require` on `doctor`, and L2 when neither is set. Nothing is run or changed by printing them.

```text
Steps to L2
  L1  Install a managed, exclusive copy of applygate (there is no managed install)
  L2  Give the agent a read-only AWS role in place of these identities: aws profile prod-admin
  L2  Keep your own sessions out of the agent's reach: ~/.kube/config
  L2  Decide who applies production changes
  The credential steps do not depend on L1 and can be done first.
```

Each step comes from the checks that are not met, not from the level number. A check that is not `ok` or `attested` names the step that closes it, and a step several checks name is printed once, with the credentials or files it is about (the first five, then a count). The steps are:

- **L1:** install the managed, exclusive copy; repair a managed install the checks found wrong; install `claude` or `codex` root-owned.
- **L2, by what the audit found:**
  - AWS: a read-only role in place of an identity that can change production without MFA.
  - AWS, when AWS refused the simulator call: the grant that lets the audit see the identity.
  - Kubernetes: bind the identity to `view`.
  - Google Cloud: `roles/viewer`, applies by impersonation only a person may use.
  - Azure: `Reader`, `Contributor` or `Owner` only through PIM.
  - A credential that could not be checked: sign in again, grant what the line names or make the CLI available.
  - A credential that can make destructive changes in an environment no config names: name the environments.
  - A credential file the agent's user can read: keep the person's sessions out of the agent's reach.
  - Nothing could be audited: said plainly, below.
  - Once the credentials have been audited and L2 is still not reached: decide who applies production changes, a person with MFA or a pipeline whose apply role the agent cannot assume.
- **L3**, only when L3 is asked for: the sandbox in managed settings, and the two attestations. When L2 is reached and L3 is not asked for, one pointer to what L3 adds.

The setup advice follows [credentials.md](credentials.md). That advice has not been checked against each provider's documentation or a real account; [limits.md](limits.md) says what has been.

Three things the steps say because the checks make them true:

- **A readable credential file clears only when the agent's user cannot read it.** `~/.aws/credentials`, `~/.kube/config`, gcloud's application default credentials and `~/.azure/accessTokens.json` each keep L2 out of reach while they are readable: a separate OS user, a runner or a CI job, or no such file. `~/.kube/config` exists on most Kubernetes users' machines.
- **A machine with nothing to audit does not reach L2.** applygate cannot show that the agent holds no credential, so L2 stays `not verified` when no AWS profile, kube context, gcloud account or Azure subscription was audited as having no destructive path.
- **A missing `aws` is reported as not checked,** where a missing `kubectl`, `gcloud` or `az` is "nothing to audit". L2 is therefore not reached on a machine without `aws`, whether or not the agent holds AWS credentials.

A block of steps ends with a fixed line: a person runs them and an agent should not, the audit covers the credentials on this machine only and from a sample, and it does not show that production is out of reach. `applygate scan --share` carries no step, since a step names credentials. `doctor --boundary` and `scan --boundary` print the same steps from the same checks.

## Requiring a level

`boundary.require` makes `applygate doctor --boundary` exit 1 below the level, and `applygate doctor` reminds you of it. It does not change decisions at run time: the hook never contacts the cloud. To make a protected tier depend on a boundary, run the check in your setup or CI and treat the exit code as the gate.
