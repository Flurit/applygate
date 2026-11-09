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

## What the check does and does not cover

- **L1** is exactly `doctor`'s managed checks. Without `install --managed --exclusive` you are at L0.
- **L2** asks the policy simulator about 19 destructive actions with MFA absent, including three on the state bucket (`s3:DeleteObjectVersion`, `s3:PutBucketVersioning`, `s3:DeleteBucketPolicy`), kubectl `auth can-i` for four verbs, Google Cloud's `testIamPermissions` for 17 destructive permissions on each project a gcloud configuration names, and the roles assigned to the signed-in principal on each Azure subscription. gcloud and az have no MFA-absent test: any destructive permission or role counts. Azure PIM roles that are eligible but not active are not seen. The gcloud and az audits are tested with stubs only. A profile that could not be checked (expired SSO, no simulator permission) is `not verified`, not ok. Each credential file the agent's user can read (`~/.aws/credentials`, `~/.kube/config`, gcloud's application default credentials, `~/.azure/accessTokens.json`) is a `not verified` check: any agent that runs as you can use it, and the audit says what it can do, not who can read it. L2 is therefore not reached while one exists.
- **L3**'s sandbox check reads Claude Code's managed settings for `sandbox.enabled` and `allowUnsandboxedCommands: false`. Those keys have not been tested live. Codex sandbox modes are not checked. A sandbox set in a file your user can change counts as not verified.
- **Not covered at any level:** a swap between the hook's verdict and the execution, Codex failing open when the hook does not start, MCP servers with their own credentials, and anything that never passes through the hook.

## Requiring a level

`boundary.require` makes `applygate doctor --boundary` exit 1 below the level, and `applygate doctor` reminds you of it. It does not change decisions at run time: the hook never contacts the cloud. To make a protected tier depend on a boundary, run the check in your setup or CI and treat the exit code as the gate.
