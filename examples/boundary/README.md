# Boundary examples

Policies and commands for the setup that [docs/credentials.md](../../docs/credentials.md) describes: credentials the agent holds that can read production and change nothing, and a way to apply that needs a person. `applygate doctor --boundary` and `applygate scan --boundary` point here from the steps they print.

They are starting points for a person to read and adapt, not something applygate applies. Nothing here is run by applygate, and an agent should not run it: it changes who may do what in your cloud.

| File | What it is |
|---|---|
| [aws-agent-readonly.json](aws-agent-readonly.json) | Inline policy for the agent's read-only role, beside AWS's `ReadOnlyAccess`: read the Terraform state, and let applygate audit the role |
| [aws-apply-mfa-trust.json](aws-apply-mfa-trust.json) | Trust policy of the apply role for a person: MFA in the last hour |
| [aws-apply-oidc-trust.json](aws-apply-oidc-trust.json) | Trust policy of the apply role for a GitHub Actions job: one repository, one environment |
| [k8s-agent-view.yaml](k8s-agent-view.yaml) | Binds the agent's identity to the `view` ClusterRole |
| [gcp-agent-viewer.sh](gcp-agent-viewer.sh) | `gcloud` commands: viewer for the agent, impersonation of the apply account for the person only |
| [azure-agent-reader.sh](azure-agent-reader.sh) | `az` command: `Reader` for the agent |

**How far each has been checked** is in the table in [docs/limits.md](../../docs/limits.md#credentials-and-the-boundary-report). Read it before relying on a file. A file marked not checked there was written from the repository's docs and from memory of how the provider behaves.

**Placeholders fail closed.** `ACCOUNT_ID`, `STATE_BUCKET`, `ORG/REPO` and `PERSON` are not valid names, so a file pasted unedited grants nothing real: AWS rejects the policy, or it matches no one. The two scripts print what they would run, run nothing until `APPLY=yes` is set, and stop while a value is unset.

**What they do not do:**

- They do not make production safe. They narrow what the agent's credentials can do. The audit that checks the result samples a few destructive actions ([docs/limits.md](../../docs/limits.md)).
- A read-only role can read the Terraform state, and state holds secrets in plain text. Putting the state behind a role the agent can read is a choice: see [docs/credentials.md](../../docs/credentials.md).
- None of them covers who can read the credentials the person's own sessions leave on disk. That is the last step of docs/credentials.md.
