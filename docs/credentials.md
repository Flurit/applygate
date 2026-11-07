# Credentials: the boundary behind the hook

applygate judges each call before it runs. A judgment can be wrong, and an agent that sets out to get round the hook looks for exactly those cases (red-team rounds 2 to 7 found new ones each time). What a wrong judgment can reach is decided by the credentials the agent's processes hold, not by the hook.

The boundary that holds whatever the hook decides:

- **The agent's credentials can read production and change nothing there.** It can plan, show and inspect.
- **Changing production needs a person.** The role that applies requires MFA from a device the person holds, which the agent cannot answer.

`applygate doctor --creds` checks this for the credentials on your machine.

## What `applygate doctor --creds` checks

```sh
applygate doctor --creds
```

The command takes each AWS profile (`aws configure list-profiles`, plus the environment's own `AWS_PROFILE` or access key) and each kube context (`kubectl config get-contexts`) the agent's environment can use, and asks the cloud about it:

- **AWS:**
  - `sts get-caller-identity` gives the identity and account.
  - The config's environments (`aws_profiles`, `aws_accounts`) and name hints give the tier.
  - `iam simulate-principal-policy` asks whether that identity may run 19 destructive actions with MFA absent: terminating instances, deleting databases, buckets, tables, clusters, functions and stacks, scheduling key deletion, changing IAM, assuming roles, and deleting state-bucket versions, turning versioning off or removing the bucket policy.
  - For an assumed role, the role's own ARN comes from `iam get-role`.
- **Kubernetes:** `kubectl auth can-i` asks, across all namespaces, about deleting namespaces, deployments and persistent volume claims, and creating cluster role bindings.

How each credential is reported:

| Report | When |
|---|---|
| `FAIL` | A production credential that can do any of those without MFA. `doctor --creds` exits 1. |
| `WARN` | A credential that can do them where no environment says which one it belongs to, or one that could not be checked (an expired SSO session, no permission to simulate). |
| `ok` | A credential that can do none of them, or one in a standard or disposable environment. |

It is read-only and changes nothing, but it contacts AWS and the clusters with the credentials it audits. Run it yourself; the hook never runs it.

### What it does not see

- **Policies the simulator does not evaluate.** The policy simulator does not evaluate service control policies, resource policies on the target (a bucket policy, a KMS key policy) or session policies (from AWS's documentation; not tested live). An SCP that denies the action makes the audit stricter than reality; a resource policy that allows it is missed.
- **The cases it samples.** It asks about a sample of destructive actions, not every one. A role allowed `s3:DeleteObject` on the state bucket but nothing on the list is reported as `ok`.
- **gcloud and az.** They are not audited yet. Check them by hand, as below.
- **Profiles it cannot assume.** A profile the agent could use but `doctor` cannot (an expired SSO session) is a `WARN`: once the session is renewed, it is whatever its permission set allows.

## Setting it up on AWS

### 1. Give the agent a read-only role in production

Create an `AgentReadOnly` role in each production account, with AWS's `ReadOnlyAccess` (or the narrower `ViewOnlyAccess`) and read access to the Terraform state:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
     "Resource": ["arn:aws:s3:::acme-tf-state-prod", "arn:aws:s3:::acme-tf-state-prod/*"]}
  ]
}
```

Plan with `-lock=false`, or also allow the lock table's `dynamodb:GetItem`, `PutItem` and `DeleteItem` (or, with S3 native locking, `s3:PutObject` and `s3:DeleteObject` on the `.tflock` key only).

Point the agent's production profile at it:

```ini
[profile prod-agent]
role_arn       = arn:aws:iam::111111111111:role/AgentReadOnly
source_profile = agent
```

### 2. Keep writes behind MFA

The role that applies trusts only sessions that passed MFA in the last hour:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "Bool": {"aws:MultiFactorAuthPresent": "true"},
      "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}
    }
  }]
}
```

```ini
[profile prod-apply]
role_arn       = arn:aws:iam::111111111111:role/TerraformApply
source_profile = person
mfa_serial     = arn:aws:iam::111111111111:mfa/person-key
```

With IAM Identity Center, give the agent's permission set read-only access. Do not rely on MFA to separate the permission set that applies from the one the agent holds: Identity Center asks for MFA at sign-in (a setting of the identity source), once for every permission set the person can use, and the sessions it issues may not carry `aws:MultiFactorAuthPresent`, so the trust policy above and the simulator's MFA-absent test may not behave as they do for a role assumed from an IAM user. This has not been tested here. Keep applying out of reach another way: a separate Identity Center user or account for the apply role that the agent's OS user never signs in as, or a CI role assumed through OIDC (docs/ci.md). `doctor --creds` and `doctor --boundary` report what the simulator says; check the apply role's own trust policy by hand.

### 3. Keep the person's sessions out of the agent's reach

This step is the one most setups miss. Credentials the person's own sessions leave on disk are readable by the agent when both run as the same OS user:

- an `aws sso login` token in `~/.aws/sso/cache` mints credentials for every permission set the person has;
- an assumed role with MFA is cached in `~/.aws/cli/cache` for its whole duration;
- `aws-vault` and the keychain hand out credentials to any process of the user unless the item asks each time.

applygate blocks the agent from writing these files, but not from reading them, and a call it misjudged could use them. So:

- Run applies as a different OS user from the agent, or from a machine or CI job the agent does not run on.
- Or keep production SSO sessions short and log out (`aws sso logout`) when done.
- With `aws-vault`, use a keychain that asks on each access (`--prompt` with a keychain set to lock, or `pass`/`1password` backends that ask).

`doctor --creds` sees a live SSO session for a production permission set that can write, and reports it as `FAIL`.

## Kubernetes

Bind the agent's identity to the `view` ClusterRole in production clusters:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: agent-view}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
subjects: [{kind: User, name: agent@example.com}]
```

Put writes behind a context whose credentials need the person: an OIDC login with MFA, or an `exec` plugin that asks (applygate guards `~/.kube/config`, so the agent cannot add one).

## Google Cloud and Azure (check by hand)

- **Google Cloud:** the agent's account gets `roles/viewer` (and `roles/storage.objectViewer` on the state bucket). Applies go through service-account impersonation that only the person may use. `gcloud auth login` stores the person's credentials in `~/.config/gcloud`, which the agent can read when it runs as the same OS user: keep them apart as for AWS.
- **Azure:** the agent gets `Reader` on production subscriptions. `Contributor` or `Owner` comes through Privileged Identity Management activation with MFA, which the person does. The Azure CLI's token cache in `~/.azure` is readable by the same OS user.

## How this fits with the managed install

The two are complementary:

- **The managed install** ([managed.md](managed.md)) keeps the hook itself out of the agent's reach.
- **The credentials** decide what a call the hook misjudged can do.

With both, an agent that gets past the hook reaches read-only credentials, and every change to production waits for a person.
