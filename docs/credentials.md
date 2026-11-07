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

The command takes each AWS profile (`aws configure list-profiles`, plus the environment's own `AWS_PROFILE` or access key), each kube context (`kubectl config get-contexts`), each gcloud account and project (`gcloud auth list`, `gcloud config configurations list`) and each Azure subscription (`az account list --all`) the agent's environment can use, and asks the cloud about it:

- **AWS:**
  - `sts get-caller-identity` gives the identity and account.
  - The config's environments (`aws_profiles`, `aws_accounts`) and name hints give the tier.
  - `iam simulate-principal-policy` asks whether that identity may run 19 destructive actions with MFA absent: terminating instances, deleting databases, buckets, tables, clusters, functions and stacks, scheduling key deletion, changing IAM, assuming roles, and deleting state-bucket versions, turning versioning off or removing the bucket policy.
  - For an assumed role, the role's own ARN comes from `iam get-role`.
- **Kubernetes:** `kubectl auth can-i` asks, across all namespaces, about deleting namespaces, deployments and persistent volume claims, and creating cluster role bindings.
- **Google Cloud:** see [below](#google-cloud-and-azure). It asks Resource Manager which of 17 destructive permissions each account holds on each project.
- **Azure:** see [below](#google-cloud-and-azure). It lists each subscription's role assignments for the signed-in principal and reports the roles that can delete or grant access.

A missing `kubectl`, `gcloud` or `az` means nothing to audit for it, not a warning.

How each credential is reported:

| Report | When |
|---|---|
| `FAIL` | A production credential that can do any of those without MFA (for gcloud and az: at all, see below). `doctor --creds` exits 1. |
| `WARN` | A credential that can do them where no environment says which one it belongs to, or one that could not be checked (an expired SSO session, no permission to simulate, no gcloud token, an `az` error). |
| `ok` | A credential that can do none of them, or one in a standard or disposable environment. |

It is read-only and changes nothing, but it contacts AWS, Google Cloud, Azure and the clusters with the credentials it audits. Run it yourself; the hook never runs it.

### What it does not see

- **Policies the simulator does not evaluate.** The policy simulator does not evaluate service control policies, resource policies on the target (a bucket policy, a KMS key policy) or session policies (from AWS's documentation; not tested live). An SCP that denies the action makes the audit stricter than reality; a resource policy that allows it is missed.
- **The cases it samples.** It asks about a sample of destructive actions, not every one. A role allowed `s3:DeleteObject` on the state bucket but nothing on the list is reported as `ok`.
- **Google Cloud and Azure** have their own limits, listed [below](#google-cloud-and-azure).
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

## Google Cloud and Azure

Both audits have been tested with stubbed CLI and API answers only, not against a live account.

### What the gcloud audit checks

- **Accounts and projects.** Every credentialed account (`gcloud auth list --format=json`) paired with the project each configuration names (`gcloud config configurations list --format=json`), plus the active pair (`gcloud config list --format=json`, with `CLOUDSDK_CORE_ACCOUNT` and `CLOUDSDK_CORE_PROJECT` taking precedence). An account no configuration pairs with a project is checked against the active project, since `--account` alone uses it. If there is no active project, it is a `WARN`. Configurations that name an account with no credentials are skipped.
- **The check.** `gcloud auth print-access-token --account=ACCOUNT` gives the account's token. applygate posts it to Resource Manager's [`projects.testIamPermissions`](https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions), which returns the permissions the caller holds out of those it is asked about. The token goes only into that request's header. It is never printed or logged. No special permission is needed to call it.
- **The permissions asked about.**
  - Deleting: `compute.instances.delete`, `compute.networks.delete`, `cloudsql.instances.delete`, `storage.buckets.delete`, `storage.objects.delete`, `container.clusters.delete`, `cloudfunctions.functions.delete`, `run.services.delete`, `spanner.instances.delete`, `bigquery.datasets.delete`, `cloudkms.cryptoKeyVersions.destroy`, `resourcemanager.projects.delete`.
  - Changing who may act: `storage.buckets.setIamPolicy`, `resourcemanager.projects.setIamPolicy`, `iam.serviceAccountKeys.create`.
  - Acting as another identity: `iam.serviceAccounts.actAs` and `iam.serviceAccounts.getAccessToken` are on the list because impersonating a service account reaches that account's rights as well as the caller's.
- **The report.** `gcloud account A on project P (environment X, tier T)`, then either `none of 17 destructive permissions` or `holds: …`. A token that cannot be had or an API error is `WARN … not checked (…)`. If the API rejects a permission on the list as invalid for a project, that error is shown as a `WARN`.

What it does not see:

- **MFA.** gcloud has nothing like AWS's MFA-absent simulation. Any destructive permission held by a credential the agent can use counts as one the agent can use.
- **What the account holds outside the project.** It checks the account itself on the project only. Rights on folders and the organization count where they are inherited by the project. Rights on other projects do not count, nor the rights of service accounts it could impersonate, beyond flagging that it can impersonate them.
- **Conditions.** IAM conditions and deny policies are evaluated by Google as they apply to this request (not tested live).
- **Application default credentials** (`~/.config/gcloud/application_default_credentials.json`) are used by Terraform and client libraries, not by `gcloud`. They are not audited. `doctor --boundary` lists the file when it is readable.

### What the az audit checks

- **Subscriptions.** Every subscription `az account list --all --output json` returns, the default one first (`AZURE_SUBSCRIPTION_ID` takes precedence over the CLI's default), up to 500.
- **Role assignments.** For each one: `az role assignment list --assignee USER --all --include-inherited --include-groups --subscription ID`. That covers assignments at the subscription, its resource groups and resources, those inherited from management groups, and those held through groups. For a service principal, `USER` is its appId.
- **Which roles count.**
  - These built-in roles count directly: `Owner`, `Contributor`, `User Access Administrator`, `Role Based Access Control Administrator`, `Virtual Machine Contributor`, `Storage Account Contributor`, `SQL Server Contributor`, `Azure Kubernetes Service Contributor Role`, `Key Vault Contributor`, `Network Contributor`.
  - These never count: `Reader`, `Monitoring Reader`, `Billing Reader`, `Security Reader`, `Log Analytics Reader`, `Cost Management Reader`.
  - For any other role, its definition is read (`az role definition list --name ROLE --subscription ID`). It counts if an `actions` or `dataActions` entry is one of these, unless a `notActions` (or `notDataActions`) entry covers that same entry: `*`, anything ending in `/delete`, a write under `Microsoft.Authorization/`, or a provider-wide wildcard ending in `/*`, which includes the provider's deletes.
  - When the check is unsure, the entry is counted. A narrower `notActions` does not cancel `*`, for example.
- **The report.** `az subscription NAME (ID) as USER (environment …)`, then either `roles allowing destructive changes: Owner at /subscriptions/…` or `no role with a destructive action`. An `az` error, or a role definition that cannot be read when no other role counts, is `WARN … not checked`.
- **Permissions needed.** The signed-in principal needs `Microsoft.Authorization/roleAssignments/read` and `Microsoft.Authorization/roleDefinitions/read`. `Reader` has both.

What it does not see:

- **Privileged Identity Management.** Roles a person is *eligible* for but has not activated do not appear. Once activated, they do, for as long as the activation lasts.
- **Conditional access.** Policies that require MFA for some actions are not evaluated. A role reported here may need MFA in practice.
- **Managed identities.** A subscription signed in as a managed identity (`systemAssignedIdentity`) may not resolve as an assignee. It is then a `WARN`.
- **Resource locks and Azure Policy deny** assignments that would stop a delete.

### Setting them up

- **Google Cloud:** the agent's account gets `roles/viewer` (and `roles/storage.objectViewer` on the state bucket). Applies go through service-account impersonation that only the person may use. Do not grant the agent `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser` on the apply account: the audit reports those as `iam.serviceAccounts.getAccessToken` and `actAs`. `gcloud auth login` stores the person's credentials in `~/.config/gcloud`, which the agent can read when it runs as the same OS user: keep them apart as for AWS.
- **Azure:** the agent gets `Reader` on production subscriptions. `Contributor` or `Owner` comes through Privileged Identity Management activation with MFA, which the person does. The Azure CLI's token cache in `~/.azure` is readable by the same OS user. While a person's activation is live, a session in that cache has the role, and the audit reports it.

## How this fits with the managed install

The two are complementary:

- **The managed install** ([managed.md](managed.md)) keeps the hook itself out of the agent's reach.
- **The credentials** decide what a call the hook misjudged can do.

With both, an agent that gets past the hook reaches read-only credentials, and every change to production waits for a person.
