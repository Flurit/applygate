# False-positive study on real plans

The question: on real Terraform, how often would a routine apply of a saved
plan have prompted (ask or block) in a protected tier and in a standard tier?
The agent-driven trial ([../agent-trial/README.md](../agent-trial/README.md))
measured prompts on agent commands; this study measures the plan gate
(`applygate plan-check`, the same evaluation the hook runs on
`terraform apply <planfile>`) on plans generated from public Terraform against
LocalStack.

## Corpus

[corpus.txt](corpus.txt) pins every repository to a commit:

- the five repositories of the agent-driven trial: every example of
  terraform-aws-vpc, every pattern of terraform-aws-eks-blueprints, every
  deployment of govuk-infrastructure and every backend root of
  cloud-platform-infrastructure; terragrunt-infrastructure-live-example is
  skipped, because its roots are terragrunt units over a separate modules
  repository and need the terragrunt binary;
- every example of fourteen terraform-aws-modules repositories (S3, security
  groups, IAM, DynamoDB, KMS, SQS, SNS, EC2, Auto Scaling, Lambda, RDS,
  Secrets Manager, CloudWatch, Route 53, ALB), the most widely used AWS
  modules, whose examples are roots written to be applied as they are.

Each root is run unmodified except for two override files written by
[tools/override.py](tools/override.py): every `provider "aws"` block (default
and each alias) gets LocalStack's dummy keys and a `default_tags` tag
`fp_study`, and a root with a remote backend or Terraform Cloud block gets a
local backend.

## Plans

[tools/run-root.sh](tools/run-root.sh) takes, per root:

| Plan | What it stands for | Counted as |
|---|---|---|
| `create` | the first apply of a new stack (empty state) | routine |
| `noop` | a re-plan with nothing changed, after the create was applied to LocalStack | routine |
| `tags` | the most common day-2 change: the provider default tag flipped from `v1` to `v2`, an in-place update of every taggable resource | routine |
| `destroy` | `plan -destroy`, the control | should prompt |

A create that LocalStack only partly supports (an RDS subnet group in a VPC
example, a Lambda function that needs Docker) still leaves most resources in
state. The day-2 plans are then taken over that state too and the root is
marked partial; the review tells the re-planned creates and the replaces of
tainted resources apart from the change itself.

`apply` mode repositories get all four; `plan-only` repositories (services
LocalStack's community edition does not provide: EKS, RDS, ELB, Auto Scaling;
or roots that need real accounts) get the create plan only. A root that cannot
be initialised or planned against LocalStack (missing required inputs, remote
state, git-crypt encrypted variables, data sources that look up real
resources) produces no plan; [evaluate.py](evaluate.py) records why.

[evaluate.py](evaluate.py) then runs `applygate plan-check --tier protected`
and `--tier standard` on every plan JSON with built-in defaults (no
`.applygate.yaml`, no user config: protected `max_destroy` 0, no scope, no
`protected_resources`). [label.py](label.py) holds the hand-review decisions
as rules and writes the summary. Each driving rule of a prompt gets one label:
`expected` (the rule did its job), `debatable`, `fp-analyzer` (the analyzer
misread the plan), `fp-policy` (the plan was read right but the rule should
not ask), or `fp-environment` (caused by LocalStack or the container, would
not happen against AWS). A prompt is justified if any driver is, and
environment-only if every driver is `fp-environment`.

Providers come from a plugin cache shared by the parallel workers. Modules
download first (`terraform get`, unlocked), then `terraform init` takes a
lock on the cache; `TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE` stops
Terraform reinstalling a cached provider over a binary another worker is
running (the roots carry no lock files).

## Results (2026-10-30)

[results/2026-10-30/summary.md](results/2026-10-30/summary.md), with
applygate 0.3.0, Terraform 1.16.1 and LocalStack 4.14.0
([meta.txt](results/2026-10-30/meta.txt)). 166 roots; 84 produced a create
plan and 64 day-2 plans, so 212 routine plans per tier. The summary lists
every routine prompt with its evidence and label; `roots.jsonl` records each
root's steps and errors. The per-plan `verdicts.jsonl` and `labels.jsonl`
(about 1 MB each) are not committed: rerun the study, or run
[evaluate.py](evaluate.py) and [label.py](label.py) on its plans, to get them.

| Tier | Prompted | Environment-only | Prompted outside LocalStack | Expected | False positives |
|---|---|---|---|---|---|
| standard | 0 | 0 | 0 (0%) | 0 | 0 (0%) |
| protected | 68 | 25 | 43 (20.3%) | 26 | 17 (8.0%) |

- **Standard** never prompted on a routine plan. Every destroy plan with
  deletes prompted in both tiers (63 of 63; block in protected, ask in
  standard).
- **Protected, expected (26), all on create plans:** RDS examples that
  create a database with deletion protection off and the final snapshot
  skipped (11), provisioners and Lambda packaging that really run on create
  (14, counting one RDS example with both), an AWS-managed admin policy
  attachment, and a security group open to the internet on all ports. One
  further driver, an `xray:*` wildcard, is debatable, on a prompt that is
  expected anyway.
- **Protected, false positives (17):** 16 from `code-execution`, which flags
  every provisioner and `external` data source in the configuration on every
  plan: on no-op and tag-change plans where the provisioner's resource is not
  created or replaced, on a provisioner with count 0, and on `external` data
  sources already read during the plan. 12 are in terraform-aws-lambda, the
  rest in examples that use its packaging. 1 from `exposure`, which re-flags
  an unchanged internet-open security group when it is updated only for its
  tags, because it reads the planned value without comparing it with the
  prior one.
- **Environment-only (25), all on day-2 plans:** replaces of resources left
  tainted by a create that failed in LocalStack (Lambda functions without
  Docker, pip packaging in the container), creates re-planned after a
  partial apply, and attributes LocalStack reads back differently.

## Limits

- The day-2 change is a default-tag flip, an in-place update. Replace-heavy
  changes (module upgrades, edits to immutable attributes) are not covered.
- Plan-only repositories gave few plans: 18 of 91 roots. govuk-infrastructure
  and cloud-platform-infrastructure need their real variables, profiles,
  git-crypt keys and existing account resources; 12 EKS patterns do not
  initialise at the pinned commit (conflicting `hashicorp/helm`
  constraints) and others need ECR Public, SSO or SSM parameters LocalStack
  lacks; the ALB examples look up a real Route 53 zone. Those roots are
  listed with their errors in the summary.
- LocalStack runs without the Docker socket, so Lambda functions do not
  start; their roots are partial and their prompts environment-only.
- terragrunt-infrastructure-live-example is skipped.
- Each prompt was reviewed once, by the author of the rules; the labels are
  in [label.py](label.py) so they can be checked and argued with.

## Safety

- Nothing runs on the host but `applygate plan-check` on plan JSON. Terraform
  runs only in the runner container, against the LocalStack sidecar, which is
  not published on the host.
- The runner has LocalStack's dummy credentials and nothing else; the AWS
  config and credentials files point at `/dev/null`; `run-root.sh` refuses to
  start unless the environment holds exactly those values and the sidecar
  endpoint, and every provider block is overridden with the dummy keys. The
  dummy keys are not valid on AWS, so a provider that ignored the endpoint
  would fail to authenticate rather than reach an account.
- `terraform apply` runs only on plans made inside the container against
  LocalStack. The repositories' provisioners (a `curl` download, a `sleep`)
  and the Lambda module's packaging script run inside the container.
- The scenario packs under `harness/` are not read.

## How to run

From this directory, with Docker and Compose v2 (rootless Docker as is; under
rootful Docker set `FP_STUDY_USER` to your `uid:gid`):

```bash
docker compose build
```

```bash
docker compose up -d localstack
```

```bash
docker compose run --rm -T runner sh /home/study/fp/tools/clone.sh
```

```bash
./run-all.sh 4
```

`run-all.sh` takes the repositories to run as arguments; running the
apply-mode repositories first gets the day-2 plans before the slow plan-only
roots. In the 2026-10-30 run, 16 apply-mode roots ran before
`run-root.sh` took day-2 plans over a partial apply and were rerun with it; a
fresh run needs no reruns.

```bash
python3 evaluate.py "$(command -v applygate)" results/$(date +%F)
```

```bash
python3 label.py results/$(date +%F)
```

`work/` (clones, plan JSON, logs) is gitignored. `docker compose down -v`
removes the containers and the provider cache.
