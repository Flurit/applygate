# applygate in CI and in Terragrunt

The same verdict the agent hooks produce is available to a pipeline and to a
Terragrunt unit through `applygate plan-check`: it reads the JSON of a saved
plan (`terraform show -json tfplan`), applies the plan-gate rules for a tier,
and exits 0 for allow, 4 for ask, 3 for block and 2 on an error. Nothing runs
`terraform apply`; the gate sits between the plan a pipeline already makes and
the apply it is about to run. Two of the three public Terraform incidents that
destroyed production ran through CI with a plan that had gone stale or carried
destroys nobody read, so this is where a plan-content check earns its place.

What `plan-check` judges: destroyed or replaced stateful resources, removed
protection (deletion protection, final snapshot, `force_destroy`, versioning),
internet exposure, IAM wildcards, changes to the state backend, destroys above
`plan_gate.max_destroy`, `protected_resources`, and `plan_gate.scope`. What it
does not judge: the workspace recorded in the binary planfile (Terraform 1.15
and later refuse that mismatch themselves) and local state freshness, which
are preflight checks in the hook path. Rules and tiers come from the
repository's `.applygate.yaml` as everywhere else; pass `--tier` to override.

## GitHub Actions

The repository ships a composite action. Make the plan, then judge it before
the apply step:

```yaml
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init -input=false && terraform plan -input=false -out=tfplan
        working-directory: envs/prod
      - uses: Flurit/applygate@v0.2.0
        id: gate
        with:
          plan: tfplan
          working-directory: envs/prod   # tier resolves from .applygate.yaml; or set tier: protected
          fail-on: block                 # block (default), ask, or never
      - run: terraform apply -input=false tfplan
        working-directory: envs/prod
```

The action installs the pinned release through `install.sh` with the cosign
signature required, runs `terraform show -json` on the planfile (or takes
plan JSON directly), and writes the verdict and findings to the job summary.
Outputs: `verdict` (allow, ask, block), `exit-code` (0, 4, 3; 2 on error) and
`summary` (the text). `fail-on: ask` makes a standard-tier ask fail the job,
which is the right setting for a protected environment whose applies need a
second pair of eyes; `fail-on: never` turns the step into a report, useful
while a team is still tuning its config. An error (unreadable plan, config
error, missing binary) always fails the job: the gate fails closed.

Inputs: `plan` (required), `tier`, `fail-on`, `working-directory`,
`terraform` (`tofu` for OpenTofu), `version` (release tag, default v0.2.0),
and `binary` to skip the download and use a binary already on the runner.
`.github/workflows/action-check.yml` in this repository exercises the action
on every push against two real AWS-provider plans.

## Any other CI

`scripts/ci-plan-check.sh` is what the action runs and has no GitHub-specific
dependency beyond writing `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY` when
they exist. Install the release (the README's verify steps, or `install.sh`
with `APPLYGATE_VERIFY_SIGNATURE=require`), then:

```bash
terraform plan -input=false -out=tfplan
PLAN=tfplan TIER=protected FAIL_ON=block scripts/ci-plan-check.sh
terraform apply -input=false tfplan
```

Or call the binary directly and branch on its exit code:

```bash
terraform show -json tfplan > tfplan.json
applygate plan-check --cwd . tfplan.json; rc=$?
case $rc in 0) ;; 4) echo "needs review" ;; 3) exit 1 ;; *) exit 1 ;; esac
```

## Terragrunt

Terragrunt runs `before_hook`s before the Terraform command, and a failing
hook aborts the run. Two hooks give a unit the plan gate and the destroy
guard; put them in the shared `root.hcl` (or `terragrunt.hcl`) so every unit
inherits them:

```hcl
terraform {
  # Gate "terragrunt apply tfplan": judge the saved plan's contents for this
  # unit's tier before Terraform applies it. The hook runs in the unit's
  # working directory, where tfplan was written by "terragrunt plan -out=tfplan";
  # --cwd points tier resolution at the live directory (envs/prod/...).
  before_hook "applygate_plan_gate" {
    commands = ["apply"]
    execute  = ["sh", "-c", "terraform show -json tfplan > tfplan.json && applygate plan-check --cwd '${get_terragrunt_dir()}' tfplan.json"]
  }

  # Refuse "terragrunt destroy" where the tier says so (block in protected,
  # ask in standard, which is also a non-zero exit and aborts the run).
  before_hook "applygate_destroy_guard" {
    commands = ["destroy"]
    execute  = ["applygate", "check", "--cwd", "${get_terragrunt_dir()}", "terraform destroy"]
  }
}
```

Use the saved-plan flow the hook expects:

```bash
terragrunt plan -out=tfplan
terragrunt apply tfplan
```

Notes. `terragrunt run --all apply` adds `-auto-approve` and still runs the
hook in every unit, so a destructive plan in one unit stops that unit only.
`applygate check` cannot prompt, so an ask verdict is an abort with the reason
printed. On a workstation, `applygate apply tfplan` is the flow that can ask:
it judges the plan the same way and takes a typed confirmation before running
the engine. The hooks need `applygate` on PATH on the machine or
runner that runs Terragrunt; `applygate doctor` from the unit directory
confirms the config it will use. Terragrunt's own `prevent_destroy = true`
remains the right setting for units that must never be destroyed at all.

## Exit codes

| Code | Meaning | Default action behaviour |
|---|---|---|
| 0 | allow | pass |
| 4 | ask | pass with `fail-on: block`, fail with `fail-on: ask` |
| 3 | block | fail (pass only with `fail-on: never`) |
| 2 | error: unreadable plan, config error, missing binary | fail, always |
