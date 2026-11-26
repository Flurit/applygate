# applygate in CI and in Terragrunt

The same verdict the agent hooks produce is available to a pipeline and to a
Terragrunt unit through `applygate plan-check`: it reads the JSON of a saved
plan (`terraform show -json tfplan`), applies the plan-gate rules for a tier,
and exits 0 for allow, 4 for ask, 3 for block and 2 on an error. Nothing runs
`terraform apply`; the gate sits between the plan a pipeline already makes and
the apply it is about to run. Two of the three public Terraform incidents that
destroyed production ran through CI with a plan that had gone stale or carried
destroys nobody read, so this is where a plan-content check earns its place.
How it sits next to Sentinel, OPA and approvals: [where-it-fits.md](where-it-fits.md).

What `plan-check` judges: destroyed or replaced stateful resources, removed
protection (deletion protection, final snapshot, `force_destroy`, versioning),
internet exposure, IAM wildcards, changes to the state backend, destroys above
`plan_gate.max_destroy`, `protected_resources`, and `plan_gate.scope`. What it
does not judge: the workspace recorded in the binary planfile (Terraform 1.15
and later refuse that mismatch themselves) and local state freshness, which
are preflight checks in the hook path. Rules and tiers come from the
repository's `.applygate.yaml` as everywhere else, and the tier from the same
signals the hook reads: the path, the selected workspace and the backend. A
replace is judged like a destroy, as in the hook, unless every replace in
the plan is a routine one ([policy.md](policy.md), step 6): such a plan exits 0
in a standard tier, where it exited 4 before, and still exits 3 in a protected
one. A runner has no trust store,
so the repository config is not read and every directory is judged protected,
and `plan-check` says so; pass `--trust-config` (the Action's `trust-config:
true`) to read the checked-out config. On pull requests from forks that config
is the contributor's. Pass `--tier protected`,
`standard` or `disposable` to override; any other value is an error (exit 2),
and so is JSON that is not a plan, such as state JSON.

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
      - uses: Flurit/applygate@v0.8.0
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

Inputs: `plan` (required), `tier`, `fail-on`, `working-directory`, `comment` and `comment-key` ([below](#a-comment-on-the-pull-request)),
`terraform` (`tofu` for OpenTofu), `trust-config` (read the repository's
`.applygate.yaml`, default false), `version` (a release tag such as v0.8.0;
anything else is an error), and `binary` to skip the download and
use a binary already on the runner. The release is installed with the
`install.sh` that comes with the action, at the ref your workflow pins, and its
signature is required. Pin the action by commit SHA to fix both.
`.github/workflows/action-check.yml` in this repository exercises the action
on every push against two real AWS-provider plans.

Which release it installs: the default of `version` in the `action.yml` your
workflow pins. From v0.6.2 on, that is the release the
action is tagged at. The action at the v0.6.0 and v0.6.1 tags installs the
release before it (v0.5.0 and v0.6.0); set `version` there to choose. For
v0.6.1 the two judge a plan the same way.

## Any other CI

`scripts/ci-plan-check.sh` is what the action runs and has no GitHub-specific
dependency beyond writing `$GITHUB_OUTPUT` and `$GITHUB_STEP_SUMMARY` when
they exist. Install the release (the verify steps in [install.md](install.md#verify-a-download), or `install.sh`
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

## A comment on the pull request

With `comment: true` the action also writes the verdict on the pull request, so
a reviewer sees it beside the diff and next to what Sentinel, OPA or a branch
policy report, without opening the job log. It is off by default, because it
needs a permission the check itself does not:

```yaml
jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # for the comment only
    # One run per pull request at a time, the newest: see "Which verdict stays".
    concurrency:
      group: plan-${{ github.event.pull_request.number || github.ref }}
      cancel-in-progress: true
    steps:
      # checkout, setup-terraform and terraform plan as above
      # comment needs v0.6.2 or later: the action at an earlier tag has no
      # such input and would run the check without commenting.
      - uses: Flurit/applygate@v0.8.0
        with:
          plan: tfplan
          working-directory: envs/prod
          comment: true
```

**What it says.** The verdict (allow, ask, block, or error when the plan could
not be judged), the plan, the tier and the environment it resolved from, and the
reasons, with the destroyed or replaced stateful resources first. Each reason
lists up to five resources; longer lists, and what was found but did not decide
the verdict, are in a collapsed block. A plan with thousands of changes still
gives a short comment, cut to fit GitHub's size limit with the rest left to the
job log.

> ### applygate plan check: ⛔ block
>
> Plan `envs/prod/tfplan` · environment `prod` (`path envs/prod/**`) · tier **protected** · 2 changes, 1 destroyed, 0 replaced
>
> The rules for a protected tier say this plan should not be applied as it is.
>
> **Why block**
>
> - **critical** plan destroys or replaces stateful resources (`stateful-destroyed`)
>   - `aws_db_instance.main (aws_db_instance) is destroyed`
> - A protected tier blocks any destroy or replace; this plan has 1 (1 named above)
> - **critical** plan removes data protection (`protection-removed`)
>   - `aws_db_instance.main: final snapshot skipped while it is being deleted`

**Which comment.** There is one comment for each plan a job judges, and later
runs update it; a plan that is fixed turns its block into an allow in place.
The comment is found by a hidden first line, a hash of:

- what was judged: `working-directory` and `plan`, as a path in the
  repository (the runner's checkout directory is not part of it), or
  `comment-key` when you set it, which is also the name the comment shows;
- who judged it: the workflow's name, the job, the job's matrix values and
  `TF_WORKSPACE`.

So two workflows, two jobs or the legs of a matrix each get their own comment
for the same plan, and none of the hash comes from files in the working
directory, so a run that fails early still finds the comment. Renaming the
workflow or the job starts a new comment and leaves the old one. Two steps of
one job that judge the same plan in the same directory (at two tiers, or after
`terraform workspace select`) share a comment: give each a `comment-key`. Until
you do, the comment shows the more severe of their verdicts and the step leaves
a notice that names `comment-key`, so an allow never covers a block of the same
run. Only a comment written by the workflow's own token (`github-actions[bot]`)
is updated; one a contributor starts with the same hidden line is ignored.

**Which verdict stays.** A hidden second line records the run that wrote the
comment. A run does not replace a comment a later run wrote, so a slow run for
an older commit cannot put its verdict over a newer one. The comparison is made
when the step reads the comments, and two runs that finish in the same second
can still cross; the `concurrency` group in the example removes that, and saves
the runner time. If two runs post a first comment at once, the comment exists
twice; both are updated from then on.

**Errors.** A check that ends in an error replaces the comment with one that
says the plan was not judged, so a comment that said allow for an earlier commit
does not stay. That covers what `plan-check` reports (an unreadable plan, a
config error) and what fails before it runs (a missing plan or working
directory, `terraform show` failing, a bad input). When applygate itself cannot
be installed (a failed download or signature check) the check does not run: a
comment an earlier run wrote is changed to say so, and where there is none, none
is made. One case is left: a job that fails before it reaches the action (the
plan step itself, say) does not run the action, and the comment keeps the
verdict of the last run that did. The failed job is what shows it.

**The check does not change.** `plan-check` runs once, as without the comment,
and with `--comment-file` writes the comment beside the output it always
printed; the verdict, the outputs and the exit code are the same. When the
comment cannot be written the step says why and the job goes on:

- the run is not for a pull request (a push, a schedule): nothing is posted;
- the token cannot comment: the job lacks `pull-requests: write`, or the pull
  request comes from a fork, where GitHub makes the token of a `pull_request`
  run read-only whatever the workflow asks;
- the installed release cannot write a comment (`version` set to v0.6.1 or
  earlier), or `gh` is not on a self-hosted runner.

The action uses the job's `github.token` for this and takes no other token. It
reads the pull request from `pull_request` and `pull_request_target` events.

**Untrusted text.** Everything in the comment that comes from the plan or the
repository (resource addresses, the rules' evidence, environment names, paths)
is untrusted. It is written only inside code spans, on one line, with control
and direction characters removed, so a resource named to look like a link, a
mention, a heading or HTML shows as its characters. A value longer than 300
bytes is cut in its middle: the end of an address, which names the resource and
says what happens to it, stays however long a module path or a `for_each` key
is. The text is the one the job log already has: resource addresses, attribute
names and the rules' wording. The plan check quotes no attribute values apart
from the action names of an IAM policy it flags and the name of a state bucket,
and the comment adds none. The text never passes through a shell command: it
goes from `plan-check` to a file and from the file to `gh`.

**On another CI.** `COMMENT_FILE=comment.md scripts/ci-plan-check.sh` writes the
same Markdown to a file for your own posting step (`COMMENT_KEY` names the
plan), and `applygate plan-check --comment-file comment.md plan.json` does it
without the script. The two hidden lines are added by
`scripts/ci-pr-comment.sh`, the GitHub posting step; the file has none.

## Terragrunt

Terragrunt runs `before_hook`s before the Terraform command, and a failing
hook aborts the run. One hook gives a unit the plan gate and the destroy
guard; put it in the shared `root.hcl` (or `terragrunt.hcl`) so every unit
inherits it:

```hcl
terraform {
  # Every apply and destroy is judged for this unit's tier before Terraform
  # runs. "terragrunt apply tfplan" (tfplan the last argument of apply) is
  # judged by the saved plan's contents; anything else (apply without a plan,
  # apply -destroy, destroy) is judged as the command it is, so a plan left
  # over from an earlier run is never judged in place of the one that runs.
  # --enforce makes the exit code follow the verdict even when your user
  # config is in observe mode. --cwd points tier resolution at the live
  # directory (envs/prod/...).
  # The arguments reach the script as positional parameters ("$@"), never as
  # text pasted into it: an option value that contains "tfplan" or a quote
  # cannot select the plan branch or end the script.
  before_hook "applygate_gate" {
    commands = ["apply", "destroy"]
    execute = concat(["sh", "-c", <<-EOT
      set -eu
      cmd=$1; dir=$2; shift 2
      last=""
      for a in "$@"; do last=$a; done
      if [ "$cmd" = apply ] && [ "$last" = tfplan ] && [ -f tfplan ]; then
        terraform show -json tfplan > tfplan.json
        applygate plan-check --cwd "$dir" tfplan.json
      else
        applygate check --enforce --no-judge --cwd "$dir" "terraform $cmd $*"
      fi
    EOT
    , "applygate-gate", get_terraform_command(), get_terragrunt_dir()], get_terraform_cli_args())
  }
}
```

On a CI runner, add `--trust-config` to the `plan-check` line, since a
runner has no trust store. This hook follows Terragrunt's documented `get_terraform_command()` and
`get_terraform_cli_args()`; it has not been run against a live Terragrunt
plan yet.

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
