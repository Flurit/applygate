# Open-source corpus trial

Date: 2026-10-28. seatbelt `main` at `48a1d26` (v0.1.1) for "before", and the same code plus the fixes in this change for "after".

This is a **stand-in for the spec's observe-mode trial**, not the trial itself. The spec asks for seatbelt in observe mode on 5 real repositories while people and agents work in them. This trial replays the commands that 5 public Terraform repositories document or run (READMEs, CI workflows, Makefiles, scripts) through `seatbelt check`, and reviews every ask and block by hand. It measures false positives on realistic infrastructure commands. It does not measure what an agent would actually do, and it never exercises the plan gate (no command in the corpus applies a saved plan).

Nothing was executed. The extractor only reads files; seatbelt ran with an empty `PATH` (so `terraform`, `aws` and `git` could not start), a fake `HOME` and no user config. Reproduce with `review/oss-corpus/run.sh <seatbelt binary> <workdir>`, which clones the repositories at the commits below. The rerun reproduces the recorded verdicts exactly.

## Repositories

| Repository | Commit | License | How environments are selected | Trial config |
|---|---|---|---|---|
| [alphagov/govuk-infrastructure](https://github.com/alphagov/govuk-infrastructure) | `70a0e1e` | MIT | Terraform Cloud workspaces `<deployment>-<env>` | `*-production` protected; `*-staging`, `*-integration` standard; strict |
| [ministryofjustice/cloud-platform-infrastructure](https://github.com/ministryofjustice/cloud-platform-infrastructure) | `fb5fe72` | MIT | S3 backend, one workspace per cluster | `live*`, `manager` protected; `cloud-platform-test-*` and the ephemeral-test account disposable; strict |
| [gruntwork-io/terragrunt-infrastructure-live-example](https://github.com/gruntwork-io/terragrunt-infrastructure-live-example) (archived) | `d106b47` | Apache-2.0 | Directory (`prod/`, `non-prod/`) | `prod/**` protected, `non-prod/**` standard; strict |
| [terraform-aws-modules/terraform-aws-vpc](https://github.com/terraform-aws-modules/terraform-aws-vpc) | `b3abd6d` | Apache-2.0 | Module; examples go to a sandbox account | `examples/**` disposable; everything else standard (`default_tier`) |
| [aws-ia/terraform-aws-eks-blueprints](https://github.com/aws-ia/terraform-aws-eks-blueprints) | `fc40e64` | Apache-2.0 | Patterns go to a sandbox account | `patterns/**` disposable; everything else standard (`default_tier`) |

The configs are in `review/oss-corpus/configs/`. They are what a careful user would write after reading each repository's README, not what each team actually uses.

## Method

1. **Extract** (`tools/extract.py`): every line of shell-like fenced code blocks in Markdown (tracking `cd` within a block), every `run:` step in GitHub Actions workflows (`${{ … }}` replaced by a placeholder), every Makefile target as `make <target>` in its directory, and every shell script as `./path/script.sh` from the repository root. 1,334 distinct commands: 1,219 from Markdown, 84 from workflows, 27 scripts, 4 make targets. 478 mention Terraform, Terragrunt, kubectl, an AWS CLI call, make or a script.
2. **Replay** (`tools/replay.py`): `seatbelt check --json --cwd <dir> -- <command>` per command, with the trial configs and again with no config (strict defaults).
3. **Review** (`tools/label.py`): every ask and block was read by hand and labelled. The rules in `label.py` record those decisions so they can be checked:
   - **expected**: the verdict is what the policy should return for that command in that tier;
   - **false positive**: the command should have been allowed (`fp-policy`, `fp-analyzer`, `fp-environment` by cause);
   - **debatable**: the spec's table asks, but the friction is arguable;
   - **noise** / **placeholder**: not a runnable command as written (HCL, JSON, tree diagrams, `<clusterName>`), excluded from the rate.

   Allowed commands that look destructive (93) were also read, to look for misses.

False-positive rate = false positives / runnable commands (all commands minus noise and placeholders).

## Results (with the trial configs, after the fixes)

| Repository | Commands | Runnable | Allow | Expected ask/block | False positives | Debatable | FP rate |
|---|---|---|---|---|---|---|---|
| govuk-infrastructure | 281 | 247 | 230 | 12 | 5 | 0 | 2.0% |
| cloud-platform-infrastructure | 251 | 239 | 226 | 13 | 0 | 0 | 0.0% |
| terragrunt-infrastructure-live-example | 17 | 17 | 17 | 0 | 0 | 0 | 0.0% |
| terraform-aws-vpc | 59 | 59 | 53 | 6 | 0 | 0 | 0.0% |
| terraform-aws-eks-blueprints | 726 | 697 | 632 | 53 | 3 | 9 | 0.4% |
| **All** | **1,334** | **1,259** | **1,158** | **84** | **8** | **9** | **0.64%** (1.35% with debatable) |

Every repository is under the spec's 5% bar. The expected asks and blocks are destroy and `-auto-approve` applies in standard tiers, state surgery in migration guides, cluster teardown scripts, and CloudFormation or S3 writes and bare `terraform apply` in environments the config does not map (strict mode treats those as protected).

| Run | False positives | FP rate | Misses found |
|---|---|---|---|
| Trial configs, before the fixes | 9 | 0.71% | 5 (credential wrappers) |
| Trial configs, after the fixes | 8 | 0.64% | 0 of those 5 |
| No config (strict), before | 16 | 1.32% | 5 |
| No config (strict), after | 8 | 0.66% | 0 of those 5 |

Without a config, 332 commands are flagged instead of 176, all in the protected tier, because every unconfigured directory counts as protected in strict mode. README instructions such as `terraform destroy` in an example directory are then blocked. That is the intended out-of-the-box behavior, but it is a lot of friction on day one, which is why `seatbelt init` starts in observe mode.

## Findings

### 1. Credential and secrets wrappers hid commands entirely (fixed)

`aws-vault exec prod-admin -- terraform destroy`, `gds aws <role> -- terraform apply`, `saml2aws exec`, `aws-sso exec`, `aws-okta exec`, `doppler run --`, `op run --`, `chamber exec`, `infisical run --` and `envchain` were unknown programs, so the wrapped command was never analyzed and the call was **allowed**. govuk runs Terraform this way (`gds aws govuk-production-admin -- terraform apply`). Five corpus commands moved from allow to block after the fix.

seatbelt now unwraps these tools and uses the profile or role they name (`prod-admin`, `govuk-production-admin`) as the AWS profile signal for tier resolution. Scenarios D53 and D54 cover this.

### 2. False positives fixed

- `aws eks update-kubeconfig` (and `aws sso login`, `aws ecr get-login-password`) only write local client configuration; they were classed as cloud writes.
- `kubectl port-forward`, `proxy` and the `relay` plugin open local tunnels; they were classed as cloud writes.
- `"$@"` inside a function or script (`retry() { … "$@" … }`, `exec "$@"`) left the program name unresolved. It now expands to the arguments.
- `${BASH_SOURCE[0]}` and `$(cd X && pwd)` / `$(cd X; pwd)` now resolve, so the common `SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` idiom keeps the script's directory, and with it the right tier.

Scenarios B31 and B32 cover the first two; unit tests cover the rest.

### 3. Remaining false positives (8)

| Count | Cause | Example |
|---|---|---|
| 3 | **Policy:** `terraform init -reconfigure` is state surgery in the spec, but govuk uses `init -backend-config <env>.backend -reconfigure` routinely to switch environments, and eks-blueprints CI uses it in validation | `gds aws govuk-test-admin -- terraform init -backend-config test.backend -reconfigure -upgrade` |
| 2 | Analyzer: a command substitution's output used as the program name | `while $(kill -0 $PID 2>/dev/null); do sleep 1; done` |
| 1 | Analyzer: a Makefile recipe calls `$(call …)`, which is not expanded | `make lint_docs` |
| 1 | Analyzer: the program is held in a variable built from a runtime loop value | `${git} reflog expire …` |
| 1 | Environment: `source venv/bin/activate` before the virtualenv exists (fresh clone) | `source venv/bin/activate` |

### 4. Debatable (9)

`kubectl delete -f example.yaml` and similar teardown in disposable example directories ask, because the spec's table makes cloud-destructive commands ask even in disposable tiers. Every one of the 9 is a sandbox teardown step.

### 5. Misses

Apart from the wrappers, one destructive command was allowed: a CI step runs `python3 .github/scripts/delete-log-groups.py`, which deletes CloudWatch log groups through boto3. Python that mentions no infrastructure CLI passes by design (`docs/limits.md`). Counting AWS SDK imports (`boto3`, `botocore`, `@aws-sdk/`) as infrastructure mentions would make such scripts ask.

One apparent miss was an extraction artifact: `./destroy.sh prod` in the EKS hub-and-spoke README was replayed from the wrong directory (the README's `cd spokes` is outside the code block). Run from `spokes/`, seatbelt blocks it, because the script selects workspace `prod`.

### 6. Configuration pitfalls seen while writing the trial configs

- **A catch-all overrides everything below it.** The first trial configs mapped `examples/**` to disposable and `**` to standard. Because the most protected match wins, every example became standard. Use `strict: false` with `default_tier` for a default, not a `**` environment. `docs/config.md` now says so.
- **Unmapped roles and paths stay protected.** govuk's ephemeral-cluster commands and `gds aws govuk-test-admin` roles were treated as protected because the trial config did not map `terraform/deployments/ephemeral/**` or the `govuk-test-*` roles. A real config would, and most of those 12 asks and blocks would become allow or ask.

## Decisions for the maintainers

1. **`init -reconfigure`**: keep as state surgery (spec), or treat as read-only when it only re-points the working directory (`-backend-config` given, no `-migrate-state`/`-force-copy`). This would remove 3 of the 8 false positives.
2. **`kubectl delete` in disposable tiers**: keep ask (spec), or allow. This would remove the 9 debatable asks.
3. **AWS SDK code**: treat `boto3`/`botocore`/`@aws-sdk/` mentions in Python or Node code as infrastructure (ask), closing the boto3 miss at the cost of asks on read-only SDK scripts.

## Limits of this trial

- Documented and CI commands are not agent behavior. An agent may run commands no README shows, and skip ones that are shown.
- The extractor guesses each command's directory from the file it came from and `cd` lines within the same block; a few commands ran from the wrong directory.
- No saved plans exist in the corpus, so the plan gate, workspace-mismatch and stale-state checks were not exercised.
- The labels are one reviewer's judgment. The rules in `label.py` and the per-command results in `review/oss-corpus/results/` make every decision checkable.
- The trial configs are mine, written from each repository's README; the teams' own mappings may differ.
