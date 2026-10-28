# Open-source corpus trial: data and tools

Report: [docs/oss-corpus-trial.md](../../docs/oss-corpus-trial.md).

- `repos.txt`: the five repositories, the exact commits used, and their licenses.
- `configs/`: the `.seatbelt.yaml` written for each repository for the trial.
- `tools/extract.py`: pulls commands from a clone (Markdown code blocks, workflow `run:` steps, Makefile targets, shell scripts). Reads files only.
- `tools/replay.py`: runs `seatbelt check` on each command with an empty `PATH`, a fake `HOME` and no user config. Never executes the commands.
- `tools/label.py`: the hand-review decisions as rules, and the summary.
- `results/`: per-command verdicts and review labels (`config-*` with the trial configs, `default-*` without a config; `before` = v0.1.1, `after` = with the fixes from this trial), plus summaries.
- `run.sh SEATBELT_BIN WORKDIR`: reproduces the trial from scratch.

The `command` fields in `results/` are lines quoted from the five repositories' documentation, workflows and scripts, which are licensed MIT (alphagov/govuk-infrastructure, ministryofjustice/cloud-platform-infrastructure) and Apache-2.0 (gruntwork-io/terragrunt-infrastructure-live-example, terraform-aws-modules/terraform-aws-vpc, aws-ia/terraform-aws-eks-blueprints). Copyright remains with their authors.
