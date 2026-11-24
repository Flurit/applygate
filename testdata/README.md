# Test data shared by more than one package

- `real_plan/`: `terraform show -json` output of two real AWS-provider plans made with mock credentials and never applied: one creates an `aws_db_instance` and an `aws_s3_bucket`, one deletes them. The plan-check, apply and pull-request-comment tests and the `action-check` workflow read them.
- `agent-trial/decisions.jsonl`: the decision log of the agent trial of 2026-10-29 (Claude Code and Codex in observe mode on five public repositories; secrets redacted when it was written). The `suggest` and telemetry tests and the experiments read it. How it was made: [review/agent-trial](../review/agent-trial/README.md).
