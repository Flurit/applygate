# Plan-gate exercise verdicts

    date: 2026-10-29T06:19:07Z
    seatbelt: seatbelt 0.1.3
    terraform: Terraform v1.16.1
    localstack: {"version":"4.14.0","s3":"running","ec2":"running","dynamodb":"running"}
    machine: Linux 7.0.0-42-generic x86_64
    config: /work/plangate/.seatbelt.yaml (enforce, strict; prod protected, staging standard)

plan-check is given the workspace's tier explicitly (--tier); the hook path resolves the tier itself from the selected workspace. "decision" is what the agent receives: the hookSpecificOutput permissionDecision, or allow when the hook prints nothing, or exit 2 (blocked by exit code).

| Workspace | Tier | Plan | Command through the hook | plan-check | Hook verdict | Enforced | Claude decision | Codex decision | Class | Findings |
|---|---|---|---|---|---|---|---|---|---|---|
| prod | protected | create | `terraform apply plans/prod-create.tfplan` | allow (5 changes, 0 deletes, 0 replaces) (exit 0) | allow | allow | allow | allow | apply-saved-plan | - |
| prod | protected | noop | `terraform apply plans/prod-noop.tfplan` | allow (0 changes, 0 deletes, 0 replaces) (exit 0) | allow | allow | allow | allow | apply-saved-plan | - |
| prod | protected | replace-bucket | `terraform apply plans/prod-replace-bucket.tfplan` | block (2 changes, 0 deletes, 2 replaces) (exit 3) | block | block | deny | deny | apply-saved-plan | critical stateful-destroyed; high destroy-count |
| prod | protected | versioning-suspended | `terraform apply plans/prod-versioning-suspended.tfplan` | block (1 changes, 0 deletes, 0 replaces) (exit 3) | block | block | deny | deny | apply-saved-plan | critical protection-removed |
| prod | protected | force-destroy | `terraform apply plans/prod-force-destroy.tfplan` | block (1 changes, 0 deletes, 0 replaces) (exit 3) | block | block | deny | deny | apply-saved-plan | critical protection-removed |
| prod | protected | open-ssh | `terraform apply plans/prod-open-ssh.tfplan` | ask (1 changes, 0 deletes, 0 replaces) (exit 4) | ask | ask | ask | deny | apply-saved-plan | high exposure |
| prod | protected | destroy | `terraform apply plans/prod-destroy.tfplan` | block (5 changes, 5 deletes, 0 replaces) (exit 3) | block | block | deny | deny | destroy | critical stateful-destroyed; high destroy-count |
| staging | standard | create | `terraform apply plans/staging-create.tfplan` | allow (5 changes, 0 deletes, 0 replaces) (exit 0) | allow | allow | allow | allow | apply-saved-plan | - |
| staging | standard | noop | `terraform apply plans/staging-noop.tfplan` | allow (0 changes, 0 deletes, 0 replaces) (exit 0) | allow | allow | allow | allow | apply-saved-plan | - |
| staging | standard | replace-bucket | `terraform apply plans/staging-replace-bucket.tfplan` | ask (2 changes, 0 deletes, 2 replaces) (exit 4) | ask | ask | ask | deny | apply-saved-plan | critical stateful-destroyed |
| staging | standard | versioning-suspended | `terraform apply plans/staging-versioning-suspended.tfplan` | ask (1 changes, 0 deletes, 0 replaces) (exit 4) | ask | ask | ask | deny | apply-saved-plan | critical protection-removed |
| staging | standard | force-destroy | `terraform apply plans/staging-force-destroy.tfplan` | ask (1 changes, 0 deletes, 0 replaces) (exit 4) | ask | ask | ask | deny | apply-saved-plan | critical protection-removed |
| staging | standard | open-ssh | `terraform apply plans/staging-open-ssh.tfplan` | allow (1 changes, 0 deletes, 0 replaces) (exit 0) | allow | allow | allow | allow | apply-saved-plan | high exposure |
| staging | standard | destroy | `terraform apply plans/staging-destroy.tfplan` | ask (5 changes, 5 deletes, 0 replaces) (exit 4) | ask | ask | ask | deny | destroy | critical stateful-destroyed |
| staging | protected | mismatch-prod-plan | `terraform apply plans/prod-create.tfplan` | allow (5 changes, 0 deletes, 0 replaces) (exit 0) | ask | ask | ask | deny | apply-saved-plan | critical workspace-mismatch |
| prod | protected | mismatch-staging-plan | `terraform apply plans/staging-create.tfplan` | allow (5 changes, 0 deletes, 0 replaces) (exit 0) | block | block | deny | deny | apply-saved-plan | critical workspace-mismatch |
| prod | protected | missing | `terraform apply plans/missing.tfplan` | n/a | ask | ask | ask | deny | apply-saved-plan | high plan-missing |
| prod | protected | garbage | `terraform apply plans/garbage.tfplan` | n/a | block | block | deny | deny | apply-saved-plan | critical plan-unreadable |
| staging | standard | missing | `terraform apply plans/missing.tfplan` | n/a | allow | allow | allow | allow | apply-saved-plan | high plan-missing |
| staging | standard | garbage | `terraform apply plans/garbage.tfplan` | n/a | ask | ask | ask | deny | apply-saved-plan | critical plan-unreadable |

Decision log entries: 40 (two per plan: one Claude, one Codex event). Raw hook outputs are in hook/, plan JSON and plan-check output in plans/.
