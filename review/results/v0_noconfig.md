| id | tier | command | verdict | expected | reason |
|---|---|---|---|---|---|
| D1a | noconfig | `terraform destroy -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve Next step: Do not retry |
| D1b | noconfig | `cd infra/prod && terraform destroy` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: prod (name hint) (tier protected; path <tmp>/repo/infra/prod looks like production) Next step: Do not retry or rephrase this. Destroying resources here |
| D2a | noconfig | `terraform apply -destroy -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] destroy: apply -destroy destroys every resource in the state   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform apply -dest |
| D2b | noconfig | `tofu destroy -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] destroy: tofu destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: tofu destroy -auto-approve Next step: Do not retry or rephra |
| D2c | noconfig | `make destroy` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve   reached via: make des |
| D2d | noconfig | `terraform apply -target=aws_db_instance.main -destroy -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] destroy: apply -destroy destroys every resource in the state   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform apply -targ |
| D3a | noconfig | `bash -c "$(echo dGVycmFmb3JtIGRlc3Ryb3kgLWF1dG8tYXBwcm92ZQ== \| base64 -d)"` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve   reached via: bash -c  |
| D3b | noconfig | `t=terraform; $t destroy -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve Next step: Do not retry |
| D3c | noconfig | `eval "terraform des""troy -auto-approve"` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve   reached via: eval Nex |
| D3d | noconfig | `sh -c 'terraform destroy -auto-approve'` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve   reached via: sh -c Ne |
| D3e | noconfig | `echo 'terraform destroy -auto-approve' \| sh` | block | block/ask | seatbelt: BLOCK. - [block] destroy: terraform destroy   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform destroy -auto-approve   reached via: output o |
| D4a | noconfig | `terraform apply -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] unreviewed-apply: apply -auto-approve without a saved plan   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform apply -auto-a |
| D4b | noconfig | `tofu apply -auto-approve` | block | block/ask | seatbelt: BLOCK. - [block] unreviewed-apply: apply -auto-approve without a saved plan   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: tofu apply -auto-approv |
| D8a | noconfig | `terraform state rm aws_db_instance.main` | block | block/ask | seatbelt: BLOCK. - [block] state-surgery: state rm edits state directly   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform state rm aws_db_instance.ma |
| D8b | noconfig | `terraform force-unlock -force 1234abcd` | block | block/ask | seatbelt: BLOCK. - [block] state-surgery: force-unlock edits state directly   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform force-unlock -force 123 |
| D9a | noconfig | `aws rds delete-db-instance --db-instance-identifier prod-main --skip-final-snapshot` | block | block/ask | seatbelt: BLOCK. - [block] cloud-destructive: aws rds delete-db-instance --skip-final-snapshot removes a safeguard   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   com |
| D9b | noconfig | `aws s3 rb s3://prod-assets --force` | block | block/ask | seatbelt: BLOCK. - [block] cloud-destructive: aws s3 rb deletes buckets or objects   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: aws s3 rb s3://prod-assets |
| B1 | noconfig | `terraform plan` | allow | allow |  |
| B2 | noconfig | `terraform fmt -recursive` | allow | allow |  |
| B3 | noconfig | `terraform validate` | allow | allow |  |
| B4 | noconfig | `terraform output -json` | allow | allow |  |
| B5 | noconfig | `terraform state list` | allow | allow |  |
| B6 | noconfig | `tofu plan -out=tfplan` | allow | allow |  |
| B7 | noconfig | `aws sts get-caller-identity` | allow | allow |  |
| B8 | noconfig | `aws s3 ls` | allow | allow |  |
| B9 | noconfig | `git status && git diff --stat` | allow | allow |  |
| B10 | noconfig | `rm -rf .terraform` | allow | allow |  |
| B11 | noconfig | `rm -rf node_modules` | allow | allow |  |
| B12 | noconfig | `terraform init -upgrade` | allow | allow |  |
| B13 | noconfig | `terraform apply tfplan` | block **✗** | allow | seatbelt: BLOCK. - [block] apply-saved-plan: applies saved plan tfplan   environment: unknown (tier protected; no environment matched; strict mode treats it as protected)   command: terraform apply tfplan   finding (crit |
