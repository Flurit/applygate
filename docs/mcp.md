# MCP tool calls

Agents increasingly change infrastructure through MCP servers instead of the shell: a Terraform server that runs `terraform destroy`, an AWS server that runs any `aws` command, a Kubernetes server that deletes a deployment. Claude Code and Codex send those calls to the hook as `mcp__<server>__<tool>` with the tool's arguments.

applygate judges a call to a **known infrastructure tool** as the command it is equivalent to, so the shell analyzer, environment tiers, preflight, plan gate and one-time approvals apply exactly as they would to that command. The verdict carries a note naming the tool and the command it was judged as, for example:

```
Note: MCP tool ExecuteTerraformCommand (awslabs terraform-mcp-server) judged as the equivalent of: terraform destroy -auto-approve
```

Every **other** MCP call (GitHub, Slack, a database browser, anything not listed below) is logged with its arguments, secrets redacted and capped at 4 KB, and allowed, as before. `applygate report` counts MCP calls per server.

## How a call is judged

- The table of known tools is data: [`internal/mcpmap/rules.json`](../internal/mcpmap/rules.json). Each entry names the server's repository, the commit read and the source files, and maps each tool to a command built from its arguments. A tool is recognized by its name (the part after the last `__`, since the server part is whatever you named the server) and by the arguments it must have, so two servers that use the same tool name are told apart.
- **Directory.** An MCP server runs its commands in its own working directory, which the hook does not know. A call is judged in a directory only when it names an absolute one (`working_directory`, `cwd`, `directory`); otherwise the directory is unknown and the call is judged at the most protected tier it could be in under the session root, as for Codex shell commands ([limits.md](limits.md)). A `cd` inside a command still establishes the directory for that command.
- **Workspaces.** A run on HCP Terraform or Terraform Enterprise is judged as the Terraform command on that workspace (`TF_WORKSPACE=<workspace> terraform destroy`), so an environment matched by `workspaces:` in your config gets its tier.
- **What cannot be read is asked about.** A known tool whose arguments are not an object or match no known form, applying an HCP Terraform run whose plan applygate cannot read, or applying a plan kept in the server's own store, gets the verdict for a command applygate cannot resolve: ask in protected and standard tiers (a block on agents that cannot ask, which a person can approve once with `applygate approve`), allow in disposable ones.
- **Errors.** A known tool is judged like a shell command, so a broken repository config or an internal error follows `on_error`. Unknown MCP calls still never block, even then.

## Known servers

From each server's source code at the commit named in `rules.json`, **not tested against the running servers**.

| Server | Tools judged | Judged as |
|---|---|---|
| awslabs aws-api-mcp-server | `call_aws` | each `aws …` command (a list is judged command by command) |
| awslabs terraform-mcp-server (last release before its removal from awslabs/mcp) | `ExecuteTerraformCommand`, `ExecuteTerragruntCommand` | `terraform`/`terragrunt` apply, destroy and run-all with `-auto-approve`, which the server always adds; init, plan, validate, output |
| awslabs cfn-mcp-server / ccapi-mcp-server | `create_resource`, `update_resource`, `delete_resource` | `aws cloudcontrol …-resource` |
| awslabs eks-mcp-server | `manage_k8s_resource`, `apply_yaml`, `manage_eks_stacks`, `add_inline_policy` | `kubectl delete/create/replace/patch/get/apply`, the stack's CloudFormation delete or deploy, `aws iam put-role-policy` |
| awslabs ecs-mcp-server | `ecs_resource_management`, `delete_app` | `aws ecs <operation>`, the service and stack deletes |
| awslabs aws-serverless-mcp-server | `sam_deploy` | the CloudFormation deploy it performs |
| hashicorp terraform-mcp-server | `create_run`, `action_run`, `delete_workspace_safely`, `force_unlock_workspace` | `terraform destroy/apply/plan` on the workspace; applying a run is asked about; workspace delete; force-unlock |
| severity1 terraform-cloud-mcp | `create_run`, `apply_run`, `force_execute_run`, `delete_workspace`, `safe_delete_workspace`, `force_unlock_workspace`, `unlock_workspace` | as above |
| nwiizo tfmcp | `apply_terraform`, `destroy_terraform`, `terraform_refresh`, `terraform_import`, `terraform_taint`, `terraform_workspace`, `create_run`, `action_run`, `delete_workspace_safely` | the Terraform command each runs; applying a stored plan is asked about |
| containers kubernetes-mcp-server | `pods_delete`, `pods_exec`, `pods_run`, `resources_create_or_update`, `resources_delete`, `resources_scale`, `helm_install`, `helm_uninstall`, `vm_lifecycle` | `kubectl …`, `helm …` |
| Flux159 mcp-server-kubernetes | `kubectl_generic`, `kubectl_delete`, `kubectl_apply`, `kubectl_create`, `kubectl_scale`, `kubectl_patch`, `kubectl_rollout`, `exec_in_pod`, `node_management`, `install_helm_chart`, `upgrade_helm_chart`, `uninstall_helm_chart` | `kubectl …`, `helm …` |
| Azure aks-mcp | `call_kubectl`, `call_helm`, `call_cilium`, `call_hubble`, `call_az`, the legacy `kubectl_resources`, `kubectl_workloads`, `kubectl_metadata`, `kubectl_diagnostics`, `kubectl_cluster`, `kubectl_config`, `az_aks_operations`, `az_compute_operations`, `az_fleet` | the command string it runs |
| GoogleCloudPlatform gke-mcp | `delete_k8s_resource`, `apply_k8s_manifest`, `patch_k8s_resource`, `delete_cluster`, `delete_node_pool`, `create_cluster`, `update_cluster`, `create_node_pool`, `update_node_pool` | `kubectl …`, `gcloud container …` |
| googleapis gcloud-mcp | `run_gcloud_command`, `delete_bucket` | `gcloud …` |
| shell command servers (Desktop Commander, mcp-server-commands, mcp-shell-server, cli-mcp-server, wcgw, Serena, iterm-mcp) | `start_process`, `interact_with_process`, `run_process`, `run_command`, `shell_execute`, `BashCommand`, `execute_shell_command`, `write_to_terminal` | the shell command, or the text typed into a running shell |

`helm`, `az` and `gcloud` commands are classified by verb, in MCP calls and in shell commands alike: `helm uninstall` and any `az`/`gcloud` command whose verb is `delete` or `purge` (or ends in `-delete`) is cloud-destructive; `list`, `show`, `describe`, `get` and `status` are read-only; anything else changes cloud resources.

## Not covered

- **Pulumi.** The source of the current Pulumi MCP server is not public, and applygate has no Pulumi rules yet.
- **AWS Lambda tool server.** It names one tool after each Lambda function, so the tool names cannot be known in advance.
- **SQL.** Database MCP tools (`run_query` and similar) are logged, not judged.
- **Calls whose effect lives elsewhere.** Applying an HCP Terraform run is asked about but not tied to the run's plan; changing a workspace's auto-apply setting, its variables or team access is logged, not judged.
- **Retargeting.** Tools that switch the kube context or fetch credentials (`kubectl_context` with `set`, `get_kubeconfig`, `az aks get-credentials`) are read-only to applygate. A Kubernetes server that runs with its own kubeconfig is judged by the context the call names, else by the current context of the kubeconfig the hook sees (`KUBECONFIG` or `~/.kube/config`), which is the server's only when both use the same file.
- **Input to a running REPL.** Text that Desktop Commander's `interact_with_process` or wcgw's `send_text` types into a running process is judged as a shell command, so code typed into a Python or Node session that is not shell may be asked about.
- **Other agents.** Only Claude Code and Codex are known to send MCP calls to the hook; the replay pack sends them in those two formats only.
