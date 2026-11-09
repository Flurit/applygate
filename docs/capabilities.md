# Capabilities

What applygate does today, on main at `03926ef` (2026-11-09), and how much of each part has been seen working. This page is an inventory: the detailed rules are in [policy.md](policy.md), the hosts in [hosts.md](hosts.md), what it does not do in [limits.md](limits.md).

Each item carries one of these marks:

- **live**: seen working against the real program (an agent host, a cloud, a real plan), with the version and date in the linked page.
- **tests**: covered by the repository's tests or replay harness, with stubs or fixtures where a real program would be needed.
- **docs**: written from the other program's documentation or source, not run against it.
- **none**: not covered.

## At a glance

| Area | What it covers | Status |
|---|---|---|
| Agent hosts | Claude Code and Codex fully; Cursor, Copilot CLI, Gemini CLI, Windsurf, Devin, OpenCode and Cline through their hook APIs | Claude Code and Codex: live on v0.5.0, not re-run on v0.6.0. The other seven: docs |
| Shell commands | Terraform, OpenTofu and Terragrunt by subcommand; aws, gcloud, az, gsutil, kubectl, helm, gh and HTTP clients by verb; tiers from paths, workspaces, backends, profiles, accounts, contexts, projects and subscriptions | tests (163-scenario replay, 918-scenario attack pack, 162-call agent trial) |
| File edits and reads | Write/Edit/apply_patch to guard and state files; reads of credential files | tests; live in Claude Code and Codex on v0.5.0 |
| Plan gate | Reads `terraform show -json` of a saved plan before apply: 14 rules, AWS resource data | tests; the GitHub Action on real AWS-provider plans in CI |
| Self-protection | Hook settings of every host, applygate's own files, files that make trusted programs run code, PATH plants | tests; a guarantee only under `install --managed` (Claude Code) |
| MCP | 15 infrastructure servers translated to the equivalent command; shell-like tools judged as shell; others logged | docs (table from each server's source) and tests |
| Model judge | Optional second opinion on calls the rules do not recognise; can only make a verdict stricter | live in Claude Code (command backend, Anthropic endpoint); measured offline before the current filter |
| Approvals | A person allows one asked call from a terminal | tests; off by default (no OS presence check) |
| `doctor --creds`, `--boundary` | Whether the credentials here can change production without a person; assurance levels L0 to L3 | tests with stubs only |
| CI | `plan-check` and the GitHub Action | live on real plan JSON in CI |

## Agent hosts

`internal/hook/capabilities.go` is the source; `applygate hosts` prints it and [hosts.md](hosts.md) is generated from it.

| Host | Install | Judged | Can ask | Command's directory | If the hook fails | Status |
|---|---|---|---|---|---|---|
| Claude Code | `hook install`, plugin, `install --managed` | Bash and any tool with a command (Monitor, PowerShell); Write, Edit, MultiEdit, NotebookEdit; Read, Grep, Glob; MCP | yes, in `default` and `bypassPermissions` modes; elsewhere ask is block | yes | blocks (2.1.295+) | live: 2.1.312 Linux 2026-10-28, 2.1.314 macOS 2026-10-30 |
| Codex | `hook install`; managed prints a `requirements.toml` snippet | shell tools, `exec_command`, `unified_exec`, `write_stdin`, `js_repl` (as `node -e`); apply_patch; MCP | no: ask is block | no: judged at the most protected tier under the session root, unless the call carries a `workdir` | allows | live: 0.159.2 and 0.165.0 Linux, 0.166.0 macOS, 2026-10-28 to 30 |
| Cursor | `hook install` | Shell; Write, Delete; Read, Grep | no | yes (`working_directory`) | blocks (`failClosed`) | docs |
| Copilot CLI | `hook install` | bash, powershell; create, edit, apply_patch; view, glob, grep | yes | no | blocks, except on timeout | docs |
| Gemini CLI | `hook install` | run_shell_command; write_file, replace; read_file, read_many_files | no | yes (`dir_path`) | allows | docs |
| Windsurf | `hook install` | command line; file writes; file reads | no | unconfirmed | allows | docs |
| Devin | `hook install` | `exec` only | no | `DEVIN_PROJECT_DIR`, else the hook's own | allows | docs |
| OpenCode | a plugin that runs `applygate hook opencode` | bash; edit, write, patch; read | no | when the call has a `workdir` | blocks while the plugin is loaded | docs |
| Cline | a `PreToolUse` script | commands; editor and write tools; reads and searches | no (a cancel ends the task) | `workspaceRoots[0]` | allows | docs |

`applygate init` installs only Claude Code and Codex, at user scope. Claude Code's pending live tests: the `*` matcher with Monitor and PowerShell, the directory after a `cd`, the prompt in acceptEdits, plan and auto modes, and v0.6.0 as a whole. Codex's: a session started in a subdirectory, the planfile search, the hook timeout.

### Tool calls

| Tool kind | What happens |
|---|---|
| Shell | The shell analyzer and classifier ([below](#shell-commands)) |
| Write, edit, patch | Each path: a guard file is tampering, a state file is state surgery |
| Read | A credential file asks |
| MCP | A known infrastructure tool is judged as its command; a call that names a guard file is judged as a write to it; any other is logged, allowed and sent to the judge if it is on |
| Unknown tool name | Never allowed unseen on its name: a command field makes it shell, an infrastructure word in any argument makes it shell, otherwise it is handled as MCP. Names on a short quiet list (TodoWrite, Task, WebFetch, …) pass through unlogged |

## Shell commands

### Tiers

A command's tier comes from the environments in `.applygate.yaml`: paths, Terraform workspaces, backends, AWS profiles and accounts (also from provider blocks), kube contexts, GCP projects and Azure subscriptions, and the name hints `prod`, `production`, `prd` and `live`. The most protected match wins; an unknown signal is protected; with `strict` (the default) a directory nothing matches is protected. An untrusted repository config is not read, so every directory is protected. Details: [policy.md](policy.md).

### Verdicts

| Class | Protected | Standard | Disposable |
|---|---|---|---|
| read-only | allow | allow | allow |
| apply-saved-plan | plan gate | plan gate | allow |
| unreviewed-apply | block | ask | allow |
| destroy | block | ask | allow |
| state-surgery | block | ask | ask |
| cloud-destructive | block | ask | ask |
| guard-tampering | block | block | block |
| hook-rewrite | ask | ask | ask |
| dynamic | ask | ask | allow |
| unknown-wrapper | ask | allow | allow |
| complex-shape | ask | allow | allow |
| mutating | ask | allow | allow |
| cloud-write | ask | allow | allow |
| credential-access | ask | ask | ask |

A command's verdict is the strictest of its actions. In observe mode every verdict is logged and the call allowed. A complex-shape command that can run code the analysis does not follow is also judged at the most protected tier under the repository root, so it can ask in a standard or disposable directory.

### Programs it understands

| Family | How deeply | Status |
|---|---|---|
| terraform, tofu, terragrunt | Every subcommand: plan, apply with or without a saved plan, `-destroy`, `-replace`, destroy, import, refresh, test, taint, `state`, `workspace`, init and its backend options, stacks; `TF_CLI_ARGS`, `-chdir`, `-var-file`, `-state`. Terragrunt `run --all` and `*-all` take the most protected unit under the directory | tests; live in the v0.5.0 agent trial |
| aws | By service and operation: credential-printing calls, `configure set`, S3 removals and `sync --delete`, removing a safeguard, then verb prefixes (delete/terminate destructive, describe/list/get read, the rest write). An S3 write to a configured state bucket is state surgery | tests |
| kubectl, oc, helm | By verb; target from `--context`/`--cluster`/`--server` or the kubeconfig; `get secret -o yaml` and `config view --raw` are credential access | tests |
| gcloud, gsutil, az | By verb, `az rest --method`, `--mode Complete`, `gsutil rsync -d`; target project or subscription from the flags or local config | tests |
| gh, glab, curl, wget, httpie | API deletes are destructive; `workflow run` and non-GET requests are cloud writes; localhost is ignored | tests |
| Agent CLIs (claude, codex, gemini, copilot, opencode, cursor-agent) | Bypass flags, settings and MCP overrides, plugin and config changes are tampering | tests |
| docker, podman | A terraform, tofu or terragrunt image is unwrapped and judged; otherwise read subcommands only | tests |
| make, npm, just, task | A readable Makefile is analysed; a destructive-looking target name is an unknown wrapper | tests |
| vault, kustomize | Read shapes on the allow-list only; no destructive classification | none |
| pulumi, cdk, flux, argocd | No rules ("Not in v1") | none |

**The allow-list (plain in a protected tier):** file and text tools (`ls`, `cat`, `grep`, `rm`, `cp`, `mv`, `sed`, `tar`, `find`, `jq`, `yq`, `curl` and the like, with their options), and by subcommand and option: `git` (about 60 subcommands, plus a check of the repository's hooks and exec keys), terraform and tofu, kubectl, helm, vault, docker and podman (read subcommands), gh, glab, trivy, kustomize, opa, conftest, infracost, terragrunt, terraform-docs; aws, az and gcloud by read verb. Anything else asks in a protected tier (strict shapes). A conformance test runs every listed option of git, docker, gh, opa, terraform and kubectl; aws, az, gcloud, helm and vault are not in CI's run.

**The analyzer follows** cd, pushd and CDPATH, variables and exports, aliases, functions, eval, source, trap, sudo, env, xargs, timeout and the other wrappers, credential and dev-environment runners, `bash -c` with start-up files, readable scripts, Makefiles, `find -exec`, git aliases and docker. Python, Perl, Node and awk code is scanned, not parsed. Anything it cannot resolve (a program name, a terraform argument, a glob, run-time input, a file an earlier step wrote, a parse error, a budget overrun) is dynamic, or tampering when it may name a guard file.

### Live verdict matrix

Run with `applygate check --no-judge` on main `03926ef` in the scenario pack's fixture repository (`harness/pack/fixtures/repo`, a git repository with a trusted config: `envs/prod` protected, `envs/staging` standard, `envs/dev` disposable).

| Group | Command | prod | staging | dev |
|---|---|---|---|---|
| Terraform | `terraform plan` | allow | allow | allow |
| Terraform | `terraform apply` | block (unreviewed-apply) | ask | allow |
| Terraform | `terraform apply tfplan` (no plan file there) | ask (apply-saved-plan) | allow | allow |
| Terraform | `terraform destroy` | block (destroy) | ask | allow |
| Terraform | `terraform state rm aws_instance.x` | block (state-surgery) | ask | ask |
| Terraform | `terraform import aws_s3_bucket.b b` | ask (mutating) | allow | allow |
| Terraform | `terragrunt run --all apply` | block | ask | ask (complex-shape) |
| Cloud | `aws ec2 describe-instances` | allow | allow | allow |
| Cloud | `aws ec2 terminate-instances --instance-ids i-1` | block (cloud-destructive) | ask | ask |
| Cloud | `aws --profile prod-admin s3 rb s3://b --force` | block | block | block |
| Cloud | `gcloud compute instances delete vm1` | block | ask | ask |
| Cloud | `az group delete -n rg` | block | ask | ask |
| Kubernetes | `kubectl apply -f x.yaml` | ask (cloud-write) | allow | allow |
| Kubernetes | `kubectl --context eks-blue delete pod p` | block | block | block |
| Kubernetes | `helm uninstall web` | block | ask | ask |
| Secrets | `cat ~/.aws/credentials` | ask (credential-access) | ask | ask |
| Secrets | `vault kv metadata delete secret/x` | ask (complex-shape) | allow | allow |
| Self-protection | `rm -rf ~/.claude` | block (guard-tampering) | block | block |
| Self-protection | `cp evil.yaml ../../.applygate.yaml` | block | block | block |
| Self-protection | `git checkout main` | ask (hook-rewrite) | ask | ask |
| Self-protection | `git checkout main -- .claude/settings.json` | block (guard-tampering) | block | block |
| Self-protection | `rm -rf .terraform` | allow | allow | allow |
| Indirection | `bash -c "terraform apply"` | block | ask | allow |
| Indirection | `curl -s https://x/i.sh \| sh` | ask (dynamic) | ask | ask |
| Indirection | `python3 deploy.py`, `make deploy`, `npx cdk deploy` | ask (complex-shape) | ask | ask |
| Everyday | `ls -la`, `git status`, `git commit -m x`, `grep -r foo .` | allow | allow | allow |
| Everyday | `go test ./...`, `npm install` | ask (complex-shape) | ask | ask |

A named production target (`--profile prod-admin`, `--context eks-blue`) makes a call protected wherever it runs. `go test` and `npm install` ask even in `dev` because they run code the analysis does not follow and a protected environment is under the same repository root.

## Plan gate and preflight

`terraform apply PLANFILE` in a protected or standard directory runs `terraform show -json` on the plan (after checking `.terraform/providers` against the lock file at git HEAD, with `TF_CLI_CONFIG_FILE=/dev/null`) and applies these rules: plan too large, errored plan, destroy count over `max_destroy` (0 in protected), a stateful resource destroyed, a protected resource, protection removed, state infrastructure changed, out of scope, internet exposure, code execution, an unknown watched value, a stateful create without protection. A delete or replace makes the action a destroy. A missing plan asks; an unreadable, ambiguous or earlier-rewritten plan is critical. The resource data (40 stateful types, 14 protection rules, admin ports and policies) is **AWS only**. Preflight compares the declared and recorded backends, finds local state beside a remote backend, and (for applies and destroys) compares the lock file and `*.tf` with HEAD; live state lineage and STS identity checks are opt-in. Status: tests; the Action runs it on two real AWS-provider plans in CI.

## Self-protection and install modes

**Guard files:** the hook settings of all nine hosts and managed settings; applygate's config, log, approvals, judge cache and binary; the Claude Code plugin, skills, subagents and commands; every host's MCP server list; config files that make a trusted program run code (`.gitconfig`, `.aws/config`, `.kube/config`, gh, docker, `.terraformrc`, ssh config, …); `.terraform/providers` and `modules`; `.git/config` and hooks; shell start-up files and the agent's shell snapshot; the agent CLIs; Homebrew's Cellar and Python start-up files; and trusted program names planted in a writable `PATH` directory. A pattern such as `**/.claude/settings.json` stands for that file under home, the repository config's directory, the nearest git root and the session directory (`CLAUDE_PROJECT_DIR`, `GEMINI_PROJECT_DIR`, `DEVIN_PROJECT_DIR`).

**What counts as tampering:** naming a guard file in any program that is not known to only read it; writing, moving, copying or extracting into a directory that holds one; removing a directory when a guard file whose loss weakens the guard exists under it; redirects, patches, `applygate trust`/`approve`/`hook install`, reinstalling applygate or an agent CLI. At a repository or session root, `git checkout`, `pull` and the other work-tree rewrites ask instead (`hook-rewrite`); a guard file git names is tampering.

| Install | What it gives | Status |
|---|---|---|
| Unmanaged (`hook install`, `init`, plugin) | Best-effort self-protection: the hook blocks the routes it knows, and an agent with your shell can in the end change anything you can. Observe mode turns it off | tests |
| `sudo applygate install --managed` | A root-owned binary, system config and trust store, and Claude Code managed settings (matcher `*`, block on failure, bypass mode disabled; `--exclusive` allows managed hooks only). The user config can then only tighten. The only setup documented as a guarantee. Not covered: the log and approvals directory, passwordless sudo, hosts other than Claude Code and Codex, credentials | docs (managed keys from the Claude Code docs; Codex snippet printed, not written) |

The plugin launcher pins the first binary it finds (by path and SHA-256), refuses one that changed, and downloads a signed release (v0.5.0) only over HTTPS with a checked hash.

## MCP

A call to a known infrastructure tool is judged as its equivalent command, with the strictest reading when several servers fit; a server that runs commands in its own directory is judged at the most protected tier under the session root. Known servers: awslabs `aws-api`, `terraform`, `cfn`/`ccapi`, `eks`, `ecs`, `serverless`; HashiCorp's Terraform server and two TFC servers; tfmcp; two Kubernetes servers; AKS; GKE; gcloud; and seven shell servers. Any other tool whose name or arguments look like a shell command is judged as one. Everything else is logged and allowed. Not covered: Pulumi, the Lambda tool server, SQL tools, workspace and kube-context retargeting. Status: docs (written from each server's source at a pinned commit, not run against the servers) and tests (15 replay and 31 attack scenarios).

## Model judge and approvals

**Judge:** off by default, turned on only in the user config, with an OpenAI-compatible endpoint or any command. It sees the calls the rules let through without recognising them (non-local programs, writes, unknown MCP tools) and can only raise a verdict: an error or timeout leaves the rule's verdict, except under a managed install, where it asks. Calls too large or too redacted to judge ask outside disposable tiers. Status: live in headless Claude Code 2.1.314 (2026-11-01 and 02); its accuracy was measured offline (143 calls; the best model caught 71 of 72 with no false escalation) before the current filter and not since; Codex, the interactive prompt and approving a judge's block: tests only.

**Approvals:** off by default and in managed installs, because there is no OS presence check (Touch ID, polkit) yet. When on, an asked call that was blocked is recorded; a person runs `applygate approve ID` at a terminal and types the environment name, and the agent's next identical call (same session, command, content, targets and plan hash) runs once within 15 minutes. A rule's block can never be approved. Status: tests.

## Credentials and assurance levels

| Command | Checks | Status |
|---|---|---|
| `doctor --creds` | AWS: the policy simulator with MFA absent on 19 destructive actions (3 on the state bucket). Kubernetes: `auth can-i` for 4 verbs. Google Cloud: `testIamPermissions` for 17 permissions per project. Azure: role assignments, inherited and group ones included. A production credential with a destructive path fails | tests with stubs only |
| `doctor --boundary` | L0 hook; L1 managed install checks pass; L2 a credential audited with no destructive path and none unverified; L3 a root-owned Claude Code sandbox plus attested CI apply and state guards. `--require L` exits 1 below it | tests with stubs only |

## CI

`applygate plan-check` judges a `terraform show -json` plan in CI (without `--trust-config` every directory is protected). The GitHub Action installs a cosign-verified release (default v0.5.0) and fails on block by default; `trust-config` is off by default, since on a fork's pull request the config is the contributor's. Status: live, on two real AWS-provider plans in `action-check.yml`. The Terragrunt `before_hook` recipe is docs only.

## Logs and other commands

The decision log is JSONL at `~/.local/state/applygate/decisions.jsonl` (mode 0600, rotated at 64 MiB, fields capped at 64 KiB), with regex redaction of keys, tokens and passwords; under a managed install it is still in the user's reach. Telemetry is off and has no default endpoint. `report` summarises the log; `suggest` proposes a config from an observe-mode log; `explain` prints the parse and decision trace; `selftest` runs the 163-scenario pack; `trust` and `approve` need a terminal.

## Test and measurement assets

| Asset | Size | Runs in CI |
|---|---|---|
| Scenario pack (`harness/pack`) | 163: 108 dangerous, 55 benign; replayed in 9 host formats, never executed | yes, exact match required (claude and codex) |
| Attack pack (`harness/pack_attack`) | 918: 771 dangerous, 147 benign controls, from every review round | yes |
| Effects oracle | allowed commands run under bash, zsh, dash and sh against fake tools: 52 hand-written and 400 generated | yes, required |
| Agent trial | 162 shell calls from Claude Code and Codex on 5 public repositories, 2026-10-29 (v0.1.3, observe mode) | replayed by hand for each change |
| OSS corpus | 1,334 commands from public repositories, static replay on v0.1.2 | no |
| Latency | command decision p95 ≤ 50 ms | yes (normal build) |
| Fuzzing | the shell analyzer, 30 s | yes |

## Gaps this inventory found

Capability:

- `vault kv metadata delete` (and other vault writes) are not classified: they ask in a protected tier only because they are not on the allow-list, and are allowed in standard and disposable tiers.
- pulumi, cdk, flux and argocd have no rules; `npx cdk deploy` asks only through strict shapes.
- The plan gate's resource data is AWS only: a Google or Azure plan gets the generic rules (destroy count, replaces) but no stateful-type or exposure rules.
- Seven of nine hosts, the managed install, every MCP translation, `doctor --creds` and `--boundary` have not been run against the real program.
- Claude Code and Codex were last tested live on v0.5.0.
- [hosts.md](hosts.md) says MCP is "not inspected" for Copilot CLI, OpenCode and Cline. The code would treat an `mcp__` tool name from them as MCP; whether they send one is not known.

Docs that disagreed with the code, corrected with this page: terraform's shape in [policy.md](policy.md) (a subcommand and option tree, not "any arguments"), the `plan-too-large` finding and the name-hint separators in [policy.md](policy.md), the lock-file check in [config.md](config.md) (`git cat-file`, not `git diff`), readable credential files at L2 in [boundary.md](boundary.md) (each is `not verified`, so L2 is not reached while one exists), and the attack-pack counts in `harness/README.md`.
