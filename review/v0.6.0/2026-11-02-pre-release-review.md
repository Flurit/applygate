# Pre-release code and architecture review (v0.6.0 candidate, 2026-11-02)

**Verdict: do not release.**
- An agent can get `terraform destroy -auto-approve` past applygate in a protected tier in more than thirty distinct ways.
- It can switch applygate off, or approve its own blocked call, in about a dozen more.
- Most of these are not new in this release. They predate it, and the review was the first time anyone attacked the code this way.

## Method

- **What was reviewed:** main at fc503b3.
- **Who reviewed it:** six independent reviewers, each covering one area:
  - the shell analyzer and classifier;
  - the decision flow and host adapters;
  - config, preflight and the plan gate;
  - security surfaces and the supply chain;
  - the model judge and MCP mapping;
  - docs against code.
- **How:** each reviewer read its area and built its own binary. It then tried real attacks with `applygate check` and with hook JSON on stdin. That was done in scratch directories with a scratch `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME`. No real infrastructure was touched and no model API was called. One plan-gate finding was confirmed with real Terraform 1.14.6 against a local `terraform_data` resource.
- **What was changed:** nothing in the repository and nothing in the developer's home directory (checked afterwards).
- **Verification:** the coordinator rebuilt the binary and reproduced a sample independently. These are marked **verified**:
  - all three critical self-protection findings;
  - the Monitor-tool bypass;
  - the config-planting routes;
  - 13 shell-analyzer bypasses;
  - the git wrapper bypasses.

  The rest were reproduced by the reviewer who found them, except where marked *from reading*.
- **Severity:**
  - **critical:** a destructive call is allowed in a protected tier, or the agent can disable applygate or approve its own call.
  - **high:** the same, but needing an unusual setup, or a wrong tier or verdict with real damage potential.
  - **medium:** wrong behaviour with limited impact, or a missing safeguard.
  - **low:** cosmetic, or hardening.

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| After merging duplicates (80 findings) | 20 | 21 | 28 | 11 |

`go test ./...` passes throughout. That is part of the finding: the test suite and the scenario pack check the paths the code was designed for, not the paths an attacker takes. `internal/classify` has no unit tests at all.

## Root causes

Most findings come from five structural decisions. Fixing these is worth more than patching findings one by one.

1. **Unknown means allowed.**
   - **Tool names:** the hook judges a fixed list of tool names. Claude Code's `Monitor` and `PowerShell` tools run shell commands and are never seen. The same is true of `apply_patch` run from the shell, unreadable shell inputs, and text typed into a running process (`tmux send-keys`, Codex `write_stdin`).
   - **Program names:** the classifier recognizes a fixed set of names. Anything that runs a command through its own options (`git -c alias.x=!…`, `ssh -o ProxyCommand`, `awk system()`, `make -p`) is allowed.
   - **The fix:** reverse the default. An unknown tool with a `command` field is a shell call. A construct the analyzer cannot model is unresolved and judged at the most protected tier.
2. **Self-protection matches names and text, not identity.**
   - **What it matches:** guard paths are compared as case-sensitive strings against the literal arguments. But macOS ignores case, and the tampering commands are blocked only when the program is literally named `applygate`.
   - **What gets through:** `.APPLYGATE.YAML`, `~/.Claude/settings.json`, symlinks, parent renames, `git mv`, `git checkout -- <file>`, `tar -x`, `curl -o`, Python writes, a renamed binary, and the `seatbelt` shim.
   - **The fix:** canonicalize paths (case and symlinks) before matching, and guard ancestors as well as files. Classify by what a program does to a guard path, not by its name.
3. **A terminal is treated as proof that a person is present.**
   - **The checks:** `applygate approve`, `applygate apply`'s confirmation and `--yes` trust any terminal. The confirmation word is the environment name, which the block message has already shown the agent.
   - **The bypass:** an agent opens a pseudo-terminal with `python3 -c 'import pty…'` or `script` and approves its own call.
   - **The fix:** approval must need something the agent cannot see or produce. For example, a random code shown only on the person's own terminal, an HMAC key kept outside the agent's reach, or a refusal when an agent process is an ancestor.
4. **The config trust model is loose.**
   - **Which config applies:** only the nearest `.applygate.yaml` is loaded, with no merge from the repository root. It is chosen from where the agent stands, not where the command runs.
   - **What it can change:** a repository config may set `mode: observe`, `on_error: allow`, `strict: false`, tiers and aliases that rebind `terraform` or `rm`. Only a few fields are tighten-only, and those rules are spread across `merge`.
   - **Why that is dangerous:** an agent that can plant one file can turn protection off (see root cause 2). So can a cloned third-party repository nested in the tree.
   - **The fix:** merge configs from the root down so that children can only tighten, resolve the config per action directory, and decide which config layer may loosen what in one place.
5. **What is on disk is trusted as what will run.**
   - The analyzer reads scripts, Makefiles and planfiles as they are before the command runs. The plan gate judges a planfile that an earlier step of the same command overwrites.
   - `terraform show` starts provider binaries from `.terraform/providers`, which the agent can write, outside the agent's sandbox.
   - **The fix:** track what the command itself writes and treat it as unresolved. Never run agent-writable code from the hook.

## Findings

Each row names the finding, its location, and how it was confirmed. Fixes are summarized per group.

### A. Self-protection: disabling applygate or approving its own call

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| A1 | critical | `applygate apply --plan-json tfplan=<fake.json> --yes tfplan` is allowed by the hook in prod. The test-only `--plan-json` replaces the plan the gate judges, then the real planfile is applied. Plain `applygate apply tfplan` is also allowed; its confirmation can be typed through a pty. | `cmd/applygate/apply.go:68-71,95-106,160`; `internal/classify/classify.go:182-199` | verified (classification); reviewer ran it with a fake engine |
| A2 | critical | Interpreter code naming applygate's own files is allowed: `python3 -c "open('…/approvals.json','w')…"`. The reviewer used it to mark its own request approved, and to set the user config to `mode: observe`. | `internal/classify/classify.go:89-96` (`isGuardMention`) | verified |
| A3 | critical | Guard paths are case-sensitive, but APFS is not. Writing `.APPLYGATE.YAML` is allowed, and that file is then loaded as the repository config (`mode: observe` disables protection). The same goes for `~/.Claude/settings.json`. | `internal/classify/classify.go:334,376`; `internal/config/config.go:338` | verified |
| A4 | critical | An agent can approve its own call through a pseudo-terminal. The confirmation word is the environment name, which the block message shows. Reproduced on Codex in prod: blocked `eval`, then a pty-wrapped `approve`, then the retry was allowed. | `cmd/applygate/approve.go:66-72`; `internal/approval/approval.go:111` | reproduced |
| A5 | critical | The `seatbelt` shim that `install.sh` installs, or any renamed copy of the binary, can run `hook remove`, `approve`, `init` and `telemetry on` unblocked. | `internal/classify/classify.go:182`; `install.sh:206` | reproduced (two reviewers) |
| A6 | critical | Writes that plant or replace a repository config are allowed: `git mv x .applygate.yaml`, `git checkout ref -- .applygate.yaml`, `git restore`, `curl -o`, `tar -x`, `unzip`, `rsync -a dir/ ./`, `git apply`. | `internal/classify/classify.go:281-343` | verified |
| A7 | high | `applygate hook install --agent claude` is not tampering. It can repoint the hook entry at a binary the agent then replaces with `true`. | `internal/classify/classify.go:184-188`; `cmd/applygate/hostinstall.go:325,363` | reproduced |
| A8 | high | The hook binary itself (for example `~/.local/bin/applygate`) and the PATH directories the plugin launcher searches first are not guard paths. Overwriting the binary with `true` makes every call allowed, and `onFailure: block` does not help. | `internal/config/config.go:251,572`; `plugin/claude-code/scripts/applygate-hook:48` | reproduced (two reviewers) |
| A9 | high | Guard matching is lexical. These are all allowed: renaming or removing a parent (`mv ~/.claude ~/.claude.bak`, `rm -rf ~/.claude`, `mv ../.. /tmp/x`), symlink routes, directory targets (`cp f ~/.claude/`, `cp -t`), extraction (`tar -C ~/.claude`, `unzip -d`), and writers missing from the list (`curl -o`, `wget -O`, `ditto`, `patch`, `cpio`, `find -delete`, `xargs rm`, `vim`, `sponge`). | `internal/classify/classify.go:281-343` | reproduced (two reviewers) |
| A10 | high | With `XDG_CONFIG_HOME` or `XDG_STATE_HOME` set (common on Linux), the user config, `telemetry.json` and the decision log are not guarded, even against `echo >` and `rm`. | `internal/config/config.go:572-579` | verified in code; reproduced (three reviewers) |
| A11 | high | The agent CLIs can turn the hook off themselves: `claude plugin disable applygate`, `claude config set disableAllHooks true`, `claude -p … --settings`. | `internal/classify/engines.go:503-518` | classification reproduced; effect from reading |
| A12 | high | An approval does not cover what a write puts in the file, or the full MCP arguments. After a person approves an `Edit` of `ci/deploy.yml` to `replicas: 5`, the agent's next edit to `replicas: 0` is allowed. | `internal/approval/approval.go:59-78` | verified in code; reproduced by a test |
| A13 | high | The judge cache can be pre-filled with `allow` entries, for example by extracting a tarball after `cd $XDG_STATE_HOME`. The key is public and uses only the backend's base name, so the judge is skipped for chosen calls. `applygate check` with another `XDG_CONFIG_HOME` writes into the real cache. | `internal/judge/cache.go:41-50`; `internal/hook/judge.go:49-57` | reproduced |
| A14 | medium | A blocking `flock` on the approvals lock, outside the deadline, can hang the hook past the host's 30 s timeout. Gemini, Copilot and Devin then let the call run (from their docs). | `internal/approval/approval.go:249`; `internal/hook/run.go:346` | reproduced (34 s) |
| A15 | medium | The approval prompt prints commands raw, so terminal escape codes can make `call:` read `terraform plan`. Redaction can also hide most of a command (`X_TOKEN=1;terraform${IFS}destroy` is shown as `X_TOKEN=[REDACTED]`). `Approve` matches on an 8-hex ID. | `cmd/applygate/approve.go:45,63`; `internal/approval/approval.go:155-162` | reproduced |

**Fix direction:**
- Canonicalize paths (case-fold on darwin and Windows, `EvalSymlinks` on the longest existing prefix), and guard ancestors as well as files.
- Classify by effect on a guard path for every writer, mover and extractor, and for interpreter bodies, whether or not they mention a tool.
- Treat any `applygate`, `seatbelt` or same-inode binary running `approve`, `apply`, `hook *`, `init` or `telemetry` as tampering.
- Make approval need a secret the agent cannot read, and bind it to content and full arguments.
- Remove `--plan-json` and `--yes` from release builds.
- Guard the resolved user config, log, telemetry file, launcher cache and `os.Executable()`.
- Cache only escalations in the judge cache.

### B. Tools the hook never judges

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| B1 | critical | Claude Code's `Monitor` (and `PowerShell`) tool runs shell commands, but is not in the installed matcher or in `shellTools`. `terraform destroy -auto-approve` through it gets exit 0 and no log entry. | `cmd/applygate/main.go:725`; `internal/hook/hosts.go:166` | verified |
| B2 | medium | Codex `apply_patch` run through the shell tool skips the guard-file check that the `apply_patch` tool gets. | `internal/hook/adapters.go:253` | reproduced |
| B3 | medium | Claude and Codex shell calls whose command cannot be read (`command: null`, a missing `tool_input`, argv form) are allowed; the other hosts treat this as an error. | `internal/hook/adapters.go:137,253` | reproduced |
| B4 | medium | MCP input with a non-string `command`, `path` or `file_path` fails Claude's typed decode. Unknown MCP tools then block, which contradicts `docs/mcp.md`, and the argv `shell_execute` entry is never judged. | `internal/hook/adapters.go:124-133` | reproduced |
| B5 | medium | Interactive sessions get around the per-command check: `tmux send-keys '…destroy…' Enter`, `screen -X stuff`, and Codex `write_stdin`. Whether Codex fires the hook for `write_stdin` is not verified. | adapters | reproduced (classification) |

**Fix:**
- Judge any tool with a string `command` or `cmd` as a shell call, and treat an unreadable shell call as an error.
- Install `*` as the Claude matcher, or add `Monitor` and `PowerShell`, and have `doctor` check the matcher.

### C. Shell analyzer bypasses (destroy allowed in a protected tier)

All rows below were reproduced by the reviewer. The ones marked ✓ were also verified by the coordinator.

| # | Sev | Construct | Example allowed in `envs/prod` | Where |
|---|---|---|---|---|
| C1 | critical ✓ | program names are case-sensitive, macOS is not | `TERRAFORM destroy -auto-approve` | `classify.go:142`; `call.go:48`; `wrappers.go:212` |
| C2 | critical | word resolution differs from the shell (zsh is the macOS default) | `$(printf -- terraform) destroy …`, `$(echo -e "\0164erraform") …`, `=terraform …`, `/usr/local/bin/terr[a]form …`, `$'terraform' …` | `analyze.go:594-606,798-845`; `stdout.go:107-131` |
| C3 | critical ✓ | working directory and variable state | `cd ../dev & terraform destroy …`; from dev `f() { cd ../prod; }; f; terraform destroy …`; `pushd/popd` | `call.go:60-84`; `analyze.go:264-312` |
| C4 | critical ✓ | constructs never walked | `case $(…) in`, `export "$(…)"`, `for ((i=$(…);…))`, `trap "…" EXIT` | `analyze.go:325-361` |
| C5 | critical ✓ | assigning builtins leave a stale value | `x=echo; read x <<< terraform; $x destroy …`; `printf -v`, `mapfile`, `declare -n` | `call.go`, `analyze.go:356` |
| C6 | critical ✓ | `xargs -I` and `parallel` placeholders | `echo terraform destroy … \| xargs -I{} sh -c '{}'`; `… \| parallel` | `call.go:206-213,501-534` |
| C7 | critical ✓ | interpreter options and missing interpreters | `python3 -Ic '…'`, `node --eval`, `perl -we`, `python3 -u script.py`, `awk 'BEGIN{system(…)}'`, `lua -e`, `tclsh` | `call.go:12-16,445-469`; `wrappers.go:25` |
| C8 | critical ✓ | programs that run commands through their own options | `git rebase -x '…'`, `git bisect run …`, `git -c alias.x='!…' x`, `ssh -o ProxyCommand=…`, `flock … -c`, `su -c`, `fish -c`, `conda run`, `nix run`, `env -S"…"` | `wrappers.go:32,43`; `call.go:186-261,331` |
| C9 | critical ✓ | Terragrunt working directory; unresolved `-chdir` | from dev: `terragrunt --working-dir ../prod destroy …`; `terraform -chdir=$(ls -d ../pro*) destroy …` is judged at dev | `engines.go:92-137` |
| C10 | critical | make flags | `make -p destroy`; from dev `make --directory=../prod destroy`; `make -n` with `+` recipe lines; `make --file=evil.mk`, `MAKEFILES=` | `make.go:27-67` |
| C11 | critical | files written earlier in the same command are read as they were before | `printf '…destroy…' > run.sh; bash run.sh`; `source`; `$(cat name)`; `ln -s ../prod p && cd p && …` (contradicts `limits.md:13`) | `analyze.go:284`; `call.go:128,406,425`; `stdout.go:169` |
| C12 | high | a parse failure or exhausted budget is judged at the current directory, so it is allowed from a disposable one | from dev: `$'cd ../prod && terraform destroy -auto-approve\n)'`; 2,100 `:;` then the destroy | `analyze.go:248-273`; `classify.go:76` |
| C13 | high | aliases are split on whitespace; self-referential aliases are dropped | `shopt -s expand_aliases` / `alias x='cd . && terraform destroy …'` / `x` | `call.go:53-58` |
| C14 | high ✓ | cloud CLI verbs and flags | `TF_CLI_ARGS_init='-migrate-state -force-copy' terraform init`; `gcloud storage rm -r gs://prod --verbosity info`; `az storage blob delete-batch`; `kubectl --cluster prod delete ns x` (ask in prod, allow in staging); `gsutil -m rm -r` | `engines.go:362-466` |
| C15 | low | force-push with clustered short flags (`git push -uf origin main`) passes the judge's filter. Plain `git push -f` is not classified by the rules at all, as documented. | `internal/judge/filter.go` | verified |

**Fix direction:**
- Fold case on program names.
- Mark any word the analyzer cannot reproduce exactly (globs, `=cmd`, unknown escapes) as unresolved.
- Run `&` on a clone and function bodies on the caller's state, and walk every node type, with a backstop that walks substitutions in any unhandled node.
- Treat `trap ARG` as `eval`, and the variable written by `read`, `printf -v` or `mapfile` as unresolved.
- Model the exec-style options of git, ssh, flock, su, conda, nix and env.
- Judge parse and budget failures at the most protected tier.
- Track paths written earlier in the command.
- Add unit tests for `internal/classify`.

### D. Configuration trust and tier resolution

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| D1 | critical | The nearest `.applygate.yaml` replaces the repository's own config, with no merge. A cloned repository nested in the tree, or a planted file (A3, A6), sets `mode: observe`, and `terraform -chdir=../../envs/prod destroy` is then allowed. | `internal/config/config.go:338-366`; `internal/hook/run.go:300` | reproduced (two reviewers) |
| D2 | high | A repository config may loosen almost everything: `mode`, `on_error`, `strict`, `default_tier`, `name_hints`, `max_destroy`, `run_show`, preflight, and `aliases` (`{terraform: ls}`, `{rm: ls}`, `{bash: ls}`). YAML merge keys apply. By design today, but it means one planted file disables protection. | `internal/config/config.go:396-476` | reproduced |
| D3 | high | The config is chosen from the event's working directory, not the action's. `terraform -chdir=<other repo>/envs/prod destroy` is judged under the current repository's config, and `**` globs are not anchored to the config's directory. | `internal/hook/run.go:300`; `internal/policy/policy.go:384`; `internal/config/config.go:445` | reproduced (two reviewers) |
| D4 | high | Symlinked and case-variant directories escape path matchers: `ln -s ../payments envs/dev/pay`, then `cd envs/dev/pay && terraform destroy` is allowed; `cd envs/Billing` too. | `internal/config/config.go:668` | reproduced |
| D5 | high | `TF_DATA_DIR` is ignored for the backend, stale state and backend-change checks, though it is honoured for the workspace. A prod backend in `.tfprod` is reported as "local". | `internal/preflight/preflight.go:97`; `internal/policy/policy.go:319` | reproduced |
| D6 | high | The documented backend pattern `s3://bucket/*` misses keys containing `/` (`payments/terraform.tfstate`). The fixture's prod backends match only through the name hint. | `internal/config/config.go:745` | reproduced |
| D7 | high | `applygate suggest` writes values from the decision log into its YAML proposal unescaped. A profile name containing newlines injected `name_hints: false` and `aliases: {terraform: ls}`, and the proposal passed its own `Check()`. | `internal/suggest/suggest.go:548,562,645` | reproduced end to end |
| D8 | medium | `kubectl`/`helm --kubeconfig` and `gcloud --configuration` are ignored when resolving the target, so the tier comes from the environment variables. | `internal/preflight/targets.go:21,48` | reproduced |

**Fix:**
- Merge configs from the repository root down so that children can only tighten, and give one function the say over which layer may change which field.
- Resolve the config and tier per action directory, after `EvalSymlinks` and case canonicalization; the stricter result wins.
- Limit `aliases` to the user config, or forbid aliases of known programs.
- Honour `TF_DATA_DIR`.
- Let `*` cross `/` in backend patterns.
- Escape logged values in `suggest`.

### E. Plan gate

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| E1 | critical | The plan is judged as it is on disk before the command runs. `terraform plan -destroy -out=tfplan && terraform apply tfplan` was allowed and destroyed the resource with real Terraform 1.14.6; `cp other.tfplan tfplan && …` too. `echo prod > .terraform/environment && terraform destroy` asks in QA rather than blocking. | `internal/policy/policy.go:502`; `internal/hook/run.go:85` | reproduced end to end |
| E2 | high | The plan gate runs `terraform show` and `state pull`. These start provider binaries from `.terraform/providers`, which the agent can write, outside the agent's sandbox. With Terragrunt, `show` evaluates `run_cmd()` and hooks. | `internal/hook/run.go:85-100` | from reading |
| E3 | medium | Replacing a resource is judged more leniently than deleting it: replace gives ask in protected and allow in standard; delete gives block and ask. | `internal/policy/policy.go:532` | reproduced |
| E4 | medium | `protected_resources` entries miss `count` and `for_each` instances (`aws_instance.bastion[0]`, `module.data["eu"]`). | `internal/plangate/plangate.go:608` | reproduced |
| E5 | medium | Values unknown at plan time hide exposure and protection removal (`cidr_blocks`, `deletion_protection`, `skip_final_snapshot`). | `internal/plangate/plangate.go:153,186` | reproduced |

**Fix:**
- Make a planfile, `.terraform` directory or `TF_DATA_DIR` written earlier in the same command a critical "plan unverifiable" finding.
- Never run Terragrunt's `show`, and verify providers against a lock file git reports unchanged.
- Treat replace like delete.
- Strip instance keys before matching `protected_resources`.
- Treat unknown watched values as findings.

### F. Model judge and MCP mapping

The escalate-only rule held: no path was found where the judge lowers a verdict or makes a rule's block approvable. The gaps are calls that never reach the model, and ways to make it error.

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| F1 | high | The filter's "local" programs can run arbitrary commands, so destructive payloads skip the judge. Examples: `git rebase -x`, `git bisect run`, `git config core.fsmonitor`, `tar --checkpoint-action=exec`, `sort --compress-program`, `rg --pre`, `go test -exec`, `go build -toolexec`, `mvn exec:exec`, `dotnet run`, `npm init <pkg>`. | `internal/judge/filter.go:76-190` | reproduced |
| F2 | high | Files written through the shell skip the judge, unlike Write and Edit, and the safe test runners then run them: `printf '…exec pulumi destroy…' > zz_test.go && go test ./...`; `sed -i` on `package.json` then `npm test`. | `internal/judge/filter.go:16-21,154-163` | reproduced |
| F3 | high | `outside()` ignores `cd`. `cd ../.. && rm -rf envs` and `cd /var && rm -rf /var/lib/postgresql` count as local. | `internal/judge/filter.go:121-133` | reproduced |
| F4 | medium | The call itself can make the judge error, and an error means no escalation: a 300 KB comment (HTTP 400), a refusal-triggering comment, or braces before the JSON answer. Commands and MCP args have no size cap. | `internal/hook/judge.go:91-104`; `internal/judge/openai.go:91-106` | reproduced (local fake) |
| F5 | medium | HCP Terraform's `create_run` with `is_destroy: 1`, `"yes"`, or `params` as a JSON string is judged as `terraform plan`. | `internal/mcpmap/rules.json`; `mcpmap.go:203-218` | reproduced |
| F6 | medium | The EKS and GKE translations drop the cluster the call names, so the tier comes from the local kube context. Flux159 `kubectl_generic` ignores `flags.context`. | `rules.json` | reproduced |
| F7 | medium | Infrastructure credential reads skip the judge: `.vault-token`, `terraform.tfstate`, `*.tfvars`, `.my.cnf`, `.s3cfg`, doctl config. | `internal/judge/filter.go:62-66` | reproduced |
| F8 | medium | The judge sees no content for Copilot `edit`, OpenCode `edit` or Cline `replace_in_file`. | `internal/judge/judge.go:178-209` | reproduced |
| F9 | low | `call_aws` with a JSON-array string is not parsed as `aws` and is allowed. | `mcpmap.go:155-161` | reproduced |
| F10 | low | `examples/judge/claude-cli.sh` runs `claude -p` in the agent's repository, so the repository's `CLAUDE.md` and hooks load into the judge. | `examples/judge/claude-cli.sh:16-19` | from reading |
| F11 | low | Shell-server mapping gaps: `interact_with_process` input to a non-shell, and bare `&&` tokens in argv. | `rules.json` | reproduced |
| F12 | low | Deadline margin: a hanging judge made the hook take 29.0 s. Telemetry can add 3 s after the verdict, which overruns 30 s. The docs say "the judge's limit is 25 seconds" and "never reached". | `internal/hook/run.go:338-343`; `backends.go:70` | measured |

### G. Secrets and data

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| G1 | medium | Redaction misses common forms, which reach the log and the judge's endpoint. Examples: `--token X`, `--password X`, `mysql -pPASS`, `curl -u user:pass`, `postgres://user:pass@`, `aws configure set aws_secret_access_key X`, `-var db_pass=…`, `github_pat_`, `sk_live_`, `glpat-`. A GCP service-account `private_key` loses its redaction because the generic pattern eats `-----BEGIN`. `Via` is never redacted. | `internal/decisionlog/log.go:53-76` | reproduced (two reviewers) |
| G2 | low | Telemetry forwards raw `version`, `agent` and `mode` strings from the log. Combined with A2, A3 or A10, an agent can put arbitrary text in reports. | `internal/telemetry/telemetry.go:255` | from reading |

### H. Failure handling

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| H1 | medium | A panic in the policy goes through `fail()`, which resolves the tier from the working directory only. From a disposable directory a panic is allowed, unlike a timeout, which blocks in every tier. | `internal/hook/run.go:190-200,330` | from reading |
| H2 | medium | Observe and error handling are decided in four places (`fail`, the timeout path, panic recovery, `Settle`). Approvals, the judge, the log and telemetry run outside the internal deadline. | `internal/hook/run.go` | from reading |

### I. Hosts, CI and the supply chain

| # | Sev | Finding | Where | Evidence |
|---|---|---|---|---|
| I1 | medium | Two adapters assume untested host behaviour in the loose direction. Cursor gets `{"permission":"allow"}` for every allowed or unchecked call, which might skip Cursor's own prompt. Claude Code is told it can ask in every mode but `dontAsk`, including the untested `auto`, `acceptEdits` and `plan`. | `internal/hook/hosts.go:354`; `adapters.go:79,124` | from reading |
| I2 | medium | `scripts/ci-plan-check.sh` writes step outputs with a fixed heredoc delimiter. A resource address containing it injected `verdict=allow`. `action.yml:70` interpolates `inputs.binary` into `run:`. | `scripts/ci-plan-check.sh:52`; `action.yml:70` | reproduced |
| I3 | low | `release.yml` grants `contents: write` and `id-token: write` to the whole job, including `go test` and a checkout with persisted credentials. | `.github/workflows/release.yml:14-17` | from reading |
| I4 | low | `install.sh` defaults to installing unsigned when cosign is missing, Homebrew checks sha256 only, and `install.sh` still installs the `seatbelt` shim (A5). | `install.sh:102,206` | from reading |
| I5 | low | `hook install` rewrites other tools' settings files through a `map[string]any` round trip, non-atomically. `isApplygateEntry` claims any command containing "applygate" and " hook ". | `cmd/applygate/hostinstall.go:358`; `main.go:618` | from reading |
| I6 | low | Each destroy action costs about 37 ms in preflight (a git lock check per action), so around 700 destroys in one command hit the 25 s deadline (this fails closed). | `internal/preflight` | measured |

### J. Docs and tests

| # | Sev | Finding | Where |
|---|---|---|---|
| J1 | high | The README says a destroy "can't hide behind a wrapper". Unknown wrappers are allowed, which `limits.md:14` documents. | `README.md:32` |
| J2 | medium | `threat-model.md` and `README.md` claim protections the code does not deliver: guarded user config and log, "hides … behind variables, eval, bash -c, here-documents, base64, Makefiles or scripts". After this review, these need to be either fixed or restated. | `docs/threat-model.md:9-22`; `README.md:58` |
| J3 | medium | README's MCP claim lacks "from each server's source, not tested against the running servers". | `README.md:79` |
| J4 | medium | The network and privacy statements leave out the judge. | `docs/limits.md:43`; `site/index.html:313`; `README.md:139-141` |
| J5 | medium | Scenario counts are stale (README "141", harness README "90 dangerous and 47 benign"; selftest has 108/55). The harness README says the original v0 pack "was not available", but it is in the repository. | `README.md:44`; `harness/README.md:3,11` |
| J6 | medium | `SECURITY.md` and `ACCEPTANCE.md` still describe MCP calls as never judged. | `SECURITY.md:30`; `docs/project/ACCEPTANCE.md:156` |
| J7 | medium | The judge's accuracy is overstated as "missed up to three calls of each set" (gpt-6-luna missed 7). The `claude` CLI row was not measured on the fifth set, though the heading implies every option was. | `docs/judge.md:44,282` |
| J8 | medium | Missing tests: a repository config cannot redirect the judge; `approvals.json` and `judge-cache.json` are guard paths; guards with XDG variables set. `internal/classify` has no unit tests. | tests |
| J9 | medium | CI does not run the Codex-format scenario replay, though Codex is "tested live". | `.github/workflows/ci.yml:43` |
| J10 | low | Smaller doc fixes: `--help` omits `check --no-judge`, `--agent` and `--plan-json`; `docs/config.md` omits `judge.reasoning_effort`; `policy.md`'s list of what an approval is bound to is incomplete; the plugin README says a `.applygate.yaml` is required; the `hosts.md` Claude Code column contradicts itself; there are no v0.6.0 upgrade notes; version strings need bumping at the tag; the CHANGELOG still says "the default endpoint". | various |

## What held up

- **Basic shell handling:**
  - plain `bash`/`sh`/`zsh -c`, here-docs and pipes into a shell;
  - `sudo`, `env`, `nice`, `timeout`, `xargs` (without `-I`), `watch`, `nohup`, `script`, `strace`, `npx`, `docker exec` and the unknown-wrapper backstop;
  - `$(which terraform)`, brace expansion, `$'\x..'`, unresolved `cd` (judged as unknown, so blocked), and `-chdir=../prod`.
- **Fail-closed input handling:** malformed JSON, oversized input, and a broken user or repository config all block. Codex and `dontAsk` turn ask into block.
- **Repository config limits:** a repository config cannot move the log, turn on live checks, turn on or configure the judge, re-enable approvals, or set `unknown_dir: session_root`. Each has a test.
- **The judge only escalates:** `Residual`, `Merge` and `approvable()`, with tests and mutation-tested guards.
- **Approvals:**
  - bound to agent, session, cwd, command and the decision's findings;
  - single use, with expiry;
  - stored with `flock`, atomic rename and 0600 permissions.

  A rule's block is never approvable.
- **Supply chain:**
  - every action pinned by SHA, no `pull_request_target`, `contents: read` in CI;
  - cosign verification against the exact workflow identity in `install.sh` and `pin-plugin-release.sh`;
  - the plugin launcher checks a sha256 committed in the plugin and fails closed.
- **Telemetry:** off by default, https only, no redirects, kill switches honoured, counts only.
- **Plan gate basics:** `plan-missing`, `plan-unreadable`, `run_show: false`, oversized and errored plans fail toward ask or block. A planfile applied in another directory is rejected by Terraform itself.
- **Tests and docs:** `go test ./...`, selftest 163/163, the Claude-format replay (108/108 caught, 1/55 benign flagged), and all relative links in the docs resolve.

## Recommended order of work

1. **Self-protection, root causes 2 and 3** (A1–A13, B1, D1–D2, E1). Until these are fixed, any other protection can be switched off by the agent it is meant to stop:
   - canonical guard paths, guarding ancestors as well as files;
   - effect-based tampering classification;
   - an approval secret the agent cannot read;
   - no `--plan-json` or `--yes` in release builds;
   - judging unknown tools that carry a command;
   - merged, tighten-only config layers;
   - detecting planfiles written by the same command.
2. **Unknown means unresolved, root cause 1** (C1–C14, B2–B5, H1). Make every construct the analyzer cannot model exactly unresolved, judged at the most protected tier, and add `internal/classify` unit tests. Turn each bypass in this report into a pack scenario first, so the fix is measured.
3. **Tier resolution and the plan gate** (D3–D8, E2–E5).
4. **Judge, MCP, redaction and CI** (F, G, I).
5. **Docs**: restate what is and is not protected, using this report (J). The threat model and README should not claim more than the fixed code does.

The scale of group C suggests a further question beyond fixing each bypass: whether the analyzer should model shell semantics at all. The alternative is to allow only a small set of plainly recognizable command shapes and treat everything else as unresolved. That would block more benign calls in protected tiers, and needs a measurement on the agent-trial and OSS-corpus traffic before deciding.
