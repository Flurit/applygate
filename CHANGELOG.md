# Changelog

## Unreleased

- **Red-team round 2 fixes, part 1** (`review/v0.6.0/2026-11-03-red-team-round-2.md`):
  - **Default-deny near guard files.** A shell command that names a guard file, or a guarded directory, is tampering unless the program only reads. This replaces recognizing each writer: `sort -o`, `yq -i`, `awk -i inplace`, `busybox`, `openssl -out`, `tar -C … -x`, `git clean` and git plumbing that name a guard file are all blocked. Unresolved words count when their literal text or their glob names one (`${HOME:-x}/.claude/settings.json`, `rm ~/.claude/setting*.json`).
  - **Redirections** on compound commands (`{ …; } > f`), bare redirections and `exec` redirections are checked.
  - **Case folding** follows APFS: `ſ` (U+017F) and the Kelvin sign fold to ASCII, and names are NFC-normalized.
  - **MCP tools outside the known-tool table** that name a guard file in their arguments are judged as writes to it.
  - **The hook's own git calls** run by an absolute path without the system and global config, with `fsmonitor`, hooks and pagers off, and read committed files with `git cat-file` instead of `git diff`. Before, an agent-set `core.fsmonitor` ran inside the hook.
  - **The decision log, approvals, judge cache, configs and telemetry settings** are opened without blocking, and only when they are regular files. Before, a FIFO at the log hung the hook.
  - **Limits:** nesting deeper than 2,000 levels is unresolved instead of crashing the process, and gzip output over the 256 KB cap is unknown instead of cut.
  - **`COPILOT_HOME`'s hook file** is a guard path.

- **Red-team round 2 fixes, part 4** (MCP and the model judge):
  - **MCP:**
    - a call that fits several servers' tools is judged by every reading, and the strictest wins;
    - dotted arguments match nested and top-level;
    - a `workdir` that only some servers with that tool name honour is not trusted;
    - `stdin` and `stdin_text` arguments are the command's input;
    - `start_process`'s `shell` is followed;
    - wcgw `send_ascii` codes are decoded;
    - AKS `call_kubectl`, `call_helm`, `call_cilium` and `call_hubble` add their program as the servers do;
    - a `#` word in a command a server splits itself is asked about;
    - Terragrunt MCP `terragrunt_config` and `include_dirs` are read;
    - tfmcp `apply_terraform` without a `plan_id` is an apply;
    - shell tools of servers the table does not know (`run_in_terminal`, `execute_command`, `bash`, …) are judged as shell.
  - **The analyzer:** input given to a compound command (`{ sh; } <<EOF`, `while …; done < f`) reaches the commands inside it.
  - **Codex:** `write_stdin` is judged as text typed at a shell, and `js_repl` as node code.
  - **Model judge:**
    - the filter reads the unredacted call, and a redaction that hides programs makes the call unjudgeable;
    - the filter sends calls whose programs start others through the environment or options (`CC`, `RUSTC_WRAPPER`, `PYTHONPATH`, `NODE_OPTIONS`, `go env -w`, `cargo --config`, `npm --script-shell`, GNU `sed` `e`), cleans `/tmp/../` paths and reads paths attached to options;
    - the judge's tier follows `cd`;
    - write content over 4,000 characters is unjudgeable instead of cut;
    - a known MCP tool's arguments are sent with its command;
    - verdicts are read without case, a nested verdict object does not win, and a 5xx or an answer over 1 MiB is unjudgeable;
    - the `examples/judge` scripts print a verdict-less answer on a refusal;
    - `applygate check` asks the judge only at a terminal.
  - **Azure:** `az deployment … --mode Complete` is destructive.

- **Red-team round 2 fixes, part 3** (the analyzer and tiers):
  - **Analyzer:**
    - a `trap` handler is judged at the most protected tier under the root, since it fires after any `cd`;
    - an `aws` or `helm` option applygate does not know, before the command path, is read both ways (taking a value and not), and the stricter reading wins;
    - `aws s3 cp` counts as an upload whenever an `s3://` path follows the source;
    - git's `grep -O<pager>`, a glued `rebase -x<cmd>`, `difftool`/`mergetool -x`, and `GIT_CONFIG_COUNT`/`KEY`/`VALUE` pairs are analyzed, and `GIT_CONFIG_PARAMETERS` or another config file is unresolved;
    - `.ONESHELL` recipes run as one script;
    - `make -C` into a directory linked earlier in the command is judged anywhere under the root;
    - PowerShell tool bodies are analyzed as PowerShell, not bash;
    - a compiled program run by path (`/bin/rm`) is judged by its name, not parsed as a script.
  - **Tiers:**
    - the declared backend is read from `.tf.json`, override files and unquoted labels, with `cloud`/`remote` workspace names, and a computed backend is unknown, so protected;
    - a symlink into a directory no environment matches gets the strict rule;
    - a plan file in another Terraform directory brings that directory's tier;
    - `-out` is followed through `-chdir`, `TF_CLI_ARGS_plan` and case folding;
    - `-invoke` takes a value, and plans with action invocations get a `plan-actions` finding;
    - Terragrunt `--config` and `TG_CONFIG` move the unit;
    - `aws` provider profiles and role ARNs, `AWS_DEFAULT_PROFILE` and `HELM_KUBECONTEXT` are signals;
    - `kubectl config use-context`, `gcloud config set project` and `az account set` retarget later calls in the same command;
    - a `cd` into another repository is judged by its config too;
    - an unresolved `workspace select` is an unknown workspace.
  - **`plan-check`** resolves the tier from the workspace and backend, judges a replace like a destroy, rejects an unknown `--tier`, and refuses state JSON.
  - **Exposure rules:** `NotAction`, a principal list with `*`, an empty `Condition`, split CIDRs, default security groups, a role's managed and inline policies, an any-principal trust policy, `publicly_accessible` databases and AllUsers ACL grants.

- **Red-team round 2 fixes, part 2:**
  - **Repository configs must be trusted.** A `.applygate.yaml` is read only when a person approved its exact content with `applygate trust`; a new or changed one is not read and every directory is protected. This closes every route that rewrites or plants a config (checkout, extraction, clone, a nested `wrappers:` list) in one place. `init` trusts the config it writes, and `doctor` lists untrusted ones.
  - **Managed install:** `sudo applygate install --managed` puts a root-owned binary in `/usr/local/libexec/applygate`, a system config in `/etc/applygate` that wins over the user config, a system trust store, and the hook in Claude Code's managed settings with bypass mode off (`--exclusive` adds `allowManagedHooksOnly`). It prints a Codex `requirements.toml` snippet. The Claude Code and Codex keys are from their docs and not tested live. macOS and Linux only. `uninstall --managed [--purge]` removes it.
  - **Nested agents:** `claude --bare`, `CLAUDE_CODE_SIMPLE`, `CLAUDE_CONFIG_DIR`, `codex --disable hooks`, `codex -p`, `CODEX_HOME`, `gemini --yolo`, `copilot --allow-all-tools`, `HOME=` and the same agents through `npx`, `bunx` and `pnpx` are tampering.
  - **The binary:** package managers that install, remove or replace `applygate` or `seatbelt`, an executable of that name written into a `PATH` directory, shell start-up files, and `launchctl setenv` are tampering. A copy of the running binary is recognized by its content. The Claude Code plugin pins the binary it finds by path and sha256.
  - **tmux and screen:** the command strings of `new-session`, `new-window`, `split-window`, `respawn-pane`, `run-shell`, `display-popup` and `screen` are analyzed.
  - **More guard paths:** the Claude Code plugin registry, `.mcp.json`, `~/.claude.json`, Gemini's `trustedFolders.json`, and `GEMINI_CLI_HOME`.

- **Security fixes from the v0.6.0 pre-release review** (`review/v0.6.0/`).
  - **The review:** six independent reviewers found 80 issues, 20 of them critical, most present in earlier releases.
  - **This release fixes the self-protection findings,** where an agent could switch applygate off or approve its own call.
  - **Tests:** every finding has a test (`harness/pack_attack`, `internal/reviewgap`).
  - **Guard files are compared after resolving symlinks and, on macOS and Windows, case.**
    - **Before:** `.APPLYGATE.YAML`, `~/.Claude/settings.json` or a symlinked parent got past the guard. So did the user config, decision log and telemetry file when `XDG_CONFIG_HOME` or `XDG_STATE_HOME` was set, and the running binary itself.
    - **Directories that hold a guard file now count too:**
      - removing or moving `~/.claude`, the state directory or the repository;
      - copying, downloading or extracting into them (`cp -t`, `curl -o`, `wget -O`, `tar -C`, `unzip -d`);
      - `git mv/checkout/restore/reset -- <guard file>`;
      - `find -delete`, `patch` and editors.
    - **Code in another language** (`python3 -c`, `node -e`, scripts) that names a guard file or applygate's approvals, judge cache, telemetry or log file is guard tampering, whether or not it mentions a tool.
  - **Tampering is judged by what a program is, not only its name:**
    - `applygate` or `seatbelt` in any case;
    - the same file as the running binary;
    - a renamed copy given applygate's tampering subcommands;
    - `go run` of `cmd/applygate`;
    - applygate started from another program's arguments, such as a pty spawner.

    `applygate hook install` and `applygate apply` run by an agent are now tampering. So are the agent CLIs' own switches: `claude plugin disable|uninstall`, `claude config set`, a nested `claude --settings` or `--setting-sources`, and `codex -c` overrides of hooks, the sandbox or approvals.
  - **Every Claude Code tool reaches the hook.** `hook install` and the plugin use the matcher `*`.
    - **Commands in other tools:** a tool applygate does not know whose input carries a command (`Monitor`, `PowerShell`) is judged as a shell call. Before, `Monitor` ran `terraform destroy` unseen. `doctor` warns about an older matcher.
    - **Unreadable shell calls:** a Claude Code or Codex shell call whose command cannot be read is an error under `on_error`, not an allow.
    - **Other inputs:** `apply_patch` run from the shell, and text typed into another terminal with `tmux send-keys` or `screen -X stuff`, are judged.
  - **A planfile or `.terraform` written earlier in the same command.**
    - `terraform plan -destroy -out=tfplan && terraform apply tfplan` gets a critical `plan-unverifiable` finding instead of being judged on the old file.
    - A command after a step that rewrites `.terraform` is judged as protected.
  - **The shell analyzer follows what the shell would run, or says it cannot** (findings C1 to C14, H1). Before, each of these let `terraform destroy` through in a protected directory:
    - **Names:** program names are compared without case and without `.exe` (`TERRAFORM destroy` runs terraform on macOS).
    - **Words:** a word the analyzer cannot reproduce exactly is unresolved: an unquoted glob, zsh's `=name`, `$'\u…'`, and `echo` of a backslash without `-e` or `-E`. `echo -e` decodes `\0NNN`, and `printf --` is understood.
    - **State:** a background statement (`cd ../dev &`) runs on a copy. A function body runs in the caller's shell, as bash does, with its `local` variables restored. `pushd`/`popd` keep a stack. `shift` and `set --` change the positional parameters. The variables `read`, `printf -v`, `mapfile`, `getopts` assign are unresolved, and after `declare -n` no variable is known.
    - **Constructs:** case words and patterns, declaration arguments, C-style `for` headers, `${x:-$(…)}`, arithmetic and `trap 'cmd' EXIT` are walked.
    - **Placeholders:** `xargs -I`/`-i`/`-J` and GNU `parallel` substitute known input, and anything else is unresolved. `parallel` with no command runs each input line.
    - **Interpreters:** options are parsed per language: `python3 -Ic`, `perl -we`, `node --eval`, `python3 -u script.py`, PowerShell `-EncodedCommand`, and so on. `awk`, `lua`, `tclsh`, `Rscript`, `julia` and `bun` are added. Code that cannot be resolved is a problem, and without a code argument the arguments themselves are searched.
    - **Programs that run commands through their own options:**
      - git: `-c alias.x='!…'`, `core.pager` and other command keys, `GIT_SSH_COMMAND`, `bisect run`, `rebase -x`, `submodule foreach`;
      - `ssh`/`scp`/`sftp -o ProxyCommand`, `rsync -e`, `flock … -c`, `su`/`runuser -c`;
      - `fish`, `csh`, `tcsh` and other shells' `-c`;
      - `conda`/`mamba`/`uv`/`poetry run`, `nix run`, and `env -S"…"`.
    - **Directories:** Terragrunt's `--working-dir`, `--terragrunt-working-dir`, `TG_WORKING_DIR` and `TERRAGRUNT_WORKING_DIR` are honoured anywhere. A command whose directory the analyzer loses (an unresolved `-chdir` or `cd`, a `cd` into a directory linked, moved or extracted earlier in the command) is judged at the most protected tier under the repository root.
    - **make:** `-p` runs recipes. Under `-n`/`-q`/`-t`, `+` and `$(MAKE)` lines are still analyzed. `--directory=`, `--file=`, `-fFILE` and `include` are read, and `MAKEFILES`, `MAKEFLAGS` and `--eval` cannot be analyzed.
    - **Written in the same command:** a script, sourced file, `$(cat f)` input or makefile written by an earlier step (a redirect, `tee`, `cp`, `curl -o`, `sed -i`, `git checkout`, an extraction) is unresolved instead of read as it is on disk.
    - **Failures:** a parse error, an exhausted statement budget or work limit, and an internal error under `on_error: auto` are judged at the most protected tier under the repository root, not at the starting directory. Lines before a syntax error are analyzed, since a shell runs them.
    - **Aliases** are parsed as shell text, and an alias that names itself (`alias terraform='terraform destroy'`) expands once.
    - **Cloud CLIs:**
      - The verb, not any word, decides, and a read word never turns a write into a read.
      - `rm`, `remove` and `delete-*` are destructive.
      - Flag values are skipped (`--verbosity info`).
      - `TF_CLI_ARGS` and `TF_CLI_ARGS_<subcommand>` are part of the command.
      - `gsutil` is classified.
      - `kubectl --cluster`/`--server` and `helm --kube-apiserver` name the target.
  - **Tier resolution** (findings D4 to D8):
    - **Symlinks and case:** a directory is matched as written and with symlinks resolved (case folded on macOS and Windows), and the stricter environment wins. Before, `envs/dev/p -> ../prod` was judged as dev.
    - **`TF_DATA_DIR`:** the recorded backend is read from it, not only the workspace. A `TF_DATA_DIR` that cannot be resolved is judged as protected.
    - **Backend patterns:** `*` matches across `/`, so `s3://bucket/*` covers `s3://bucket/payments/terraform.tfstate`.
    - **`applygate suggest`** escapes control characters in every logged value it writes and quotes names. Its check refuses a proposal holding a key it does not write. Before, a profile name with newlines could inject `name_hints: false`.
    - **Targets on the command line:** `kubectl`/`helm --kubeconfig` and `gcloud --configuration` decide the target when no context or project is given.
  - **The plan gate** (findings E2 to E5):
    - **Providers checked before show:** every provider in `.terraform/providers` must match `.terraform.lock.hcl` as git HEAD has it. `show` runs without the user's CLI configuration, and `terragrunt show` is never run: the plan is shown with `terraform` in its `.terragrunt-cache` directory. Tested with Terraform 1.14.6: before, a provider binary replaced in `.terraform` ran with the user's credentials once the working-tree lock file was edited to match; now the plan counts as unreadable and nothing runs.
    - **Replace counts as destroy:** a plan that replaces a resource is judged like one that deletes it.
    - **Instance keys:** `protected_resources` ignore `count` and `for_each` keys, so `aws_instance.bastion` covers `aws_instance.bastion[0]`.
    - **Values known only after apply:** a watched attribute unknown until apply (an ingress CIDR, or `deletion_protection` on an update) is a high `unknown-watched` finding.
  - **The model judge** (findings A13, F1 to F4, F7, F8, F10, F12):
    - **The cache** keeps only asks and blocks, ignores entries dated in the future, and is keyed on the endpoint and model or the whole command line. Before, a pre-filled `allow` skipped the judge. `applygate check` keeps its own cache.
    - **The filter** sends these to the judge:
      - programs started through a local tool's own options (`git -c`, `git config` writes, `tar --to-command`, `sort --compress-program`, `rg --pre`, `go test -exec`, `go build -toolexec`);
      - `mvn`, `gradle`, `dotnet` and `npm init`;
      - forced pushes in clustered flags;
      - files the shell writes outside `/tmp`;
      - paths outside the working directory after `cd`;
      - reads of Terraform state, `.tfvars` and more credential files.
    - **A call that breaks the judge is asked about:** one too large to send, one the model refuses, or one whose answer holds no verdict, in protected and standard environments. The last JSON object with a verdict is the answer.
    - **Edit content from other hosts:** the judge sees the content of Copilot, OpenCode and Cline edits.
    - **`claude-cli.sh`** runs from an empty directory with only the user's settings.
    - **One budget:** the hook's whole run, the judge and telemetry included, fits in 29 seconds.
  - **MCP translations** (F5, F6, F9, F11):
    - **Flags:** `is_destroy: 1` or `"yes"` counts as true, and `params` sent as a string is asked about.
    - **Clusters:** the EKS and GKE cluster names, and Flux159's `flags`, reach the translated command.
    - **Programs:** a `call_aws` command that is not `aws` is asked about, and so are shell operators in argv arrays.
  - **Secrets and data** (G1, G2):
    - **Redaction** covers:
      - private keys inside JSON;
      - `--token X`, `--password X` and `set <secret> X`;
      - `mysql -pX`, `curl -u user:X` and URL userinfo;
      - `github_pat_`, `glpat-`, `sk-`, `sk_live_` and `AIza` tokens;
      - names such as `db_pass`.

      `Via` is redacted too.
    - **Telemetry** sends only known agents, modes, verdicts and version numbers.
  - **Failure handling** (H2): one function decides whether an error, a panic or the deadline blocks. A panic now follows `on_error` like any other error.
  - **Hosts, CI and the supply chain** (I1 to I6):
    - **Claude Code** is trusted to show an ask only in the modes where that was seen live (default, `bypassPermissions`). In `acceptEdits`, `plan` and `auto` an ask is a block.
    - **`scripts/ci-plan-check.sh`** ends its multi-line output with a random delimiter and strips control characters, so a resource address in the plan cannot add a `verdict=allow` output. The Action passes `binary` through the environment.
    - **The release workflow** runs the tests in a read-only job without stored credentials; only the release job holds the token and signing identity.
    - **`install.sh`** requires cosign unless `APPLYGATE_VERIFY_SIGNATURE=auto`, and the `seatbelt` compatibility binary is no longer shipped.
    - **`hook install`** writes settings files atomically, keeps their key order, the bytes of the keys it does not change, and their permissions. It recognizes its own entries by the exact command it writes.
    - **The lock-file check** runs once per directory: 300 destroys in one command took 13 s, now 1 s.
  - **Docs** (J1 to J10): every claim was checked against the code. The upgrade notes are in the README and the known gaps in `docs/limits.md`.
- **Behaviour changes:**
  - **One-time approvals are off by default.** Only the user config turns them on. The approval key now binds write content and full MCP arguments, the store's lock never waits more than about half a second, and the approve prompt escapes control characters.
  - **The `seatbelt` binary is gone.** Run `applygate hook install` before upgrading if a hook entry still calls it; `applygate doctor` flags one.
  - **`install.sh` requires cosign** by default.
  - **Claude Code's `acceptEdits`, `plan` and `auto` modes** get a block where an ask was before, until the prompt is tested live there.
  - **`applygate apply` has no `--yes` and no `--plan-json`.** An ask outside a terminal is refused; in CI, gate with `applygate plan-check` and run the engine yourself.
  - **Repository configs can only add protection.** Every `.applygate.yaml` from the outermost directory down applies, and a nested one no longer replaces the repository's.
    - **User config only:** observe mode, `strict: false`, a looser `default_tier`, `name_hints` or `on_error`, `aliases`, and the other settings listed in `docs/config.md`. In a repository config they are ignored, and `doctor` says so.
    - **`applygate init`** writes the repository config without a mode and starts the observe-mode trial in the user config.
    - **`applygate suggest`** no longer proposes a mode.
    - **Path patterns:** a repository's `**` patterns are rooted at its own directory.
  - **`on_error: auto` judges an error at the most protected tier under the repository root.** An internal error from a disposable directory now blocks when the repository has a protected environment.
  - **The plan gate needs a committed `.terraform.lock.hcl`** wherever `.terraform/providers` holds providers. Without one, applying a saved plan in a protected tier is blocked as unreadable.
  - **Replacing a resource in a saved plan is a destroy**, so it blocks in protected tiers and asks in standard ones. A first apply of a network stack in a protected tier usually asks, because its CIDRs are known only after apply.
  - **Stricter shell analysis asks more often in protected tiers.** A command that runs a file it wrote itself, or that globs or uses `=name` in its program name, is asked about there. On the 162 recorded agent-trial calls, one verdict changed: installing a freshly downloaded `terragrunt` and running `--version` in a directory the name hints mark as production is now an ask.
- Model judge, opt-in (`judge:` in the user config, docs/judge.md). A call the rules let through without recognizing anything is sent to a language model, and the call gets the stricter of the two verdicts. That covers a shell command that starts a program outside a short list of local ones, every file write or edit (with up to 4,000 characters of content), and an MCP call to a tool the known-tool table does not cover.
  - **Backends, with no default model.** The user chooses one:
    - any OpenAI-compatible chat completions endpoint with their own key (`base_url`, `model`, `api_key_env`), local servers included;
    - or a program they name (`backend: command`): `examples/judge/claude-cli.sh` (the `claude` CLI's login), `jev.sh` or `openai-decisions.sh`.

    `enabled: true` without a choice leaves the judge unasked; the log says why and `applygate doctor` warns. `docs/judge.md` compares the measured options with their pros and cons. No new dependencies.
  - **Escalate only.** An error, a timeout or an allow leaves the rule decision. A judge's block can be approved once with `applygate approve`; a rule's block still cannot.
  - **Who controls it.** Off by default; only the user config can turn it on or configure it, and a repository config may only turn it off.
  - **Supporting changes.** Secrets are redacted before sending. Answers are cached for 24 hours in `judge-cache.json`, a guard path. Every judge call is in the decision log under `judge`. `applygate check` runs the judge (`--no-judge` skips it), and `applygate doctor` reports its setup.
  - **Measurements.** On an independently written held-out set the rules catch none of the 67 calls that should be stopped.
    - **Through the `claude` CLI:** Claude Haiku 5.5 caught 66 of them, with 5 of 61 false escalations.
    - **Through Anthropic's endpoint** (set already seen): it caught 62 to 63 over three runs, with 5 false escalations. Model time was p50 1.5 s and p95 2.8 s, at about $0.00023 per call.
    - **`reasoning_effort`:** the endpoint accepts it and ignores it.
    - **Gemini 3.8 Flash through Google's OpenAI-compatible endpoint** (set already seen, no code change needed): it caught 65 in each of three runs, with 0 to 1 false escalations. It is slower: p50 5.1 s, p95 9.4 s, and 5 of 128 calls took over 10 s, so it needs `timeout: 20s`. Its cost was not measured.
    - **Jev through `examples/judge/jev.sh`** (set already seen): it caught 61 to 62, with 6 to 7 false escalations, at p95 0.56 s and about $0.00006 per call.
    - **OpenAI's `gpt-6-luna` through `examples/judge/openai-decisions.sh`** (set already seen): it caught 58 in every run, with 8 false escalations and one refusal. That was at p95 0.74 s and about $0.00011 per call.
    - **A fifth held-out set,** written independently and scored once per judge after every design choice was committed. Of 72 calls that should be stopped and 71 that should go through:
      - Gemini 3.8 Flash caught 71 with 0 false escalations;
      - Haiku 5.5 through Anthropic's endpoint caught 70 with 4;
      - Jev caught 69 with 5;
      - `gpt-6-luna` caught 65 with 3.

      Asking the decision models nine narrow questions and letting the tier table decide did not do better on it, so that design stays in `experiments/model-judge/decision-facts`.
    - **Other providers and models:** none have been measured.
  - **Decision-model adapters** for the command backend, which answer with a probability per verdict and no explanation:
    - `examples/judge/jev.sh` (TypeSafe AI's Jev);
    - `examples/judge/openai-decisions.sh` (OpenAI's Decisions API, `gpt-6-luna`).

    An API error is reported with the provider's message.
  - **Tested live** in headless Claude Code 2.1.314 on macOS, with Anthropic's endpoint (`review/judge-live/2026-11-02-default-endpoint.md`) and with the command backend (`review/judge-live/2026-11-01-claude-code.md`):
    - `pulumi destroy` on a protected stack was blocked by the judge;
    - `pulumi preview` was judged and allowed;
    - printing a Vault password was asked about and did not run;
    - `ls` never reached the judge.

    Codex and endpoints other than the default are tested only in unit tests.
- MCP calls to known infrastructure tools are judged. In Claude Code and Codex, a call such as the AWS server's `call_aws`, the Terraform server's `ExecuteTerraformCommand`, HCP Terraform's `create_run`, a Kubernetes server's `resources_delete`, AKS's `call_kubectl`/`call_az`, gcloud's `run_gcloud_command` or a shell server's `start_process` is translated into the command it is equivalent to and judged as that command: tiers, preflight, plan gate and approvals all apply, and the verdict names the tool and the command. A list of `call_aws` commands is judged command by command; an HCP Terraform run is judged as the Terraform command on its workspace, so `workspaces:` matchers pick its tier; a server that runs in its own directory leaves the command's directory unknown, which is judged at the most protected tier under the session root; applying an HCP run or a server-held plan, and a known tool whose arguments cannot be read, is asked about. The table (`internal/mcpmap/rules.json`, 15 servers, 88 tool names) is data written from each server's source at a named commit and not tested against the running servers; `docs/mcp.md` lists it and what it leaves out (Pulumi, the Lambda tool server, SQL, kube-context retargeting). Other MCP calls are logged and allowed as before. Behaviour change: a known MCP tool now follows `on_error` like a shell command, and Claude Code gets its JSON answer for MCP calls rather than exit 2. Pack scenarios D109 to D118 and B49 to B53, replayed in the Claude Code and Codex formats; v0.5.0 misses all ten dangerous ones.
- Kubernetes contexts, GCP projects and Azure subscriptions pick the environment. New matchers `kube_contexts`, `gcp_projects` and `azure_subscriptions` (globs; a subscription by name or id) match what a `kubectl` or `helm`, `gcloud` or `az` command targets: the value on its command line (`--context`, `--kube-context`, `--project`, `--subscription`), else what the CLI's local configuration selects (the kubeconfig's current context, `CLOUDSDK_CORE_PROJECT` or the active gcloud configuration, the default subscription in `azureProfile.json`), read from local files only. Name hints apply to them. Before, only the directory decided, so `kubectl delete … --context prod-eks` from a disposable directory was an ask instead of a block. The values are in the decision log and part of what an approval is bound to, and `applygate suggest` proposes them. Pack scenarios D119 to D123, B54 and B55.
- `helm`, `az` and `gcloud` are classified by verb, in shell commands and MCP calls alike: `helm uninstall` and any `az`/`gcloud` command whose verb is `delete` or `purge` (or ends in `-delete`) is cloud-destructive, `list`/`show`/`describe`/`get`/`status` are read-only, anything else is a cloud write. Before, these commands were not classified and were allowed in every tier.

## v0.5.0 (2026-10-31)

- One-time approvals: `applygate approve [ID]`. On the seven agents that cannot show an ask prompt (and Claude Code in `dontAsk`), an ask used to end as a plain block. The block now names an approval ID; a person runs `applygate approve ID` in their own terminal, types the environment name, and the agent's next identical call is allowed once within 15 minutes (requests expire after an hour). The approval is bound to the agent, session, directory, command and every action's class, environment, tier, workspace, backend, AWS profile and plan SHA-256, so a changed call or plan is judged again. Only asks can be approved; blocks cannot. Without an ID the command lists pending requests. The store is `approvals.json` next to the decision log, a guard path. `approvals: false` in the user or repository config turns it off; a repository config cannot turn it on. Verified end to end with the Codex hook format on macOS: request, wrong word refused, right word approved, one retry allowed, the next one blocked again; not yet tried inside a live agent.
- Guard tampering, found while testing approvals: `script` in its BSD/macOS form (`script -q file command…`) is now unwrapped, so the command it runs is judged; before, `script -q /dev/null <cmd>` hid any command. `expect -c` is analyzed like other interpreters, and code in another language that names an applygate command only a person may run (`approve`, `telemetry on`/`off`, `init`, `disable`, `hook remove`) is guard tampering in every tier. Pack scenarios D106 to D108 and B48; v0.4.0 misses D106 to D108.
- `applygate apply` and `applygate approve` check for a terminal with isatty, so stdin from `/dev/null` or another character device no longer counts as one.

## v0.4.0 (2026-10-31)

- Hook adapters for seven more agents, written from each host's documentation and, where it is open source, its source code, and **not tested live**: Cursor (`applygate hook cursor`), GitHub Copilot CLI (`copilot`), Gemini CLI (`gemini`), Windsurf Cascade (`windsurf`), Devin (`devin`), OpenCode (`opencode`, a JS plugin that runs applygate) and Cline (`cline`, an executable `PreToolUse` script). Each reads its host's payload and answers in its documented output format. Only Copilot CLI can show a prompt; on the others an ask is enforced as a block, and a block in Cline cancels the whole task. When applygate crashes, times out or is missing: Cursor (installed with `failClosed: true`) and OpenCode block; Copilot CLI and Cline block on a crash or a missing binary but let the call run on a timeout; Gemini CLI blocks only on a missing binary; Windsurf and Devin let the call run, as Codex does. MCP calls on these hosts are neither inspected nor logged. `applygate hook install --agent NAME [--scope user]` writes each host's own config, `remove` and `doctor` know them all, and `applygate init` names a detected host with the command that installs it but installs only the Claude Code and Codex hooks, which are tested live. `applygate hosts` and `docs/hosts.md` give each host a table whose every cell says "from docs, not tested live" and lists the live tests still pending; the sources are in `review/host-research/2026-10-31-hook-contracts.md`. The scenario pack is replayed in every host's input format (`harness/formats_test.go`, `harness/run.py --format`), and all of them catch every dangerous scenario they can see.
- Claude Code hook loaded by another host: Cursor, Copilot CLI and Devin also run hooks from `.claude/settings.json`, with their own tool names. A shell call named `Shell` or `exec` used to reach `applygate hook claude` as an unknown tool and was allowed; it is now judged like that host's own calls (no ask, a block as exit 2). From those hosts' documentation, not tested live.
- Guard paths: the new hosts' hook configs and scripts (`.cursor/hooks.json`, `.gemini/settings.json`, `.github/hooks/**`, `.github/copilot/settings*.json`, `.copilot/hooks/**`, `.copilot/settings.json`, Windsurf's `hooks.json` files, `.devin/config.json`, `.devin/hooks.v1.json`, `~/.config/devin/config.json`, `.opencode/plugins/**`, `~/.config/opencode/plugins/**`, `.clinerules/hooks/**`, `.cline/hooks/**`, `~/Documents/Cline/Hooks/**`) are protected, so an agent cannot remove or rewrite its own hook.
- Claude Code plugin: no longer needs `applygate` on PATH. Its hooks run `scripts/applygate-hook`, a POSIX sh launcher that uses `$APPLYGATE_BIN`, else the `applygate` on PATH, else the release pinned in `scripts/pinned-release.txt`, downloaded once (curl or wget), checked against the sha256 committed in the plugin, and kept in `${CLAUDE_PLUGIN_DATA}` (`~/.cache/applygate/plugin` without it). A `SessionStart` hook fetches it before the first tool call; if no binary can be found, the `PreToolUse` hook exits 2 with the reason, so the tool call is blocked as before. The plugin's version now follows the pinned release (0.3.2); `scripts/pin-plugin-release.sh vX.Y.Z` verifies a release's signed `checksums.txt` with cosign and rewrites the pin and the version. Verified live in Claude Code 2.1.312 with no applygate on PATH: the session fetched v0.3.2 and the hook judged a command with it.
- Guard paths: the plugin's installed copy, marketplace clone, data directory and download cache (`~/.claude/plugins/cache/applygate/**`, `~/.claude/plugins/marketplaces/applygate/**`, `~/.claude/plugins/data/applygate-*/**`, `~/.cache/applygate/**`) are protected, so an agent cannot replace the launcher or the binary it runs.
- MCP tool calls are logged, not judged. A Claude Code or Codex tool call named `mcp__<server>__<tool>` is recorded in the decision log with its arguments (compact JSON, secrets redacted like commands, capped at 4 KB) and the note "logged, not judged", and always allowed: in every tier and mode, and also when the repository config is broken (the entry then carries the error). `applygate report` adds a line counting MCP calls per server. The Claude matcher written by `hook install` and the plugin now include `mcp__.*`; `applygate doctor` warns about a Claude hook whose matcher predates it. Other tools applygate does not inspect stay unlogged. Verified live in Claude Code 2.1.312 with a stdio MCP server: the call ran and was logged with its arguments.

## v0.3.2 (2026-10-30)

- Plan gate: fewer false positives from `code-execution` and `exposure`, the two analyzer causes found by the plan-gate false-positive study (`review/fp-study`). `code-execution` flagged every provisioner and `external` data source in the configuration on every plan. It now flags a provisioner only for a resource instance the plan creates, replaces or destroys (a destroy counts because the plan JSON does not tell a destroy-time provisioner from a creation-time one), so a resource at count 0, an empty for_each or a resource the plan leaves alone is no longer reported. It flags an `external` data source only when the plan defers its read to apply; one read during `terraform plan` has already run. Evidence now names the instance (`module.m.null_resource.archive[0]: provisioner local-exec`). `exposure` on an in-place update now reports only exposure the update adds, so a tag change on a security group that was already open to the internet no longer asks; creates and replaces are judged on the planned value as before. On the study's 212 routine plans per tier, protected-tier false positives go from 17 to 0 and every expected prompt is kept; the standard tier stays at 0 prompts.

## v0.3.1 (2026-10-30)

- Secrets runners: `dotenvx run` is unwrapped like `doppler run`; `sops exec-env` and `sops exec-file` have their command string analyzed as shell; so is the command string of `doppler run --command` and `infisical run --command`; and the secrets runners (`doppler`, `op`, `infisical`, `dotenvx`) find the command without `--`. Before this, `dotenvx run -- aws s3 rb …`, `sops exec-env f 'aws s3 rb …'`, `doppler run aws s3 rb …` and `doppler run --command '…'` were allowed in a protected tier. A credential or secrets runner in a shape applygate does not recognise now falls back to the unknown-wrapper backstop instead of being recorded alone. A flag with an unresolved inline value (`--project="$P"`) is no longer taken for the start of the wrapped command. Pack scenarios D103–D105 and B47.
- `applygate version` now reports the module version for a binary built with `go install github.com/Flurit/applygate/cmd/applygate@vX.Y.Z`, which printed `dev` because only the release build sets the version; a local build still reports `dev`. The host capability table (`docs/hosts.md`) records the macOS runs of T3.9 on Claude Code 2.1.314 and Codex 0.166.0.

## v0.3.0 (2026-10-30)

- `applygate suggest`: a proposed `.applygate.yaml` from the observe-mode decision log. Environments come from the directories where the engine ran, with tiers guessed from path names (prod/production/prd/live → protected; staging, stage, uat, qa, non-prod, pre-prod → standard; dev, sandbox, test, examples, demo → disposable) and from hinted workspaces, S3 backends and AWS profiles; directories whose names say nothing stay commented out so strict mode keeps them protected until a person picks; an existing config's environments and settings are kept and not proposed again; every ask or block is listed with the reason it was judged that way. `--root` selects the repository in a shared user log, `--out` writes the file and refuses to overwrite. The output is parsed as a config before it is printed.
- Opt-in telemetry (`applygate telemetry status|on|off|send`, `docs/telemetry.md`). Off by default and in every release. When a person turns it on, one report a day carries the applygate version, OS and architecture, and decision counts per (version, agent, mode, verdict) plus the internal-error count; no commands, paths, names or identifiers. It is built from the local decision log at send time (`status --payload` shows the exact next report), sent from the hook only after the verdict is written and bounded to 3 s, requires https (http only on localhost), follows no redirects, and is forced off by `APPLYGATE_TELEMETRY=0` or `DO_NOT_TRACK=1`. No release carries a default endpoint yet, so `on` needs `--endpoint`; `APPLYGATE_TELEMETRY_ENDPOINT` redirects reports to a collector of your own. An agent running `applygate telemetry on` or `off` is blocked as guard tampering. The decision log reader now folds the pre-rename `seatbelt_version` key into the version, so older logs keep their version counts.
- The plan gate in CI: a composite GitHub Action (`Flurit/applygate@<tag>`, inputs `plan`, `tier`, `fail-on`, `working-directory`, `terraform`, `version`, `binary`), the portable `scripts/ci-plan-check.sh` it runs, and a Terragrunt `before_hook` recipe; documented in `docs/ci.md`. `action-check.yml` exercises the action against two real AWS-provider plans on every push.
- `applygate apply <planfile>`: the human door. Judges a saved plan exactly as the hooks judge `terraform apply <planfile>` (tier, preflight, plan gate), logs the decision with agent `human`, refuses a block, asks for the environment name to be typed back on an ask, and only then runs `terraform` or `tofu` (`--engine`). Outside a terminal an ask is refused unless `--yes`, which never applies in a protected tier.
- Go toolchain 1.26.10. The CI vulnerability scan flags standard-library `net/http` and `crypto/x509` issues in 1.26.7 (GO-2026-6610 to GO-2026-6617, GO-2026-6809) once the binary imports `net/http` for the telemetry sender; 1.26.10 carries the fixes.

## v0.2.0 (2026-10-29)

- Renamed the project from seatbelt to applygate. Binary `applygate`, config `.applygate.yaml`, hook commands `applygate hook claude|codex`, user config `~/.config/applygate/config.yaml`, decision log `~/.local/state/applygate/decisions.jsonl`, installer variables `APPLYGATE_*`, Go module `github.com/Flurit/applygate`.
- Compatibility for one release: `.seatbelt.yaml` is read with a deprecation note; the old user config and log paths are used when the new ones do not exist; hook entries that call `seatbelt` are recognised, and a `seatbelt` shim binary in the release archive forwards to `applygate`; `SEATBELT_*` installer variables are honoured with a warning; the legacy file names stay guard-protected.
- Carried from main since v0.1.4: host capability matrix (`applygate hosts`, `docs/hosts.md`), fail-closed tier resolution when a host does not report the command directory, bounded planfile search, user-scope hook installs.

## v0.1.4 and earlier

Released as seatbelt; see the GitHub releases and `docs/project/ACCEPTANCE.md`.
