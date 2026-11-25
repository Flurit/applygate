# Policy

applygate decides every tool call the same way. It analyzes the call, classifies each operation the call would start, resolves an environment tier for each one, runs preflight and (for saved plans) the plan gate, and returns the strictest verdict: allow, ask or block. Every ask or block carries the reason, the evidence and a next step.

This page is the reference for that decision: the [decision flow](#decision-flow) in ten steps, the [verdict table](#verdict-table), and the [findings](#findings) of preflight and the plan gate. The config keys it names are described in [config.md](config.md), and what the analysis cannot see in [limits.md](limits.md).

## Terms

- **Action:** one operation a call would start: a program a shell command runs, a redirect, or a file a tool writes or reads. A call can hold several actions.
- **Class:** what kind of operation an action is, such as `read-only`, `destroy` or `guard-tampering`. The [verdict table](#verdict-table) lists the classes.
- **Tier:** how protected the environment an action targets is: protected, standard or disposable. Tiers come from the environments in your config.
- **Guard file:** a file applygate's protection depends on, such as an agent's hook settings or applygate's own config ([threat-model.md](threat-model.md#self-protection)).
- **Finding:** something preflight or the plan gate found, with a severity. The [findings table](#findings) lists them.
- **Unknown:** a value the analysis cannot resolve. An unknown target is judged as protected, never treated as absent.

## Decision flow

Other pages refer to these steps by number.

### Step 1: The event is normalized

The hook adapter turns the agent's event into one internal event: agent, tool, command or paths, working directory, session, and whether the host can show an ask prompt.

### Step 2: The shell command is analyzed

The analyzer parses the command as bash and walks it in order.

**What it tracks:** `cd`, assignments, `export`, prefix assignments, loops over literal lists, functions with positional parameters, aliases, and `$0` in scripts.

**What it unwraps,** to reach the command that would really run:

- `bash/sh/zsh -c`, `eval` and `source`;
- credential and secrets runners: `aws-vault exec`, `aws-okta exec`, `gds aws`, `saml2aws exec`, `aws-sso exec`, `envchain`, `doppler run`, `op run`, `chamber exec`, `infisical run`, `dotenvx run`, and the command string of `doppler`/`infisical run --command` and `sops exec-env`/`exec-file`. The profile or role they name counts as the AWS profile;
- development-environment runners: `direnv exec`, `mise`/`rtx exec`, `asdf exec`, `devbox run`, `nix develop|shell -c`, `nix-shell --run`;
- wrappers listed under `wrappers:` in the config;
- here-documents and here-strings, and pipes into a shell;
- `sudo`, `env` (including `-C` and `-S`), `timeout`, `nice`, `nohup`, `xargs`, `watch`, `find -exec`, `ssh`, `docker run <terraform image>`;
- Makefile recipes and readable shell scripts.

**Commands that programs run through their own options** are analyzed too: git aliases and `rebase -x`, `ssh -o ProxyCommand`, `flock -c`, `su -c`, `conda run`, `nix run`, `env -S`.

**Static output** is computed for `echo`, `printf`, `cat`, `base64 -d`, `base32 -d`, `gzip`/`gunzip`/`zcat`, `tee`, `xxd -r -p`, `rev`, `dirname`, `basename`, `pwd` and `which`.

**What it cannot resolve becomes a problem** (class `dynamic`), not a guess:

- a word the shell would expand against the disk or locale: an unquoted glob, zsh's `=name`, `$'\u…'`;
- a variable assigned at run time: `read`, `printf -v`, `mapfile`, `declare -n`;
- a placeholder with unknown input: `xargs -I`, `parallel`;
- interpreter code built from variables;
- a file an earlier step of the same command writes: a script, a sourced file, `$(cat f)` input, a makefile.

**Other rules of the walk:**

- Program names are compared without case, and shell builtins with it.
- A background statement runs on a copy of the state. A function body runs in the caller's shell.
- A parse error, an exhausted budget or a lost directory is judged at the most protected tier under the repository root (step 4).

**Python and Node code** given with `-c`/`-e`, a here-document or a script file is not parsed.

- It is a problem only when its text mentions an infrastructure tool, an AWS SDK or a guard file.
- A body that does so but can only read and write ordinary files is instead recorded as a note and allowed. That means: no process start, code loading, network, decoder or function passed by reference; no guard, credential or state file named anywhere in it; and every write to a literal path that resolves to a repository configuration file under the working directory, by the rules in [limits.md](limits.md).

**A backstop for programs it does not recognize:**

- A standalone `terraform`, `tofu` or `terragrunt` argument is treated as the start of the command the program runs (`madeup-tool run -- terraform destroy`). So is the value of a `--run`/`--command`/`-c` flag that starts with one.
- The backstop skips text and search programs, version control, editors, package managers, quoted strings and the values of message flags (`-m`, `--message`, `--title`, …).
- It drops unknown Terraform subcommands it reaches that way (`brew install terraform tflint`).

### Step 3: Each action gets a class

The classifier assigns a class to each program invocation, redirect and file tool call.

#### Strict shapes

Strict shapes (`strict_shapes`, on by default; only the user config can turn it off) add one more action to a shell command that is not **plain**. A command is not plain when it:

- does not parse;
- uses any construct other than simple commands joined by `&&`, `||`, `|` or `;`. That covers functions, `$(…)`, `$((…))`, `let`, loops and conditionals, subshells, `[[ ]]`, declarations such as `export`, `${x:-…}` and other non-plain parameter expansions, `$'…'`, and background or negated statements;
- has a part the analyzer could not resolve;
- sets a variable that is not on a short safe list ([Variables](#variables));
- runs a program whose call does not fit its exact shape ([Exact shapes](#exact-shapes)).

The added action has class `complex-shape`. It is judged in each directory the command runs in: it asks in a protected environment and is allowed elsewhere (see the note under the [verdict table](#verdict-table)). It catches constructs that make the shell run code the analyzer does not follow, such as an exported function, arithmetic on a variable holding `$(…)`, `PS4` under tracing and `BASH_ENV=/dev/stdin`.

The measured cost of strict shapes on real agent calls is in [limits.md](limits.md).

#### Exact shapes

An exact shape says, for one program, which calls cannot run another program: the subcommands and options it may use, or "any arguments" for a program with no such option (`ls`, `cat`, `grep`). `terraform` and `tofu` list their options per subcommand ([limits.md](limits.md)).

- **A program named by a path** is plain only in a system directory (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`, `/opt/homebrew/bin`): a file called `./sort` is not `sort`.
- **An argument that cannot be resolved** may be any option, so a shape that denies options does not take one.
- **Examples of shapes:**
  - `git` without `-c`, `-p`, `--upload-pack`, `--exec`, `ext::` URLs or subcommands outside its list;
  - `tar` with its usual create, extract and list options only;
  - `sed` scripts without the `e`, `w` and `W` commands or the `e` and `w` flags;
  - `kubectl` and `helm` without plugins, another kubeconfig or a post-renderer;
  - `go` only for `version`, `env`, `list` and `doc`.
- **A program with no shape is not plain:**
  - shells and interpreters;
  - most wrappers (`bash -c`, `python3`, `xargs`, `timeout`, `nohup`);
  - package managers and runners (`npm`, `npx`, `pip`, `cargo`, `brew`, `pre-commit`);
  - pagers (`man`, `less`);
  - `make`, which runs its recipes in a shell its Makefile or command line chooses.
- **`terragrunt`** is plain only for `hclfmt`, `hcl fmt`, `help` and its version, since it evaluates `terragrunt.hcl`, whose `run_cmd()` and hooks run programs.
- **Options that are not plain:** `curl -K`, `tflint --config`, `infracost --terraform-binary`, `actionlint -shellcheck`, `go … -toolexec`, `kustomize --enable-helm`, GNU `tar -T`, `sed -f` (in any cluster) and abbreviated `sed` options. Neither is `checkov` in a directory with a `.checkov.yaml`.
- **Wrappers:** a wrapper counts as the program it runs, and a `make` recipe's programs count too.

#### Variables

- A variable the command sets for a program (`X=1 cmd`, `env X=1 cmd`), or an upper-case one it sets in the shell, must have a literal value and a name on the safe list (`AWS_PROFILE`, `AWS_REGION`, `TF_LOG`, `TF_WORKSPACE`, `TF_VAR_*`, `LC_*`, `NO_COLOR`, …).
- `PAGER`, `GIT_PAGER` and `AWS_PAGER` may only be empty or `cat`.
- A lower-case shell variable (`d=/tmp/x`) is local and plain. The exceptions change what a name runs: zsh's special parameters (`path`, `fpath`, `functions`, `commands`, `aliases`, `builtins`, the `*_functions` hook arrays and the like) and any array or subscripted assignment.
- `hash NAME=PATH` and `hash -p` are not plain.
- `read`, `mapfile`, `readarray` and `getopts` that assign an upper-case name (`PATH`, `HOME`) or a zsh special array are not plain.

#### Repository state (git)

A git command is plain only when everything git reads on its own is known to run nothing.

- **Git directories.**
  - They are found as git finds them, on the physical path: a `.git` directory that is a repository, a gitfile, a bare repository, `commondir`. A `.git` that is not a repository is passed over, as git does.
  - The result is checked against the hook's own git (`rev-parse`): a disagreement is not plain.
  - Every submodule's directory under `modules/` is included. None may hold a hook other than `*.sample`.
  - `git --bare`, `--git-dir` and `--work-tree` are not plain.
- **Config files.**
  - The files read are the system config (`/etc/gitconfig`, the Homebrew and Xcode copies), the global one (`~/.gitconfig`, `$XDG_CONFIG_HOME/git/config`, or `GIT_CONFIG_GLOBAL`), each repository's `config` and `config.worktree`, and every file they `include`.
  - Every key in them must be on a safe list (`user.*`, `color.*`, `core.autocrlf`, `remote.*.url` to a network URL, `branch.*`, `pull.rebase` and so on).
  - The keys that name a program pass only with a known one: `core.editor` and `sequence.editor` an editor, `core.pager` and `pager.*` a pager, `gpg.program` gpg or `ssh-keygen`, `credential.helper` one of git's own helpers, GitHub CLI's or Git Credential Manager (checked for commands that reach a remote only), `filter.lfs.*` Git LFS.
  - An unknown key asks, so a key that runs a command cannot pass by being missing from a list.
- **Environment.** Git variables in the agent's own environment that name a program or another git directory (`GIT_DIR`, `GIT_SSH_COMMAND`, `GIT_CONFIG_PARAMETERS`, …) are not plain.
- **Remotes.**
  - The repository a command that reaches a remote names (`fetch`, `pull`, `push`, `clone`, `ls-remote`, `archive --remote`) must be a network URL (`https`, `http`, `ssh`, `git`), an scp-like address (`host:path`), a configured remote whose URL is one, or a name git would not take as a path.
  - Anything else is a local repository, whose hooks, upload-archive config or git run here, and is not plain. So is another URL scheme (it runs `git-remote-<scheme>` from `PATH`) and `clone -c`.
  - `gh` and `glab` subcommands that run git (`pr checkout`, `pr merge`, `repo sync`, `repo clone`, `mr checkout`) get the same state check.
  - Words after `--` for `git clone` are not plain.
- **The same command.** These are not plain:
  - a command that names a path in a git directory's hooks or config (`x.git/config` included);
  - a git command after an earlier step that can write git state without naming it (`git init`, `git clone`, an extracted archive, a recursive copy, a directory moved or linked).
- **Writes.** `git config` that sets a key off the safe list is not plain. With `--global`, `--system` or `--file` it is tampering in every tier.

#### Terraform state

A plain `terraform` or `tofu` call that may start providers stays plain only when all of these hold:

- every provider under `.terraform/providers` matches `.terraform.lock.hcl` as committed at git HEAD;
- that lock file is the one on the branch's upstream (when it has one);
- the configuration runs no program:
  - no data source that runs one (`data "external"`, `local_command`, `shell_*`);
  - no provider or backend block with an `exec` block, or with a `shared_config_files`, `shared_credentials_files`, `config_path` or `config_paths` that names anything but the user's own `~/.aws` and `~/.kube` files.

Details:

- **Which calls may start providers:** every subcommand but `fmt`, `version`, `output`, `init`, `get`, `modules`, `providers`, `providers lock`/`mirror`, `state list`, `state pull`, `workspace …`, `force-unlock`, `taint`, `untaint` and `metadata functions`. `graph` of any type starts providers and is checked.
- **How the configuration is read:** with Terraform's HCL and JSON parsers (`.tf`, `.tofu` and their `.json` forms), with the local modules it calls in any form, the modules `init` downloaded and every directory the module manifest names. A file over 1 MiB or one that does not parse counts as one that may run a program.
- **The same command:** a call after an earlier step of the same command writes the directory's configuration, `.terraform`, lock file or state is not plain either.

#### Persistent shells

Some MCP tools type input into a shell that keeps running between calls: iTerm's `write_to_terminal`, wcgw's `BashCommand`, Desktop Commander's `interact_with_process`.

- Input that defines shell state is tampering in every tier: an alias, a function, `hash`, `export`, a bare assignment, `shopt`, `setopt`, `source`, `eval` and other state builtins. The next call is judged on its own and would run what this one left.
- Every input to such a shell is judged as protected, since an earlier input may have changed its directory.
- A terraform call there that may start providers is not plain.

### Step 4: Each action gets a tier

For each action, the tier comes from the config and from name hints.

#### Signals from the config

Paths, workspaces, backends, AWS profiles and optional accounts. For `kubectl`, `helm`, `gcloud` and `az`: the kube context, GCP project or Azure subscription the command targets.

- When signals disagree, the most protected tier wins.
- If nothing matches, the tier is protected in strict mode (the default) or `default_tier` otherwise.
- Workspace and Azure subscription names match without regard to case.

#### Name hints

The words `prod`, `production`, `prd` and `live` are hints of a protected target.

- **Whole words only.** The word must stand between `/ _ . : - @ + = , ~`, whitespace or the ends. So `acme-prod-tfstate` matches and `acme-products-tfstate` does not.
- **Cancelled by a neighbour.** The word is ignored when the word just before it is `non`, `not`, `no` or `pre`, or the word just after it is `like`, `test` or `sandbox`. So `non-prod`, `non_prod`, `pre-prod`, `not-live` and `prod-like` are not hints, while `my-prod`, `nonprod-live` and `non-prod/us-east-1/prod` are. Only the adjacent words count, and glued forms such as `nonprod` and `preprod` were never whole words.
- **Where they are checked:** the path, the workspace, the AWS profile, the backend URL, the backend's `bucket`, `key`, `workspace_key_prefix`, `dynamodb_table` and `address` values, and the name of a `-backend-config` file.

#### Backend values

- **Recorded backend.** The values come from `.terraform/terraform.tfstate`. When an init in the same command line passes `-backend-config` files or `key=value` pairs, they come from those instead (the two paths use the same rules).
- The values are read whether or not the backend type is known (a directory may have no `backend` block and no `.terraform` yet).
- **`-backend-config` files** are read as Terraform reads them: as HCL, or as JSON when the name ends in `.json`. The backend is unknown when the file does not parse (an unquoted `bucket=x` included), holds a computed value, cannot be read, or is written by an earlier step of the same command.
- **Declared backend.** It is read from `.tf` and `.tf.json` files, override files last, with quoted or unquoted labels. `cloud` and `remote` workspace names are signals too.
- **Computed values.** A backend value that is computed (a variable or local, which OpenTofu allows, a function call, a template), or a `.tf.json` backend that does not parse, makes the backend unknown. A computed value in the declared block stays unknown when `-backend-config` sets other keys.
- **An unknown backend is judged as protected.**

#### Local state

- Local state named with `-state`, `-state-out` or `-backup`, or by a `local` backend's `path`, brings the tier of its directory. When no environment matches that directory, it brings the tier of an unknown directory (protected under strict).
- `workspace new -state=PATH` passes that tier to later commands in the same directory.

#### Provider blocks and variables

- **AWS providers.** The `profile` and the `assume_role` (and `assume_role_with_web_identity`) `role_arn` of every `aws` provider block, aliases included, are signals. They are matched against `aws_profiles`, `aws_accounts` and name hints.
- **Other providers.** The google `project`, the kubernetes `config_context` and the azurerm `subscription_id` are signals too.
- **Where provider blocks are read:** under any local name `required_providers` gives the provider, and in the local and downloaded modules. A value from a module's caller is unknown.
- **Variables.** A value that is `var.NAME` gives every value the variable can have: `-var`, `-var-file`, `TF_VAR_NAME`, `terraform.tfvars`, `*.auto.tfvars` and its default. A variable with no value found, an unreadable `-var-file` or any other computed value makes the target unknown, and judged as protected.

#### Terragrunt

- `terragrunt run --all`, `run-all` and `*-all` commands get the most protected tier among the units (`terragrunt.hcl`) under the directory.
- The unit's `remote_state` values are name hints. The literal parts of a value built with functions count.
- A local `terraform.source`, `--source` or `TG_SOURCE` brings the tier of the directory it names.
- `--config` (`TG_CONFIG`) judges the call in both the config's directory and the working directory.
- A unit's `remote_state` and local `terraform.source` are signals for `run --all` and `plan-check`.
- `stack run` is judged at the most protected tier anything under the directory could have.

#### Targets named by the command or the environment

- The AWS profile is `AWS_PROFILE`, else `AWS_DEFAULT_PROFILE`.
- helm's context is `--kube-context`, else `HELM_KUBECONTEXT`.
- A `kubectl config use-context`, `gcloud config set project` or `az account set` earlier in the same command is the target of the later calls that name none.

#### Unknown signals are protected, not absent

Each of these is unknown, and judged as protected:

- a workspace selected earlier in the same command with a name that cannot be resolved;
- a variable that selects a target (`TF_WORKSPACE`, `AWS_PROFILE`, `KUBECONFIG`, `TF_CLI_ARGS*`, `CLOUDSDK_*`, `AZURE_CONFIG_DIR`, …) exported with a value that cannot be resolved;
- arguments that cannot be resolved to a terraform call that changes infrastructure or state;
- a `-backend-config` that cannot be resolved before a later call in the directory;
- a credential runner's unresolved profile;
- the variables a secrets runner (`doppler`, `op`, `chamber`, `infisical`, `dotenvx`) sets.

Relative config paths in those variables are resolved against the command's directory.

#### Earlier steps and containers

- **A directory the same command writes.** A terraform call whose directory an earlier step of the same command writes is judged as protected. That covers the configuration, `.terraform`, the lock file or state, and a tree that `git checkout`, `reset`, `merge`, `pull`, `init -from-module` or an extraction rewrites.
- **Terraform containers.** A container's `-e` variables are the call's environment, and its in-container paths are mapped back through its mounts. `--env-file` makes the tier signals unknown.

#### Paths, links and other repositories

- **`..`** is resolved where the path so far really leads, after symlinks, as the kernel resolves it (`-chdir=m/..` with `m` a link into `prod` is `prod`). A `cd` through such a path goes there with `-P` and is unknown without it, since the shell's logical and physical answers differ.
- **Repository configs** are found from the directory's real path, so a directory reached through a link from outside the repository still gets the repository's config.
- **A directory reached through a symlink** is matched as written and as it resolves. A target no environment matches gets the strict or `default_tier` rule.
- **Another repository.** A command whose directory is under a repository config the session's config did not read (a `cd` or `-chdir` into another repository) is also judged by that repository's config, and the stricter tier wins.

#### The directory a command is judged in

- **Where it starts.** The directory comes from the agent's hook event:
  - Claude Code: the event's `cwd`, which is the shell's current directory at the time of the call (it follows an earlier `cd`).
  - Codex: `tool_input.workdir`, `working_directory` or `cwd` when the event carries one, relative values resolved against the event's `cwd`.
- **Inside the command.** A `cd` moves it from there. The decision log records the directory used as the action's `dir`.
- **Start-up files.** A shell started with `BASH_ENV` or `ENV` set, `ZDOTDIR` (zsh) or `--rcfile` runs that start-up file first, and the analyzer reads it there too. One it cannot name or read exactly is unresolved.
- **`hash -p PATH NAME`** makes a later `NAME` run `PATH`.
- **A zsh glob qualifier that runs code** (`*(e:…:)`, `*(+f)`) is unresolved.

#### When the host does not report the command's directory

Codex 0.165.0 sends no workdir, so the event's `cwd` is only the session root ([hosts.md](hosts.md)). The command could run anywhere under that root.

With `unknown_dir: most_protected` (the default), its tier is the most protected one it could have there:

- the root itself with its signals;
- every environment whose path globs could match a directory under the root;
- every environment matched by workspace, backend, AWS profile or account (a directory under the root could carry any of those);
- the strict or `default_tier` rule for a directory under the root that matches no environment. This is skipped when one environment's `/**` glob covers the whole subtree.

Also:

- Name hints on subdirectory names are not considered.
- The action's `matched` starts with `command directory not reported by codex; judged at the most protected tier under <root> (<env>, tier <tier>)`, so the decision log and `applygate explain --dir-unknown` show why.
- A `cd`, `pushd` or `-chdir` inside the command establishes the directory for that invocation.
- With `unknown_dir: session_root` (user config only) the command is judged at the root as if it ran there, and `matched` says so.

#### When the analysis loses the directory, or stops

The action is judged the same way, under the repository root (the directory of the outermost `.applygate.yaml`, else the event's directory), whatever `unknown_dir` says. `matched` says why.

The analysis **loses the directory** on:

- a `cd` or `-chdir` to a computed path;
- a bare `cd NAME` after the command sets `CDPATH` or `shopt -s cdable_vars` (a `CDPATH` from your own environment is followed as bash does);
- a `cd` to a tilde form other than `~` and `~/…` (`~-`, `~+`, `~user`);
- a script written earlier in the same command;
- a `command_not_found_handle` (which runs at any later point);
- a `cd` into a directory an earlier step links, moves or extracts into;
- a login `su -`;
- a `popd` past the stack;
- a command whose name, or an `eval` or `source` whose text, cannot be resolved;
- `find -execdir`;
- a directory option before the command a runner starts (`pnpm -C`, `yarn --cwd`, `mise --cd`, `poetry -C`, `parallel --wd`);
- a Terraform container whose `-w` is not under a mount.

The analysis **stops** on a parse error, the statement budget or the work limit.

### Step 5: Preflight

Preflight looks for:

- the backend changed since init;
- stale or archived state. When `preflight.live_state` is on in the user config, a read-only state pull also compares lineage and serial;
- for applies and destroys: lock-file and source drift since HEAD.

### Step 6: Plan gate

The plan gate runs for `apply <planfile>`. It compares the planfile's workspace with the selected workspace, then applies the `show -json` rules ([Findings](#findings)).

**A plan that deletes or replaces any resource is reclassified as `destroy`.** A replace destroys the old instance, so it is judged like a delete.

**One exception: a plan whose only deletes and replaces are routine replaces is a `routine-replace`,** which a standard tier allows and a protected tier still blocks. A replace is routine when all of these hold:

- the resource is of a type that holds no data and that its provider replaces on routine change. The list is `aws_launch_template`, `aws_launch_configuration`, `aws_ecs_task_definition`, `aws_lambda_layer_version`, `aws_lambda_permission`, `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`, `terraform_data` and `null_resource` (`routine_replace_types` in `internal/plangate/rules/aws.json`). A type that is not on the list is not routine, whatever it is;
- the plan deletes it and creates it, and nothing else;
- it is not a stateful type and not listed in `protected_resources`;
- no `exposure`, `unknown-watched` or `code-execution` finding names it. A rule replaced by one open to the internet, or a `null_resource` whose provisioner would run, is asked about as before.

One delete, or one replace that is not routine, makes the whole plan a `destroy`. To have a routine replace asked about again, list the address under `protected_resources` ([config.md](config.md)).

**Which tier the plan brings:**

- **A plan file kept in another Terraform directory** was made against that directory's state, so that directory's tier joins the command's (`terraform apply ../prod/tfplan` from `dev` is a protected-tier action).
- **A plan file kept outside one** (`/tmp`) says nothing about where it was made, unless its directory is in a configured environment's paths (`envs/prod/out/tfplan` is prod's).
- **The planfile's path is resolved physically,** so `m/../tfplan` through a link `m` is where the link leads.
- **A plan read from `/dev/…` or `/proc/…`** (`apply /dev/stdin < ../prod/tfplan`) has no directory and is judged as protected.
- **When the two workspaces differ,** the action is judged by the more protected of the two tiers (a `prod` plan applied from `staging` is a protected-tier action, and the log records that tier). So the critical `workspace-mismatch` finding blocks whichever side is protected.

**A plan the same command writes or moves:**

- A planfile that an earlier step of the same command writes, or names as an argument of a program applygate does not model (`aws s3 cp`, `scp`, `rclone`, `7z x`, a script), is a critical `plan-unverifiable` finding, since the plan on disk is not the one that would be applied.
- Such a plan brings the tier of the directory its `plan -out` ran in (`terraform -chdir=../prod plan -out=/tmp/p && terraform apply /tmp/p` is prod's). Written by anything else (`cp`, `ln`, a download), it is judged as protected.

**When the command's directory is unknown** (step 4) and a relative planfile is not in the reported directory, applygate first searches for it under the root. The search is bounded: `.git` and `.terraform` are skipped, and it stops at 8 levels or 20,000 directories.

- One copy identifies the command directory, which is then judged as known and is where `show -json` runs.
- Several copies are a critical `plan-ambiguous` finding, and nothing is read.
- No copy keeps `plan-missing`.
- A search cut short by its limits, the depth limit included, is `plan-ambiguous` too.

**How the plan is read:**

- Before `show -json` runs, the providers it would start are checked against `.terraform.lock.hcl` as git HEAD has it.
- With Terragrunt the plan is shown with `terraform` in the `.terragrunt-cache` directory that holds it, never with `terragrunt show` ([limits.md](limits.md)).
- The engine is `plan_gate.engines` when set, else the name on `PATH`. Under a managed install it must be owned and writable by root only, or the plan is unverifiable ([managed.md](managed.md)).

### Step 7: Verdict

Verdict = max(class × tier, finding severity × tier) across all actions.

- If the host cannot ask, ask becomes block.
- Observe mode logs the verdict and returns allow.

### Step 8: MCP calls

- A call to a known infrastructure MCP tool is first translated into the command it is equivalent to and judged by steps 2 to 7 as that command. The table and its limits are in [mcp.md](mcp.md).
- A shell tool of a server the table does not know is judged as a shell command.
- A call that names a guard file is judged as a write to it.
- Other MCP calls are logged and allowed, or go to the model judge (step 10) when it is on.

### Step 9: One-time approvals

Approvals (`approvals`) are off by default and can be turned on in the user config only.

**Why off by default:** on one machine an agent can reach any terminal the person can, so no approval channel is out of its reach without an operating-system check, which applygate does not have yet. Until then an ask on a host that cannot prompt stays a block.

**When the user config turns approvals on:**

- The hook records a request for an ask enforced as a block, and its message names an ID.
- A person who runs `applygate approve ID` at a terminal and types the environment name (the tier when the environment has no name) allows the agent's next identical call once, within 15 minutes. A request expires after an hour.
- **What "identical" means.** The approval is bound to:
  - the agent, session, tool, kind of call, working directory and whether the host reported it;
  - the command, file paths, the full content of a write and the full arguments of an MCP call;
  - for every action: its class, engine, command, directory, environment, tier, workspace, backend, AWS profile, kube context, GCP project, Azure subscription and plan SHA-256.

  So a changed command, file content, directory, environment or plan is judged afresh.
- A policy block can never be approved.
- An agent that runs `applygate approve`, including through `script`, `expect` or code in another language, is blocked as guard tampering in every tier.
- The store (`approvals.json` next to the decision log) is a guard path.

### Step 10: Model judge

The model judge (`judge`) is off by default and can be turned on in the user config only ([judge.md](judge.md)).

- **Which calls go.** After step 7, a call whose verdict is allow goes to a language model when it passes the judge's filter and a part of it was not recognized: a command outside the local-only programs, any file write, an MCP call the table does not cover. The part after a recognized, allowed action counts: `aws s3 cp x s3://b/x && pulumi destroy --yes` is judged.
- **The result.** The verdict becomes the stricter of the two. The model's escalation is an action of class `model-judge`, and step 9 applies to it, including to a block it gives.
- **Failures.** An error, a timeout or an allow leaves the decision unchanged.

## Verdict table

| Class | Protected | Standard | Disposable |
|---|---|---|---|
| read-only | allow | allow | allow |
| apply-saved-plan | plan gate | plan gate | allow |
| unreviewed-apply | block | ask | allow |
| destroy | block | ask | allow |
| routine-replace (a saved plan whose only replaces are routine, step 6) | block | allow | allow |
| state-surgery | block | ask | ask |
| cloud-destructive | block | ask | ask |
| guard-tampering | block | block | block |
| hook-rewrite (git rewrites a repository or session work tree that holds hook files or the repository config) | ask | ask | ask |
| dynamic | ask | ask | allow* |
| unknown-wrapper | ask | allow | allow |
| mutating (import, refresh, test) | ask | allow | allow |
| cloud-write (create/update calls) | ask | allow | allow |
| credential-access | ask | ask | ask |
| complex-shape (strict shapes) | ask | allow* | allow* |

\* A complex-shape command that can also run code the analysis does not follow (python3, perl, an unresolved program name, a nested agent) is judged a second time at the most protected tier under the repository root. So it asks in a standard or disposable directory when a protected environment is under the root ([limits.md](limits.md) lists the costs of this cross-directory rule).

**`init -reconfigure`** is state surgery only when it is bare or migrates state.

- With `-backend-config` (resolved files or `key=value` pairs) and without `-migrate-state`/`-force-copy` it is read-only, because it only re-points the working directory.
- Later commands in the same command line are then judged against the backend the config describes, and the config file's name is a name hint (`production.backend` → protected).
- The open-source corpus trial found `init -reconfigure` used routinely to switch environments ([the trial report](../review/oss-corpus/trial.md)).

## Finding severity × tier

| Severity | Protected | Standard | Disposable |
|---|---|---|---|
| critical | block | ask | log |
| high | ask | log | log |

## Findings

The Source column says what the finding is read from: the plan (its `show -json` output, or the search for the file), the planfile's own record of its workspace, the command line, or preflight.

| Rule | Severity | Source |
|---|---|---|
| destroy-count (destroys + replaces > `max_destroy`; protected default 0) | high | plan |
| stateful-destroyed (types in `rules/aws.json`) | critical | plan |
| protected-resource (addresses matching `protected_resources` in config, any type; `count` and `for_each` keys are ignored on both sides, so `aws_instance.bastion` covers `aws_instance.bastion[0]` and `module.data` covers `module.data["eu"]`) | critical | plan |
| code-execution (a provisioner such as local-exec/remote-exec on a resource the plan creates, replaces or destroys, or an `external` data source whose read the plan defers to apply: applying runs code with the user's credentials) | high | plan |
| stateful-unprotected-create (a database created with no safety net: deletion protection off **and** final snapshot skipped) | high | plan |
| stateful-create-note (a database created with only one safeguard off, e.g. protection off but a final snapshot kept) | info | plan |
| protection-removed (deletion protection, final snapshot, retention 0, force_destroy, versioning, PITR, …) | critical | plan |
| exposure (0.0.0.0/0 or ::/0, or a split such as 0.0.0.0/1, on admin/DB ports or all ports, default security groups included; public bucket ACL, AllUsers grant, policy or access block, where a policy's `*` principal counts alone or in a list and an empty `Condition` limits nothing; IAM `*`, `svc:*` or `NotAction` allows; admin policy attachments, a role's `managed_policy_arns` and inline policies; a trust policy any principal may assume; `publicly_accessible` databases; on an in-place update, only exposure the update adds) | high | plan |
| unknown-watched (an attribute the exposure rules check on a created or updated resource, or a protection rule checks on an updated or replaced one, is known only after apply, such as a CIDR from another resource or a computed `deletion_protection`) | high | plan |
| state-infrastructure (the backend bucket or lock table) | critical | plan |
| out-of-scope (`plan_gate.scope`) | high | plan |
| plan-errored, plan-unreadable (plan exists but cannot be read) | critical | plan |
| plan-too-large (the `show -json` output is over 16 MiB, so it is not parsed) | critical | plan |
| plan-missing (the plan file does not exist, so there is nothing to apply) | high | plan |
| plan-actions (the plan invokes Terraform actions, which run provider operations the resource changes do not describe) | high | plan |
| plan-ambiguous (the command directory is unknown and several copies of the relative planfile exist under the session root, so the plan that would be applied cannot be identified) | critical | plan |
| plan-unverifiable (an earlier step of the same command writes the planfile, or names it as an argument of a program applygate does not model, so the plan on disk is not the one that would be applied; step 6) | critical | command |
| workspace-mismatch (planfile workspace ≠ selected; the action takes the more protected of the two workspaces' tiers) | critical | planfile |
| backend-changed | high | preflight |
| backend-config-unreadable (an init in the same command points at a `-backend-config` file that cannot be read; only on later state-changing commands) | high | preflight |
| stale-state | high | preflight |
| state-lineage (local state file is from another lineage, behind or ahead of the remote serial; only with `preflight.live_state`) | high | preflight (state pull, opt-in) |
| lockfile-drift | high | preflight (git) |

IAM `Resource: "*"` on its own is not flagged, because it is very common. This is deliberate.
