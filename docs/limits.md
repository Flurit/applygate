# Limits

applygate reduces the chance that a mistaken or manipulated agent damages infrastructure. It cannot guarantee that it won't. Use it together with plan-only credentials and an isolated runner.

This page lists what applygate does not see, cover or guarantee, the harmless commands it asks about or blocks, and what has not been tested. Each limit is listed once, under the topic it belongs to. The rules themselves are in [policy.md](policy.md).

## Terms used on this page

- **Verdict.** allow, ask or block. On a host that cannot show a prompt, an ask is enforced as a block.
- **Tier, environment.** Every directory and target is protected, standard or disposable. An environment is a named entry in the config that gives a tier to what it matches. With the default `strict: true`, a directory that no environment matches is protected.
- **Tier signal.** A fact that selects the tier: the path, workspace, backend, AWS profile, kube context, GCP project or Azure subscription. A name hint is `prod`, `production`, `prd` or `live` as a word in one of those names.
- **Engine.** `terraform`, `tofu` or `terragrunt`.
- **Repository root.** The directory of the outermost `.applygate.yaml`, else the session directory.
- **Most protected tier under the root.** The most protected tier that any directory under the root could have. applygate uses it when it does not know where a command runs.
- **Plain command, strict shapes.** A plain command is a list or pipeline of known programs, each called with subcommands and options that are known not to run another program. With `strict_shapes: true` (the default), a shell command that is not plain asks in a protected directory. In a repository with no config it asks only when it names an infrastructure tool or a guard file ([A repository with no config](#a-repository-with-no-config)).
- **Unresolved.** A word, value or file that the analysis cannot work out without running the command.
- **Code the analysis does not follow.** A program or construct whose effect the analysis cannot work out, such as an interpreter or an unresolved program name. A command that can run such code is also judged at the most protected tier under the root ([the cross-directory rule](#commands-that-can-run-code-the-analysis-does-not-follow)).
- **Guard file, tampering.** A guard file controls the hook, the agent or a program the hook trusts: hook settings, applygate's config, and others. An agent's change to one is guard tampering, which is blocked in every tier.
- **State surgery.** A write, move or removal that touches a Terraform state file. It is blocked in a protected tier and asked about in the others.
- **Managed install.** A root-owned install that the agent's user cannot change ([managed.md](managed.md)).

## What it cannot see

- **Paths around the hook.** If the agent can reach cloud credentials and run code by any route the hook does not inspect, applygate does not see it. Examples: an MCP server with its own credentials, a tool the matcher does not cover, or a process started earlier in the background.
- **Calls the rules do not recognize are allowed.** Examples: other infrastructure-as-code tools, PaaS CLIs, database clients, object storage, SDK code that does not mention a known tool, unknown scripts and MCP tools. The opt-in [model judge](judge.md) sends them to a language model, which may make the verdict stricter. It is a model, so it misses some and can be fooled, and it is off by default.
- **Allowed programs run code with the agent's credentials.** `terraform plan` (providers and external data sources), `make`, `pytest`, `go test`, `npm test`, and `git` hooks and filters all run code. A plain shape says that the command line is harmless, not that what it runs is.
- **The verdict and the execution are separate events.** The file, the directory or a link that the hook read can change before the command runs. Parsing does not address this.
  - **Saved plans.** `terraform apply tfplan` is read when the hook runs and applied later from the same path. A process that swaps the file in between applies another plan. A managed install does not close this. `applygate apply` is not affected: it copies the plan file once into a private directory and gives the engine that copy.
  - **A host whose hook does not start** runs the command unjudged ([Agents and hosts](#agents-and-hosts)).
- **Shapes are a table.** A program is plain with certain subcommands and options because none of them is known to run another program or write a file. If one does, it is not covered.
  - Most programs are plain only with options listed by exact name. An abbreviated long option is not plain.
  - These programs take any arguments, because no option of theirs is known to write or run anything, and their GNU and BSD option tables are long: `grep`, `egrep`, `tr`, `cmp`, `stat`, `df`, `du`, `column`, `od`, `jq`, `nl`, `fold`, `comm`, `join`, `paste`, `sha256sum`, `shasum`, `md5sum`, `id`, `whoami`, `uname`, `printenv`, `shellcheck` and the shell builtins.
  - `aws`, `az` and `gcloud` operations (some 15,000 for `aws`) are not listed one by one. The global options are an exact list. An operation is plain when its verb is a read verb, and any other option is accepted by its form (a lower-case `--name`; for `az` also `-x`).
  - Some writers have no option table: `tar`, `rsync`, `dd`, `7z`, `cpio`, `patch`, `bzip2` and the like, `openssl`, `sed -i`, `find`, `aws` and the remote copies. What they write is worked out by rules over their words, and those rules do not know which options take a value. `rsync`, `dd`, `7z`, `cpio`, `patch`, `bzip2`, `openssl` and `scp` are never plain, so a protected directory asks about them whatever the rule finds. `tar`, `sed`, `find` and `aws` can be plain.
- **What strict shapes trusts.** A program found on `PATH` by name is taken to be the program it names. So is a program that git config names (an editor, a pager, gpg, a credential helper). Writing one into a `PATH` directory the user can write is blocked as tampering, but a route the hook does not see can place one there. On Apple silicon the Homebrew prefix is the user's to write.

## Shell analysis

### The shell model is bash

- **The hook is not told which shell runs the command.** The command is parsed and modelled as bash. `zsh`, `fish`, `dash` and BSD option parsing can differ from what was analyzed.
- **zsh.** These zsh forms are handled:
  - its own tables (`functions`, `commands`, `path`), `hash NAME=PATH`, its hook functions, `chdir`, `repeat N`, the `nocorrect` and `-` modifiers, and a `cd` as the last element of a pipeline;
  - `cd OLD NEW` and `pushd OLD NEW`, which replace OLD with NEW in the working directory: the directory becomes unknown;
  - a brace expansion in a redirect target, which zsh writes to each name (bash refuses): a write to each name;
  - `>!`, `>>!`, `>&!` and `&>!`: redirects to the next word;
  - `~+` and `~-`: expanded, or unknown.

  Other zsh-only syntax that bash parses differently may not be handled: `$=x`, arrays with 1-based indexes, `zmodload zsh/mapfile`, `emulate -c`, global aliases, `autocd`, `zmv` and `zargs`.
- **Other shells.** `fish`, `csh`, `tcsh`, `nu`, `elvish` and `xonsh` code is read with the bash parser. Text it cannot parse is a problem (an ask in protected tiers). Text it parses differently from that shell is analyzed as bash.
- **New spellings keep turning up.** Every review of the shell analysis has found spellings it did not model. Expect more after any release.
- **Aliases and functions from the user's shell profile are not known.** Only aliases defined in the same command or in config (`aliases:`, default `tf: terraform`) are expanded. They are expanded wherever the name appears, as if `expand_aliases` were on. An alias also takes effect on the line that defines it, which a shell does not do, so the program of that name is followed as well.
- **Functions and wrappers.** A function is not what `command`, `env`, `exec`, `nohup`, `timeout`, `nice`, `sudo`, `xargs` or `find -exec` start. A command that defines such a function and calls it through one of them is not followed. `unset -f` forgets a function. `unset NAME` of a function name that may also be a variable is not followed. `echo`, `printf`, `pwd`, `dirname`, `basename` and `which` are not evaluated when a function or alias has their name.

### Values known only at run time

- **Unresolved values.** These are unresolved:
  - environment variables applygate cannot see, and `read` from stdin;
  - command substitutions other than `echo`, `printf`, `cat`, `base64`, `xxd`, `rev`, `which` and `dirname`;
  - words the shell would expand against the disk or the locale: an unquoted glob, zsh's `=name`, `$'\u…'`;
  - the variables assigned by `read`, `printf -v`, `mapfile` and `getopts`, and every variable after `declare -n`;
  - a brace sequence of more than about a million words, and a word or variable value that grows past 64 KiB through expansion.

  In a command position they cause an ask. As plain arguments to non-infrastructure programs they do not. Each unresolved word records why it is unresolved (the variable, command substitution, glob, positional parameter or arithmetic), and `applygate explain` prints the reason. An unresolved terraform option, `-chdir` value or subcommand makes the call not plain.
- **Evaluation the analysis cannot show to be harmless** is treated as code it does not follow. `n=$(wc -l < f); [[ $n -gt 3 ]]` is such a case and asks outside a disposable directory. The forms are:
  - arithmetic (`$((x))`, `(( ))`, `let`, a C-style `for`, `[[ a -eq b ]]`, `${x:off:len}`, `${a[i]}`) whose operand is not a number or a variable holding one;
  - a variable name with a `$(…)` subscript given to `read`, `declare`, `unset`, `printf -v` or `test -v`, with or without `command` in front;
  - `mapfile -C`, `compgen -C`, `complete -C`;
  - a `PS4`, `PS1` or `PROMPT_COMMAND` that holds a command, and `set -k`;
  - `${!x}`, `${x@P}` and `${x@E}`, which run a command substitution held in the value;
  - a chain of more than 20,000 `&&`, `||`, `|` or `+`;
  - a process substitution given to `bash`, `source` or `.`.
- **Variables that hold a command.** `EDITOR`, `VISUAL`, `PAGER` and the other variables a program runs are judged as the command they hold.
- **Exported variables.** `set -a` and `set -o allexport` export every later assignment. Assigning a variable that the hook's own environment already has (`AWS_PROFILE`) changes what a child process sees. Both are read.
- **Encoded payloads.** `base64 -d`, `base32 -d`, `gzip`/`gunzip`/`zcat`, `xxd -r -p`, `rev` and `tee` piped into a shell are decoded and the result is analyzed. Decoder output is capped at 256 KB. An encoding applygate does not implement, or a payload built from unresolved values, is an ask.
- **Files written earlier in the same command.** A script, sourced file, `$(cat f)` input or makefile that an earlier step writes is unresolved. It is not read as it is on disk.
  - The steps followed are redirects, `tee`, `cp`/`mv`/`ln`/`install`/`rsync`, `dd of=`, `curl -o`/`wget -O`, `sed -i`/`perl -i`, `tar`/`unzip` extraction and the git commands that rewrite the work tree.
  - A file written another way (an interpreter's `open()`, a program the analyzer does not model) is read as it is on disk. Guard files are not affected by this: any program that names one is tampering unless it only reads ([threat-model.md](threat-model.md)).
- **Commands over 1 MiB** are not parsed. They count as code the analysis does not follow.
- **A shell that reads its commands from somewhere else.** A shell with no command string and no script reads its input from a descriptor opened earlier (`exec <<< TEXT; bash`, `exec 3< FILE; bash <&3`), from a file opened for reading and writing (`bash <> FILE`) or from the terminal. It is code the analysis does not follow, and so is a `>(bash)` sink. A here-document, a here-string, `< FILE` and a pipe on the same command are followed. `bash --version` and `--help` are not affected.

### What counts as a write

- **Redirections on a command with no program** (`env > FILE`, `cd . > FILE`, `set > FILE`, `sudo env > FILE`) are writes, as on any command.
- **Other write forms that are read:** `>&`, `env -S`, `env -C`, `sed -Ei`, `find -fprint`, `tar c`, `tar -r`/`-u`, a decompression, `tree -o`, `git log --output`, `aws s3 cp`, `aws` calls that save their answer to a file (`get-*`, `eks update-kubeconfig --kubeconfig`), `cp`/`mv`/`ln --target-directory=DIR`, `zip -mj` clusters, `zip NAME` (also `NAME.zip`), `7z a`, `openssl -out FILE`, `touch`, and `tar` old-style clusters (`tar xfC a.tar DIR` extracts into DIR). `find` takes its global options (`-P`, `-H`, `-L`, `-Ox`, `-D`) first. `unzip -l` and the other listing forms write nothing. An empty directory that `mkdir` creates replaces nothing and is not counted.
- **A plain call is judged on the reading that made it plain.** For a program with an option table, the write rule uses the words the table matched: the destination of `cp -at DIR`, the `-O` inside `curl -sO`, an operand after `--` that starts with a dash.
- **A call that is not plain is read leniently.** An unlisted option is taken as a flag and an unresolved word as an operand. A rule that names one operand then names every operand that may be it: for `cp`, all but the first. So a call of a writer with an unlisted option counts every operand but the first as written, and a state or guard file among them is judged as written.
- **The content of a write is not judged.** A `.tf` file that gains a `local-exec` provisioner, or a `terragrunt.hcl` that gains a `before_hook`, is a file edit, exactly as `sed -i` or `cat >` on the same file is. It runs only through a later `apply` or `terragrunt` command, which is judged on its own. `terraform plan -out` over a configuration file is not guarded, as any other write of one is not.
- **`git`'s writes to the work tree** are judged by what the subcommand does, not by its options.
- **`applygate suggest --out PATH`** writes any new path that is not a state or guard file.

### Wrappers and runners

- **Wrappers that are taken apart.**
  - Credential and secrets runners: `aws-vault exec`, `aws-okta exec`, `gds aws`, `saml2aws exec`, `aws-sso exec`, `envchain`, `doppler run`, `op run`, `chamber exec`, `infisical run` and `dotenvx run`, with or without `--`. The command string of `doppler run --command`, `infisical run --command` and `sops exec-env`/`exec-file` is analyzed as shell.
  - Development-environment runners: `direnv exec`, `mise`/`rtx exec`, `asdf exec`, `devbox run`, `nix develop|shell -c` and `nix-shell --run`.
  - Any program listed under `wrappers:` in the config.
- **Environments loaded by a runner are unknown.** The secrets runners set variables applygate cannot see. `direnv exec`, `mise exec`, `asdf exec`, `devbox run`, `nix develop -c` and `sops exec-env` load variables (`AWS_PROFILE`, `TF_WORKSPACE`, …) from files the hook does not read. Those tier signals are unknown, not absent, so the call is judged as protected. `doppler run -- terraform plan` and `mise exec -- terraform plan` ask in a disposable directory too.
- **Unknown wrappers.** For any other program, a backstop analyzes the arguments from a standalone `terraform`, `tofu` or `terragrunt` onward, and the value of a `--run`/`--command`/`-c`/`--cmd`/`--exec`/`-x` flag that starts with one of them. A command guessed this way asks. Not seen:
  - an unknown program that runs `aws`, `kubectl` or another CLI from its arguments (a team's own runner), unless it is listed under `wrappers:`;
  - a command passed as one quoted argument without such a flag (`foo run "terraform destroy"`). Quoted strings are where text mentions live, so they are left alone ([backstop.md](../review/oss-corpus/backstop.md)).
- **"Followed" is decided per invocation.** A program counts as taken apart only when the invocation itself started others that the analysis follows: `make` with its recipes, a terraform image's command, `xargs`, `bash -c` with literal text, `pnpm exec terraform`. A program name that was once used as a followed wrapper is not followed by name elsewhere.
- **A repository config's `wrappers` entry** cannot name a program the classifier reads the arguments of (plain, `g`-prefixed or versioned names). That filter is a name list. A review reported that a program missing from it (`busybox`, `bsdtar`, `rename`) declared as a wrapper lowered a block to an ask; this is not known to be fixed.
- **`xargs -0`, `-d` and `-L`** split the input another way, so its text is unknown. **GNU `parallel`** quotes the arguments it appends, and the analysis appends them unquoted, so a command built that way can be analyzed in the wrong directory.
- **Other task runners are not followed:** `task`, `just`, `mise run`, `npm --prefix … run` and `docker compose run`. They are programs with no shape.
- **Wrappers that run a command somewhere else** (`mosh`, `vagrant ssh`, `kubectl exec`, `aws ssm send-command`, `az vm run-command`) are judged in the local directory.
- **Renamed engine binaries** (`terraform_1.5.0`, `tofu1.6`, `tg`) are not recognized as Terraform, OpenTofu or Terragrunt. They are programs with no shape, so the destroy and apply rules do not apply to them.

### make

- **Variables** are expanded only when the Makefile defines them literally. `include` is followed for literal file names. A target-specific variable is not analyzed.
- **What is read:** option clusters (`-sC dir`), abbreviations of long options (`--dir`, `--direc`), `MAKEFLAGS`, `--eval`, command-line variables, and `export` and `.EXPORT_ALL_VARIABLES` in a Makefile. `make -j` and `-l` take an optional number, so `make -j destroy` runs `destroy`.
- **What cannot be analyzed:** `MAKEFILES`, and a Makefile that uses `define`, `ifeq` and the other conditionals, pattern rules, functions, `.DEFAULT_GOAL`, `$(eval)`, `$(call)` or `$(shell)`. Such a `make` runs in an unknown directory. It asks in protected tiers, and in a disposable directory too when the config has a protected environment anywhere under the root.

### Containers and remote shells

- **`ssh host '…'`** is analyzed with an unknown directory, which is protected in strict mode.
- **Images.** `docker run … hashicorp/terraform …` is unwrapped only when the image name contains `terraform`, `tofu` or `terragrunt`. The image of `docker`, `podman` and `nerdctl run` or `create` is the first word after the options, not a later word that mentions terraform.
- **Directories.** A Terraform container is judged in the host directory mounted at its `-w`. Without both a mount and `-w`, its directory is unknown. The container's own filesystem is not mapped except through `-v` and `--mount`.
- **Options.** Container options glued to their value (`-eVAR=val`, `-ieVAR=val`) are read.
- **`docker exec CONTAINER terraform …`** is judged in an unknown directory. `docker exec CONTAINER sh -c '…'` is a program the analysis does not follow.

### Options that run programs

- **Followed:** `ssh -o 'ProxyCommand …'` (also the space form), `rsync -e` glued or clustered, `scp -S`, `flock -c` anywhere, `git --upload-pack`, `--receive-pack`, `--exec` and `filter-branch`'s filters, and `sudo -D DIR`. `rg --hostname-bin` is known to run a program and is not plain.
- **Matched as the program reads them.** A single-dash option of several letters is matched glued to its value (`zip -TTprog`). For a program that parses options with Go's `flag` package, the double-dash spelling is the same option (`go list --toolexec`, `go env --w`, `actionlint --shellcheck`). Git options that run a program are matched in a cluster (`rebase -qx CMD`) and by any unique prefix (`--exe`, `--tree-f`, `--open-f=`).
- **Not covered:** the `libvirt` provider's `uri` command parameter and other provider attributes that name a program.

### Code in other languages

- **Not parsed as programs.** `python -c`, `node -e`, here-documents piped into an interpreter and scripts with non-shell shebangs are not executed or parsed.
  - If the code mentions terraform, tofu, kubectl, aws operations or guard files, applygate treats it as dynamic (ask) or as tampering.
  - Mentions of an AWS SDK count too: `boto3`, `botocore`, `aws-sdk`, `@aws-sdk/`, `github.com/aws/aws-sdk-go`. A script that calls AWS directly asks in protected and standard tiers, including a script that only reads.
  - If the code mentions none of these, it passes. SDKs for other clouds, and code that loads the SDK indirectly (a helper module in another file), are not recognized.
- **Input typed into a running process.** Input that an MCP shell server types into a running process is judged as a shell command, whatever the process is. Code typed into a Python or Node session may be asked about ([mcp.md](mcp.md)).
- **Perl, Ruby, PHP and PowerShell bodies** are never treated as file edits.

### File-only Python and Node bodies

Coding agents edit `.tf` and `.hcl` files with small `python3 - <<'EOF'` scripts whose text mentions `terraform` (a regex over `${terraform.workspace}`, an HCL block being inserted). A Python or Node body that mentions a tool is treated as a file edit and allowed only when every condition below holds. The decision log notes it: `python3 code mentions terraform but only reads and writes files … treated as a file edit`. Any other body that mentions a tool keeps its ask or block, and the reason names the construct (`uses subprocess`, `uses getattr()`, `passes open by reference`, `open() writes to a path it builds at run time`, `names the state file terraform.tfstate`, `writes run.sh (not a repository configuration file)`, `writes ../x.tf outside the working directory`).

The check reads text, not a program. A body with no tool mention at all is not examined.

1. **The body is known in full.** It is a literal `-c`/`-e` argument, a quoted or fully resolved here-document, or a script file on disk. Text from a decoder pipe or an unresolved variable never qualifies. The interpreter's other arguments must resolve and name no guard or state file.
2. **It names no sensitive file anywhere in its text,** strings and comments included:
   - a state file: `.tfstate`, `.terraform/`, `.terraform.lock.hcl`;
   - guard or hook config: `.applygate.yaml`, `.claude/settings*`, `managed-settings*`, `.codex/`, `.cursor/`, the config's `protected_paths` and `log_path`;
   - a credential store: `.aws/credentials`, `.aws/config`, `~/.aws`, `.terraformrc`, `.terraform.d/credentials.tfrc.json`, `.netrc`, `.pypirc`, `.npmrc`;
   - a shell start-up file (`.bashrc`, `.profile`, `.zshrc`, `.envrc`, …), `.ssh`, `.kube`, `.docker`, `.git/hooks`, `authorized_keys`, `crontab`/`cron.d`, `sitecustomize` or `.pth`.

   The directory names need a path boundary, so `provider.aws` or `module.aws` in HCL text and the word `applygate` in a comment are not matches. The cost: an edit that inserts an HCL block containing `terraform.tfstate` as text asks.
3. **It imports only text and file modules,** found anywhere in the code (after `if …:` and `try:` too).
   - Python: `re`, `sys`, `os`, `json`, `glob`, `io`, `yaml`, `hcl2`, `csv`, …
   - Node: `fs`, `path`, `os`, `util`, …, with or without `node:`.
   - These keep the body opaque: a local helper module; a network, cloud-SDK or decoder module; `pathlib` (its `/` joins cannot be followed), `fileinput`, `tempfile`, `asyncio`; `import os as …`, `from os import …`; importing a file function by name (`from io import FileIO`).
4. **Nothing in its code names a way to run, load or reach into anything,** called or passed by reference.
   - Python code is first split from its string literals and comments, so these checks see identifiers only: `subprocess` (as a substring, so `create_subprocess_shell` counts), `os.system`, `os.exec*`, `os.popen`, `os.spawn*`, `os.fork*`, `os.chdir`, `os.environ`, `os.fdopen`, `pty`, `shutil`, `importlib`, `__import__`, `eval`, `exec`, `compile`, `getattr`, `setattr`, `help`, `breakpoint`, `ctypes`, `pickle`, `sys.modules`, `sys.call_tracing`, `sys._getframe` and frame attributes, `operator.attrgetter`/`methodcaller`/`call`, `string.Formatter`, `argparse.FileType`, `__call__` and every other double-underscore or private (`._x`) attribute, `yaml.load`/`Loader`, and `os`, `io` or `sys` reached through another module (`glob.os`, `yaml.io.open`).
   - A writing file function (`open`, `io.FileIO`, `os.rename`, `os.replace`, `os.symlink`, `os.remove`, …) used without a call is "passed by reference" and keeps the ask: `f=open`, `map(os.system, …)`, `[open][0]`, `functools.partial(os.replace, …)`.
   - Node bodies are checked as whole text, because their regular-expression literals make a scanner ambiguous. That is more conservative. The names are `child_process`, `execSync`, `spawn`, `exec`, `fork`, `.call`/`.apply`/`.bind`, `eval`, `new Function`, `vm`, computed `require(…)`/`import(…)`, `fetch`, `process.binding`, `process.chdir`, writes to `process.env`, `globalThis`, `constructor`, a member reached with a string (`fs['writeFileSync']`), and a writing `fs` function used without a call (`const w = fs.writeFileSync`). The destructuring idiom `const {writeFileSync} = require('fs')` is fine unless it aliases a name.
5. **It builds no text at run time:** `\x..`/`\u....` escapes, `chr()`, `fromhex`, `[::-1]`, `base64`, `atob`, `fromCharCode`. Identifiers are NFKC-folded first, as Python does.
6. **Every write target passes a positive rule.** This covers every file the body writes, creates, renames, links, copies or removes: `open` with a writing or unknown mode, `io.FileIO`, `os.open`, `os.remove`/`rename`/`replace`/`symlink`/`link`/`mkdir`/`chmod`/…, `fs.writeFileSync`/`renameSync`/`symlinkSync`/`cpSync`/….
   - **The target is named by a complete string literal,** or by a name bound exactly once to one and never bound again. A binding by any of these does not count: a `for` loop or comprehension, a `with`/`except`/`import … as` alias, a `def`, `lambda`, `function`, arrow or `catch` parameter, a `def` or `class` name, a `match`/`case` capture, tuple or object destructuring, an ES `import`, `global`/`nonlocal` or a walrus.
   - **The path stays under the working directory** once resolved against it: no `..` escape and no absolute path elsewhere. With the directory unknown, only a relative path without `..` is judged, on its own text.
   - **It has no hidden segment:** `.github/`, `.git/`, `.envrc`, `.tflint.hcl`, guard directories.
   - **It is not a tool manifest:** `package.json`, `pyproject.toml`, `Pipfile`, `Cargo.toml`, `docker-compose.yml`, `buildspec.yml`, `atlantis.yaml`, …
   - **It ends in a repository-configuration extension:** `.tf`, `.tfvars`, `.hcl`, `.json`, `.yaml`/`.yml`, `.md`, `.txt`, `.toml`, `.tftpl`, `.tpl`, `.csv`, `.rst` (so `.tf.json` and `.auto.tfvars.json` too). `mkdir`, `rmdir` and the like need no extension.
   - **A target it cannot resolve keeps the body opaque:** concatenation, an f-string or template literal with substitutions, `%` or `.format`, `.join`, `os.path.join`, a reassigned or rebound name, a keyword argument. The check fails closed.
   - Reads of unresolved paths are fine. Reads are not held to the positive rule; a read of a state or credential file is caught by condition 2.

## Directories and tiers

### When the host does not report the command's directory

Some hosts run a command in a directory that the hook is not told. [hosts.md](hosts.md) says, for each host and version tested, whether the directory reaches the hook. It does not on Codex 0.165.0, Copilot CLI, Windsurf, Devin and Cursor's `beforeShellExecution`. Codex 0.166.0 sends the command's directory as the event's `cwd`, but the event names no version, so applygate treats that `cwd` as unconfirmed too. An MCP server that runs commands in its own working directory also leaves the directory unknown. applygate reads `tool_input.workdir`, `working_directory` or `cwd` whenever a host sends one.

- **The rule.** The command is judged at the most protected tier it could be in under the directory the host did report (on Codex 0.165.0, the session root): every environment whose path globs could match a directory under it, every environment matched by workspace, backend or AWS profile, and the strict or `default_tier` rule for an unmatched directory. Name hints on subdirectory names are not considered. [policy.md](policy.md) has the rule in full.
- **What you see.** The action's `matched` line in the decision log and in `applygate explain --dir-unknown` says `command directory not reported by codex; judged at the most protected tier under <root> (<env>, tier <tier>)`.
- **A `cd` inside the command.** An absolute `cd`, `pushd`, `-chdir` or `-C` establishes the directory for that invocation. A relative `cd`, `-chdir`, `make -C` or `env -C` does not, because the session directory is not where the command starts. The model chooses the directory, and two directories under the root can share a relative path (a link `a/envs/dev` to `envs/prod`).
- **The cost is over-protection.** A bare `terraform destroy` under a root that also holds `envs/prod/**` is a protected-tier destroy (block), even if the host ran it in a disposable example directory. Under the default `strict: true` any root is protected. So with the default config, a session rooted in a repository with a protected directory cannot run a destroy or an unreviewed apply anywhere in it without an absolute `cd` in the command or a less protected root.
- **What you can do.** Tell the agent to `cd` to the absolute path inside the command. Or launch the session from the subdirectory. Or set `unknown_dir: session_root` in the user config ([config.md](config.md)): relative paths then resolve against the session root and the command is judged as if it ran there. A repository config cannot set it.
- **Saved plans.** For `apply <planfile>` with a relative planfile that is not in the root, applygate searches for it under the root. The search skips `.git` and `.terraform` and stops at 8 levels or 20,000 directories.
  - Exactly one copy identifies the command directory, and the plan gate reads the plan there.
  - Several copies are a critical `plan-ambiguous` finding: a block in protected tiers and an ask elsewhere, which Codex enforces as a block.
  - No copy keeps `plan-missing`.
  - A search that reaches its depth limit is `plan-ambiguous` too. A deep repository can therefore block `apply <planfile>` until the command `cd`s into the directory.
  - `terraform apply tfplan` after a relative `-chdir` is `plan-ambiguous`.
- **Guard-file names.** On these hosts a relative path with a guard file's name (`hooks.json`, `settings.json`, `config.toml`, `config.yaml`, …) is judged as that guard file.
- **File edits.** Codex `apply_patch` paths are relative to the session directory, so file edits are resolved correctly.

### When the analysis loses the directory

When the analysis cannot follow where a command runs, or stops, the command is judged at the most protected tier under the repository root. [policy.md](policy.md) lists the cases. They are:

- a `cd` or `-chdir` to a computed path, and an unresolved terraform option (`-chdir=$x`);
- unresolved words before a terraform subcommand (`terraform $x`, `$(<f)`, `xargs -a f terraform`), which may hold `-chdir=DIR`;
- a `cd` to a directory that does not exist and that no earlier step of the command creates (a `cd` after `mkdir` keeps the path);
- a `cd` into a directory that an earlier step links, moves, copies or extracts into;
- a `cd` whose path goes through a symlink and then `..`, unless it uses `-P`;
- a bare `cd NAME` after the command sets `CDPATH` or `shopt -s cdable_vars`;
- a `popd` past the stack, and a login shell (`su -`);
- a command whose name cannot be resolved, or an `eval` or `source` whose text cannot be resolved. `eval "$(direnv export bash)"; terraform apply` is such a case. A later destroy in a disposable directory is then judged at the most protected tier under the root;
- `find -execdir` and `-okdir`;
- a directory option before the command a runner starts: `pnpm -C`, `yarn --cwd`, `npm --prefix`, `mise -C`/`--cd`, `poetry -C`, `parallel --wd`, `env --chd`;
- a `trap` handler, since it fires after any `cd`;
- a parse error, the statement budget or the work limit. A shell runs the lines before a syntax error, so those lines are analyzed too.

### Commands that can run code the analysis does not follow

- **The rule (the cross-directory rule).** A shell command that is not plain and can run code the analysis does not follow is also judged at the most protected tier under the repository root, in every tier. In a disposable or standard directory next to a protected environment it asks. So `perl -e 'system("terraform -chdir=../prod destroy")'`, `awk 'BEGIN{system(…)}'`, `sed '…/e'`, `tar --checkpoint-action=exec=…`, `node -e`, `python3 -c` and a loop whose body runs one of them do not run unasked from `envs/dev`.
- **What counts as code the analysis does not follow:**
  - a program with no shape: `python3`, `perl`, `ruby`, `node`, `awk`, `sed` with `e` or `w`, `tar` with checkpoint actions, a nested agent such as `codex exec`;
  - a program name, variable or part the analysis could not resolve: a `PATH` set to an unresolved value, a `$(…)` it could not follow;
  - a command that does not parse or is too long;
  - a repository whose git state or terraform configuration the scans could not vouch for: `init` followed by `plan` or `destroy` in the same command, terragrunt with `run_cmd` or hooks, a directory that cannot be followed;
  - a bare word typed to a shell through Codex's `write_stdin`.
- **What does not count:** a wrapper the analysis took apart (`make` with its Makefile, `xargs`, `docker run`, `pnpm exec`, an alias, a function). What it runs is judged as the invocations it expands to. A loop over literal words, a function, `$((1+2))`, `[[ ]]` and a command substitution of followed programs do not count on their own.
- **The cost.** Run from a disposable directory under a root that holds a protected environment, these ask: a `python3` script, `make` with no Makefile or `make test`, `npm test`, `pytest`, `cargo test`, `go test`, `docker build`, `rsync`, `dd`, `git push`, `terragrunt plan`, a `PATH` set to an unresolved value, `init` followed by `plan`, `apply` or `destroy` in one command, terragrunt `run_cmd`, a nested `codex exec`, a bare `y` typed through `write_stdin`, and a `cd` into a directory that cannot be followed. A variable assignment that is not plain asks too: `export FOO=bar` and `FOO=bar ls`.
- **It judges at the tier, not the target.** The rule cannot tell that a `python3` script only edits files. The judge, when on, can, and says so in the ask message. A reviewed allow list of scripts is not built.
- **Where it does not apply:** a plain command, and a repository with no protected environment under its root (the most protected tier there is standard or disposable). Whether Claude Code's `Bash` tool and Codex's `write_stdin` keep a function or a `PATH` that one call sets for a later call in another repository has not been verified.

### A repository with no config

- **The rule.** Where no `.applygate.yaml` covers the directory, there is no managed install and `strict_shapes` is not set, a command that is not plain is asked about only when it names an infrastructure tool or a guard file ([policy.md](policy.md), "Strict shapes"). The directory still counts as protected: a command applygate recognises is blocked or asked about as anywhere else.
- **What it lets through.** A command that is not plain, names none of those words, and still reaches infrastructure or a guard file. Replayed in a repository with no config, 73 of the 765 dangerous reproductions of the attack pack are allowed, from 25 review findings; with the full rule 5 are. The kinds:
  - a file planted by an earlier call that a later, ordinary-looking call runs: a git hook, `core.fsmonitor` or `core.sshCommand` behind `git status`, `git commit` or `git push`; an archive unpacked over hook or git files (`tar xf`, `unzip -o`, `rsync -a`, `cp -R … .git/`);
  - an option that makes a trusted program run another: `rg --pre sh`, `sort --compress-program=sh`, `go list -toolexec`, `curl -K`, `sed -f`, `tar -T`, `zip -TT`, `actionlint -shellcheck`, `podman --runtime`;
  - a program applygate has no option list for: `./sort destroy -auto-approve`, `checkov`, `infracost`, `trivy`, `tflint --config`;
  - a write through an option or a shell form the full rule does not accept: `curl -o`, `wget -o`, `tree -o`, `gzip -k`, `find -fprint`, `echo x >| out.tf`, `hash ls=./tail; ls`.
- **The list is pinned.** `harness/testdata/no_config_allowed.txt` holds the 73 ids, and `TestAttackPackWithoutConfig` fails when a reproduction that is not on it becomes allowed. The replay renames `envs/prod` to `envs/main`, because a directory named `prod` is protected by its name and keeps the full rule. The figures are from the Claude Code event format on macOS.
- **It is a word match.** The words are looked for in the command as written and in what the analysis resolved. A name assembled when the command runs, or one that is only in a file the command reads, is not seen. `aws`, `vault`, `oc` and the others match as whole words wherever they stand, so a path such as `tools/aws/report.sh` keeps the ask.
- **What stays asked there whatever it names:** a script or sourced file that cannot be read, interpreter code that mentions infrastructure or cannot be analyzed, a program or file named by something that cannot be resolved, and a redirect or removal whose target cannot be resolved.
- **To get the full rule:** `strict_shapes: true` in the user config, a repository config, or a managed install.
- **Not measured:** how often the narrower rule matters to an agent that is trying to get around the check. Without a managed install that agent has other routes ([Self-protection](#self-protection)).

### Tier signals

- **Signals not read:**
  - Terragrunt `dependency` and `include` blocks that point outside the unit, and a remote `terraform.source` (its module's own backend block). The unit's `remote_state`, a local source, `--source`, `TG_SOURCE`, `--config` and the working-directory options are read.
  - Provider profiles and roles set in modules, or through anything other than a literal or a bare `var.NAME`. Those are unknown, so protected.
  - The backend recorded inside a binary planfile. A plan file kept in another Terraform directory brings that directory's tier, but a plan copied elsewhere carries only its workspace.
  - The `remote` backend's workspace prefix, which is never joined to the selected workspace name.
- **Backend blocks** are read with a small parser that only understands literal string attributes. Partial configuration (`-backend-config`) is visible only through the `.terraform` cache.
- **An unknown signal is judged as protected.** These make the target unknown:
  - an unresolved value in a tier signal: `TF_WORKSPACE=$X`, a profile read at run time, an unresolved `-backend-config`;
  - a `.tf` value that is computed (OpenTofu variables in a backend block), which makes every command in that directory protected;
  - a Terragrunt `remote_state` or `generate "backend"` whose values are computed (locals, `get_env`);
  - a `-backend-config` file Terraform would reject (`bucket=x` unquoted);
  - a provider profile held in a variable with no value applygate can find;
  - a configuration file over 1 MiB or one that does not parse (tfvars included), a chain of more than ten local modules, and an unreadable `terragrunt.hcl`;
  - a kubectl, helm or cloud CLI call whose context, profile or project is an unresolved word (`--context "$(cat f)"`, `--profile $P`): it asks.
- **Local state.** A local state file in a directory that no environment matches gets the tier of an unknown directory (protected under strict). `workspace new -state=PATH` passes that state's tier to later commands in the directory.
- **Terragrunt `run --all`, `run-all` and `*-all`** are judged at the most protected unit under the directory: each `terragrunt.hcl`, up to 2,000 directories. Past that, or through a symlink, they get the most protected tier anything there could have.
- **Matching.**
  - A workspace or Azure subscription named in a config matches without regard to case. An environment named `Payments` and a workspace `payments` are one.
  - A path pattern's case is folded whole on a case-insensitive file system.
  - `@`, space, `+`, `=`, `,` and `~` separate the words of a name hint.
  - Backend patterns match after normalizing the host's case, the default port, percent-encoding, repeated slashes, and a prefix's leading and trailing slashes.
- **Other signals that are read:** a kubernetes or helm provider's nested `kubernetes` block, `config_path`, `host` and `KUBE_CONFIG_PATH`; the awscc `profile` and azapi `subscription_id`; a Terragrunt `generate` block's contents; hints for the provider's kube context, project and subscription; Terragrunt's single-dash options (`-working-dir`, `-config`, `-source`) and `--queue-include-dir`. A `terragrunt.hcl.json` unit is a unit. `terragrunt exec` and `backend delete|migrate` are classified. `plan-check` uses a local backend's path and linked state as the hook does.

## Terraform, providers and modules

- **`terraform plan` runs code and is not judged by the plan gate.** Providers and data sources run with the agent's credentials. In a protected directory strict shapes asks about a call that may start providers unless the rule below holds.
- **A call that may start providers is plain only when applygate understands what Terraform would load.** That is every subcommand but a short list ([policy.md](policy.md)); `graph` of any type and `query` are checked like `plan`. All of these must hold:
  - every configuration file of the directory, and of every module it calls, reads and parses within the 1 MiB cap, whatever its extension;
  - every module source is a literal that is local, or remote and already installed in the module manifest;
  - every provider is on a closed list of registry providers whose attributes the scan models: aws, awscc, google, google-beta, azurerm, azuread, azapi, kubernetes, helm, random, null, time, tls, archive, local, http, dns, cloudinit, template;
  - an installed provider is in the lock file, and every provider under `.terraform/providers` matches `.terraform.lock.hcl` as committed at git HEAD;
  - with providers installed, the repository has an upstream branch that holds the same lock file;
  - the configuration runs no program: no `data "external"`, `check` block data source or `shell_script` resource, and no provider or backend block with an `exec` block or attribute (the helm provider's `kubernetes` object and dynamic blocks included), or with `shared_config_files`, `shared_credentials_files`, `config_path` or `config_paths` naming anything but the user's own `~/.aws` or `~/.kube` files. `init` and `state` calls scan a backend block for the same.
- **The provider list is a table.** A provider added to it without checking its attributes is a false allow.
- **What the provider check trusts.**
  - The `terraform` binary on the hook's `PATH`. Without a managed install, an agent can put one there by a route the hook does not see. Under a managed install the engine must be root's alone ([managed.md](managed.md)).
  - A lock-file entry that was committed with a replaced provider's hash.
  - The upstream branch. The lock file committed at HEAD must match the upstream branch's. With providers installed, a repository with no upstream branch is not plain at all. A nested repository (a `git init` inside the tree) is not recognized as one; it is caught only because it has no upstream branch.
  - The effects of the provider plugins themselves.
  - It reads `.terraform/providers` (or `TF_DATA_DIR`), not provider `dev_overrides` in the CLI configuration, which is a guard file.
- **A lock-file comparison that runs out of time** is a finding.
- **Files the scan reads:** `*.tfquery.hcl`, `*.tftest.hcl`, `tests/`, the stacks files, OpenTofu's external key provider, `init`'s `-backend-config` files and pairs, and the backend recorded by the last init. OpenTofu `encryption` blocks are covered by an older, narrower scan only.
- **`http` data sources and provider-side code paths** are not flagged.
- **Terragrunt.** `terragrunt apply PLAN` reads `DIR/PLAN`, while Terragrunt applies the copy in its cache. Only strict shapes asks about it.

## State files

- **The rule is by name.** A program that is not known to only read, and that names a state file, is state surgery in that file's directory, whatever the program calls its output option. The name can be a word, an option's value, `--out=FILE`, `-oFILE`, a part of a list, or text inside a script word such as awk's `print > "terraform.tfstate"`.
  - **Not covered:** a state file under another name (`prod.tfdata`, a backend file the configuration renames) and a path built at run time. Only the unresolved-name rule below covers those.
  - **Readers keep working:** `cat`, `jq`, `grep`, `cut`, `sort`, `sed` and `awk` (a state file named as a word of its own), `ls`, `wc`, `diff`, the archivers and copiers (which have their own rules) and `terraform` itself. Copying a state file to a backup name stays allowed.
  - **The cost:** a reader missing from that list (an unusual viewer, `infracost --path terraform.tfstate`) is treated as a writer. Run it from a person's terminal.
- **Unresolved names.** `rm`, `mv`, `cp`, `ln`, `tee`, `truncate`, `dd` and `rsync` given a name the analysis cannot resolve (`for f in …; do rm $f; done`, `rm $(find …)`, `xargs rm`) may name a state file anywhere under the root. So may a redirect to an unresolved word (`> "$f"`). They ask next to a protected environment. A loop that removes `*.tmp` asks.
- **A redirect, a Write or an Edit onto a state file** is judged in that file's directory, not the working directory's.
- **Operations on a directory or work tree.** These are state surgery:
  - `rm`, `mv`, `cp`, `git reset --hard`, `git checkout -f` and a directory copy that touch a state file or `terraform.tfstate.d`, by name, glob or directory;
  - a removal, move or extraction of an ancestor directory, `find … -delete` outside the state directory, and a glob that matches a state file as a destination;
  - `tar xf`, `tar -C DIR -xf` in any option order, `unzip`, `git clean`, `git stash` and the other commands that write the working tree, in a directory that holds a state file (`*.tfstate`, `terraform.tfstate.d`). Run them elsewhere or by hand;
  - `git checkout`, `merge`, `pull`, `stash`, `clean` and the other git commands that rewrite the work tree. They are judged against every state file in the repository, not only the directory they run in.
- **Terraform's own options.** `plan -out` and `-generate-config-out` over a state file (`terraform plan -out=terraform.tfstate`) are state surgery from any directory.
- **State in a bucket.** `aws s3 cp`, `mv`, `rm` and `s3api put-object`, `copy-object`, `delete-object` and the like on a `.tfstate` object are state surgery. So is an `aws s3` or `s3api` write, move or delete of any key in a bucket that matches a `backends:` pattern of an environment, in that environment's tier.

## Git

- **Work-tree rewrites where a guard file is.** `git checkout`, `switch`, `pull`, `merge`, `rebase`, `stash`, `reset --hard`, `restore`, `clean`, `cherry-pick`, `revert`, `apply` and `am` rewrite the work tree. They can bring in a guard file (`.applygate.yaml`, `.claude/settings.json`) without naming it.
  - At home and in applygate's own places they are tampering.
  - At a repository-level root (a config's directory, the git root, a session directory) they ask in every tier, with the class `hook-rewrite`. They are routine, they bring in hook files only when a commit holds them, and a rewritten `.applygate.yaml` is not read until a person trusts it again. Hosts that cannot ask block them: Codex, and most of the hosts in [hosts.md](hosts.md) that were not tested live.
  - A guard file that git names (`git checkout -- .claude/settings.json`, `git checkout -- .applygate.yaml`) is tampering everywhere.
  - `git clean` counts only the directory it runs in.
- **Not covered:**
  - a command that rewrites a guard file without naming it and is not on that list, such as `git checkout-index -a`. For repository configs, trust covers it: a rewritten config is not read. For the other guard files only a managed install does ([managed.md](managed.md));
  - a guard file that a `git pull` or `checkout` places at a repository-level root once the person approves the ask;
  - a wildcard git pathspec (`:(glob)**/settings.json`) onto a guard file.
- **State files.** The git commands that rewrite the work tree are also judged against every state file in the repository ([State files](#state-files)).
- **Which git commands ask** is under [Asks and blocks you may not expect](#git-commands).
- **Git config.** A git command is plain only when every key in every git config it reads is on a safe list ([policy.md](policy.md)). `remote.*.promisor`, `remote.*.partialclonefilter` and `extensions.partialclone` are off the list. `git lfs install`'s filter is on it; another tool's filter or diff driver is not. `git config --show-scope`, `--show-origin` and `--name-only` are read as reads.

## Cloud CLIs and network requests

- **HTTP clients.** A `curl`, `wget`, `http`/`https`/`xh` or `gh`/`glab api` call to a host other than this machine that sends a request other than GET, HEAD or OPTIONS is a cloud write, and with DELETE a cloud delete. A signed or socket request counts too. `-G` with `-d` stays a read. What makes a request a write:
  - an explicit method: `-X`, `--request`, `--method`, an httpie method word;
  - any body, form or upload: `-d`/`--data*`, `--json`, `-F`/`--form`, `-T`, `wget --post-data`/`--post-file`/`--body-*`, httpie `key=value`, `key:=json`, `key@file`, `gh api -f`/`-F`/`--input`;
  - a method that cannot be resolved.

  An example of why: `curl -X POST https://app.terraform.io/api/v2/runs … -d @run.json` starts an HCP Terraform run that can carry `is-destroy`. The cost: a webhook, a chat message or an API POST asks in a protected or standard directory.
- **A request through any other client is outside the hook:** `python3`, `node` and `ruby` code that has no AWS SDK name in its text, `nc`, `socat`, `openssl s_client`, `grpcurl`, `aria2c`, `go run`, `pip` and `npm` install scripts, a Terraform provider or `local-exec`. The rules do not recognize them, so they are allowed unless the code names an infrastructure tool.
- **A request to this machine is not a cloud call.** `kubectl port-forward` is plain, and a `curl -X DELETE` sent to this machine through it or through `kubectl proxy` reaches the cluster.
- **`gh`.** `gh api -X DELETE`, `gh repo|secret|variable|release delete` and `gh workflow run` are cloud calls: a block or an ask in a protected tier.
- **Destructive verbs.** `aws` operations that start with `close-`, `leave-`, `disassociate-`, `cancel-` or `reject-` are destructive. `gcloud projects delete PROJECT` takes the project as its target.
- **Read verbs that have effects.** `aws` operations are read by their verb prefix, so `aws … test-failover` and `test-invoke-method` count as reads and are allowed. `vault secrets disable` and `vault kv destroy` have no destructive class: strict shapes asks about them in a protected directory, and they are allowed elsewhere. `kubectl apply --prune` and `kubectl replace --force` are judged as writes, not deletes.
- **Secret-printing reads** are credential access, an ask in every tier: `aws secretsmanager get-secret-value`, `ssm get-parameter --with-decryption`, `sts get-session-token`, `ecr get-login-password`, `kubectl get secret -o yaml|json`, `kubectl config view --raw`, `az keyvault secret show`, `gcloud secrets versions access`. Not covered: `terraform state pull`, `terraform show -json`, `terraform output -json` and `helm get values -a`, which can print secrets and are allowed.
- **Sign-in commands** `gcloud auth activate-service-account` and `az login` are allowed in a protected directory. They are not judged as a change of account.
- **The plan gate's cloud rules are AWS-first** ([Plan gate](#plan-gate)).

## Self-protection

- **Without a managed install, self-protection is best-effort** ([threat-model.md](threat-model.md)). One review pass found ten routes past it. They are not fixed one by one. The managed install is the documented guarantee.
- **Default-deny looks at what a command names.** A program that names a guard file is tampering unless it only reads. A route that changes a guard file without naming it is not caught: code in another language that writes the file without naming it, a process the agent started earlier, or a git command that rewrites the work tree ([Git](#git)).
- **A change through a path that cannot be resolved** asks nowhere. It is blocked when the same command names a place that holds a guard file (`~/.claude`, `~/.ssh`, …): `for f in ~/.claude/*; do rm $f; done`.
- **Host files and switches that are not guard files.** These sit next to guarded ones and are not on the list: `opencode.jsonc`, `.opencode/plugin/`, `~/.codex/managed_config.toml`, `~/.codex/rules/`, `.gemini/.env`, the variables `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and `OPENCODE_CONFIG`, and `copilot --config-dir`. `~/.azure/config` is not a guard file either; the Azure CLI's dynamic extension install can run code from an `index_url` set there (from the CLI's documented behaviour, not run).

### Where guard files are looked for

- **Guard roots.** A pattern such as `**/.claude/settings.json` stands for that file under each of these roots:
  - home;
  - the directory of the outermost repository config, read or not;
  - the nearest git root: the nearest directory with a `.git` entry, found without running git;
  - each session directory the hook's environment names: `CLAUDE_PROJECT_DIR` (Claude Code), `GEMINI_PROJECT_DIR` (Gemini CLI), `DEVIN_PROJECT_DIR` (Devin).

  A host's event `cwd` is not taken as the session directory: Codex 0.166.0 sends the command's directory there.
- **Placing.** At every guard root, moving, copying or extracting into a directory that holds a guard file is tampering. It counts every guard file the directory could hold, whether the file is there or not. So `tar -xf`, `unzip`, `cp -r x/. .` and `mv x .claude` are blocked at a git root or session directory that holds hook settings.
- **Removing.** `rm`, `rmdir`, `unlink`, `srm`, `mv`'s sources, `zip -m`, `find -delete` and `-exec rm`, and `git clean` remove. A directory they remove counts when a guard file under it exists and its loss can weaken the guard. `rm -rf .claude` (with hook settings) and a `find . -delete` above hook settings are blocked.
  - **Always counted:** hook settings, applygate's own files, the plugin's files, the agent CLIs, and the files that pick a cloud account or cluster (`~/.aws/config`, `~/.kube/config`, `~/.config/gh`, `~/.docker/config.json`, `~/.terraformrc`, `~/.terraform.d`).
  - **Not counted for a removal,** by name or as a directory's content, because they matter only for what is placed in them: Terraform providers and modules, `.terraform.d/plugins`, `.git/config` and hooks, MCP server lists, Claude Code skills, subagents and commands, `~/.gitconfig` and `~/.config/git`, ssh config, Docker CLI plugins, `.curlrc`, `.wgetrc`, tflint, helm plugins, Azure CLI extensions, Claude Code's shell snapshots and session env, start-up files, go's env file, and `site-packages` start-up files.
  - So `rm -rf .terraform`, `.github`, `.vscode`, `.cache` or `.codex` (when nothing under them can weaken the guard), `mv .terraform /tmp/x`, `git -C . log`, and `git clean` in a subdirectory are allowed. `rm -rf .git` asks in a protected tier (strict shapes).
- **Not covered:**
  - a session directory of a host whose hook gets none of those variables (Codex, Cursor, Copilot CLI, Windsurf, Cline, OpenCode), unless it is the git root;
  - a `.claude` below a guard root that is not the session's directory. `rm -rf sub` with `sub/.claude/settings.json` is not blocked: its hooks run only for a session started in `sub`. Placing one there by name is still tampering;
  - a guard file created between the decision and the removal.

### Config trust

- **A `.applygate.yaml` that is a symlink is never read,** because it cannot be trusted. A repository that shares its config by a link is judged protected until the link is replaced by the file. `applygate init` does not write through a dangling `.applygate.yaml` link.
- **A config file over 1 MiB is not read.** A repository config that large is untrusted, so the repository is protected. A user or system config that large is an error.
- **A trusted nested config can become the repository's** when the outer one is removed. Trust binds a file's content to its path, not to its place in the chain. Trust a nested config only if you accept its environments applying on their own.
- **A trusted repository config's path patterns are not confined to its tree.** A pattern with `..` or an absolute path can claim directories outside the repository.
- **A repository config may turn the judge off** for its subtree. A config is read only once a person has trusted it, so a cloned or planted config cannot do this unseen. Under a managed install a trusted repository config can still turn the judge off, and can set `plan_gate.show_timeout`.

### Managed install

- **Untested parts.** The Claude Code managed settings keys are from its docs and have not been tested live. Nor has whether `claude --bare` or `CLAUDE_CODE_SIMPLE` skip managed hooks. The Codex `requirements.toml` snippet is printed, not written, and not tested live. Windows is not supported.
- **Loosening settings in the user config are ignored** under a managed install. They belong in the system config.
- **A Homebrew or user-installed engine** makes every saved plan unverifiable under a managed install, until the system config names a root-owned one in `plan_gate.engines`.
- **Some of applygate's messages name `sudo` without its full path.** Under a managed install, run `/usr/bin/sudo` ([managed.md](managed.md)), which also lists what a managed install does not cover.

### The Claude Code plugin and the installers

- **Plugin pin after an upgrade.** The Claude Code plugin blocks every call once the pinned binary changes, an upgrade included, until a person removes `pinned-binary` from the plugin's data directory.
- **What the plugin's launcher does.** It starts `/bin/sh`, runs its helpers from `/usr/bin` and `/bin` only, skips relative `PATH` entries when it looks for applygate, and pins a binary it downloads. A cached binary without a pin is downloaded and checked again.
- **Open in the launcher:**
  - it hashes the binary and then runs it, and the file can change in between;
  - it pins an empty hash for a binary it cannot read, and every later call then blocks;
  - where `sha256sum` is missing it falls back to `shasum`, a Perl script that honours `PERL5OPT` and `PERL5LIB`;
  - a download in hook mode can stall for about a minute.
- **Homebrew** (`Flurit/tap`) checks the archive's sha256 only, not the cosign signature. `install.sh` and the GitHub Action verify the signature ([install.md](install.md)).
- **`install.sh`** copies and `chmod`s the target of an archive member that is a symlink.

## Plan gate

- **applygate never runs `plan`.** For `apply <planfile>` it runs `terraform show -json <planfile>` (`tofu` for OpenTofu). `show` is read-only, but it starts the provider plugins in `.terraform/providers` (or `TF_DATA_DIR`) to load their schemas, and the agent can write that directory. So before `show` runs:
  - every provider there must match an `h1:` hash in `.terraform.lock.hcl` as git HEAD has it. A lock file edited in the working tree is not trusted, a replaced provider does not match, and a directory without a committed lock file cannot have its plan read;
  - `show` runs without the user's CLI configuration (`TF_CLI_CONFIG_FILE=/dev/null`), so `dev_overrides` cannot point it at other binaries;
  - with Terragrunt the plan is shown with `terraform` in the one `.terragrunt-cache` directory that holds it (`TG_TF_PATH` or `TERRAGRUNT_TFPATH` from the hook's own environment names another binary). `terragrunt show` is never run, because it evaluates `run_cmd()` and hooks.

  If any of this fails, the plan counts as unreadable. That is a critical finding, so protected tiers block. Set `plan_gate.run_show: false` to skip running `show`; applying saved plans in protected tiers is then blocked.
- **What that check does not cover** is listed under [Terraform, providers and modules](#terraform-providers-and-modules). The opt-in `preflight.live_state` runs `terraform state pull`, which reads the user's CLI configuration for credentials and is not provider-checked.
- **Values known only after apply.** A watched attribute that the plan does not know, such as a security group CIDR taken from a VPC created in the same plan, is a high `unknown-watched` finding: an ask in a protected tier. A first apply of a network stack in a protected tier is therefore usually asked about.
- **The rules are AWS-first.** GCP and Azure resources are counted for destroy and replace, but their stateful types and protections are not known. `protected_resources` in config covers addresses of any type.
- **Provisioners and external data sources.** The `code-execution` finding reads provisioners from the plan's `configuration` block and flags them for the instances the plan creates, replaces or destroys.
  - The plan JSON does not say whether a provisioner is a creation-time or a destroy-time one, so a destroy flags both kinds.
  - A plan produced without configuration (hand-built JSON) reveals no provisioners.
  - An `external` data source is flagged only when its read is deferred to apply (a `read` in `resource_changes`). One read during `terraform plan` has already run by the time the gate sees the plan.
- **The workspace check** reads the workspace that Terraform 1.x and OpenTofu record in the planfile (protobuf field 13 → 3). This was verified on a Terraform 1.16.1 planfile only.
- **Where a saved plan gets its tier.**
  - A plan read from `/dev/…` or `/proc/…`, or written earlier in the same command by anything other than `plan -out`, is judged as protected.
  - One made by `plan -out` in another directory brings that directory's tier. One kept in a configured environment's path brings that environment's tier.
  - A plan that is a hard link is judged as protected. One that is a symlink is judged in the directory it leads to.
  - An earlier step that names the planfile as an argument (other than a plain reader such as `cat` or `sha256sum`) makes the plan unverifiable.
- **Exposure and protection rules.**
  - A protection removed by deleting the setting or the block (true to null, a removed block) is a `protection-removed` finding, since the plan does not show the provider's default.
  - Blocks of an internet-wide split (32 prefixes of `/5`) count as `0.0.0.0/0`. A wildcard with a short fixed part (`o-*`, `vpce-*`, `AIDA*`) does not limit a principal. Ports 23, 139, 445, 2375, 2376, 5601, 5900, 9092 and 10250 are admin ports.
  - A policy condition is read this way: the values of one condition key are ORed, `IfExists` and `ForAllValues` do not limit, and an account wildcard in an ARN is every account.
- **Not a finding:**
  - widening an already-public resource policy on an update (a bucket policy public for one prefix made public for all of it). The exposure rule reports whether a policy is public, not how much;
  - an S3 lifecycle rule that expires objects, since it is often deliberate;
  - resource shapes the exposure rules do not know;
  - `deferred_changes` and `complete: false` in the plan.
- **Routine replaces are allowed in a standard tier.** A saved plan whose only deletes and replaces are replaces of a listed type that holds no data is not asked about there ([policy.md](policy.md), step 6). A protected tier still blocks it.
  - **What such a replace can still do.** A replaced permission, policy attachment or security group rule is gone for the seconds between the delete and the create. A replaced launch template loses its version history, and a scale-out in that gap can fail. A replaced Lambda layer version deletes the old artifact unless `skip_destroy` is set. None of these is asked about in a standard tier.
  - **The list is a table, from what is known of the providers.** It was not checked against each provider's documentation, and it is AWS and Terraform's own types only. A listed type that turns out to lose data on replace is a false allow; say so in an issue. A type that is not listed keeps the ask.
  - **How often this prompt fired is not measured.** The plan-gate study covered creates, no-ops and tag changes, not replaces.
  - **To have one asked about again,** list its address under `protected_resources` ([config.md](config.md)).

## MCP tools and tools no table describes

- **Known infrastructure MCP tools** (AWS, HCP Terraform, Kubernetes, Helm, gcloud, az and shell-command servers) are judged as the command they are equivalent to. The table of known tools was written from each server's source code and not tested against the running servers. What it covers and what it does not (Pulumi, the Lambda tool server, SQL, effects that live in HCP Terraform, kube-context retargeting) is in [mcp.md](mcp.md).
- **Every other MCP call is logged and allowed.** Its arguments are logged redacted and capped at 4 KB; `applygate report` counts the calls per server.
- **The matcher.** Claude Code sends MCP calls only to hooks whose matcher covers them. `hook install` and the plugin write the matcher `*`, and `applygate doctor` warns about a narrower one.
- **Generic shell tools.** A shell tool of a server the table does not know is judged by its arguments, not only its name. Any `command`, `cmd`, `script` or `cmdline` field is judged, and every command field present. The argument list is taken from `args`, `arguments`, `argv`, `options`, `parameters`, `flags`, `extra_args`, `subcommand` and similar names, and from an array command. Every case of a known tool that the arguments fit is judged. Arguments that are not an object are asked about. A call classified as MCP without an `mcp__` prefix is judged.
- **Tools no table describes.** A tool such as Claude Code's `Monitor`, or `PowerShell` with another field name, or a host's new shell or file tool, is judged as a shell call when any field holds a command or any string names an infrastructure program (terraform, kubectl, aws, helm, gcloud, docker, …). A program and its arguments in separate fields (`executable` and `arguments`, `command` and `args`) are judged as one command. Otherwise the arguments are scanned for guard files, as an unknown MCP tool's are, and the call is logged.
  - The host's bookkeeping tools (`TodoWrite`, `Task`, `Agent`, `WebFetch`, `WebSearch`, `AskUserQuestion`, `ExitPlanMode`, `Skill`, `ToolSearch`, `SendMessage`) pass unlogged. The hosts' planning, scheduling and publishing tools are not read as shell text.
  - The cost: a note or message tool whose text mentions a program name is asked about.
- **Not covered:** MCP gateway tools that wrap known tools (`call_tool`, `proxy`). The wrapped call is not translated. A review also reported an unknown tool whose program, directory and arguments sat in fields with other names (`prog`, `dir`, `argv`): they were joined in the wrong order and, with `strict_shapes: false`, allowed. This is not known to be fixed.
- **A cost:** a read-only MCP tool with `run`, `exec`, `node` or `script` in its name asks.

## Model judge

The judge is off by default. How it works, what is sent and how it was measured are in [judge.md](judge.md).

- **A model can be wrong** and can be fooled. On the last measurement the judges missed between 1 and 7 of 72 calls that should be stopped.
- **Its accuracy was measured with an earlier filter.** The filter now sends more calls to the judge. Accuracy has not been measured again with the current filter.
- **The filter is a list.** It decides which calls reach the judge. Its lists of credential files, and of programs and options that load code from a path, are not complete; a call that uses one that is missing is not sent.
- **What the filter sends.**
  - A variable on a command is harmless only if it is listed (`LANG`, `NO_COLOR`, `TF_LOG`, …).
  - `cp`, `mv`, `ln`, `tar x`, `unzip`, `git apply` and in-place editors write like a redirect.
  - A write outside the working tree by any local program that is not a plain reader goes to the judge: `uniq IN OUT`, `sort -o`, `gofmt -w`, `go build -o`, `cargo --target-dir`, `docker build --output`, `find -fprint`.
  - Git options that run a program are matched as git matches them.
- **What the judge sees.** It is told the tier of the profile, context, project or stack a command names. A deletion shows it the text that is removed. It sees Cursor's `contents`. Redaction hides the value of a `--credentials-*` or `--secrets-*` flag from it.
- **Unjudgeable calls.** A private-key header with no end marker in a command, a file or MCP arguments makes the call unjudgeable, because redaction removes everything after it. An unjudgeable call that names production asks in a disposable directory too. That check strips quotes and JSON punctuation and reads content and paths.
- **`applygate check`** does not ask the judge inside an agent session. An agent that opens a pty and unsets the agent's variables can still probe the judge through it.

## Agents and hosts

What each host can do with the hook, as verified live, is the generated table in [hosts.md](hosts.md) (`applygate hosts` prints it). The limits that follow are the ones that shape applygate's behaviour.

- **Claude Code: where an ask is shown.** applygate leaves an ask to Claude Code's prompt only in the modes where the prompt was seen live: `default`, `auto` and `bypassPermissions`. In every other mode (`dontAsk`, `acceptEdits`, `plan`) it enforces an ask as a block. Whether `acceptEdits` and `plan` would show the prompt has not been tested. `auto` is the starting mode of interactive sessions since Claude Code 2.1.283; its prompt for a hook's ask is documented and was seen on 2.1.322.
- **Claude Code: `bypassPermissions`.** Claude Code still shows the ask prompt in this mode. That was observed live on Claude Code 2.1.312, but it is not documented, so it could change. If a later version allows an ask silently in this mode, applygate's ask there no longer stops the call.
- **Claude Code: the `*` matcher** with `Monitor` and `PowerShell` calls is tested only with replayed events.
- **Codex does not support ask.** It fails the hook and runs the tool, so applygate turns every ask into a block. Codex hooks need to be trusted with `/hooks` before they run.
- **Codex fails open on crashes.** Codex has no `onFailure` setting. A missing, killed or crashed hook lets the tool call run (observed: exit 127 and an exit with no status code both proceed). applygate recovers panics inside its own process and blocks, so the remaining fail-open case is the binary not starting. This cannot be fixed from inside the hook. Use Codex's own sandbox (`--sandbox read-only`/`workspace-write`) and approval settings as the backstop, keep plan-only credentials, and run `applygate doctor`. It checks that the hook entry exists and the binary is executable, and flags hook entries it does not recognize.
- **Launch directory (project scope).** Claude Code and Codex read project settings only from the directory the session is launched in, not from its ancestors. A hook installed at `<repo>/.claude/settings.json` is silent if the agent is started from a subdirectory such as `<repo>/envs/prod`. This was observed on Claude Code 2.1.312; the Codex side follows its docs and is not tested live.
  - `applygate init` therefore installs the hook at user scope (`~/.claude/settings.json`, `~/.codex/hooks.json`), where it fires from any directory of any repository. `applygate hook install` defaults to project scope and takes `--scope user`.
  - A user-scope hook also runs in repositories that have no `.applygate.yaml`. Those are judged by the user config or the defaults (enforce, strict).
  - `applygate doctor` fails (exit 1) when it is run in a subdirectory of a repository whose hook is project-scoped only and no user-scope hook exists for that agent. It prints the install command that fixes it. It warns when a project hook and a user hook are both installed, since the hook then runs twice.
  - For organisations, managed settings are the answer that neither developers nor agents can remove ([threat-model.md](threat-model.md)).
- **Adapters written from documentation.** The adapters for Cursor, Copilot CLI, Gemini CLI, Windsurf (Cascade), Devin, OpenCode and Cline follow each host's documentation and source as read on 2026-10-30 and 2026-10-31 ([hook contracts](../review/host-research/2026-10-31-hook-contracts.md)). None has been run inside its host.
  - The scenario pack replays through each of them in the documented payload format (`go test ./harness`, `harness/run.py --format NAME`). That checks applygate's reading and writing of those formats, not the hosts.
  - Where a host does not document a field, the adapter is conservative. A shell call whose command it cannot read fails per `on_error`. A write tool without a known path field has every one-line string argument checked as a path. A directory the payload does not name is unconfirmed.
  - Gemini CLI, Windsurf and Devin let a tool call run when the hook crashes or is missing. Cline does on a timeout, and a Cline cancel ends the whole task.
- **A hook loaded by another host.** Cursor, Copilot CLI and Devin also run hooks from `.claude/settings.json`. The Claude Code hook then receives their tool names (`Shell`, `exec`). applygate judges those shell calls like that host's own (no ask; a block is exit 2), so a cross-loaded hook does not let a shell command through as an unknown tool. Whether those hosts apply the Claude Code matcher to their own tool names is not documented, so install the host's own hook and do not rely on this.
- **Cursor's allow.** Under `failClosed`, applygate must print a permission for every call, so a call it does not judge gets `{"permission":"allow"}`. Whether that skips Cursor's own approval prompt is not documented and has not been tested live.

### One-time approvals

- **Off by default, with no operating-system presence check.** Turned on in the user config, `applygate approve ID` lets a person allow one asked call on an agent that cannot ask ([policy.md](policy.md)). It is meant for a person at a terminal: the command checks that its input is a real terminal (isatty) and wants the environment name typed. The hook blocks an agent that runs it directly, through `script` or `expect`, or from Python, Node or other code that names it.
- **An agent that can reach a real terminal can approve its own call.** One review did so through a desktop app's terminal MCP tool, which runs in a real TTY. This is why approvals are off by default.
- **The store is a guard path,** protected only against the routes the hook inspects.
- **The approval matches the call as the hook sees it.** It cannot tell whether the files a script reads changed between the request and the retry.
- **Approval IDs are 8 characters long.**
- **`applygate approve` is not offered** for a call whose display is cut by an unclosed private-key header.

## When applygate fails

- **Errors applygate catches** (a malformed event, a repository config error) follow the user config's `on_error` and mode. With `auto`, the default, they block when the most protected tier under the repository root is protected or unknown, and allow otherwise, since a command that was not analyzed could run anywhere under the root.
- **An internal error blocks a command that names an infrastructure program,** whatever `on_error` resolves to for the root. `on_error: allow` still allows.
- **A recovered panic** follows `on_error` and mode too, with these exceptions:
  - `on_error: allow` does not apply where a protected tier is in reach. A panic is a failure of the analysis, not a configured error.
  - A panic after the policy already asked or refused (in the judge or the log) never turns that into an allow, in any tier, observe mode aside.
  - A panic in the recovery itself (rendering, the decision log) or in the watchdog answers with a block.
  - `applygate check` recovers and exits 2. A panic in telemetry, which runs after the verdict is written, is dropped.
- **How a block is delivered.** A block is exit 2 for Claude Code and Codex. Cline gets a cancel, since it ignores exit codes.
- **Deadlines.** A decision that misses the internal 25 s deadline (a slow `terraform show`, for example) cancels the work in flight, the `show` subprocess included, and blocks in every tier whatever `on_error` says. A watchdog holds the whole run, config reading and the judge included, to 29 s. Past that the hook answers with a block itself, in observe mode too, since the config may not have been read.
- **Many file arguments are slow.** One review measured about 13 ms of CPU per file argument: `rm -f` of 2,000 files took about 25 s, which is the deadline.
- **A user config that cannot be read** blocks in every mode, since its `on_error` and mode are what is unknown. Without an absolute home directory the hook blocks every call.
- **Observe mode never blocks,** including on errors. The exceptions are the two cases above: the watchdog, and a user config that cannot be read.
- **Failures applygate cannot catch** (the binary missing or killed, the agent's own hook timeout) are decided by the agent. Claude Code blocks because `applygate hook install` sets `"onFailure": "block"` (Claude Code 2.1.295 or later; older versions fail open). Codex fails open. The other hosts are listed in [hosts.md](hosts.md).

## Decision log and messages

- **Size.** A decision-log entry redacts at most 512 KB of text. Fields past that are recorded by size only. A verdict's text is capped at 16 KB.
- **What is redacted.** The log redacts the backend, profile, context, project, plan path and next step of an action, and paths and the working directory (in the judge's copy too). Redaction runs on the decoded strings of MCP arguments. It covers `PASSWORD 'x'`, `sqlcmd -P`, JWTs and SigV4 signatures. `--bypass-*` is not treated as a secret name. A verdict's text is redacted like the log and shows control, escape, carriage-return and direction characters written out.
- **Redaction is by pattern and misses some forms.** Reported and not known to be fixed: `{"name": "…PASSWORD", "value": …}` lists, escaped quotes, `--auth`, `Authorization: Negotiate`, `--cookie`, `zip -P` and `vault login`.
- **Rotation keeps one older log file.**

## Credentials and the boundary report

- **What holds without the hook.** Only controls the agent cannot reach: plan-only or MFA-gated apply credentials, a versioned, object-locked remote state bucket, a host sandbox, and a reviewed apply path. [credentials.md](credentials.md) describes the first. `applygate doctor --boundary` checks what it can and reports an assurance level ([boundary.md](boundary.md)).
- **The credential audit is a sample.** It samples 19 AWS actions (three on the state bucket), four kubectl verbs, 17 Google Cloud permissions and Azure role assignments, and sees no other provider. The CI apply path and the state guards are attested, not checked.
- **What the audit has been run against.** It was run against real accounts for the first time on 2026-11-14, on one machine.
  - One AWS IAM user was audited end to end: its identity, then the policy simulator with MFA absent. Three AWS profiles and one gcloud account whose sign-in had expired were reported as not checked.
  - On 2026-11-15 a second IAM user, signed in through `aws login`, was identified and then refused the simulator call by AWS, because it lacked `iam:SimulatePrincipalPolicy` on itself. It was reported as not checked, with the grant to make ([credentials.md](credentials.md)). After that grant the audit ran and found five destructive actions allowed without MFA. That was reported as a credential in no named environment while no config named the account, and as `FAIL` (`doctor --creds` and `doctor --boundary --require L2` exit 1) once a user config named the account protected.
  - The Google Cloud audit was run the same day against one user account on one project. It reported the 14 of 17 destructive permissions the account holds: as a warning with no config naming the project, and as `FAIL` with one.
  - Not yet run against the real service: an AWS assumed role or SSO profile, the root user, a Google Cloud service account, and the Kubernetes and Azure audits.
- **Reads of credential files.** The hook asks about a read of the three AWS credential paths and Terraform's credentials file by `cat`, `less`, `more`, `head`, `tail`, `grep`, `rg`, `awk`, `base64`, `xxd`, `od`, `strings`, `bat`, `nl`, `cp`, `scp` and `curl`. Not covered: `sed`, `cut`, `sort`, `jq`, a redirect, a path named by a glob (`cat ~/.aws/cred*`), and the kube, gcloud, Azure, ssh and Docker files ([credentials.md](credentials.md)).
- **Credentials files that run a program.** A credentials file that a command names through `AWS_CONFIG_FILE`, `KUBECONFIG` or the like, and that holds a `credential_process` or an `exec` plugin, asks. So does one written earlier in the same command.

## Scan

`applygate scan` judges past calls with today's files and reads only Claude Code and Codex sessions. [scan.md](scan.md) lists what that leaves out. It has been run on the real session files of one machine (Claude Code 2.1.3xx, Codex 0.162 to 0.166). `scan --boundary` runs the credential audit of `doctor --boundary`, with the limits above.

## The Action and CI

- **What ran live.** On 2026-11-16, on throwaway pull requests of this repository, with a build from the branch: posting and updating the comment in place, a comment each for matrix legs and jobs that judge the same plan, two steps sharing one comment, an error comment, an older run leaving a newer run's comment alone, and a job without `pull-requests: write`. The released Action ran on 2026-11-24: `Flurit/applygate@v0.6.2` on Linux x86-64, Linux arm64 and macOS arm64 runners, a block and an allow on each, with the comments updated in place by a second run.
- **Tested with scripts only, or not at all:** a pull request from a fork, two runs posting a first comment at the same moment, `pull_request_target`, GitHub Enterprise Server, a self-hosted runner without `gh`, Windows runners, a pull request with more than 100 comments, and a reusable workflow called from two jobs.
- **The comment is found by name.** The name is the workflow, the job, its matrix values, `TF_WORKSPACE` and the plan (or `comment-key`). Renaming the workflow or the job starts a new comment and leaves the old one as it was. A plan outside the checkout is named by its absolute path, which can differ between self-hosted runners.
- **A job that stops before the Action runs** (a failed `terraform plan`, say) writes nothing, so the comment keeps the verdict of the earlier commit. Its footer shows the commit it judged.
- **The job summary and the `summary` output hold plan text.** The step summary puts the verdict text in a code fence without escaping it, so plan text that contains a fence can close it. A workflow that interpolates the `summary` output into a `run:` step runs text that a pull request controls.
- **The default `fail-on: block` passes a plan whose findings are asks,** such as an IAM wildcard policy or an unprotected stateful create ([ci.md](ci.md)).
- **The release pipeline.** The release job restores a Go build cache that the test job can write.

## Asks and blocks you may not expect

These are the costs of the rules: harmless commands that are asked about or blocked. Unless a line says otherwise, an ask here comes from strict shapes: it applies in a protected directory, and in a directory next to a protected one when the command can also run code the analysis does not follow. A command that changes something is still judged on its class (a destroy, a cloud write and so on); in a protected tier it also asks as not plain. In a repository with no config these asks apply only to a command that names an infrastructure tool or a guard file ([A repository with no config](#a-repository-with-no-config)). Turn strict shapes off with `strict_shapes: false` in the user config if you accept the shell constructs it covers.

Where a line says a program is plain "with listed options", the lists are in the source: `internal/shell/allow.go`, `allow_tools.go`, `allow_cli.go`, `allow_git.go` and `allow_scan.go`.

### Shell constructs

- **Not plain:** loops, `python3` edits, `export`, `xargs`, `timeout`, `${x:-…}`, and a variable off the safe list (`PAGER=less`, `KUBECONFIG=…`).
- **Redirects.** A plain command may use only the redirections every shell reads alike: `>`, `>>`, `<`, here-documents and here-strings, and `>&`/`<&` to a descriptor number, with one literal word as the target. Not plain: a target with a glob, brace, tilde, `$`, backtick or leading `=`; `>|`, `>!`, `<>`, `&>` (in dash a background job and a redirect) and `{fd}>`. So `echo x > out{1,2}.txt` and a write to a variable target ask.
- **`cd`** takes one operand and `-P`/`-L`. `cd -` and zsh's `cd OLD NEW` are not plain.
- **`sed -i` on macOS.** `sed -i` takes the next word as the backup suffix, as BSD sed does. So `sed -i 's/a/b/' eks.tf` asks: BSD sed would read `eks.tf` as the script.
- **Persistent shells.** Input typed into a persistent shell is judged as protected. A destroy there blocks in a disposable directory too, and a terraform call that starts providers asks.

### File and text tools

- **Plain only with listed options, by exact name:** `rm`, `mkdir`, `touch`, `chmod`, `ln`, `cp`, `mv`, `tee`, `sort`, `uniq`, `tree`, `diff`, `xxd`, `base64`, `gzip`, `gunzip`, `unzip`, `date`, `hostname`, `file`, `gofmt`, `tfsec`, `gsutil`, `find`, `cat`, `head`, `tail`, `wc`, `cut`, `ls`, `basename`, `dirname`, `realpath`, `readlink` and `seq`. `sed` and `tar` accept only listed options, and `sed`'s script is read too. Any other option, and any abbreviation (`--recur`, `sort -oout`), asks.
- **These ask:** `gzip`/`gunzip` without `-c`, `-l` or `-t` (they compress or expand in place), `uniq IN OUT`, `xxd -r IN OUT`, `base64 -o`, `sort -o`/`-T`, `tree -o`, `gofmt -w`, `date` with a time operand, `hostname NAME`, `file -C`, and `find` with `-exec`, `-delete` or `-fprint*`. A `find` whose start point is a variable asks.
- **Pagers:** `man` and `less` ask.

### curl, wget, zip, yq, rg, printf, tflint and actionlint

- **Plain only with listed options, by exact name.** Abbreviations (`curl --silen`) ask.
- **`curl` and `wget` may name one output file per call** (`-o`, `-O`, `-P`), which is judged as a write. These ask: a second output; a glob variable in the output name (`-o 'out_#1'`); `-w` with `%output{…}` or `@file`; `-K`, `--next`, `--create-dirs`, `--output-dir`, `-c`, `-D`, `--stderr`, `--trace*`, `--libcurl`, `--hsts`, `--alt-svc`, `--etag-save`, `--engine`; wget `-o`, `-a`, `-i`, `-b`, `-r`, `-m`, `-e`, `--content-disposition`, `--save-cookies`. So a curl call that saves headers or cookies asks, and so does a recursive or mirrored wget download.
- **Others that ask:** zip `-O`, `-b`, `-T`; `yq -s` and `yq --security-enable-system-operator`; `rg --pre`/`-z`.

### terraform and tofu

- **Plain subcommands:** `plan`, `apply`, `destroy`, `init`, `validate`, `fmt`, `show`, `output`, `import`, `get`, `graph`, `version`, `stacks configuration list`, `providers` (none, `schema`, `lock`), `state list|show|pull` and `workspace list|show|select`. Each lists its own options (as Terraform 1.14 and OpenTofu document them). `-no-color` is accepted everywhere. `-state` is allowed for reads only.
- **Not plain:** `-state-out`, `-backup`, `-generate-config-out`, `-plugin-dir`, graph `-type`, `-chdir` after the subcommand, `console`, `test`, `refresh`, `taint`, `state rm|mv|push`, `workspace new|delete`, `workspace select -or-create` (it makes a workspace and its state), `providers mirror`, and any other unlisted subcommand.
- **These ask in protected tiers:** `terraform apply|destroy -state=FILE`. `terraform import` asks outside a disposable directory.
- **Providers and modules.** `plan`, `validate`, `console`, `show`, `graph`, `query` and the other subcommands that start providers ask in a protected directory when the conditions under [Terraform, providers and modules](#terraform-providers-and-modules) do not hold. The common cases:
  - a provider outside the list: datadog, cloudflare, github, pagerduty, the external provider and the like;
  - a remote module that `init` has not installed;
  - providers that do not match a committed lock file, a repository that does not commit `.terraform.lock.hcl` included;
  - installed providers and no upstream branch, or a committed lock file that differs from the upstream branch's;
  - a `data "external"` or another construct that runs a program;
  - a `data "archive_file"` whose `output_path` is outside the module, names a state file or cannot be resolved (the provider writes the archive during plan);
  - a provider `host` that is not localhost.
- **`init`.** `terraform init -upgrade`, `-plugin-dir`, `-from-module`, `-lockfile`, `-get-plugins`, or `get -update` (one or two dashes, with or without `=value`) installs what the lock file does not vouch for. A terraform call after it in the same command asks. A plain `init && plan` asks too, unless the providers are already installed to match a committed lock file, and it asks when the configuration calls a module `init` would fetch.
- **A terraform call after an earlier step of the same command writes its directory's configuration or state** (`printf … > x.tf && terraform plan`, `git pull && terraform plan`) is judged as protected and asks. Run the steps as separate calls.

### terragrunt

- **Plain only for** `hclfmt`, `hcl fmt`, `--version`/`-version` and `--help`/`-h`. Every other command asks in a protected directory, `terragrunt version`, `terragrunt help` and `terragrunt fmt` included. Terragrunt evaluates `terragrunt.hcl`, whose `run_cmd()` and hooks run programs.

### git commands

- **Options are listed per subcommand,** for 58 subcommands, by exact name. Left out for every subcommand: `--ext-diff`, `--textconv`, `--exec`, `rebase -x`/`-i`, `--upload-pack`/`--receive-pack`, `grep -O`, signing, `--edit` and the interactive forms, `--help`, `--output`, `--template`, `--git-dir`, `--work-tree`, `archive -o`/`--remote`, `format-patch` without `--stdout`, `branch -d/-m/-u`, and any abbreviated long option. An unresolved word is not plain, since a variable may be `--output=f`.
- **These ask:** `git commit` without a message source (`-m`, `-F`, `-C`, `--no-edit`, `--dry-run`) and `git tag -a` without `-m`/`-F`, since they open the editor; `git rebase -i`, `git add -p`, `git commit -S`; `merge`, `pull` and `rebase` with `-s` other than a built-in strategy; `git gc`, `notes` writes, `bundle create`/`unbundle`, `symbolic-ref` with a second operand, `reflog expire|delete`.
- **These ask because they can move the upstream branch that the provider check trusts:** `git push`, `git remote add|set-url|…`, `git branch -u|-m|-d`, `git branch --unset-upstream`, and `git update-ref` or `symbolic-ref`.
- **Repository state.** A git command asks when any git config it reads has a key off the safe list, when the repository has a hook, when a git alias points to another git command, or after `git init`, `git clone`, an extraction or a recursive copy earlier in the same command.
- **Network commands.** A git network command whose repository is a word that is not a URL, an scp-like address or a configured remote asks when a directory of that name exists. `git --bare` asks.
- **Blocked as tampering:** `git config` of a key that runs a program (`core.editor`, `core.fsmonitor`, `alias.*` with `!`, `gpg.program` with arguments), `git config --global` of such a key, `git replace`, and a write to `.git/config` or `.git/hooks/**`.

### gh and glab

- **Plain:** read verbs, plus `pr create|comment|merge|checkout|close|reopen|ready|edit` and `issue create|comment|close|reopen|edit`.
- **These ask:** `--web`, `--editor`, downloads, `gh pr review`, `release create`, `workflow run`, `repo create|delete`, `auth login`, aliases and extensions.

### kubectl, helm, vault, aws, az and gcloud

- **`kubectl`** is plain for `get`, `describe`, `logs`, `top`, `explain`, `api-resources`, `api-versions`, `version`, `cluster-info`, `events`, `wait`, `completion`, `port-forward`, `rollout status|history`, `auth can-i|whoami` and the read `config` subcommands.
- **`helm`** is plain for `list`, `get`, `status`, `history`, `show`, `search`, `template`, `lint`, `version`, `env`, `verify`, `completion` and `repo|dependency list`.
- **`vault`** is plain for `status`, `version`, `read`, `list`, `kv get|list`, `kv metadata get`, `token lookup` and `secrets|auth|policy list|read`. Its options are Go flags after the subcommand, with one dash or two.
- **`aws`** is plain for read operations (`describe-`, `list-`, `get-`, `batch-get-`, `head-`, `lookup-`, `search-`, `validate-`, `filter-`, `estimate-`, `test-`, `wait`, `tail`, `query`, `scan`), `s3 ls`, `configure get|list` and `eks update-kubeconfig`. **`az` and `gcloud`** are plain for read verbs.
- **Options that are not plain:**
  - the global options that send a call to another cluster, server or identity than the context names: `--kubeconfig`, `--server`, `--cluster`, `--user`, `--token`, `--as` and the certificate options; helm's `--kube-apiserver`, `--kube-token`, `--kube-as-*`, `--registry-config` and `--repository-config`;
  - options that write files: `--profile-output`, `--cache-dir`, `--log-file`, `helm template --output-dir`;
  - `kubectl -k`, `helm --dependency-update`, `--verify` and the credential options;
  - `aws --cli-auto-prompt` and `--generate-cli-skeleton`, `gcloud --flags-file` (it reads more options from a file) and `--access-token-file`;
  - for `aws`, `az` and `gcloud`, a word that may be an option and cannot be resolved.
- **So these ask in protected tiers:** `kubectl apply|delete|exec`, `aws s3 cp|sync`, `helm install|upgrade`, every `az` or `gcloud` command with a write verb, and any `kubectl`, `helm` or `vault` option that is not listed.
- **A subcommand that runs a program here** widens the directory the command is judged in, under the cross-directory rule: `ssm start-session`, `kubectl exec|edit|diff|cp|debug|run`, `az ssh|run-command`, `gcloud compute ssh`, `helm install|upgrade|plugin`, and an unlisted `terraform` subcommand. Other write subcommands do not.

### docker and podman

- **Plain:** read subcommands. `-H` takes only `unix://`, `tcp://` and `npipe://`. For podman, no runtime, conmon, hook, remote or storage option is plain.
- **These ask:** `docker run`, `docker ps -H ssh://…`, `docker compose up|run`.

### make, package managers and build tools

- **`make`** asks in a protected directory.
- **These ask:** `npx`, `npm`, `pip`, `cargo`, `brew`, `go build` and `go test`.

### Policy and cost tools

- **`infracost`** is plain for `version`, `help`, `output --path` and `configure get`. `breakdown` and `diff` run terraform. `configure set` and `auth` ask.
- **`terraform-docs`** is plain for its format subcommands. It asks with `-c`, an `--output-*` option, or a `.terraform-docs.yml` in a directory it reads.
- **`checkov`** asks with external checks or `--config-file`. Its config files are checked.
- **`trivy`** asks with `-o`, `-c`/`--config` or `--kubeconfig`.
- **`kustomize`** is plain for `build` and `version`. Plugin options, `-o` and `edit` ask.
- **`opa`** is plain for `eval`, `test`, `fmt`, `check`, `inspect`, `parse` and `version`. `opa build` and `opa fmt -w` ask.
- **`conftest`** is plain for `test`, `verify`, `parse` and `version`. `conftest fmt` and `--update` ask.

### Blocked in every tier: a person does it

- **Programs on `PATH`.** Writing `terraform`, `tofu` or `terragrunt` into a `PATH` directory (`~/.local/bin`, `/usr/local/bin`, …), so an agent cannot install an engine there. Writing any other program strict shapes trusts into a `PATH` directory. Placing `ssh`, a `git-remote-*` helper or a Kubernetes or AWS credential plugin there. Writing into Homebrew's Cellar (a symlinked program on `PATH` ends there).
- **Python start-up files:** a `.pth`, `sitecustomize.py` or `usercustomize.py` file.
- **Terraform's plugin directories:** writing under `.terraform/providers`, `.terraform/modules` or `~/.terraform.d/plugins`.
- **Agent CLIs.** Installing, updating or replacing one: `claude update`, `npm i -g @anthropic-ai/claude-code`, `brew upgrade codex`, a copy into `~/.local/share/claude`.
- **Agent settings commands:** `claude mcp add`, `claude plugin install`, `codex features …`, `codex mcp add` and `gemini extensions …`.
- **Nested agents with their own configuration:** a nested `claude --mcp-config`, `--strict-mcp-config`, `--plugin-dir` or `--agents`, `copilot --additional-mcp-config`, `gemini --extensions`, and `codex -c mcp_servers.*`, `-c notify` or `-c profiles.*`.
- **Files in which a program names a command:** a skill, subagent or command in `.claude/`, any host's MCP server list, `~/.gitconfig`, `~/.aws/config`, `~/.kube/config`, and `aws configure set` (a write of `~/.aws/config`).
- **Commands that set such a value:** `gh alias set`, `gh config set pager|editor|browser`, `kubectl config set-credentials --exec-command` and `aws configure set …credential_process`.
- **Other guard paths:** Claude Code's shell snapshots and session environment files, `~/.ssh/config` (and `config*` beside it), Docker CLI plugins, `~/.curlrc`, Azure CLI extensions, `~/Library/LaunchAgents`, fish, `environment.d`, systemd user units and oh-my-zsh custom files.

## Open findings from reviews

Lines on this page that say "open", "reported", "not covered" or "not known to be fixed" come from the pre-release reviews of v0.6.0. The findings, with their reproductions, are in the review records: [1](../review/v0.6.0/2026-11-04-red-team-round-7.md) and its [fix plan](../review/v0.6.0/2026-11-04-round-7-fix-plan.md), [2](../review/v0.6.0/2026-11-04-red-team-round-9.md), [3](../review/v0.6.0/2026-11-05-red-team-round-10.md), [4](../review/v0.6.0/2026-11-05-red-team-round-11.md) and the [reassessment](../review/v0.6.0/2026-11-05-reassessment.md), which concluded that parsing cannot carry "never allowed" by itself.

## Numbers to read with care

- **The "17 / 17" comparison** is a self-authored scenario set against self-chosen guards.
- **The attack pack** consists of the reviewers' own finds. It shows that fixed findings stay fixed, not how much is covered.
- **About a third of real agent calls ask in a protected directory.**
- **Asks in repositories with no config, on one machine.** `applygate scan` on the machine applygate is developed on (2026-11-25, 192 sessions, about 12,300 ordinary shell commands, every repository without a config) found 59% of those commands asked about under the full rule and 32% under the rule for a repository with no config; the infrastructure verdicts were the same (212 blocks, 25 asks). Of the asks that remain, 43% are scripts the replay could not read, many of them deleted since. Under the full rule nine in ten of the strict-shapes asks were in the applygate checkout, where commands name `terraform` all day, so another machine will differ.

## Untested

Untested areas are listed with their topic: hosts and Claude Code modes under [Agents and hosts](#agents-and-hosts), the managed install under [Self-protection](#managed-install), MCP servers under [MCP tools](#mcp-tools-and-tools-no-table-describes), the credential audits under [Credentials](#credentials-and-the-boundary-report), the Action under [The Action and CI](#the-action-and-ci), the planfile workspace check under [Plan gate](#plan-gate), and the judge under [Model judge](#model-judge). Two more have no other home.

- **The option tables are checked against the real programs only where those are installed.** A conformance test runs every listed option and fails on a write outside a scratch directory, an unaccounted file or a started program.
  - A program that is not installed is skipped. `curl` and `zip` run on the development machine, and the Ubuntu CI image also has `yq`. `wget`, `rg`, `tflint` and `actionlint` may run on neither, so their entries rest on review of the tables. The same holds for an option of a program variant that is missing, such as BSD `date -v` or GNU `tree` on a minimal CI image.
  - `git`, `docker`, `gh`, `opa`, `terraform` and `kubectl` are in the run. `helm` and `vault` run only where they are installed; CI does not install them. `aws`, `az` and `gcloud` are not in it.
  - An option shared by several subcommands runs once (per family for git, per program for the others). The test checks the spelling of an option, not each subcommand's use of it.
  - `gh` and `glab` options are listed from the documentation and run once per option name, not per verb. The podman options are the docker ones.
- **The effects oracle** is a CI test. It runs destructive commands through many spellings, asks the guard, and runs every allowed command under bash, zsh, dash and sh against fake `terraform`, `tofu`, `aws`, `kubectl`, `helm`, `az` and `gcloud` programs that record what they were asked to do. It does not cover:
  - a command, program form or wrapper that nobody wrote. A clean run proves nothing about them;
  - an option that the real tool treats as a target and the fake does not record;
  - file effects outside the prod directory;
  - the hook adapters' own parsing (Claude Code, Codex), which the replay pack covers instead;
  - zsh-only behaviour on Linux. CI's Ubuntu runner has no zsh, so that is checked on macOS only.

## Not built

- **Backup isolation checks, receipts and Pulumi rules.**
- **Plan-gate rules for GCP, Azure and Kubernetes resources.** Their CLI commands are classified; plans are judged with AWS rules only.
- **A credential broker.** The credential boundary is described in [credentials.md](credentials.md).
- **An integrity record at hook start:** a hash of the hook entries and user config, recorded at install and checked on every call. An agent that can write the files can rewrite the record too, and a hash of a whole settings file would block on every legitimate settings change. A managed install is the answer instead.
- **An operating-system presence check for approvals.**
- **A reviewed allow list of scripts** for the cross-directory rule.

## Network calls applygate makes

Only the user config or the person at the terminal can enable any of them:

- the optional model judge, which sends each call it judges (redacted) to the endpoint or program the user chose ([judge.md](judge.md));
- the optional STS identity check (`preflight.live_identity`);
- the optional state pull for lineage comparison (`preflight.live_state`);
- after a person runs `applygate telemetry on`, one anonymous usage report a day ([telemetry.md](telemetry.md)).
