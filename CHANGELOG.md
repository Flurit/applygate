# Changelog

## Unreleased (reassessment root fixes)

- **Unknown values carry a reason** (`shell.Word.Why`): a word the analysis cannot resolve records what made it unknown; unknown terraform options, `-chdir` values and subcommands make a call not plain and say why; `applygate explain` shows it.
- **A positive rule for Terraform configuration** (`preflight.Understood`): providers that may start are plain only when every config file of the directory and its modules parses within the cap, module sources are local or installed, providers are on a closed list and locked, and the lock file is held by an upstream branch. Replaces the deny-list scans as the first line for `tfquery`, `graph -type=plan`, files over 1 MiB, modules `init` fetches and unresolved `-chdir`.
- **Recovered panics fail closed:** `on_error: allow` does not apply to a panic where a protected tier is in reach; a panic after the policy asked or refused never allows; a panic in the recovery or the watchdog goroutine blocks; `applygate check` exits 2. Tests inject panics at each stage.
- The attack pack gains 23 scenarios (`reassess-6`, one for each of the ten criticals the reassessment said no allow-list reaches, and their variants). Costs: `docs/limits.md` ("Reassessment: the root fixes").

## Unreleased (boundary contract)

- **`applygate doctor --boundary [--require L1|L2|L3]`** reports an assurance level L0 to L3: managed exclusive install, audited credentials, host sandbox in managed settings plus attested CI apply and state guards. `boundary.require` and `boundary.attest` are user or system config only. Docs: `docs/boundary.md`.
- **`doctor --creds` and `--boundary` ask about three state-bucket actions** (`s3:DeleteObjectVersion`, `s3:PutBucketVersioning`, `s3:DeleteBucketPolicy`): 19 actions, up from 16.
- **README promise restated:** applygate is a pre-execution reviewer that allows only recognized commands in protected tiers, not a guarantee that a command is never allowed; the guarantee comes from the boundary. "Parses the way the shell does" now says bash, with other shells in part; the 17 / 17 comparison is labelled as our own scenario set.

## Unreleased

- **Effects oracle extended and made a gate** (`harness/oracle_test.go`, `oracle_gen_test.go`): cloud effects (fake `aws`, `kubectl`, `helm`, `az`, `gcloud` that log argv and the cloud environment), `terraform apply` of saved plans (a destructive plan, a plan made in another workspace, `-state` at the prod state), seeded generated spellings (program forms, directory changes and wrapper chains; the seed is logged), and its own CI step on Ubuntu and macOS. **It found a second bypass:** a here-document body was read as a shell word, which drops backslashes, so `bash <<'EOF'` around `sh -c 'sh -c '\''X=1 terraform destroy -auto-approve'\'''` was allowed and ran a prod destroy; fixed (`hdocWord`), scenarios `AL5-H4` to `AL5-H7`.
- **Allow-list, stages 3 to 5** (`review/v0.6.0/2026-11-05-allow-list-plan.md`): positive grammars for redirects and `cd`; `terraform`, `tofu`, `aws`, `az`, `gcloud`, `kubectl`, `helm` and `vault` plain only for listed subcommands and options; and an effects oracle (`harness/oracle_test.go`) that runs what the guard allows under bash, zsh, dash and sh against fake tools. **The oracle found a bypass on its first run:** from a dev directory, `cd ../pro* && echo '{}' > .claude/settings.json` was allowed and rewrote the prod hook settings; fixed. The attack pack gains 21 scenarios (849). Not done (writer tables, `git` option lists, `docker`/`gh` and others): `docs/limits.md` ("Allow-list, stages 3 to 5").
- **Allow-list, stage 2:** `curl`, `wget`, `zip`, `yq`, `rg`, `printf`, `tflint` and `actionlint` are plain only with the options listed by exact name (`internal/shell/allow_tools.go`); one output file per `curl`/`wget` call, no option files, header, cookie or trace outputs, no recursion, no preprocessors. The conformance test gains sample operands and a list of the options whose output file the analysis judges. No verdict changed on the agent trial; the attack pack gains 17 scenarios (828 in all). Costs and what is left: `docs/limits.md` ("Allow-list, stage 2").
- **Allow-list, stage 1** (`review/v0.6.0/2026-11-05-allow-list-plan.md`): 24 programs that were plain with any arguments are plain only with the options listed by exact name (`internal/shell/allow.go`); the rest of the old list is audited in `inert`. A conformance test runs every listed option with the real program and fails on a write outside the scratch directory, an unaccounted file or a started program. No verdict changed on the agent trial; the attack pack gains 13 scenarios (811 in all). Costs and what is not done: `docs/limits.md` ("Allow-list, stage 1").
- **Network requests with a body are writes** (reassessment quick gap, `review/v0.6.0/2026-11-05-reassessment.md`): `curl`, `wget`, `http`/`xh` and `gh api` calls to a host other than this machine that send anything but GET, HEAD or OPTIONS (explicit method, body, form, upload, unresolved method) are cloud writes; with DELETE, deletes. An HCP Terraform run created with `curl -d` was allowed before. No verdict changed on the agent trial. `docs/limits.md` gains "Reassessment: quick gaps and facts the earlier text left out".
- **Red-team round 11 fixes** (`review/v0.6.0/2026-11-05-red-team-round-11.md`): fixed by family; details and costs in `docs/limits.md` ("Costs of the round-11 fixes").
  - **State files by rule:** a program not known to only read that names a state file in any spelling is state surgery in that file's directory; `find -P`, `~+`, `--target-directory=`, `zip -mj`, `git archive -o`, `opa`/`kustomize`/`az rest`/`gh` outputs, `curl --hsts`, `wget --save-cookies`, `tar -r`, aws outfile calls, redirects, Write and Edit (C4 to C11, R6-1).
  - **zsh:** `cd OLD NEW`, brace expansion and `>!` in redirects (C1 to C3). **Unreported directory:** relative `cd`/`-chdir`/`-C` from it is unknown (R3-1). **Runners:** `direnv`, `mise`, `asdf`, `devbox`, `nix` environments are unknown (R6-2). **Buckets:** `aws s3` writes to a `backends:` bucket are state surgery; backend patterns are normalized (R6-3, R3-4).
  - **Fixed a round-10 crash:** `cp *.txt "$DEST"` panicked in the unresolved-name rule; an internal error now blocks commands that name an infrastructure program (R5-1).
  - Git option clusters and prefixes, terragrunt single-dash options, `gcloud projects delete`, `curl -X DELETE`, `gh` deletes, secret-printing reads, `yq` system operator; plan gate (deleted protections, CIDR unions, broad wildcards, admin ports); `applygate apply` applies the judged bytes; judge filter, MCP argument names, redaction of JSON strings, verdict message safety, size cap, `init` symlink, `install.sh` symlink, launcher retry, wrappers refusal (R4-1 to R4-9, R5-2 to R5-13, R3-2 to R3-6, R1-10 to R1-13).
  - The attack pack gains 48 reproductions and controls (790 in all). Cost on the agent trial: no verdict changes in prod, staging or dev.
  - Not done: listed in `docs/limits.md` ("Not done (round 11)").
- **Red-team round 10 fixes** (`review/v0.6.0/2026-11-05-red-team-round-10.md`): fixed by family; details and costs in `docs/limits.md` ("Costs of the round-10 fixes").
  - **"Followed" is decided per invocation,** not by program name: an unknown program with a standalone `terraform` word, or a second use of a name followed once, is not followed; a docker image is the first word after the options, not any word that mentions terraform (C2, C6).
  - **Shell semantics the analysis did not model are unseen code:** a bare shell reading an untracked stdin (`exec <<< TEXT; bash`, `bash <> FILE`, `>(bash)`), `${!x}` and `${x@P}`, functions through `command`/`env`/`exec`/wrappers, `unset -f`, same-line aliases, shadowed echo/pwd/printf, `xargs -0`/`-d`, `make -j TARGET`, `command printf -v`, an unresolved `-chdir=$x` (C1, C3, C4, C5, C7, C8).
  - **Strict-shape options:** single-dash multi-letter options glued (`zip -TTprog`), the double-dash spelling for Go-flag programs (`go list --toolexec`, `go env --w`, `actionlint --shellcheck`), `rg --hostname-bin` (C10 to C12).
  - **State:** `plan -out`/`-generate-config-out` over a state file, `aws s3`/`s3api` on a `.tfstate` object, and `rm`, `mv`, `cp`, `tee`, `dd`… with an unresolved name ask next to a protected environment (C9, R1-8, R3-6).
  - **Judge, MCP, scans:** any recognized action no longer hides the rest of a command from the judge; an unclosed private-key header makes a call unjudgeable; Cursor's `contents`; unknown tools with split program and arguments; `data "archive_file"` output paths; git promisor keys; lock-file comparison timeout; log redaction of every action field; repository `wrappers` limited to unknown programs (R4-4, R4-5, R4-6, R5-6, R1-7, R2-2, R5-9, R5-10, R3-7).
  - The attack pack gains 44 reproductions and controls (742 in all); `Y7H-C3` (a loop that removes `*.tmp`) asks now. Cost on the agent trial: no verdict changes in prod, staging or dev.
  - Not done: strict shapes by allow list, R2-1 (unverified), and the mediums listed in `docs/limits.md`.

- **The cross-directory rule is enabled.** A shell command that is not plain and can run code the analysis does not follow (python3, perl, awk, `sed …/e`, `tar --checkpoint-action`, a nested agent, an unresolved name or `PATH`, `init` followed by `plan`, terragrunt `run_cmd`) is also judged at the most protected tier under the repository root, so from a disposable or standard directory next to a protected one it asks. Syntax alone, and wrappers the analysis takes apart (`make`, `xargs`, `docker run`, an alias or function), do not. Cost on the agent trial: prod unchanged, staging and dev 40 more asks of 162 (`docs/limits.md`). The attack pack gains 14 scenarios (698 in all); eight benign controls ask now and two of `harness/pack`'s benign scenarios (B34, B46) expect an ask.

- **Red-team round 9 fixes** (`review/v0.6.0/2026-11-04-red-team-round-9.md`): the 17 criticals and the highs, by rule where a rule covers the family (costs in `docs/limits.md`).
  - **Structural defaults:** an unknown tool name is looked into and logged, not allowed unseen; `git config --show-scope KEY VALUE` is a write; a configuration file the hook cannot read in full (over 1 MiB, unparsable, tfvars, a long module chain) makes the target unknown; a redirect on a command with no program (`env > FILE`) is a write.
  - **The shell analyzer follows what it can show and stops at what it cannot:** `set -a` and exported-name reassignment; arithmetic and array subscripts that run a command (`read`, `declare`, `let`, `$((x))`, `[[ -eq ]]`); `mapfile -C`, `compgen -C`, prompt variables; unresolved words that may hold `-chdir`; glued `-eVAR=val`; `make -sC`, `MAKEFLAGS`, `--eval`, command-line variables and `export` in a Makefile; chains over 20,000 links (a stack overflow before).
  - **Scans read what Terraform reads:** `*.tfquery.hcl`, `*.tftest.hcl`, `init -backend-config`, the recorded backend, OpenTofu's external key provider, modules `init` fetches; `terraform graph` of any type starts providers; writes under `.terraform/providers` are blocked.
  - **State surgery:** `git checkout REV`, `tar -C DIR -xf`, ancestor directories, `find -delete`, glob destinations and `plan -out=terraform.tfstate`, judged against every state file in the repository.
  - **Targets and tiers:** helm's nested kubernetes block, `config_path`, `host`, `KUBE_CONFIG_PATH`, awscc, azapi, Terragrunt `generate` blocks, name hints for provider contexts, projects and subscriptions, `@` and space in names, case folding of whole patterns, `plan-check` local-backend state, `terragrunt exec` and `backend`, `terragrunt.hcl.json` units.
  - **Judge and MCP:** generic shell tools judged by their arguments (`args`, `argv`, any command field); every matching case of a known tool; non-object arguments asked about; recognized read-only actions no longer hide the rest of a command; a positive list of harmless variables; in-tree copies and extractions judged as writes; command-named targets reach the judge's tier; `check` does not ask the judge inside an agent session; plan conditions' values ORed.
  - The attack pack gains 82 round-9 reproductions and controls (684 in all). Cost on the agent trial: no verdict changes in prod, staging or dev.

- **Red-team round 8 fixes** (`review/v0.6.0/2026-11-04-red-team-round-8.md`): fixed by rule where a rule covers the family, not by listing the reported spelling.
  - **Writers and redirections:** `>&` and `<&` with a file word are writes; `env` is parsed as GNU env is (option clusters, unique-prefix long options, `-S`, `-C`, `-u`); `sed`, `gsed`, `perl`, `ruby`, `yq` in-place clusters, `find -fprint*`, `tar c`, decompressors, `tree -o`, `git --output`, `aws s3api get-object` and `gh`/`glab` checkouts write their targets (8C1, 8C2, 8C4, 8C5, 8C10).
  - **Checks that skipped a case:** init and state calls scan the backend; `check` blocks, shell resources, provider `exec` forms and computed Terragrunt backends are covered; `init -plugin-dir`, `-upgrade`, `get -update` and an `init` the lock file does not vouch for count as installs (8C6, 8C7, 8C8, 8H13, 8H14).
  - **Effects across directories:** git config keys that run programs, hooks and the repository config, `EDITOR` and the other program variables, process substitution, `make --dir` abbreviations and credential files named by environment variables are judged where they run (8C3, 8C9, 8C11, 8C12, 8C13, 8C14).
  - **Names and state:** a default value in a guard file's name, `patch` text naming a guard file, unscoped agent packages in `npx`/`bunx`, `git replace`, glob and directory removal and copies of state, symlinked state directories, `GOOGLE_PROJECT` and `ARM_SUBSCRIPTION_ID` tier signals (8H1, 8H2, 8H3, 8H4, 8H6, 8H15, 8H16).
  - **Strict shapes:** `git push`, remote and branch mutators, `infracost` and `terraform-docs` options are not plain (8H7, 8H8, 8H9); unresolved contexts and profiles ask (8H10); the judge's filter matches abbreviated options and `applygate trust`/`doctor --creds` mentions (8H11).
  - The attack pack gains 72 round-8 reproductions and controls (602 in all).
  - Cost on the agent trial: 59 of 162 calls in a protected directory are asked about or blocked, against 54; staging and dev are unchanged.

- **Red-team round 7 fixes, R7-3: the highs** (`review/v0.6.0/2026-11-04-red-team-round-7.md`, plan in `2026-11-04-round-7-fix-plan.md`):
  - **Shapes:** `terragrunt version` and `fmt` are not plain (only `--version`, `hclfmt`, `hcl fmt` and help); checkov's config is looked for in the home directory and each `-d` directory; `podman --runtime`, `--conmon` and the other options that name a program are not plain; Git LFS's `extension`, `customtransfer` and `standalonetransferagent` keys are off the safe list, and with LFS configured a command that writes the working tree checks the credential helper too (7H4, 7H7, 7H8, 7H12).
  - **Makefiles:** one that uses `define`, conditionals, pattern or default rules, `.DEFAULT_GOAL`, `.RECIPEPREFIX`, `.SHELLFLAGS`, `$(eval)`, `$(call)` or `$(shell)` is not analyzed, and `make` then runs in an unknown directory (7H11).
  - **State files:** `sort -o`, `xxd -r`, `uniq`, `base64 -o`, `yq -i`, `gzip`, `zip`, `curl -o`, an extraction, `git clean`, `git stash` and the other tree-rewriting commands are state surgery when they can replace a state file (7H9).
  - **Classes:** `terraform stacks` approving or applying plans is an unreviewed apply (its read subcommands read); `helm test` changes the cluster; `kubectl --context X --cluster Y --user Z` and `helm --kube-context X --kube-apiserver …` act on a cluster other than the context's and are judged as unknown (7H10, 7H13).
  - **Guard:** `ssh`, `git-remote-*`, `git-merge-*`, `git-credential-*`, `docker-credential-*`, the Kubernetes and AWS credential plugins and the other helpers a plain call starts are guarded in `PATH` directories; Homebrew's Cellar and Python's `.pth`, `sitecustomize` and `usercustomize` files are guard paths; a change through a path that cannot be resolved (`rm $f` over `~/.claude/*`, `xargs rm`, an expansion inside a guard file's name, a redirect to one) is tampering (7H1, 7H3, 7H6).
  - **Tiers:** workspaces and Azure subscriptions match without regard to case; the google `project`, kubernetes `config_context` and azurerm `subscription_id` of provider blocks are tier signals, under any local name and in modules; the plan search for hosts that do not report the directory treats a symlinked directory as an incomplete search (7H19, 7H21, 7H22).
  - **Plan gate:** the OpenSearch and Elasticsearch domain policy is read from `access_policies`; a `"*"` principal is public unless the condition names a key that limits who is reached; `Allow` with `NotPrincipal`, admin policies in exclusive attachment sets and SSO, public snapshots and images and layers, and inline bucket, EFS and API Gateway policies are exposure (7H20).
  - **Judge:** strict shapes no longer hides an unknown shell program from the judge; `git push` with an abbreviated `--mirror`, `--prune`, `--delete` or `--force` option and `/usr/bin/env | cat` reach it; `~/.m2/settings.xml`, shell history, `~/.fly` and a few more credential files are in its filter (7H2, 7H16).
  - Cost on the agent trial: no verdict changes in prod, staging or dev against main.

- **Red-team round 7 fixes, R7-1: four rules for the round-6 checks** (`review/v0.6.0/2026-11-04-red-team-round-7.md`, plan in `2026-11-04-round-7-fix-plan.md`):
  - **Unknown, not absent.** A tier signal whose value cannot be resolved makes the target protected: `TF_WORKSPACE=$X`, `AWS_PROFILE` set by `read`, `KUBECONFIG`, `TF_CLI_ARGS*`, an unresolved `-backend-config` before a destroy, unresolved arguments to a changing terraform call, an unresolved credential-runner profile, and the variables a secrets runner sets. `read`, `mapfile`, `readarray` and `getopts` assigning an upper-case name are not plain. Relative config paths in the environment are resolved against the command's directory (7C10, 7C11, 7C17).
  - **Written earlier means not plain.** A terraform call whose directory an earlier step of the same command writes (configuration, `.terraform`, lock file, state, or a tree that `git reset`, `git merge`, `init -from-module` or an extraction rewrites) is judged as protected and is not plain. Overwriting, removing or moving a state file is state surgery by any writer; a state copied into another Terraform directory carries its source's tier. `workspace new -state` is state surgery. Stream plans are recognised by any spelling; `plan -state=FILE -out=p` gives `p` FILE's tier (7C12, 7H17, 7H18).
  - **Ask the program.** The git directory is found on the physical path, passing over a `.git` that is not a repository, and checked against the hook's own git; `--bare` is not plain. A network subcommand's repository must be a network URL, an scp-like address or a configured remote; `archive --remote` counts. Every terraform subcommand outside a short read-only list is checked for providers, `graph` and `query` included. The configuration is parsed with Terraform's HCL and JSON parsers, `.tofu` included, following modules in any form and the module manifest; provider and backend `exec` blocks and config-file attributes count as running programs. aws providers count under any local name and in modules. Configuration reads are capped at 1 MiB (7C1, 7C2, 7C4, 7C5, 7C13, 7H5, 7H15).
  - **Shapes and shell:** zsh's `chdir`, `nocorrect` and `-`, and hook functions that change directory; `gh` and `glab` commands that run git; `helm` and `trivy --kubeconfig`; `sed` read as this machine's sed reads it; `go list -export`; terragrunt units' own signals in `run --all` and `plan-check`, and `stack run`; container `-e` and `--env-file`; `{}` inside a `find -exec` argument; input to a persistent shell judged as protected (7C3, 7C6 to 7C9, 7C14 to 7C16, 7C21).
  - **Guard and managed install:** guard paths are checked as written as well as resolved, so Homebrew's symlinked programs are guarded; the go env file and the agent CLIs' install locations are guard paths, and installing or updating an agent CLI is tampering; under a managed install the hook's git must be root-owned, the command judge runs in `/` with a home it cannot be given start-up files in and without `APPLYGATE_JUDGE_*` or proxy variables, an openai judge must use HTTPS with no proxy, and `doctor` reports a user-writable `claude` or `codex` (7C18, 7C19, 7C20).
  - Cost on the agent trial: 54 of 162 calls in a protected directory are asked about or blocked, against 51; 13 in staging and in dev, against 12.
- **The credential boundary, R7-2 option A** (`docs/credentials.md`): `applygate doctor --creds` asks AWS (`sts get-caller-identity`, `iam simulate-principal-policy` with MFA absent) and each kube context (`kubectl auth can-i`) whether the credentials the agent's environment can use may make destructive changes, and fails for production ones that can. The guide shows read-only agent roles, MFA-gated apply roles, Kubernetes `view` bindings, and why the person's SSO and cached role sessions must not share the agent's OS user.

- **Red-team round 6 fixes, strict shapes that check what programs read** (R6-2, design C in the fix plan):
  - **git:** every git directory git can reach (bare repositories, gitfiles, `commondir`, submodules) and every config file it reads (system, global, repository, worktree, includes) is checked; every key must be on a safe list, and keys that name a program pass only with a known one. Local repositories as remotes, `clone -c`, and git after a step that can write git state in the same command are not plain. `git config` is parsed with its valued options and subcommands, and a global write off the safe list is tampering (6C6, 6C7, 6C8).
  - **terraform:** a plain call that starts providers must find them matching the lock file committed at HEAD, which must match the upstream branch's, and no data source that runs a program (6H21).
  - **Programs:** `make` and `terragrunt` (but `hclfmt`) are not plain; nor are `curl -K`, `tflint --config`, `infracost --terraform-binary`, `actionlint -shellcheck`, `go -toolexec`, `kustomize --enable-helm`, `tar -T`, `sed -f` in any cluster or abbreviated, or an unresolved word where a shape denies an option. A program named by a path outside the system directories is not plain (6C9, 6C10, 6C11).
  - **zsh:** its special parameters, subscripted assignments and `hash NAME=PATH` are not plain; a `cd` as a pipeline's last element leaves the directory unknown; hook functions (`chpwd`, `zshexit`, `TRAP*`) are judged as running at any time (6C12).
  - **Persistent MCP shells:** input that defines shell state is tampering in every tier (6C16).
  - Cost on the agent trial in a protected directory: 51 of 162 calls asked about or blocked, against 47.

- **Red-team round 6 fixes, first milestone** (`review/v0.6.0/2026-11-03-red-team-round-6.md`, plan in `2026-11-03-round-6-fix-plan.md`):
  - **The hook's time and size are bounded.** A watchdog answers with a block when the run passes its 29 s budget, whatever is still running; config files over 1 MiB are not read (a repository config that large is untrusted); brace sequences and expansion past 64 KiB are unresolved. An 8 GiB sparse `.applygate.yaml` took 38 s and let Codex, Copilot, Gemini and Cline run the call; it now takes 0.05 s (6C17, 6H5).
  - **The managed judge is out of the user's reach.** The judge cache reads back only `ask` and `block` and is not used under a managed install; a managed `command` judge must be a root-owned program named by its full path, with root-owned scripts, a fixed `PATH` and a short list of variables; a judge that fails under a managed install makes the call unjudgeable (6C3, 6C4, R2-11).
  - **More guard paths:** Claude Code's shell snapshots and session environment files, `~/.ssh/config`, Docker CLI plugins, `~/.curlrc`, Azure CLI extensions, launch agents, fish, `environment.d`, systemd user units and oh-my-zsh custom files (6C1, 6C2, 6H1, R2-12).
  - **Nested agents:** `claude --mcp-config`, `--plugin-dir` and `--agents`, `copilot --additional-mcp-config`, `gemini --extensions` and `codex -c mcp_servers.*` or `notify` are tampering (6C5).
  - **Directories:** a command whose name, or an `eval` or `source` whose text, cannot be resolved leaves the directory unknown; so do `find -execdir`, runner directory options (`pnpm -C`, `yarn --cwd`, `mise --cd`, `poetry -C`, `parallel --wd`, `env --chd`) and a Terraform container whose `-w` is not under a mount, which is otherwise judged in the mounted directory (6C13, 6C14).
  - **Saved plans and state:** a plan read from `/dev/…`, or written in the same command by anything but `plan -out`, is protected; a `plan -out` elsewhere brings its directory's tier; a plan in a configured environment's path brings that tier; a state file in an unmatched directory gets the unknown-directory tier; `workspace new -state` passes its tier on; `terragrunt run --all` takes the most protected unit beneath it (6C15, 6H6, 6H9, 6H12).
- **The source builds and vets on Windows again** (not a release target): the approvals lock uses `LockFileEx` there and the terminal check the console mode, and CI vets for Windows.

- **Red-team round 5 fixes** (`review/v0.6.0/2026-11-03-red-team-round-5.md`, plan in `2026-11-03-round-5-fix-plan.md`):
  - **Exact shapes.** Strict shapes no longer trusts a list of program names: each program has a shape that says which of its calls can run no other program (subcommands and options), and a call outside it asks in a protected environment. Pagers and editors (`MANPAGER`, `PAGER`, `LESSOPEN`, `EDITOR`), `man -P`, `rg --pre`, `sort --compress-program`, git's `--upload-pack`, `--receive-pack`, `--exec`, `-c`, `ext::` and `filter-branch`, `tar --checkpoint-action` and `--to-command`, `zip -TT`, `sed`'s `e` command, `go generate` and `-toolexec`, `npx`, `brew` and kubectl or helm plugins are no longer plain (5C1, 5C3, 5C5, 5C6, 5H1 to 5H3). A variable set for a program must be on a short safe list. A `make` recipe's programs are checked too.
  - **Repository git state.** A git command is plain only when its repository has no hooks and no config key that runs a command, and a command that writes a git directory's hooks or config is not plain (5C4).
  - **Bounded criticals:** a `cd` or `pushd` to a directory that does not exist leaves the directory unknown (5C2); a repository config is parsed from the bytes its trust was checked against (5C7); an MCP tool's working directory is resolved after symlinks (5C8); a saved plan reached through a symlink is judged in the directory it leads to, and a hard-linked one as protected (5C9).
  - **What an allowed write can plant:** Claude Code skills, subagents, commands and every plugin's files, every host's MCP server list, the config files in which git, aws, kubectl, gh, docker, terraform, tflint, wget or helm names a command, and any program strict shapes trusts placed in a `PATH` directory the user can write, are guard files (5H4, 5H10). `claude mcp add`, `claude plugin install`, `codex features`, `codex mcp add`, `gemini extensions`, and `git config --global`, `gh alias`, `kubectl config set-credentials` or `aws configure set` that plant a command, are tampering in every tier (5H11).
  - **The hook and its launcher:** `preflight.live_identity` runs `aws` through `plan_gate.engines` (root's alone under a managed install) (5H5). The Claude Code plugin starts `/bin/sh`, runs its helpers from the system directories, skips relative `PATH` entries and pins a binary it downloads (5H10). Without an absolute home directory the hook blocks (5H13). The strict-shapes parse and alias parses have the nesting guard (5H14).
  - **Hosts that do not report the command's directory:** a relative path with a guard file's name is judged as that guard file (5H8).
  - **MCP:** the guard check of unknown tools cleans paths before its length check and, when arguments are too large or deep to walk, looks for guard names in their text (5H9); an array `command` is one command (5H12).
  - **Managed install:** messages and docs name `/usr/bin/sudo` and the managed binary by full path, and recommend `--exclusive` (5H7); the install and doctor check every directory above the managed files (5H15).
  - **Plan gate and cloud CLIs:** every admin port in a widened range is named, so an update that widens an open rule is seen; `s3:**` and `iam:?*` are wildcards; public SQS, SNS, KMS, ECR and Secrets Manager policies, `aws_lambda_permission` for `*`, a function URL without authorization and `authenticated-read` are exposure; `gcloud auth print-access-token` and `az account get-access-token` are credential access; `az rest --method delete` is a delete; `kubectl auth reconcile` is a write, and a delete with `--remove-extra-*`.

- **Red-team round 4 fixes** (`review/v0.6.0/2026-11-03-red-team-round-4.md`, plan in `2026-11-03-round-4-fix-plan.md`):
  - **The managed install is the documented guarantee.** Without one, self-protection is best-effort, and the README, threat model and limits say so.
  - **Strict shapes are on** (`strict_shapes`, user config only to turn off). In a protected environment a shell command that is not a plain list or pipeline of known programs asks; a wrapper or shell counts as the program it runs. This covers exported functions, arithmetic on a variable holding `$(…)`, `PS4` under tracing and `BASH_ENV=/dev/stdin` (4C1 to 4C4). Measured cost: 29 of 162 real agent calls (18%) ask in a protected directory.
  - **Tiers:**
    - `-backend-config` files are read as HCL or JSON, as Terraform reads them; a file that does not parse, a computed value, a missing file, or one written earlier in the same command is an unknown backend (4T3, 4T4). A computed value in the declared block stays unknown (4H9).
    - `..` is resolved after symlinks for `-chdir`, planfiles, `TF_DATA_DIR` and redirections; a `cd` through a symlink and `..` is unknown unless `-P` (4T1, 4T2).
    - A provider `profile` or `role_arn` in `var.NAME` takes every value the variable can have (`-var`, `-var-file`, `TF_VAR_*`, tfvars, the default); otherwise it is unknown (4H10).
    - `-state`, `-state-out`, `-backup` and a local backend's `path` bring their directory's tier (4H11).
    - Terragrunt `remote_state` values, a local `terraform.source`, `--source` and `TG_SOURCE` are signals, and `--config` judges both directories (4H12, 4H26).
    - Repository configs are found from the directory's real path (4H15).
  - **Plan gate:** a planfile downloaded or named by an earlier step (`aws s3 cp`, `scp`, `rclone`, `7z x`, a script) is unverifiable (4H13); IAM trust policies, attachment ARNs, default security groups and `publicly_accessible` known only after apply are flagged (4H14).
  - **MCP:** a command a server splits itself (`call_aws`, `call_kubectl`, …) is judged as the one argv it becomes, so a newline no longer splits it for the analyzer only (4M1).
  - **Managed install:** the plan gate runs an engine only from `plan_gate.engines` or a root-owned `PATH` entry (4H1), and writing `terraform`, `tofu` or `terragrunt` into a `PATH` directory is tampering everywhere. The user config's `judge` section is ignored. The trust hint names the managed binary's path.
  - **The log:** fields are redacted before they are cut, a private key cut off is redacted to the end, and one entry redacts at most 512 KB, so a huge command cannot push the hook past the host's timeout (4H3).

- **Red-team round 2 fixes, part 1** (`review/v0.6.0/2026-11-03-red-team-round-2.md`):
  - **Default-deny near guard files.** A shell command that names a guard file, or a guarded directory, is tampering unless the program only reads. This replaces recognizing each writer: `sort -o`, `yq -i`, `awk -i inplace`, `busybox`, `openssl -out`, `tar -C … -x`, `git clean` and git plumbing that name a guard file are all blocked. Unresolved words count when their literal text or their glob names one (`${HOME:-x}/.claude/settings.json`, `rm ~/.claude/setting*.json`).
  - **Redirections** on compound commands (`{ …; } > f`), bare redirections and `exec` redirections are checked.
  - **Case folding** follows APFS: `ſ` (U+017F) and the Kelvin sign fold to ASCII, and names are NFC-normalized.
  - **MCP tools outside the known-tool table** that name a guard file in their arguments are judged as writes to it.
  - **The hook's own git calls** run by an absolute path without the system and global config, with `fsmonitor`, hooks and pagers off, and read committed files with `git cat-file` instead of `git diff`. Before, an agent-set `core.fsmonitor` ran inside the hook.
  - **The decision log, approvals, judge cache, configs and telemetry settings** are opened without blocking, and only when they are regular files. Before, a FIFO at the log hung the hook.
  - **Limits:** nesting deeper than 2,000 levels is unresolved instead of crashing the process, and gzip output over the 256 KB cap is unknown instead of cut.
  - **`COPILOT_HOME`'s hook file** is a guard path.

- **Red-team round 3 fixes** (`review/v0.6.0/2026-11-03-red-team-round-3.md`):
  - **Trust:** only a regular file is trusted, so a symlinked `.applygate.yaml` no longer borrows another config's trust. A config that cannot be read is untrusted (protected) instead of falling to `on_error`. `applygate trust` trusts the bytes it showed and refuses a file changed before confirmation, and shows the config with its line breaks.
  - **Managed install:** the system config is read first and the user config may then only tighten; loosening user settings are ignored and noted. Existing managed directories are taken over (root-owned, mode 0755).
  - **Guard paths:** `APPLYGATE_*`, `CLAUDE_PLUGIN_DATA`, `CLAUDE_PLUGIN_ROOT`, `XDG_STATE_HOME` and `XDG_CACHE_HOME` on a nested agent are tampering; the plugin's data directory under `XDG_CACHE_HOME` and `CLAUDE_PLUGIN_DATA`, and both systems' managed Claude Code directories, are guard paths. An unknown MCP tool that names a guard file is a write unless every word of its name says it reads (`search_and_replace` writes). Split string literals (`'.'+'x'`, implicit concatenation, `os.path.join`) are rejoined for the guard check.
  - **Shell:** `BASH_ENV`, `ENV`, `ZDOTDIR` and `--rcfile` start-up files are run before the command; `CDPATH` and `cdable_vars` make a bare `cd` unknown (an environment `CDPATH` is followed exactly); tilde forms other than `~` are unknown; `hash -p` remaps are followed; `command_not_found_handle` bodies are analyzed; a script written in the same command is judged anywhere under the root; zsh glob qualifiers that run code are unresolved; a wrapper's skipped words stop at an infrastructure CLI.
  - **Backends:** read with HashiCorp's HCL parser, `.tf.json`, OpenTofu's `.tofu` files and override files included and dot-files skipped; a computed value, a parse error, or Terraform and OpenTofu reading different backends is an unknown backend. Provider blocks are read the same way.
  - **Plan gate:** action lists `show -json` never writes (`["Delete"]`, `["update","delete"]`, unknown actions) count as deletes.
  - **MCP and the judge:** tfmcp `destroy_terraform` without `plan_id` is a destroy; camelCase shell tool names are recognized; `git apply --directory` or `--unsafe-paths` goes to the judge.
  - **The log:** fields are cut to 64 KB before redaction, so a huge command no longer pushes the hook past the host's timeout; the log rotates at 64 MB; MCP arguments are redacted before they are cut. Redaction covers SSM parameter values, `--from-literal`, `vault kv put`, `gh secret set --body`, `az login -p`, secrets piped into secret stores, Cookie headers and Slack webhooks.
  - **CI and releases:** `plan-check --trust-config` (the Action's `trust-config`) reads the repository config on a runner, and `plan-check` says when a config was not read. Signature checks bind the workflow repository and tag ref.
  - **Docs:** `--plugin-dir` is for trying the plugin; the binary pin, telemetry, the matcher, the agents table and `uninstall --managed` are described as they work.

- **Red-team round 2 fixes, part 5** (data, supply chain, docs):
  - **Redaction:** quoted multi-word values, `-p'x'`, `docker login -p`, `redis-cli -a`, `sshpass -p`, PGP private keys, JSON `Authorization`, Azure `AccountKey` and SAS `sig`, Vault `hvs.` and npm tokens, and values containing `$`. The log's notes and `matched` lines are redacted, and an approval request lists the programs a redacted command starts.
  - **The log:** a line over 16 MB is counted and skipped instead of hiding every later entry from `report`, `suggest` and telemetry.
  - **Events:** keys that differ only in case (`command` and `COMMAND`) make an event malformed.
  - **Config errors:** a broken repository config follows the user config's `on_error` and mode; a user config that cannot be read still blocks.
  - **User scope:** `init` and `hook install --scope user` follow `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.
  - **Telemetry:** the version is a release number or `other`.
  - **The Action:** installs with its own `install.sh` instead of one fetched from a moving ref, accepts only a release tag as `version`, rejects a `binary` with a newline, and keeps workflow commands in plan text from running. `ci-plan-check.sh` uses a private temp file.
  - **Releases and CI:** the release job runs in the `release` environment with an exact goreleaser version; checkouts do not keep credentials; `govulncheck` is pinned; `install.sh` and the plugin launcher download over HTTPS only; the documented verify command names the exact workflow identity.
  - **`check --enforce`** exits by the verdict under observe mode, and the Terragrunt hook in `docs/ci.md` is one hook that judges a saved plan by its contents and anything else, `apply -destroy` included, as the command.
  - **Docs:** observe mode turning self-protection off is stated; `doctor` names every ignored repository setting; `init`, MCP, "Not in v1", the contributor and harness docs are current; `docs/project/RELEASE.md` and `scripts/bump-version-refs.sh` cover the version pins at the tag.

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
