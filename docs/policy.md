# Policy

`policy.Decide` analyzes the tool call, classifies each operation it would start, resolves an environment tier for each one, runs preflight and (for saved plans) the plan gate, and returns the strictest verdict. Every ask or block carries the reason, the evidence and a next step.

## Decision flow

1. The hook adapter turns the agent's event into one internal event: agent, tool, command or paths, working directory, session, and whether the host can show an ask prompt.
2. `internal/shell` parses the command as bash and walks it in order. It tracks `cd`, assignments, `export`, prefix assignments, loops over literal lists, functions with positional parameters, aliases, and `$0` in scripts. It unwraps `bash/sh/zsh -c`, `eval`, `source`, credential and secrets runners (`aws-vault exec`, `aws-okta exec`, `gds aws`, `saml2aws exec`, `aws-sso exec`, `envchain`, `doppler run`, `op run`, `chamber exec`, `infisical run`; the profile or role they name counts as the AWS profile), development-environment runners (`direnv exec`, `mise`/`rtx exec`, `asdf exec`, `devbox run`, `nix develop|shell -c`, `nix-shell --run`), wrappers listed under `wrappers:` in the config, here-documents and here-strings, pipes into a shell, `sudo`, `env` (including `-C` and `-S`), `timeout`, `nice`, `nohup`, `xargs`, `watch`, `find -exec`, `ssh`, `docker run <terraform image>`, Makefile recipes and readable shell scripts. It computes static output for echo, printf, cat, base64 -d, base32 -d, gzip/gunzip/zcat, tee, xxd -r -p, rev, dirname, basename, pwd and which. Whatever it cannot resolve becomes a **problem** (dynamic), not a guess. Code given to `python`/`node` (`-c`/`-e`, a here-document, a script file) is not parsed; it is a problem only when its text mentions an infrastructure tool, an AWS SDK or a guard file, and a Python or Node body that does so but can only read and write ordinary files (no process start, code loading, network, decoder, function passed by reference or guard, credential or state file named anywhere in it, and every write to a literal path that resolves to a repository configuration file under the working directory, by the rules in [limits.md](limits.md)) is instead recorded as a note and allowed. For a program it does not recognize, a backstop treats a standalone `terraform`, `tofu` or `terragrunt` argument as the start of the command the program runs (`madeup-tool run -- terraform destroy`), and so the value of a `--run`/`--command`/`-c` flag that starts with one. It skips text and search programs, version control, editors, package managers, quoted strings and the values of message flags (`-m`, `--message`, `--title`, …), and drops unknown Terraform subcommands it reaches that way (`brew install terraform tflint`).
3. `internal/classify` assigns a class to each invocation, redirect and file tool call.
4. For each action, the tier comes from config (paths, workspaces, backends, AWS profiles, optional accounts) plus name hints (`prod`, `production`, `prd`, `live` as a whole word between `/ _ . : -` or the ends, so `acme-prod-tfstate` matches and `acme-products-tfstate` does not; the word is ignored when the word just before it is `non`, `not`, `no` or `pre`, or the word just after it is `like`, `test` or `sandbox`, so `non-prod`, `non_prod`, `pre-prod`, `not-live` and `prod-like` are not hints while `my-prod`, `nonprod-live` and `non-prod/us-east-1/prod` are; only the adjacent words count, and glued forms such as `nonprod` and `preprod` were never whole words). Name hints are checked on the path, workspace, AWS profile, the backend URL, the backend's `bucket`, `key`, `workspace_key_prefix`, `dynamodb_table` and `address` values, and the name of a `-backend-config` file. The backend values come from `.terraform/terraform.tfstate`, or, when an init in the same command line passes `-backend-config` files or `key=value` pairs, from those (the two paths use the same rules). The values are read whether or not the backend type is known (a directory may have no `backend` block and no `.terraform` yet), and `-backend-config` files may write values quoted or unquoted (`bucket = "x"`, `bucket="x"`, `bucket=x`). When signals disagree, the most protected tier wins. If nothing matches, the tier is protected in strict mode (the default) or `default_tier` otherwise.
5. Preflight: backend changed since init, stale or archived state (and, when `preflight.live_state` is on in the user config, a read-only state pull that compares lineage and serial), and (for applies and destroys) lock-file and source drift since HEAD.
6. Plan gate for `apply <planfile>`: planfile workspace vs. selected workspace, then the `show -json` rules. When the two workspaces differ, the action is judged by the more protected of the two tiers (a `prod` plan applied from `staging` is a protected-tier action, and the log records that tier), so the critical workspace-mismatch finding blocks whichever side is protected. A plan containing pure deletes is reclassified as **destroy**.
7. Verdict = max(class × tier, finding severity × tier) across all actions. If the host cannot ask, ask becomes block. Observe mode logs the verdict and returns allow.

## Verdict table

| Class | Protected | Standard | Disposable | Source |
|---|---|---|---|---|
| read-only | allow | allow | allow | roadmap |
| apply-saved-plan | plan gate | plan gate | allow | roadmap |
| unreviewed-apply | block | ask | allow | roadmap |
| destroy | block | ask | allow | roadmap |
| state-surgery | block | ask | ask | roadmap |
| cloud-destructive | block | ask | ask | roadmap |
| guard-tampering | block | block | block | roadmap |
| dynamic | ask | ask | allow | roadmap |
| unknown-wrapper | ask | allow | allow | roadmap open decision ("ask in protected tiers") |
| mutating (import, refresh, test) | ask | allow | allow | added |
| cloud-write (create/update calls) | ask | allow | allow | added |
| credential-access | ask | ask | ask | added (scenario S10) |

`init -reconfigure` is state surgery only when it is bare or migrates state: with `-backend-config` (resolved files or `key=value` pairs) and without `-migrate-state`/`-force-copy` it is read-only, because it only re-points the working directory. Later commands in the same command line are then judged against the backend the config describes, and the config file's name is a name hint (`production.backend` → protected). This deviates from the original plan, which lists `init -reconfigure` as state surgery; the open-source corpus trial found it used routinely to switch environments ([oss-corpus-trial.md](oss-corpus-trial.md)).

## Finding severity × tier

| Severity | Protected | Standard | Disposable |
|---|---|---|---|
| critical | block | ask | log |
| high | ask | log | log |

## Findings

| Rule | Severity | Source |
|---|---|---|
| destroy-count (destroys + replaces > `max_destroy`; protected default 0) | high | plan |
| stateful-destroyed (types in `rules/aws.json`) | critical | plan |
| protected-resource (addresses matching `protected_resources` in config, any type) | critical | plan |
| code-execution (provisioners such as local-exec/remote-exec, or `external` data sources, in the plan's configuration: applying runs code with the user's credentials; scenario S12) | high | plan |
| stateful-unprotected-create (a database created with no safety net: deletion protection off **and** final snapshot skipped) | high | plan |
| stateful-create-note (a database created with only one safeguard off, e.g. protection off but a final snapshot kept) | info | plan |
| protection-removed (deletion protection, final snapshot, retention 0, force_destroy, versioning, PITR, …) | critical | plan |
| exposure (0.0.0.0/0 or ::/0 on admin/DB ports or all ports; public bucket ACL, policy or access block; IAM `*` or `svc:*` actions; admin policy attachments) | high | plan |
| state-infrastructure (the backend bucket or lock table) | critical | plan |
| out-of-scope (`plan_gate.scope`) | high | plan |
| plan-errored, plan-unreadable (plan exists but cannot be read) | critical | plan |
| plan-missing (the plan file does not exist, so there is nothing to apply) | high | plan |
| workspace-mismatch (planfile workspace ≠ selected; the action takes the more protected of the two workspaces' tiers) | critical | planfile |
| backend-changed | high | preflight |
| backend-config-unreadable (an init in the same command points at a `-backend-config` file that cannot be read; only on later state-changing commands) | high | preflight |
| stale-state | high | preflight |
| state-lineage (local state file is from another lineage, behind or ahead of the remote serial; only with `preflight.live_state`) | high | preflight (state pull, opt-in) |
| lockfile-drift | high | preflight (git) |

IAM `Resource: "*"` on its own is not flagged, because it is very common. This is a deliberate narrowing of the original plan's "IAM wildcard actions or resources".
