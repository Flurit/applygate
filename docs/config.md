# Configuration

applygate reads `~/.config/applygate/config.yaml` (user, optional) and the nearest `.applygate.yaml` above the working directory (repository). Values from the repository file win, except for the user-only settings marked below. Unknown keys are rejected.

```yaml
version: 1
mode: observe            # observe | enforce
strict: true             # unknown environment = protected
default_tier: standard   # tier for unknown environments when strict is false
on_error: auto           # auto (block in protected/unknown, allow elsewhere) | block | allow
name_hints: true         # treat prod/production/prd/live as a whole word in names (paths, workspaces, profiles, backend bucket/key/workspace_key_prefix/dynamodb_table/address) as protected; non-/not-/no-/pre- before the word and -like/-test/-sandbox after it cancel the hint (docs/policy.md step 4)
unknown_dir: most_protected   # most_protected | session_root: how a command is judged when the host does not report its directory (Codex 0.165.0); a repository config may set most_protected but not session_root
log_path: ~/.local/state/applygate/decisions.jsonl   # user config only
aliases: {tf: terraform}

environments:            # any matching signal applies; the most protected match wins
  - name: prod
    tier: protected      # protected | standard | disposable
    match:
      paths: ["envs/prod/**"]                 # relative to this file
      workspaces: ["prod", "production"]
      backends: ["s3://acme-tf-state-prod/*"] # s3://bucket/key
      aws_profiles: ["prod*"]
      aws_accounts: ["123456789012"]          # only with preflight.live_identity

plan_gate:
  max_destroy: {protected: 0}   # -1 = unlimited; default 0 protected, unlimited otherwise
  scope: ["module.app.*"]       # optional: changes outside are a high finding
  run_show: true                # run "<engine> show -json <planfile>" for apply <planfile>
  show_timeout: 20s

preflight:
  stale_state: true
  backend: true
  lockfile: true                # runs "git diff HEAD" read-only
  live_identity: false          # user config only: aws sts get-caller-identity (network)
  live_state: false             # user config only: "<engine> state pull" to compare lineage/serial (network)

protected_paths: []             # extra guard files the agent may not modify
wrappers:                       # extra programs that run a command given in their arguments
  - name: company-run           # company-run PROFILE terraform apply ...
    skip: 1                     # positional arguments before the command (used when there is no "--")
    profile_arg: 1              # optional: the positional that names an AWS profile or role
protected_resources: []         # address globs whose destroy/replace is critical, e.g. ["aws_instance.bastion", "module.data.*"]
```

**Defaults.** Because the most protected matching environment wins, an environment that matches everything (`paths: ["**"]`) overrides every less protected one: `examples/**` → disposable plus `**` → standard makes the examples standard too. For a default, set `strict: false` and `default_tier` instead.

`unknown_dir` applies when the host reports only the session root and not the directory a command runs in (Codex 0.165.0; see [hosts.md](hosts.md)). `most_protected` (the default) judges the command at the most protected tier it could be in under the root: every environment whose `paths` could match a directory under the root, every environment with `workspaces`, `backends`, `aws_profiles` or `aws_accounts` matchers, and `strict`/`default_tier` for an unmatched directory ([policy.md](policy.md) step 4). `session_root` judges it at the root as if it ran there, which is what applygate v0.1.4 and earlier did. Only the user config can set `session_root`; a repository config may set `most_protected` to switch it back on, and any other value in a repository config is ignored. A `cd` or `-chdir` inside the command always wins over this setting.

`wrappers` lists a team's own runners that execute the command in their arguments, so applygate analyzes that command instead of the runner. The command starts after `--` when there is one, otherwise after `skip` positional arguments; `profile_arg` names the positional that is an AWS profile or role, which counts as a tier signal like `AWS_PROFILE`. Built-in runners (`aws-vault`, `gds aws`, `direnv`, `mise`, `nix-shell`, …) need no entry, and an unknown runner around `terraform`, `tofu` or `terragrunt` is caught by the backstop anyway; list a runner here when it wraps other tools such as `aws` or `kubectl`, or to get its profile argument used for the tier. Entries from the user and repository configs are combined.

`protected_resources` extends the plan gate's built-in stateful-type list with addresses that matter in *this* repository whatever their type: a bastion host, a module holding data, a specific bucket. Globs match the full Terraform address (`module.x.*`, `aws_instance.*`). A destroy or replace of a matching resource in a saved plan is a critical finding, so protected tiers block and standard tiers ask.

`preflight.live_state` makes the only other network call besides `live_identity`. When local state files sit next to a remote backend (the `stale-state` finding), applygate runs `<engine> state pull` (read-only) and compares each local file's lineage and serial with the remote state. A local file from another lineage, behind the remote serial, or ahead of it becomes a high `state-lineage` finding with the serials in the evidence. Like `live_identity`, only the user config can turn it on; a repository config cannot.

## Writing the file from the observe log

`applygate suggest` proposes this file from the decision log instead of starting from the `init` template. It reads the log (the user config's `log_path`, or `--log FILE`), keeps the decisions that ran under the repository root (the directory of the nearest `.applygate.yaml`, else the working directory, or `--root DIR`), and prints a config with the evidence in comments:

- **Environments** for every directory where Terraform, OpenTofu or Terragrunt ran and whose path carries a name hint: `prod`, `production`, `prd`, `live` → protected; `staging`, `stage`, `stg`, `uat`, `qa`, `non-prod`, `pre-prod` → standard; `dev`, `sandbox`, `test`, `examples`, `demo` → disposable. The `paths` glob stops at the hinted component (`envs/prod/**`, not `envs/prod/us-east-1/**`), and the most protected component wins. Hinted workspaces, `s3://` backends and AWS profiles join the environment of their tier.
- **Directories whose names say nothing** are written as commented-out entries with their command counts. The file alone keeps them protected under `strict: true`; a person picks the tier.
- **Signals without a hint** (a backend bucket, a profile) are listed in comments to add by hand.
- **Every ask and block** in the repository, most frequent first, with the reason it was judged that way: no environment matched, state surgery, a dynamic command, a plan-gate finding. Programs asked about as unknown wrappers appear as a commented `wrappers:` entry.

When a `.applygate.yaml` already exists at the root, its `mode`, `strict`, `on_error`, environments, `plan_gate.max_destroy`, `protected_resources` and `wrappers` are kept, and only directories it does not cover are proposed. `--out FILE` writes the proposal and refuses to overwrite an existing file; without it the YAML goes to stdout. The proposal is parsed as a config before anything is printed.

The decision log is JSON Lines with mode 0600, stored outside the repository. Values that look like secrets (AWS keys, `*_SECRET*=`, tokens, bearer headers, private keys) are redacted before writing.
