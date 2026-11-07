# Configuration

applygate reads these config files. Unknown keys are rejected.
- **The user config,** `~/.config/applygate/config.yaml` (optional; `applygate doctor` prints its path).
- **The system config,** `/etc/applygate/config.yaml`, only under a managed install ([managed.md](managed.md)). It is read first and may set anything, and the user config may then only tighten, like a repository config. It is used only when root owns it and nobody else can write it.
- **Every trusted `.applygate.yaml`** from the outermost directory above the command down to the command's own directory.

**A repository config must be trusted.** applygate reads a `.applygate.yaml` only when a person approved its exact content with `applygate trust` (`/usr/bin/sudo /usr/local/libexec/applygate/applygate trust` under a managed install). It shows each untrusted config and asks you to type `trust`. A config that is new or changed since is not read, and every directory is judged as protected; `doctor` lists them. Its directory is still the repository root for self-protection: removing, moving, extracting or copying into the repository's `.claude` directory (or any other directory holding a guard file there) is tampering, as it is under a trusted config. `trust` trusts the exact bytes it showed you, and refuses if the file changed before you confirmed. Only a regular file can be trusted: a `.applygate.yaml` that is a symlink, or that cannot be read, is not read either. In CI, where there is no trust store, `plan-check --trust-config` (the Action's `trust-config: true`) reads the checked-out config. `applygate init` trusts the config it writes. Trust is stored by path and SHA-256 in `~/.config/applygate/trusted.json`, or `/etc/applygate/trusted.json` under a managed install.

**Only the user config can loosen protection.** A repository config is written to the repository, which an agent or a cloned project may control, so it can only add protection.
- **The outermost repository config** is the repository's. It defines the environments, and may tighten any other setting.
- **A nested one** (a subproject, a cloned tool) may only add protected environments and other protection. No layer replaces another.
- **These settings are user-only:**
  - `mode: observe`;
  - `strict: false`;
  - a `default_tier`, `name_hints: false` or `on_error` looser than the current value;
  - `aliases`;
  - `plan_gate.scope`, a larger `plan_gate.max_destroy`, `plan_gate.run_show: false`;
  - preflight switches set to `false`;
  - `wrappers` over a shell, engine or interpreter;
  - `approvals: true`, `unknown_dir: session_root`, `log_path`, the network checks and the model judge;
  - `strict_shapes: false` and `plan_gate.engines`.

  In a repository config they are ignored, and `doctor` says which. Under a managed install the same holds for the user config, and its `judge` and `plan_gate.engines` are ignored whatever they say.
- **Path patterns.** A repository config's paths, including `**` patterns, are relative to its own directory. The user config's `**` patterns match anywhere.

```yaml
version: 1
mode: enforce            # observe | enforce; observe only from the user config
strict: true             # unknown environment = protected
default_tier: standard   # tier for unknown environments when strict is false
on_error: auto           # auto (block when anything under the repository root is protected/unknown) | block | allow
name_hints: true         # treat prod/production/prd/live as a whole word in names (paths, workspaces, profiles, backend bucket/key/workspace_key_prefix/dynamodb_table/address) as protected; non-/not-/no-/pre- before the word and -like/-test/-sandbox after it cancel the hint (docs/policy.md step 4)
unknown_dir: most_protected   # most_protected | session_root: how a command is judged when the host does not report its directory (Codex 0.165.0); a repository config may set most_protected but not session_root
approvals: false         # user config only: on agents that cannot show an ask prompt, let a person allow one asked call with `applygate approve ID` (docs/policy.md step 9). Off by default: on one machine the agent can reach any terminal the person can, so turning this on trusts that no agent runs `applygate approve` in a way applygate does not recognise
log_path: ~/.local/state/applygate/decisions.jsonl   # user config only
strict_shapes: true      # in a protected environment, ask about a shell command that is not a plain list or pipeline of known programs in their exact shapes (docs/policy.md step 3); false only from the user config
aliases: {tf: terraform} # user config only

environments:            # any matching signal applies; the most protected match wins
  - name: prod
    tier: protected      # protected | standard | disposable
    match:
      paths: ["envs/prod/**"]                 # relative to this file; a directory is matched as written and with symlinks resolved
      workspaces: ["prod", "production"]
      backends: ["s3://acme-tf-state-prod/*"] # s3://bucket/key; * matches across /
      aws_profiles: ["prod*"]
      aws_accounts: ["123456789012"]          # only with preflight.live_identity
      kube_contexts: ["prod-eks", "arn:aws:eks:*:123456789012:cluster/*"]   # kubectl and helm
      gcp_projects: ["acme-payments-prod"]    # gcloud
      azure_subscriptions: ["Payments Production"]   # az: subscription name or id

plan_gate:
  max_destroy: {protected: 0}   # -1 = unlimited; default 0 protected, unlimited otherwise
  scope: ["module.app.*"]       # optional: changes outside are a high finding
  run_show: true                # run "<engine> show -json <planfile>" for apply <planfile>
  show_timeout: 20s
  engines: {}                   # user or system config only: absolute paths of the terraform, tofu, terragrunt and aws the hook runs; without one it looks the name up on PATH (docs/managed.md)

preflight:
  stale_state: true
  backend: true
  lockfile: true                # runs "git diff HEAD" read-only
  live_identity: false          # user config only: aws sts get-caller-identity (network)
  live_state: false             # user config only: "<engine> state pull" to compare lineage/serial (network)

protected_paths: []             # extra guard files the agent may not modify

judge:                          # user config only; a repository config may only set enabled: false (docs/judge.md)
  enabled: false                # send calls the rules do not recognize to a model you choose, which may make the verdict stricter
  backend: openai               # openai (any OpenAI-compatible endpoint) or command (a program you name)
  base_url: ""                  # required for openai: no provider is chosen for you (docs/judge.md compares them)
  model: ""                     # required for openai
  api_key_env: ""               # the variable holding the key; empty sends none
  reasoning_effort: ""          # sent as reasoning_effort only when set (some endpoints ignore it)
  command: []                   # required for command
  timeout: 10s
  skip_mcp: []                  # MCP tool globs never sent, for tools that only read
wrappers:                       # extra programs that run a command given in their arguments
  - name: company-run           # company-run PROFILE terraform apply ...
    skip: 1                     # positional arguments before the command (used when there is no "--")
    profile_arg: 1              # optional: the positional that names an AWS profile or role
protected_resources: []         # address globs whose destroy/replace is critical, e.g. ["aws_instance.bastion", "module.data.*"]
```

**Defaults.** Because the most protected matching environment wins, an environment that matches everything (`paths: ["**"]`) overrides every less protected one: `examples/**` → disposable plus `**` → standard makes the examples standard too. For a default, set `strict: false` and `default_tier` instead.

`kube_contexts`, `gcp_projects` and `azure_subscriptions` match what a `kubectl` or `helm`, `gcloud` or `az` command targets, also when it comes through an MCP tool ([mcp.md](mcp.md)). The value is the one on the command line (`--context`, `--cluster` or `--server` for kubectl, `--kube-context` or `--kube-apiserver` for helm, `--project`, `--subscription`), else what the CLI's own local configuration selects: the current context of the kubeconfig named by `--kubeconfig`, `KUBECONFIG` or `~/.kube/config`; the configuration named by gcloud's `--configuration`; `CLOUDSDK_CORE_PROJECT` or that (else the active) gcloud configuration's `core/project`; the default subscription in `~/.azure/azureProfile.json` (name or id). These are local file reads, never a network call. As with every signal, the most protected match wins, so a `kubectl delete` run from a disposable directory against a protected cluster is judged protected, and the name hints apply too (`prod-eks` looks like production).

`unknown_dir` applies when the host reports only the session root and not the directory a command runs in (Codex 0.165.0; see [hosts.md](hosts.md)). `most_protected` (the default) judges the command at the most protected tier it could be in under the root: every environment whose `paths` could match a directory under the root, every environment with `workspaces`, `backends`, `aws_profiles` or `aws_accounts` matchers, and `strict`/`default_tier` for an unmatched directory ([policy.md](policy.md) step 4). `session_root` judges it at the root as if it ran there, which is what applygate v0.1.4 and earlier did. Only the user config can set `session_root`; a repository config may set `most_protected` to switch it back on, and any other value in a repository config is ignored. A `cd` or `-chdir` inside the command always wins over this setting.

`wrappers` lists a team's own runners that execute the command in their arguments, so applygate analyzes that command instead of the runner. The command starts after `--` when there is one, otherwise after `skip` positional arguments; `profile_arg` names the positional that is an AWS profile or role, which counts as a tier signal like `AWS_PROFILE`. Built-in runners (`aws-vault`, `gds aws`, `direnv`, `mise`, `nix-shell`, …) need no entry, and an unknown runner around `terraform`, `tofu` or `terragrunt` is caught by the backstop anyway; list a runner here when it wraps other tools such as `aws` or `kubectl`, or to get its profile argument used for the tier. Entries from the user and repository configs are combined.

`protected_resources` extends the plan gate's built-in stateful-type list with addresses that matter in *this* repository whatever their type: a bastion host, a module holding data, a specific bucket. Globs match the full Terraform address (`module.x.*`, `aws_instance.*`). A destroy or replace of a matching resource in a saved plan is a critical finding, so protected tiers block and standard tiers ask.

`preflight.live_state` makes the only other network call besides `live_identity`. When local state files sit next to a remote backend (the `stale-state` finding), applygate runs `<engine> state pull` (read-only) and compares each local file's lineage and serial with the remote state. A local file from another lineage, behind the remote serial, or ahead of it becomes a high `state-lineage` finding with the serials in the evidence. Like `live_identity`, only the user config can turn it on; a repository config cannot.

## Writing the file from the observe log

`applygate suggest` proposes this file from the decision log instead of starting from the `init` template. It reads the log (the user config's `log_path`, or `--log FILE`), keeps the decisions that ran under the repository root (the directory of the nearest `.applygate.yaml`, else the working directory, or `--root DIR`), and prints a config with the evidence in comments:

- **Environments** for every directory where Terraform, OpenTofu or Terragrunt ran and whose path carries a name hint: `prod`, `production`, `prd`, `live` → protected; `staging`, `stage`, `stg`, `uat`, `qa`, `non-prod`, `pre-prod` → standard; `dev`, `sandbox`, `test`, `examples`, `demo` → disposable. The `paths` glob stops at the hinted component (`envs/prod/**`, not `envs/prod/us-east-1/**`), and the most protected component wins. Hinted workspaces, `s3://` backends, AWS profiles, kube contexts, GCP projects and Azure subscriptions join the environment of their tier.
- **Directories whose names say nothing** are written as commented-out entries with their command counts. The file alone keeps them protected under `strict: true`; a person picks the tier.
- **Signals without a hint** (a backend bucket, a profile) are listed in comments to add by hand.
- **Every ask and block** in the repository, most frequent first, with the reason it was judged that way: no environment matched, state surgery, a dynamic command, a plan-gate finding. Programs asked about as unknown wrappers appear as a commented `wrappers:` entry.

When a `.applygate.yaml` already exists at the root, its `mode`, `strict`, `on_error`, environments, `plan_gate.max_destroy`, `protected_resources` and `wrappers` are kept, and only directories it does not cover are proposed. `--out FILE` writes the proposal and refuses to overwrite an existing file; without it the YAML goes to stdout. The proposal is parsed as a config before anything is printed.

Telemetry is not a config key, so a repository can never turn it on for its users: it is switched by `applygate telemetry on|off` and lives in `~/.config/applygate/telemetry.json` ([telemetry.md](telemetry.md)).

The decision log is JSON Lines with mode 0600, stored outside the repository. Values that look like secrets (AWS keys, `*_SECRET*=`, tokens, bearer headers, private keys) are redacted before writing.
