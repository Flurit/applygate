# Configuration

seatbelt reads `~/.config/seatbelt/config.yaml` (user, optional) and the nearest `.seatbelt.yaml` above the working directory (repository). Values from the repository file win, except for the user-only settings marked below. Unknown keys are rejected.

```yaml
version: 1
mode: observe            # observe | enforce
strict: true             # unknown environment = protected
default_tier: standard   # tier for unknown environments when strict is false
on_error: auto           # auto (block in protected/unknown, allow elsewhere) | block | allow
name_hints: true         # treat prod/production/prd/live in names as protected
log_path: ~/.local/state/seatbelt/decisions.jsonl   # user config only
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
protected_resources: []         # address globs whose destroy/replace is critical, e.g. ["aws_instance.bastion", "module.data.*"]
```

`protected_resources` extends the plan gate's built-in stateful-type list with addresses that matter in *this* repository whatever their type: a bastion host, a module holding data, a specific bucket. Globs match the full Terraform address (`module.x.*`, `aws_instance.*`). A destroy or replace of a matching resource in a saved plan is a critical finding, so protected tiers block and standard tiers ask.

`preflight.live_state` makes the only other network call besides `live_identity`. When local state files sit next to a remote backend (the `stale-state` finding), seatbelt runs `<engine> state pull` (read-only) and compares each local file's lineage and serial with the remote state. A local file from another lineage, behind the remote serial, or ahead of it becomes a high `state-lineage` finding with the serials in the evidence. Like `live_identity`, only the user config can turn it on; a repository config cannot.

The decision log is JSON Lines with mode 0600, stored outside the repository. Values that look like secrets (AWS keys, `*_SECRET*=`, tokens, bearer headers, private keys) are redacted before writing.
