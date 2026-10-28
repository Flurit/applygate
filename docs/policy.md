# Policy

`policy.Decide` analyzes the tool call, classifies each operation it would start, resolves an environment tier for each one, runs preflight and (for saved plans) the plan gate, and returns the strictest verdict. Every ask or block carries the reason, the evidence and a next step.

## Decision flow

1. The hook adapter turns the agent's event into one internal event: agent, tool, command or paths, working directory, session, and whether the host can show an ask prompt.
2. `internal/shell` parses the command as bash and walks it in order. It tracks `cd`, assignments, `export`, prefix assignments, loops over literal lists, functions with positional parameters, aliases, and `$0` in scripts. It unwraps `bash/sh/zsh -c`, `eval`, `source`, here-documents and here-strings, pipes into a shell, `sudo`, `env` (including `-C` and `-S`), `timeout`, `nice`, `nohup`, `xargs`, `watch`, `find -exec`, `ssh`, `docker run <terraform image>`, Makefile recipes and readable shell scripts. It computes static output for echo, printf, cat, base64 -d, base32 -d, gzip/gunzip/zcat, tee, xxd -r -p, rev, dirname, basename, pwd and which. Whatever it cannot resolve becomes a **problem** (dynamic), not a guess.
3. `internal/classify` assigns a class to each invocation, redirect and file tool call.
4. For each action, the tier comes from config (paths, workspaces, backends, AWS profiles, optional accounts) plus name hints (`prod`, `production`, `prd`, `live`). When signals disagree, the most protected tier wins. If nothing matches, the tier is protected in strict mode (the default) or `default_tier` otherwise.
5. Preflight: backend changed since init, stale or archived state (and, when `preflight.live_state` is on in the user config, a read-only state pull that compares lineage and serial), and (for applies and destroys) lock-file and source drift since HEAD.
6. Plan gate for `apply <planfile>`: planfile workspace vs. selected workspace, then the `show -json` rules. A plan containing pure deletes is reclassified as **destroy**.
7. Verdict = max(class × tier, finding severity × tier) across all actions. If the host cannot ask, ask becomes block. Observe mode logs the verdict and returns allow.

## Verdict table

| Class | Protected | Standard | Disposable | Source |
|---|---|---|---|---|
| read-only | allow | allow | allow | spec |
| apply-saved-plan | plan gate | plan gate | allow | spec |
| unreviewed-apply | block | ask | allow | spec |
| destroy | block | ask | allow | spec |
| state-surgery | block | ask | ask | spec |
| cloud-destructive | block | ask | ask | spec |
| guard-tampering | block | block | block | spec |
| dynamic | ask | ask | allow | spec |
| unknown-wrapper | ask | allow | allow | spec open decision ("ask in protected tiers") |
| mutating (import, refresh, test) | ask | allow | allow | added |
| cloud-write (create/update calls) | ask | allow | allow | added |
| credential-access | ask | ask | ask | added (spec S10) |

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
| code-execution (provisioners such as local-exec/remote-exec, or `external` data sources, in the plan's configuration: applying runs code with the user's credentials; spec S12) | high | plan |
| stateful-unprotected-create (a database created with no safety net: deletion protection off **and** final snapshot skipped) | high | plan |
| stateful-create-note (a database created with only one safeguard off, e.g. protection off but a final snapshot kept) | info | plan |
| protection-removed (deletion protection, final snapshot, retention 0, force_destroy, versioning, PITR, …) | critical | plan |
| exposure (0.0.0.0/0 or ::/0 on admin/DB ports or all ports; public bucket ACL, policy or access block; IAM `*` or `svc:*` actions; admin policy attachments) | high | plan |
| state-infrastructure (the backend bucket or lock table) | critical | plan |
| out-of-scope (`plan_gate.scope`) | high | plan |
| plan-errored, plan-unreadable (plan exists but cannot be read) | critical | plan |
| plan-missing (the plan file does not exist, so there is nothing to apply) | high | plan |
| workspace-mismatch (planfile workspace ≠ selected) | critical | planfile |
| backend-changed | high | preflight |
| stale-state | high | preflight |
| state-lineage (local state file is from another lineage, behind or ahead of the remote serial; only with `preflight.live_state`) | high | preflight (state pull, opt-in) |
| lockfile-drift | high | preflight (git) |

IAM `Resource: "*"` on its own is not flagged, because it is very common. This is a deliberate narrowing of the spec's "IAM wildcard actions or resources".
