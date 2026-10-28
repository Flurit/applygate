# seatbelt

A deterministic, local pre-execution check for coding agents (Claude Code, Codex, and others with pre-tool hooks) that touch Terraform or OpenTofu infrastructure. Before the agent runs a tool call, seatbelt returns **allow**, **ask** or **block**, with a reason and a next step the agent can act on.

> Working name. Status: v1 core, pre-release. Not yet tested with a live agent; see [ACCEPTANCE.md](ACCEPTANCE.md) for what has and has not been verified.

## Why another guard

Command-pattern matching is table stakes. In our v0 test slice, existing guards on default configs caught few Terraform scenarios: cc-safety-net 1 of 17 and Vectimus 5 of 17. A competent hand-written Rego/regex policy reached 14 of 17, but it still missed base64, variable and `eval` obfuscation, and it blocked harmless text such as `git commit -m "never run terraform destroy"`. A matcher cannot do better than that, because it reads text, not commands, and it cannot see what a change will do.

seatbelt does two things a matcher cannot:

1. **Shell-aware command analysis.** It parses commands the way bash does ([mvdan/sh](https://github.com/mvdan/sh)), tracks `cd`, variables, `export`, loops and functions, unwraps `bash -c`, `eval`, here-documents, `sudo`/`env`/`timeout`/`xargs`/`find -exec`, reads Makefile recipes and shell scripts, and decodes `echo … | base64 -d | sh`. It tells commands apart from text: `grep "terraform destroy"` is a grep. Anything it cannot resolve statically, such as fetched text piped into a shell, it **refuses** (ask) instead of guessing.
2. **Preflight and plan-level checks.** It maps the working directory, workspace, backend and AWS profile to an environment tier. It flags a saved plan made in another workspace (read from the planfile itself), a backend block changed since `init`, stale or archived state files, and lock-file or module-source drift. For `apply <planfile>` it reads `show -json` and checks for destroyed or replaced stateful resources, removed protection (deletion protection, final snapshots, force-destroy, versioning), internet exposure, IAM wildcards, and changes to the state backend itself.

It is not a sandbox and not an AI reviewer. No model is in the decision path, there is no telemetry, and it makes no network calls by default.

## Quickstart

```bash
go install github.com/Flurit/seatbelt/cmd/seatbelt@latest   # or build: go build -o bin/seatbelt ./cmd/seatbelt
cd your-infra-repo
seatbelt init                            # writes .seatbelt.yaml in observe mode
$EDITOR .seatbelt.yaml                   # map paths/workspaces/profiles to tiers
seatbelt hook install --agent claude     # or --agent codex
seatbelt doctor
seatbelt check "terraform -chdir=envs/prod destroy"
```

After a few days in observe mode, run `seatbelt report` to see what would have been blocked, review any likely false positives, then set `mode: enforce`.

## Verdicts

| Class | Examples | Protected | Standard | Disposable |
|---|---|---|---|---|
| Read-only | plan, show, output, validate, fmt, state list, describe/list | allow | allow | allow |
| Apply of a saved plan | `terraform apply tfplan` | plan gate | plan gate | allow |
| Unreviewed apply | `apply -auto-approve` with no plan | block | ask | allow |
| Destroy | destroy, `apply -destroy`, `-replace`, a plan that deletes | block | ask | allow |
| State surgery | state rm/mv/push, force-unlock, taint, init -reconfigure | block | ask | ask |
| Cloud CLI destructive | `aws … delete-*`, `s3 rb`, terminate, `kubectl delete` | block | ask | ask |
| Guard tampering | skip-permissions flags, edits to hook config, seatbelt config or log | block | block | block |
| Dynamic / unresolvable | `eval "$(curl …)"`, `sh -c "$X"`, `curl … \| bash` | ask | ask | allow |

Plan gate: in protected tiers critical findings block and high findings ask; in standard tiers critical findings ask; in disposable tiers findings are logged. Unknown environments count as protected in strict mode, which is the default. The full table, including the classes seatbelt adds beyond the spec, is in [docs/policy.md](docs/policy.md).

## Commands

| Command | Purpose |
|---|---|
| `seatbelt hook claude\|codex` | Hook entry point; reads one PreToolUse event on stdin |
| `seatbelt check "<cmd>"` | Dry-run a command (exit 0 allow, 4 ask, 3 block) |
| `seatbelt explain "<cmd>"` | Parse → classify → decide trace |
| `seatbelt plan-check plan.json` | Evaluate `terraform show -json` output |
| `seatbelt report` | Summarize the decision log |
| `seatbelt selftest` | Run the embedded scenario pack against this binary |
| `seatbelt init`, `doctor`, `hook install/remove` | Setup |

## What happens when seatbelt fails

Hooks fail open by default in most agents, so this matters:

- **Internal errors it can catch** (malformed event, config error, panic, its own 25 s deadline): with `on_error: auto` (the default) it **blocks** in protected or unknown tiers and allows elsewhere. Blocking uses exit code 2, which Claude Code and Codex both treat as a block.
- **Crashes it cannot catch, or the agent's hook timeout** (process killed, binary missing): the agent decides. Claude Code proceeds unless the hook has `"onFailure": "block"`, which `seatbelt hook install` sets (it needs Claude Code v2.1.295 or later; older versions fail open). Codex's behavior here is not documented.
- **Observe mode** never blocks, including on errors.

See [docs/limits.md](docs/limits.md) and [docs/threat-model.md](docs/threat-model.md).

## Repository layout

```
cmd/seatbelt/         CLI
internal/shell/       shell-aware analyzer (parse, resolve, unwrap; refuses what it cannot resolve)
internal/classify/    command classes for terraform/tofu/terragrunt, aws, kubectl, agents, guard files
internal/config/      .seatbelt.yaml and tier resolution
internal/preflight/   workspace, backend, stale state, lock-file drift, planfile workspace
internal/plangate/    plan JSON rules; AWS resource lists in rules/aws.json (data, not code)
internal/policy/      verdict table and Decide()
internal/hook/        Claude Code and Codex adapters, error behavior
internal/decisionlog/ JSONL log with redaction, report
harness/              scenario pack, fixtures, Go regression test, run.py replay runner
```

## License

Apache-2.0. See [LICENSE](LICENSE). Maintained by Flurit.
