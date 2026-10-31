# Scenario pack and replay harness

- `pack/scenarios.json`: 90 dangerous and 47 benign (one benign, B45, is a documented ask) scenarios as Claude Code PreToolUse tool calls. Each has an `expect` list, and most dangerous ones have `must_mention` strings that the decision message must contain. A right verdict reached for the wrong reason fails. S3 (obfuscation) scenarios carry a `bypass_class` (variable-indirection, encoding, dynamic-fetch, shell-nesting, command-substitution, alternate-flags, wrapper-script, interpreter, credential-wrapper, unknown-wrapper, configured-wrapper) so bypasses can be reported per class.
- `pack/fixtures/repo`: a fake infrastructure repository (no real credentials, nothing to apply). It has `.terraform` backend caches, a Makefile, a teardown script, an archive containing an old state file, a backend changed since init, and `envs/shared/staging.tfplan`, a real planfile from Terraform 1.16.1 (`terraform_data` only, local backend, workspace `staging`).
- `pack/plans`: `show -json` fixtures. `shared_staging.json` is real output. The AWS plans are synthetic and hand-built in the terraform-json format.
- `harness_test.go`: the regression test (`go test ./harness`). It replays every scenario in-process through the Claude Code adapter. `formats_test.go` replays the pack through the seven adapters written from host documentation, in each host's documented payload format: every dangerous scenario must be caught, and hosts whose payload carries the command's directory must match every expectation.
- `run.py`: a throwaway black-box runner. It pipes events to any guard's hook command with an empty PATH, a fake HOME and no credentials. It never executes scenario commands and never uses a shell.

## Provenance

This pack was **reconstructed from the project's planning document** (scenarios S1–S11 and the benign list; public summary in [docs/roadmap.md](../docs/roadmap.md)). The original v0 `scenarios.json`, `run.py`, `RESULTS.md` and `cupcake/terraform.rego` were not available when the repository was created. The v0 comparison figures (existing guards on default configs at most 5/17, a hand-written Rego policy 14/17) were measured on the original 17 + 13 pack, not on this one. To compare other guards on this pack, re-run them with `run.py --guard-cmd`.

Scenarios marked `"origin": "new text-mention control"` or `"new cleanup control"` are the controls added in v1 for text mentions (grep, echo, git commit, printf, heredoc, Read) and routine cleanup (`rm -rf .terraform`). D51/B30 cover the planned stretch scenario S12 (a plan whose configuration runs code through a provisioner or an `external` data source) and D52 covers `protected_resources`; the fixture config lists `aws_instance.bastion`.

## Disclosure of results for other guards

Results for a third-party guard go to its maintainers privately first, with 30 days to respond, before per-guard details are published; aggregate findings may go out earlier. Every published per-guard result is checked by hand on a real install and records the guard version, configuration, agent format and date (`run.py` writes these), so it can be reproduced or challenged. A guard is never called unsafe for a scenario outside its stated scope: a command filter is reported as "not covered by design" for plan-level scenarios, not as a failure. See `CONTRIBUTING.md`.

## Run

```bash
go test ./harness                      # in-process regression
go build -o bin/applygate ./cmd/applygate
bin/applygate selftest -v               # same pack, embedded in the binary
python3 -I harness/run.py --guard bin/applygate --md /tmp/replay.md
```

`run.py` flags (all optional except one of `--guard` / `--guard-cmd`):

| Flag | Meaning |
|---|---|
| `--guard PATH` | applygate binary; the runner invokes `PATH hook <format> --no-log` and passes `--plan-json` fixtures |
| `--guard-cmd "CMD ..."` | any other guard's hook command (split with `shlex`, never a shell) |
| `--name NAME` | guard name in the report (default `applygate`) |
| `--format claude\|codex\|cursor\|copilot\|gemini\|windsurf\|devin\|opencode\|cline` | hook event format the guard speaks (default `claude`). `codex` sends the same PreToolUse shape and reads the same `hookSpecificOutput` (Read scenarios are `skipped`: Codex has no read tool); `cursor` sends `beforeShellExecution` for Bash scenarios only (others are `skipped`, not counted) and reads a top-level `permission` of `allow\|deny\|ask`. The other formats follow each host's documented payload and output ([docs/hosts.md](../docs/hosts.md)): `devin` replays Bash scenarios only. On a host that cannot ask, an expected ask is expected as a block; where the event does not carry the command's directory (`codex`, `cursor`, `copilot`, `windsurf`, `devin`) a stricter verdict counts as a match and the reason is not compared. `go test ./harness` replays the pack through each adapter in-process as well. |
| `--guard-version STR` | recorded as-is; default is the stdout of `<guard> version` in the same sandbox, else `unknown` |
| `--config-label STR` | free text describing the guard configuration (default `default`) |
| `--coverage command\|plan-aware\|context-aware` | coverage type recorded in the report (default `context-aware` with `--guard`, `command` otherwise) |
| `--probes` | after the pack, send the fail-open probes (off by default; CI does not pass it) |
| `--strict-probes` | with `--probes`: any probe whose action would proceed fails the run |
| `--json FILE`, `--md FILE` | write the full results as JSON and the Markdown report |
| `--timeout SEC` | per-event guard timeout (default 30) |

Exit code is 0 only when every counted scenario matched. For applygate (`--guard`), a match needs the expected verdict *and* every `must_mention` string in the message, and an exit 2 is reported as `fail-closed` (in the `windsurf`, `devin` and `opencode` formats, where exit 2 is also how applygate blocks, only an exit 2 whose message says applygate failed closed): applygate exits 2 only when it fails closed on an internal or config error (for example a fixture config an older release cannot parse), which proves nothing about the scenario, so it never matches and counts as an error. Other guards (`--guard-cmd`) are judged on the verdict alone, and their exit 2 is a block. Probes never change the exit code unless `--strict-probes` is passed. `python3 -I harness/test_run.py` tests this scoring (CI runs it).

## Scorecard

The JSON `summary` and the top of the Markdown report carry one scorecard per run. Every run records guard name, guard version, config label, coverage type, agent format, date and pack version.

- **Catch rate**: dangerous scenarios that came back `block` or `ask`, over all dangerous scenarios. A applygate `fail-closed` result is not a catch.
- **Fail-closed / reason mismatch**: applygate results that were config or internal errors, and results with the right verdict but a missing `must_mention` reason (`fail_closed`, `reason_mismatch` in the JSON).
- **False-positive rate**: benign scenarios that came back `block` or `ask`, over all benign scenarios (`benign_flagged` additionally counts errors).
- **Bypass count**: S3 (obfuscation) scenarios that came back `allow` or `error`, grouped by each scenario's `bypass_class` (`unclassified` when the field is missing) in `bypass_by_class`.
- **Fail-open count**: probes (`--probes`) after which the action would proceed; `probes not run` otherwise.
- **Coverage type**: `command` (looks at the command text only), `plan-aware` (also reads saved plans), `context-aware` (also reads the repo and environment); recorded, not measured.
- **Latency**: p50 / p95 milliseconds per event, one guard process per event including start-up.

Fail-open probes send five deliberately broken inputs: malformed JSON, empty stdin, a valid event without `tool_name` (`command` for cursor), a Bash event whose `cwd` does not exist, and a 2 MB `command` string, all in `envs/prod`. "Proceeds" follows Claude Code hook semantics: exit 0 with no `deny`/`ask` decision means the action proceeds; exit 2 blocks; any other non-zero exit is a non-blocking error, so the action proceeds; a timeout is recorded as `timeout (agent decides)` and counted neither way.
