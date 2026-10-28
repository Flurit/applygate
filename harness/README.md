# Scenario pack and replay harness

- `pack/scenarios.json`: 50 dangerous and 29 benign scenarios as Claude Code PreToolUse tool calls. Each has an `expect` list, and most dangerous ones have `must_mention` strings that the decision message must contain. A right verdict reached for the wrong reason fails.
- `pack/fixtures/repo`: a fake infrastructure repository (no real credentials, nothing to apply). It has `.terraform` backend caches, a Makefile, a teardown script, an archive containing an old state file, a backend changed since init, and `envs/shared/staging.tfplan`, a real planfile from Terraform 1.16.1 (`terraform_data` only, local backend, workspace `staging`).
- `pack/plans`: `show -json` fixtures. `shared_staging.json` is real output. The AWS plans are synthetic and hand-built in the terraform-json format.
- `harness_test.go`: the regression test (`go test ./harness`). It replays every scenario in-process through the Claude Code adapter.
- `run.py`: a throwaway black-box runner. It pipes events to any guard's hook command with an empty PATH, a fake HOME and no credentials. It never executes scenario commands and never uses a shell.

## Provenance

This pack was **reconstructed from the spec** (S1–S11 and the benign list). The original v0 `scenarios.json`, `run.py`, `RESULTS.md` and `cupcake/terraform.rego` were not available when the repository was created. The v0 comparison figures (cc-safety-net 1/17, Vectimus 5/17, hand-written Rego 14/17) were measured on the original 17 + 13 pack, not on this one. To compare other guards on this pack, re-run them with `run.py --guard-cmd`.

Scenarios marked `"origin": "new text-mention control"` or `"new cleanup control"` are the controls added in v1 for text mentions (grep, echo, git commit, printf, heredoc, Read) and routine cleanup (`rm -rf .terraform`).

## Run

```bash
go test ./harness                      # in-process regression
go build -o bin/seatbelt ./cmd/seatbelt
bin/seatbelt selftest -v               # same pack, embedded in the binary
python3 -I harness/run.py --guard bin/seatbelt --md /tmp/replay.md
```
