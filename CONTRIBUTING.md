# Contributing

seatbelt is small on purpose: a shell-aware analyzer, a classifier, preflight checks, a plan gate and a policy table. Changes that keep it deterministic, local and honest about its limits are welcome.

## Ground rules

- **Never execute scenario commands.** The scenario pack is a corpus of destructive commands. Tests and the replay runner only ever build synthetic hook events; `harness/run.py` runs the guard with an empty `PATH`, a fake `HOME` and no credentials. Keep it that way.
- **No cloud credentials in tests or fixtures.** Plan fixtures are hand-built or generated from `terraform_data`-only configurations with a local backend.
- **No model in the decision path, no telemetry, no network by default.** Opt-in network checks (`live_identity`, `live_state`) stay user-config-only.
- **Rule lists are data.** Add resource types, protections and admin policies to `internal/plangate/rules/aws.json`, not to Go code.
- **Document deviations.** Anything that differs from the [roadmap](docs/roadmap.md) goes in `docs/project/spec-alignment.md` and, if it changes a verdict, in `docs/policy.md`.

## Adding a scenario

1. Append it to `harness/pack/scenarios.json` with an `id`, `spec` (S1–S14, `plan` or `benign`), `kind`, `title`, `cwd` (relative to `pack/fixtures/repo`), `tool`, `tool_input`, `expect`, and `must_mention` strings the message must contain. S3 cases take a `bypass_class`.
2. Plan-level scenarios reference a `show -json` fixture under `pack/plans` by `plans: {"<planfile>": "<fixture>.json"}`.
3. Run `go test ./harness`, `go build -o bin/seatbelt ./cmd/seatbelt && bin/seatbelt selftest -v` and `python3 -I harness/run.py --guard bin/seatbelt`.

## Adding a guard to the comparison

`harness/run.py --guard-cmd "<hook command>" --name <guard> --format claude|codex|cursor --guard-version <v> --config-label <label> --coverage command|plan-aware|context-aware --probes` replays the pack and writes a scorecard. Record the version and configuration; test the vendor's default and hardened configurations separately.

## Disclosure of comparison results

- The harness runs nothing destructive; bypass strings are scenario inputs, not exploit code.
- Results for a third-party guard go to its maintainers privately first, with 30 days to respond, before per-guard details are published. Aggregate findings may be published earlier.
- Every per-guard result is checked by hand on at least one real install before publication, with version, configuration, agent format and date recorded so it can be challenged.
- A tool is never called unsafe for a scenario outside its stated scope; plan-level scenarios are "not covered by design" for command filters.

## Before a pull request

```bash
gofmt -l . && go vet ./... && go test -race -count=1 ./...
go build -o bin/seatbelt ./cmd/seatbelt && bin/seatbelt selftest
python3 -I harness/run.py --guard bin/seatbelt --md /tmp/replay.md
```

CI also runs `govulncheck` and a short fuzz of the shell analyzer. Releases are cut from `v*` tags by `.github/workflows/release.yml`.

## Security reports

Please report a bypass of the guard privately to the maintainers (see the repository's security policy or contact Flurit) rather than in a public issue. Include the exact command string and the configuration; do not include real credentials or state.
