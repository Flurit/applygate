## What and why

## How it was tested
- [ ] `go test ./...`
- [ ] `go build -o bin/seatbelt ./cmd/seatbelt && bin/seatbelt selftest`
- [ ] `python3 -I harness/run.py --guard bin/seatbelt` (verdict and reasons)
- [ ] New or changed behavior has a scenario in `harness/pack/scenarios.json` that fails without this change

## Docs
- [ ] Verdicts or rules changed: `docs/policy.md` updated
- [ ] Deviates from the roadmap: `docs/project/spec-alignment.md` updated
