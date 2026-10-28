# v1 acceptance report

Date: 2026-10-28. Build: commit on `main` at the time of writing. Machine: Linux x86-64, 8 cores, Go 1.26.7, Terraform 1.16.1 (used only to generate one fixture planfile; see below).

This report separates what was **measured**, what is **assumed**, and what is **untested**. Nothing here was run against a live agent, real cloud credentials or real infrastructure.

## Checklist (from the spec)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Passes the v0 scenario pack at the agreed threshold | **Partly.** Passes the *reconstructed* pack. The original v0 pack was not available, and no threshold has been agreed. | `go test ./harness`, `seatbelt selftest`, `harness/run.py`: 50/50 dangerous caught (block or ask), 0/29 benign flagged, 79/79 exact expected verdict, and every `must_mention` reason string present. |
| 2 | Observe-mode trial on 5 real repositories with a false-positive review | **Not done.** | Observe mode, the redacted 0600 JSONL log and `seatbelt report` exist and are unit-tested (`TestObserveModeLogsWouldBlock`). No real repository has been run. |
| 3 | Installs in under 5 minutes on macOS and Linux | **Not measured.** | On Linux, `init` → `hook install --agent claude` → `hook install --agent codex` → `doctor` → `hook remove` were exercised in a temp directory and work. No timing was taken and there is no install script or release binary yet. On macOS, the unit tests, selftest and replay pass in CI (run 40625938359); install was not exercised there. |
| 4 | Works with Claude Code and one more agent (Codex) | **Built, not verified live.** | Both adapters follow the hook docs as read on 2026-10-28. They are tested with synthetic events only: Claude through all 79 scenarios, Codex in `TestCodexAdapter` (deny on destroy, ask→deny, argv-form command, `apply_patch` on hook config). Never run inside Claude Code or Codex. |
| 5 | Fail-closed behavior verified by chaos tests | **Partly.** | `TestFailureBehavior`, `TestBrokenRepoConfigFailsClosed` and `TestPanicRecoveryFailsClosed`/`TestPanicRecoveryObserveAllows` cover malformed JSON, a missing `tool_name`, an internal panic (inside and outside `policy.Run`), the internal deadline (timeout), a config error, and `on_error` auto/block/allow plus observe. **Agent-dependent, verified live in T3:** process kill, a missing binary, and the agent's own hook timeout. Claude Code blocks these via `onFailure: block` (set by `hook install`, needs v2.1.295+). **Codex has no `onFailure` and fails open** on a missing/killed/crashed hook (observed: exit 127 and no-status-code both run the tool); seatbelt's in-process panic recovery leaves the binary-not-starting case as the only Codex fail-open path. |
| 6 | Docs: quickstart, threat model and limits | **Done (draft).** | `README.md` quickstart, `docs/threat-model.md`, `docs/limits.md`, `docs/policy.md`, `docs/config.md`. The quickstart has not been followed end to end on a clean machine. |
| 7 | Signed release with provenance | **Not done.** | No release pipeline, signing or attestations yet. CI uses version-tagged actions, not SHA-pinned ones. |

## Measured

- **Scenario pack:** 79 scenarios (50 dangerous, 29 benign). By spec ID, the dangerous ones are S1 ×1, S2 ×3, S3 ×15, S4 ×3, S5 ×2, S6 ×4, S7 ×1, S8 ×6, S9 ×4, S10 ×6, S11 ×1, plus 4 extra plan-rule cases. Result: 50/50 caught, 0/29 flagged.
- **Reason checks:** 50 dangerous scenarios assert substrings of the decision message, so a right verdict for the wrong reason fails. Mutating the policy so prod destroy is ask fails 14 scenarios. Disabling `eval` handling fails D07.
- **Text mentions and cleanup** (task item 4): `grep -rn "terraform destroy"`, `echo "…terraform destroy…"`, `git commit -m "…terraform destroy -auto-approve"`, `rg 'apply -auto-approve'`, `printf … >> NOTES.md`, a here-document into a file, the Read tool on a runbook that mentions destroy, `rm -rf .terraform` in prod, and `rm -rf .terraform .terraform.lock.hcl && terraform init`. All are allowed (B10, B13–B17, B20, B24, B28).
- **Obfuscation:** in the pack, D05–D15 and D45–D49. In unit tests, also `xxd -r -p`, `rev`, brace expansion, `find -exec`, `docker run hashicorp/terraform`, aliases, functions with `$1`, `env -C`, `watch`, and field splitting. A property test checks 2,000 random quotings (plain, '', "", \, $'\xNN') of four destructive argvs, optionally wrapped in `bash -c`, `eval` or `env`.
- **Fuzzing** of the shell analyzer: about 6 minutes across three runs. One crash was found (anonymous function, nil name) and fixed; its input is kept in `testdata/fuzz` as a regression case. No input took longer than 2 s under a watchdog. Fuzz throughput sometimes dropped to 0/sec with no slow input detected; this was not investigated further.
- **Latency:**
  - Command-only decisions in process: p50 0.65 ms, p95 2.9 ms (n=1,300, `TestCommandLatency`).
  - Black-box, one process per event including start-up: p50 3.8 ms, p95 about 5 ms (`run.py`, 3 runs).
  - A 1,000-resource plan evaluates in about 17 ms (`TestLargePlanLatency`).
  - Spec targets are 50 ms and 1 s. These numbers do not include `terraform show -json`, which seatbelt runs for real saved plans; its cost is the engine's and was not measured.
- **Planfile workspace:** the workspace is read from a real Terraform 1.16.1 planfile (`TestPlanWorkspace`, D18).
- **Preflight:** lock-file and module-source drift against a real temporary git repo; stale state, archived state and a backend changed since init against fixtures.

## Assumed

- Claude Code: a hook `allow` would skip the user's permission prompt, so seatbelt prints nothing on allow. `ask` cannot be shown in `bypassPermissions`/`dontAsk`, so it is enforced as block. Exit 2 blocks regardless of JSON.
- Codex: the PreToolUse input matches the documented fields (`tool_input.command`, possibly argv). `apply_patch` paths come from the `*** Update File:` headers. `ask` is unsupported, so it becomes deny.
- OpenTofu writes the same planfile protobuf layout (field 13 → 3) as Terraform. It was not checked with an OpenTofu planfile.
- AWS plan JSON shapes in the synthetic fixtures (`aws_db_instance`, `aws_s3_bucket_versioning`, security groups, IAM) match what the AWS provider emits. They were hand-written, not generated by the AWS provider.
- The hook process environment (HOME, AWS_PROFILE, TF_WORKSPACE) matches the agent's shell environment.

## Untested

- Any live agent session; any real repository; install on macOS (tests pass there in CI); Windows (not supported).
- `terraform show -json` invoked by the hook on a real saved AWS plan (only fixture JSON is used in tests).
- Optional live STS identity check (`preflight.live_identity`).
- Terragrunt beyond argument classification (`run-all`, `run --all`).
- The GuardFall corpus itself: the bypass classes named in the spec were reproduced, but the published corpus was not run.
- Comparison of other guards on the reconstructed pack (the v0 figures in the README come from your RESULTS.md on the original pack and were not re-measured here).

## Deviations from the spec

- **Added classes:** mutating (import/refresh/test), cloud-write and credential-access, with verdicts in `docs/policy.md`. Unknown wrappers ask in protected tiers, as the spec's open decision proposed.
- **Destroy reclassification:** a saved plan with pure deletes is reclassified as destroy, so it is blocked in protected tiers. Replaces count toward `max_destroy` (high) instead.
- **IAM `Resource: "*"`** without wildcard actions is not flagged.
- **Name hints:** `prod`, `production`, `prd` and `live` in a path, workspace, backend or profile make a tier protected unless `name_hints: false`.
- **Not implemented from the preflight list:** the optional read-only state pull that compares lineage and serial.
