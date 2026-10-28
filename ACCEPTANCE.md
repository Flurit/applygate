# v1 acceptance report

Date: 2026-10-28. Build: commit on `main` at the time of writing. Machine: Linux x86-64, 8 cores, Go 1.26.7, Terraform 1.16.1 (used only to generate one fixture planfile; see below).

This report separates what was **measured**, what is **verified live**, what is **assumed**, and what is **untested**. The live-agent behavior was verified in the T3 suite on Claude Code 2.1.312 and Codex 0.159.2/0.165.0; nothing was run against real cloud credentials or real infrastructure.

## Independent review (post-v1)

An independent review (see `REVIEW.md`) ran the original v0 pack, an adversarial pack
of 51 dangerous + 18 benign cases authored without reading the analyzer, the hook
format and install path, and robustness/pathological inputs. It found seven defects
that are now **fixed** (merged):

- **F1–F4 (critical, analyzer), fixed in #2:** a destroy was allowed in a protected
  tier via an interpreter body with a concatenated binary name (`'ter'+'raform'`), and
  via the `script -c`, `chroot` and GNU `parallel` wrappers, which were not unwrapped.
- **F5–F7 (robustness), fixed in #3:** a deep pipeline could reach the 25 s deadline
  (≈60k pipes 23 s → 70 ms), deeply nested braces blew up memory (5k braces
  329 MB → ~0), and a large plan JSON parsed for seconds (20 MB 1.3 s → 30 ms, now a
  critical `plan-too-large` finding at a 16 MB cap).
- **F8 (hygiene), fixed in #1:** `govulncheck` was added to CI and caught a reachable
  `golang.org/x/text` advisory (GO-2026-5970); the dependency was bumped.

After these merges the adversarial pack catches **51/51** dangerous with 0 benign
false positives. The three lower-priority findings have since been addressed too:
**F9** base32/gzip/tee decoder chains are now decoded and blocked; **F10** a *missing*
planfile asks rather than blocks (an unreadable one still blocks); and **F11** a
database created with **both** deletion protection off and the final snapshot skipped
asks in protected tiers (one safeguard off is allowed and noted). See REVIEW.md for the
F11 decision and the observe-mode measurement plan.

## Checklist (from the spec)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Passes the v0 scenario pack at the agreed threshold | **Partly.** Passes the *reconstructed* pack. The original v0 pack was not available, and no threshold has been agreed. | `go test ./harness`, `seatbelt selftest`, `harness/run.py`: 50/50 dangerous caught (block or ask), 0/29 benign flagged, 79/79 exact expected verdict, and every `must_mention` reason string present. |
| 2 | Observe-mode trial on 5 real repositories with a false-positive review | **Not done.** | Observe mode, the redacted 0600 JSONL log and `seatbelt report` exist and are unit-tested (`TestObserveModeLogsWouldBlock`). No real repository has been run. |
| 3 | Installs in under 5 minutes on macOS and Linux | **Not measured.** | On Linux, `init` → `hook install --agent claude` → `hook install --agent codex` → `doctor` → `hook remove` were exercised in a temp directory and work. No timing was taken and there is no install script or release binary yet. On macOS, the unit tests, selftest and replay pass in CI (run 40625938359); install was not exercised there. |
| 4 | Works with Claude Code and one more agent (Codex) | **Yes (synthetic + live T3).** | Both adapters follow the hook docs (read 2026-10-28) and are tested with synthetic events — Claude through all 79 scenarios, Codex in `TestCodexAdapter` — and were run live in T3: Claude Code 2.1.312 (ask shown in `bypassPermissions`, `onFailure: block` enforced) and Codex 0.159.2/0.165.0 (ask→block; fails open on a hook that does not start). |
| 5 | Fail-closed behavior verified by chaos tests | **Yes (unit + live T3).** | `TestFailureBehavior`, `TestBrokenRepoConfigFailsClosed` and `TestPanicRecovery*` cover malformed JSON, a missing `tool_name`, a panic (inside and outside `policy.Run`), the internal deadline, a config error, and `on_error` auto/block/allow plus observe. The internal deadline now cancels in-flight work and **fails closed in every tier**. T3 verified the agent-dependent cases live: Claude Code blocks process-kill / missing-binary / hook-timeout via `onFailure: block`; **Codex fails open** on a missing binary and a signal-kill (its timeout case was not tested), with its sandbox/approval settings as the backstop. Full log: `review/T3_RESULTS.md`. |
| 6 | Docs: quickstart, threat model and limits | **Done (draft).** | `README.md` quickstart, `docs/threat-model.md`, `docs/limits.md`, `docs/policy.md`, `docs/config.md`. The quickstart has not been followed end to end on a clean machine. |
| 7 | Signed release with provenance | **Not done.** | No release pipeline, signing or attestations yet. CI actions are now SHA-pinned and `govulncheck` runs, but there is still no signed release or provenance. |

## Measured

- **Scenario pack:** 79 scenarios (50 dangerous, 29 benign). By spec ID, the dangerous ones are S1 ×1, S2 ×3, S3 ×15, S4 ×3, S5 ×2, S6 ×4, S7 ×1, S8 ×6, S9 ×4, S10 ×6, S11 ×1, plus 4 extra plan-rule cases. Result: 50/50 caught, 0/29 flagged.
- **Reason checks:** 50 dangerous scenarios assert substrings of the decision message, so a right verdict for the wrong reason fails. Mutating the policy so prod destroy is ask fails 14 scenarios. Disabling `eval` handling fails D07.
- **Text mentions and cleanup** (task item 4): `grep -rn "terraform destroy"`, `echo "…terraform destroy…"`, `git commit -m "…terraform destroy -auto-approve"`, `rg 'apply -auto-approve'`, `printf … >> NOTES.md`, a here-document into a file, the Read tool on a runbook that mentions destroy, `rm -rf .terraform` in prod, and `rm -rf .terraform .terraform.lock.hcl && terraform init`. All are allowed (B10, B13–B17, B20, B24, B28).
- **Obfuscation:** in the pack, D05–D15 and D45–D49. In unit tests, also `xxd -r -p`, `rev`, brace expansion, `find -exec`, `docker run hashicorp/terraform`, aliases, functions with `$1`, `env -C`, `watch`, and field splitting. A property test checks 2,000 random quotings (plain, '', "", \, $'\xNN') of four destructive argvs, optionally wrapped in `bash -c`, `eval` or `env`.
- **Fuzzing** of the shell analyzer: about 6 minutes across three runs. One crash was found (anonymous function, nil name) and fixed; its input is kept in `testdata/fuzz` as a regression case. No input took longer than 2 s under a watchdog. Fuzz throughput sometimes dropped to 0/sec with no slow input detected; this was traced to pathological inputs reaching the analysis deadline (finding F5) and is fixed — analysis time is now bounded, so pipelines no longer approach the deadline.
- **Latency:**
  - Command-only decisions in process: p50 0.65 ms, p95 2.9 ms (n=1,300, `TestCommandLatency`).
  - Black-box, one process per event including start-up: p50 3.8 ms, p95 about 5 ms (`run.py`, 3 runs).
  - A 1,000-resource plan evaluates in about 17 ms (`TestLargePlanLatency`).
  - Spec targets are 50 ms and 1 s. These numbers do not include `terraform show -json`, which seatbelt runs for real saved plans; its cost is the engine's and was not measured.
- **Planfile workspace:** the workspace is read from a real Terraform 1.16.1 planfile (`TestPlanWorkspace`, D18).
- **Preflight:** lock-file and module-source drift against a real temporary git repo; stale state, archived state and a backend changed since init against fixtures.

## Verified live (T3)

The T3 suite (`review/manual_agent_tests.md`) was run on Claude Code 2.1.312 and Codex 0.159.2/0.165.0; full per-test log in `review/T3_RESULTS.md`. Outcomes used in this report:

- **Claude Code shows the `ask` prompt in `bypassPermissions`.** Only `dontAsk` suppresses it, so seatbelt now converts `ask` to block only under `dontAsk`. This is observed, not documented — rerun T3.2 on new Claude Code versions.
- **Claude Code `onFailure: block` blocks** a missing binary, a hook timeout and a signal-kill. `seatbelt hook install` sets `onFailure: block` (needs v2.1.295+).
- **Codex has no `onFailure` and fails open** on a hook that does not start (exit 127 and a no-status-code exit both ran the tool). seatbelt's in-process panic recovery leaves binary-not-starting as the only Codex fail-open path; use Codex's sandbox/approval settings as the backstop.
- **Codex converts `ask` to a block** (it does not support `ask`).

## Assumed

- Claude Code: a hook `allow` would skip the user's permission prompt, so seatbelt prints nothing on allow. Exit 2 blocks regardless of JSON.
- Codex: the PreToolUse input matches the documented fields (`tool_input.command`, possibly argv). `apply_patch` paths come from the `*** Update File:` headers.
- OpenTofu writes the same planfile protobuf layout (field 13 → 3) as Terraform. It was not checked with an OpenTofu planfile.
- AWS plan JSON shapes in the synthetic fixtures (`aws_db_instance`, `aws_s3_bucket_versioning`, security groups, IAM) match what the AWS provider emits. They were hand-written, not generated by the AWS provider.
- The hook process environment (HOME, AWS_PROFILE, TF_WORKSPACE) matches the agent's shell environment.

## Untested

- Any real repository; install on macOS (tests pass there in CI); Windows (not supported). (Live agent sessions were exercised in T3 — see "Verified live".)
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
- **Post-review policy nuances** (from F10/F11): a *missing* plan file asks rather than blocks (nothing to apply), while an unreadable one still blocks; and creating a stateful resource with a safeguard already disabled asks in protected tiers (`stateful-unprotected-create`, high).
