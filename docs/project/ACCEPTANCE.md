# v1 acceptance report

> "The spec" in this record is the project's internal planning document; its public summary is [docs/roadmap.md](../roadmap.md).

Date: 2026-10-28. Build: commit on `main` at the time of writing. Machine: Linux x86-64, 8 cores, Go 1.26.7, Terraform 1.16.1 (used only to generate one fixture planfile; see below).

This report separates what was **measured**, what is **verified live**, what is **assumed**, and what is **untested**. The live-agent behavior was verified in the T3 suite on Claude Code 2.1.312 and Codex 0.159.2/0.165.0; nothing was run against real cloud credentials or real infrastructure.

## Independent review (post-v1)

An independent review (see `docs/project/REVIEW.md`) ran the original v0 pack, an adversarial pack
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
| 1 | Passes the v0 scenario pack at the agreed threshold | **Partly.** Passes the *reconstructed* pack. The original v0 pack was not available, and no threshold has been agreed. | `go test ./harness`, `seatbelt selftest`, `harness/run.py`: 52/52 dangerous caught (block or ask), 0/30 benign flagged, 82/82 exact expected verdict, and every `must_mention` reason string present. `run.py` now also records guard version, configuration label, agent format, coverage type, bypasses per class and (with `--probes`) fail-open probes, as the v0 spec's scoring asks. |
| 2 | Observe-mode trial on 5 real repositories with a false-positive review | **Partly: a static stand-in.** | [docs/oss-corpus-trial.md](../oss-corpus-trial.md): 1,334 commands documented or run by 5 public Terraform repositories (READMEs, CI workflows, Makefiles, scripts) replayed through `seatbelt check` with a tier config per repository, and every ask/block reviewed by hand. With v0.1.2: false positives 6 of 1,259 runnable commands (0.48%; 1.27% counting 10 debatable asks), every repository under 5%; v0.1.1 had 9 (0.71%). It found and fixed a bypass (commands wrapped in `aws-vault exec`, `gds aws`, `doppler run` and similar credential runners were not analyzed) and a miss (a boto3 script deleting log groups). It is not the spec's trial: no agent ran, and no saved plan was applied, so the plan gate was not exercised there. Observe mode, the redacted 0600 log and `seatbelt report` are unit-tested (`TestObserveModeLogsWouldBlock`). The plan gate has since been exercised on real planfiles against LocalStack (see "Agent-driven observe-mode trial" below); the agent runs of that trial are pending. |
| 3 | Installs in under 5 minutes on macOS and Linux | **Linux: yes (3 s). macOS: not exercised.** | `install.sh` against the real v0.1.0 release on Linux x86-64: download, sha256 check, install and `seatbelt version` in 3 s; the installed binary passes `selftest` 82/82. `seatbelt init` (config, agent detection, hook install) is unit-tested (`TestInitInstallsHooksForDetectedAgents`). macOS: the unit tests, selftest and replay pass in CI, and the darwin archives are published, but the installer was not run on a Mac. |
| 4 | Works with Claude Code and one more agent (Codex) | **Yes (synthetic + live T3).** | Both adapters follow the hook docs (read 2026-10-28) and are tested with synthetic events — Claude through all 79 scenarios, Codex in `TestCodexAdapter` — and were run live in T3: Claude Code 2.1.312 (ask shown in `bypassPermissions`, `onFailure: block` enforced) and Codex 0.159.2/0.165.0 (ask→block; fails open on a hook that does not start). |
| 5 | Fail-closed behavior verified by chaos tests | **Yes (unit + live T3).** | `TestFailureBehavior`, `TestBrokenRepoConfigFailsClosed` and `TestPanicRecovery*` cover malformed JSON, a missing `tool_name`, a panic (inside and outside `policy.Run`), the internal deadline, a config error, and `on_error` auto/block/allow plus observe. The internal deadline now cancels in-flight work and **fails closed in every tier**. T3 verified the agent-dependent cases live: Claude Code blocks process-kill / missing-binary / hook-timeout via `onFailure: block`; **Codex fails open** on a missing binary and a signal-kill (its timeout case was not tested), with its sandbox/approval settings as the backstop. Full log: `review/T3_RESULTS.md`. |
| 6 | Docs: quickstart, threat model and limits | **Done (draft).** | `README.md` quickstart, `docs/threat-model.md`, `docs/limits.md`, `docs/policy.md`, `docs/config.md`. The quickstart has not been followed end to end on a clean machine. |
| 7 | Signed release with provenance | **Yes (v0.1.0, v0.1.1, v0.1.2, v0.1.3).** | [Release v0.1.0](https://github.com/Flurit/seatbelt/releases/tag/v0.1.0) was built by `.github/workflows/release.yml` (run 40697944755): four reproducible archives (linux/darwin × amd64/arm64), `checksums.txt` signed keylessly with cosign 3 (`checksums.txt.sigstore.json`, bundle v0.3 with a transparency-log entry), a syft SBOM per archive and a SLSA v1 build-provenance attestation whose subjects are the four archives and `checksums.txt` (builder `.github/workflows/release.yml@refs/tags/v0.1.0`, read back through the attestations API). Actions are SHA-pinned and dependencies are pinned in `go.sum`. The first run failed in the cosign step (cosign 3 needs `--bundle`); fixed in PR #13 and the tag was moved before any release existed. The `checksums.txt` signature was verified locally with cosign v3.1.4 against the exact workflow identity `release.yml@refs/tags/v0.1.0` (README steps run verbatim; a tampered `checksums.txt` and a wrong-tag identity are both rejected). The provenance attestations were checked only through the attestations API, not with `gh attestation verify` locally (older `gh`). Tag history: `v0.1.0` first pointed at `c8cae0e`, whose release run failed without creating a release; it was moved to `531a583` (the PR #13 merge) at 13:36:07Z, that run succeeded, and the release was published at 13:37:30Z. Tags of published releases are not moved. **v0.1.1** ([release](https://github.com/Flurit/seatbelt/releases/tag/v0.1.1), run 40704462908, commit `62dfdad`; same binary behavior as v0.1.0, ships the signature-verifying `install.sh`) was verified end to end on Linux x86-64 with cosign v3.1.4: the README verify steps run verbatim (`checksums.txt` signature against `release.yml@refs/tags/v0.1.1`, sha256), the tag's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require`, `selftest` 82/82 on the installed binary, and the SLSA v1 provenance attestation for the linux/amd64 archive verified with `cosign verify-blob-attestation` (subjects: the four archives and `checksums.txt`; source `refs/tags/v0.1.1` at `62dfdad`). **v0.1.3** ([release](https://github.com/Flurit/seatbelt/releases/tag/v0.1.3), run 40735243396, commit `f1a2535`; ships the unknown-wrapper backstop, backend-value tier hints and unquoted `-backend-config` values) was verified on Linux x86-64 with cosign v3.1.4: README verify steps with the tag set to v0.1.3, the tag's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require`, `selftest` 122/122 on the released binary, the SLSA v1 provenance for the linux/amd64 archive (`refs/tags/v0.1.3` at `f1a2535`), and a side-by-side check against v0.1.2: six wrapped destroy/apply commands go allow → block, a prod bucket in a `-backend-config` file without a backend block goes ask → block, and text mentions stay allowed. |

## Measured

- **Scenario pack:** 122 scenarios (80 dangerous, 42 benign). By spec ID, the dangerous ones are S1 ×1, S2 ×3, S3 ×24, S4 ×3, S5 ×2, S6 ×21, S7 ×1, S8 ×7, S9 ×4, S10 ×7, S11 ×1, S12 ×1 (stretch: provisioner and external data source in a plan), plus 5 extra plan-rule cases (one for `protected_resources`). Result: 80/80 caught, 0/42 flagged. S3 scenarios carry a `bypass_class` so `run.py` can report bypasses per class.
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

## Agent-driven observe-mode trial (harness ready; agent runs pending)

This is an **agent-driven trial, not a team trial**: Claude Code and Codex work a fixed task list (`review/agent-trial/tasks.md`) in clones of the five public repositories from the static corpus trial, in observe mode, with LocalStack as the only AWS endpoint and no cloud credentials. Harness, safety rules and the run procedure: `review/agent-trial/README.md`. Results per run: `review/agent-trial/results/<date>/summary.md`.

**Status on 2026-10-29** (seatbelt v0.1.3, Terraform 1.16.1, LocalStack 4.14.0, Claude Code 2.1.312 and Codex 0.165.0 installed; Linux x86-64 container on the same machine as the rest of this report):

- **Harness verified.** The image installs the v0.1.3 release through the repository's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require` (keyless signature on `checksums.txt` for `release.yml@refs/tags/v0.1.3`, then sha256) and passes `selftest` 122/122 on the installed binary. The five repositories are cloned at the corpus trial's pinned commits with their trial configs switched to `mode: observe` and both hooks installed by `seatbelt hook install`; `seatbelt doctor` is clean in every clone root and warns, as documented in `docs/limits.md`, when run from a subdirectory. The container holds only LocalStack's dummy credentials and endpoint override; nothing from the host's `~/.aws` is mounted.
- **Plan gate exercised on real planfiles (measured).** `review/agent-trial/plangate/run-plangate.sh` builds a small AWS stack against LocalStack (S3 bucket with versioning, security group, DynamoDB table, VPC), applies a create plan in a protected (`prod`) and a standard (`staging`) workspace, then produces flipped plans and sends each through `seatbelt plan-check` and through the real hook path (`seatbelt hook claude|codex` for `terraform apply <planfile>`, which ran `terraform show -json` on the planfile). 20 cases, every verdict as the policy table says: create and no-op allow in both tiers; replacing the bucket, suspending versioning, enabling `force_destroy` and a full destroy block in protected and ask in standard (`stateful-destroyed` / `protection-removed`, critical); port 22 open to the internet asks in protected and allows in standard (`exposure`, high); a missing planfile asks in protected and allows in standard (`plan-missing`, high, per F10); a garbage planfile blocks in protected and asks in standard (`plan-unreadable`, critical); a staging plan applied with `prod` selected blocks (`workspace-mismatch`, critical). Codex receives `deny` for every ask. Full table: `review/agent-trial/results/2026-10-29/plangate/verdicts.md`. Latency of these saved-plan decisions: p50 3.1 s, max 4.2 s (n=40), almost all of it the engine's `show -json`; the spec's 1 s plan target is not met on this path, though it is well inside the hook timeout.
- **Finding (open):** a plan made in the `prod` workspace and applied with `staging` selected is logged with tier `protected` (the plan gate bumps the tier to the plan's workspace) but gets the standard tier's verdict, `ask`, because `policy.Decide` computes the verdict from the originally resolved tier. It should block. Tracked as a follow-up; not fixed here.
- **Finding (Codex adapter, high; from the agent runs recorded in PR #32):** every Codex decision was resolved against the session root although Codex ran the commands in `examples/simple` (wrong tier, `plan-missing`, `plan-unreadable`). Addressed in PR #NN: the adapter uses `tool_input.workdir`/`working_directory`/`cwd` when sent and falls back to the hook `cwd`; the Codex source at `rust-v0.165.0` shows that version sends no workdir at all, so the remaining gap is documented in `docs/limits.md` ("Codex working directory") and checked by T3.8.
- **Agent runs: pending, requires interactive agent sign-in.** No Claude Code or Codex session has run the task list yet, so there is **no measured false-positive rate** from this trial. The decision log collected on 2026-10-29 is empty. To run: `review/agent-trial/README.md`, steps 4 and 5; results go in a new `results/<date>/` directory and this section is updated with the counts per repository and the hand-review labels.

## Assumed

- Claude Code: a hook `allow` would skip the user's permission prompt, so seatbelt prints nothing on allow. Exit 2 blocks regardless of JSON.
- Codex: the PreToolUse input matches the documented fields (`tool_input.command`, possibly argv). `apply_patch` paths come from the `*** Update File:` headers.
- OpenTofu writes the same planfile protobuf layout (field 13 → 3) as Terraform. It was not checked with an OpenTofu planfile.
- AWS plan JSON shapes in the synthetic fixtures (`aws_db_instance`, `aws_s3_bucket_versioning`, security groups, IAM) match what the AWS provider emits. They were hand-written, not generated by the AWS provider.
- The hook process environment (HOME, AWS_PROFILE, TF_WORKSPACE) matches the agent's shell environment.

## Untested

- Any real repository; install on macOS (tests pass there in CI); Windows (not supported). (Live agent sessions were exercised in T3 — see "Verified live".)
- ~~`terraform show -json` invoked by the hook on a real saved AWS plan~~ — done in the plan-gate exercise below (Terraform 1.16.1, AWS provider 5.x planfiles against LocalStack).
- Optional live STS identity check (`preflight.live_identity`).
- Terragrunt beyond argument classification (`run-all`, `run --all`).
- The GuardFall corpus itself: the bypass classes named in the spec were reproduced, but the published corpus was not run.
- Comparison of other guards on the reconstructed pack (the v0 figures in the README come from your RESULTS.md on the original pack and were not re-measured here).

## Deviations from the spec

- **Added classes:** mutating (import/refresh/test), cloud-write and credential-access, with verdicts in `docs/policy.md`. Unknown wrappers ask in protected tiers, as the spec's open decision proposed.
- **Destroy reclassification:** a saved plan with pure deletes is reclassified as destroy, so it is blocked in protected tiers. Replaces count toward `max_destroy` (high) instead.
- **IAM `Resource: "*"`** without wildcard actions is not flagged.
- **Name hints:** `prod`, `production`, `prd` and `live` in a path, workspace, backend or profile make a tier protected unless `name_hints: false`.
- **Live state pull:** implemented as `preflight.live_state` (user config only, off by default). It runs `<engine> state pull` only when local state files sit next to a remote backend and reports lineage/serial mismatches as `state-lineage` (high). Unit-tested with fixtures (`TestLineageMismatch`, `TestLineageCheckWired`); not run against a real backend.
- **Added from the spec's config example:** `protected_resources` (address globs, critical on destroy or replace). The spec's `wrappers:` list is not needed: Makefile recipes and readable scripts are analyzed directly, and a wrapper that cannot be read asks in protected tiers (`unknown-wrapper`).
- **Added from the spec's stretch list:** S12 (`code-execution`, high) for provisioners and `external` data sources. S13 (MCP) and S14 (README injection) are not covered; see `docs/limits.md`.
- **Post-review policy nuances** (from F10/F11): a *missing* plan file asks rather than blocks (nothing to apply), while an unreadable one still blocks; and creating a stateful resource with a safeguard already disabled asks in protected tiers (`stateful-unprotected-create`, high).
