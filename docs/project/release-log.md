# Release verification log

What was checked on each release after it was published, newest first. [RELEASE.md](RELEASE.md) says what to check; this file records that it was done and what was seen. Releases up to v0.1.4 were published under the project's old name, seatbelt.

## v0.7.0

**v0.7.0** ([release](https://github.com/Flurit/applygate/releases/tag/v0.7.0), run 45625902819, commit `0e463e8`; one verdict changes: a saved plan whose only deletes and replaces are routine replaces is allowed in a standard tier, with the new class `routine-replace`; a protected tier blocks every replace as before, and no other rule, verdict, tier or default changed) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4 on 2026-11-25:

- the install.md verify steps with the tag set to v0.7.0 against `release.yml@refs/tags/v0.7.0` (the v0.6.3 identity is rejected)
- sha256 of all four archives and their SBOMs against the signed `checksums.txt`
- the build-provenance attestation of all four archives with `gh attestation verify` 2.102.0 (signer `release.yml@refs/tags/v0.7.0` at `0e463e8`; a check of the darwin/amd64 archive against `refs/tags/v0.6.3` is rejected)
- `applygate version` 0.7.0 and `selftest` 169/169 exact (113/113 dangerous) on the released darwin/amd64 binary
- the verdict this release changes, with `plan-check` on that binary and the pack's plans: the routine replace plan (`harness/pack/plans/replace_routine.json`) allowed in a standard tier (exit code 0, where the v0.6.3 binary exits 4) and blocked in a protected one (exit code 3); the same replace beside an instance replace still asked about in a standard tier (exit code 4)
- `plan-check` on that binary with the two real AWS plans in `testdata/real_plan`, as before: the delete blocked in a protected tier (exit code 3), the create asked about in a protected tier (exit code 4) and allowed in a standard one
- the tag's `install.sh` (the same bytes as the tagged file) with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.7.0 in 5 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.7.0` through the public proxy and checksum database (`h1:DKeOx2oY…`, origin `refs/tags/v0.7.0` at `0e463e8`) reporting 0.7.0
- the Claude Code plugin re-pinned to v0.7.0 with `scripts/pin-plugin-release.sh`, and the four archive sha256 values in `packaging/homebrew/applygate.rb` taken from the signed `checksums.txt`
- the Homebrew upgrade, the same day: `Flurit/homebrew-tap` at `ca1ea66` carries this repository's formula with the tap's source note, and after `brew update && brew upgrade Flurit/tap/applygate` (Homebrew 7.0.16) the machine has 0.7.0 from the tap. The installed binary has the sha256 of the one in the verified darwin/amd64 archive, reports 0.7.0, passes `selftest` 169/169 and allows the routine replace plan in a standard tier (exit code 0)

The tag was pushed after both workflows had passed on the commit, on the day the changelog section is dated. **The approval gate held:** the test job passed and the release job waited under three minutes for the `release` environment's approval, which is recorded under the owner's account; the session that pushed the tag did not enter it.

Not run for this release: the routine replace through a live agent's hook (it was judged with `plan-check` and in the scenario pack only), the plugin's launcher fetching the pinned release with no applygate on PATH, the Action at the tag from a workflow, and the hook on Linux.

## v0.6.3

**v0.6.3** ([release](https://github.com/Flurit/applygate/releases/tag/v0.6.3), run 45548170817, commit `c329fb7`; a cleanup release: the documentation organised by topic, `docs/limits.md` corrected against the code, the largest source files split by responsibility; no rule, verdict, tier or default changed) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4 on 2026-11-25:

- the install.md verify steps with the tag set to v0.6.3 against `release.yml@refs/tags/v0.6.3` (the v0.6.2 identity is rejected)
- sha256 of all four archives and their SBOMs against the signed `checksums.txt`
- the build-provenance attestation of all four archives with `gh attestation verify` 2.102.0 (signer `release.yml@refs/tags/v0.6.3` at `c329fb7`; a check of the darwin/amd64 archive against `refs/tags/v0.6.2` is rejected)
- `applygate version` 0.6.3 and `selftest` 163/163 exact (108/108 dangerous) on the released darwin/amd64 binary
- `plan-check` on that binary with the two real AWS plans in `testdata/real_plan`: the delete blocked in a protected tier (exit code 3), the create asked about in a protected tier (exit code 4) and allowed in a standard one
- `applygate hosts` on that binary naming the acceptance report at its new path, the one output this release changed
- the tag's `install.sh` (the same bytes as the tagged file) with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.6.3 in 231 s on a slow connection
- `go install github.com/Flurit/applygate/cmd/applygate@v0.6.3` through the public proxy and checksum database (`h1:9G4K/oIM…`, origin `refs/tags/v0.6.3` at `c329fb7`) reporting 0.6.3
- the Claude Code plugin re-pinned to v0.6.3 with `scripts/pin-plugin-release.sh`, and the four archive sha256 values in `packaging/homebrew/applygate.rb` taken from the signed `checksums.txt`
- the Homebrew upgrade, the same day: `Flurit/homebrew-tap` at `d502e8a` carries this repository's formula with the tap's source note, and after `brew update && brew upgrade Flurit/tap/applygate` (Homebrew 7.0.16) the machine has 0.6.3 from the tap. The installed binary has the sha256 of the one in the verified darwin/amd64 archive, reports 0.6.3 and passes `selftest` 163/163

The tag was pushed after both workflows had passed on the commit. **The approval gate held:** the test job passed and the release job waited about seven minutes for the `release` environment's approval, which is recorded under the owner's account; the session that pushed the tag did not enter it.

Not run for this release: the plugin's launcher fetching the pinned release with no applygate on PATH, the Action at the tag from a workflow, the hook on Linux, and any agent live.

## v0.6.2

**v0.6.2** ([release](https://github.com/Flurit/applygate/releases/tag/v0.6.2), run 43907944846, commit `9c3ad4f`; ships the Action's pull-request comment with the plan check's verdict (opt-in), `plan-check --comment-file`, and an Action that installs the release it is tagged at; no rule, verdict, tier or default changed) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4 on 2026-11-16: the install.md verify steps with the tag set to v0.6.2 against `release.yml@refs/tags/v0.6.2` (the v0.6.1 identity is rejected), sha256 of all four archives and their SBOMs against the signed `checksums.txt`, the build-provenance attestation of all four archives with `gh attestation verify` 2.102.0 (signer `release.yml@refs/tags/v0.6.2` at `9c3ad4f`; a check of the darwin/amd64 archive against `refs/tags/v0.6.1` is rejected), `applygate version` 0.6.2 and `selftest` 163/163 exact (108/108 dangerous) on the released darwin/amd64 binary;

- `plan-check --comment-file` on that binary writing the comment for the two real AWS plans in `testdata/real_plan` (block with exit code 3 for the delete, ask with exit code 4 for the create)
- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.6.2 in 80 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.6.2` through the public proxy and checksum database (`h1:GrIqGdNI…`, origin `refs/tags/v0.6.2` at `9c3ad4f`) reporting 0.6.2
- the Claude Code plugin re-pinned to v0.6.2 with `scripts/pin-plugin-release.sh`, its launcher fetching and running 0.6.2 with no applygate on PATH and blocking the `script`-wrapped destroy
- the four archive sha256 values in `packaging/homebrew/applygate.rb` taken from the signed `checksums.txt`. The tag was pushed after both workflows had passed on the commit. **The approval gate held, with the same caveat as v0.6.1:** the test job passed and the release job waited about three minutes for the `release` environment's approval. The approval was recorded under the owner's account, but it was entered by the coding agent that prepared the release, on the owner's instruction in the session, not clicked by the owner. **The Action at the v0.6.2 tag was run from a workflow on 2026-11-24,** eight days after the release, on a throwaway pull request of this repository (#157, closed without merging; runs 45343550361 and 45344240713): `uses: Flurit/applygate@v0.6.2` with `comment: true` on `ubuntu-latest` (Linux x86-64), `ubuntu-24.04-arm` (Linux arm64) and `macos-latest` (macOS arm64). On each runner the install step verified the signature and installed 0.6.2, `applygate version` reported 0.6.2 and `selftest` gave 163/163 exact (108/108 dangerous)
- the delete plan in `testdata/real_plan` was blocked in a protected tier (exit code 3, the step failed) and the create plan was allowed in a standard tier
- each plan in each job got one comment, six in all, and the second run updated the same six comments in place. Before that day the Action at the tag had not been run from a workflow, and the comment had been posted only with a build from the branch ([limits.md](../limits.md)). The Action check in CI uses a binary built from the checkout, so it does not exercise the download. No agent was tested live for this release, since the hook's decision path did not change. The Homebrew upgrade was run on 2026-11-24, after the tap was updated (`Flurit/homebrew-tap` commit `e8e20f8`), on the same Intel Mac with Homebrew 7.0.13: `brew upgrade Flurit/tap/applygate` replaced 0.6.1 with 0.6.2, the installed binary is byte for byte the one in the signed darwin/amd64 archive, and `brew test` (which runs `applygate version` and `applygate selftest`) passed. A first-time `brew install` of 0.6.2 on a machine without the tap was not run. The Linux binaries ran only in the workflow above (version, selftest and two plan checks on each architecture)
- the hook was not run on Linux for this release.

## v0.6.1

**v0.6.1** ([release](https://github.com/Flurit/applygate/releases/tag/v0.6.1), run 43680654583, commit `98c6637`; ships `applygate scan` with `--boundary` and `--share`, and a boundary report that names every audited credential; no rule, verdict, tier or default changed) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4 on 2026-11-15: the install.md verify steps with the tag set to v0.6.1 against `release.yml@refs/tags/v0.6.1`, sha256 of all four archives and their SBOMs against the signed `checksums.txt`, the build-provenance attestation of all four archives with `gh attestation verify`, `applygate version` 0.6.1 and `selftest` 163/163 exact (108/108 dangerous) on the released darwin/amd64 binary;

- the tag's `install.sh` (the same bytes as the tagged file) with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.6.1 in 80 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.6.1` through the public proxy and checksum database (`h1:5fqjZb5I…`, origin `refs/tags/v0.6.1` at `98c6637`) reporting 0.6.1
- the Claude Code plugin re-pinned to v0.6.1 with `scripts/pin-plugin-release.sh`, its launcher fetching and running 0.6.1 with no applygate on PATH and blocking the `script`-wrapped destroy
- the four archive sha256 values in `packaging/homebrew/applygate.rb` taken from the signed `checksums.txt`. **The approval gate held, with a caveat:** the `release` environment required a reviewer and allowed only `v*` tags, the test job passed, and the release job waited about eleven and a half hours until it was approved. The approval was recorded under the owner's account, but it was entered by the coding agent that prepared the release, on the owner's instruction in the session, not clicked by the owner. No agent was tested live for this release, since the hook's decision path did not change
- what was run live is the credential audit behind `scan --boundary`, against real AWS and Google Cloud accounts on 2026-11-14 and 15 ([limits.md](../limits.md)). `brew install Flurit/tap/applygate` was run on 2026-11-16, after the tap was updated (`Flurit/homebrew-tap` commit `8481446`), on the same Intel Mac with Homebrew 7.0.13 and without the tap added beforehand: it added the tap, installed 0.6.1, and `brew test` (which runs `applygate version` and `applygate selftest`) passed. This is the first release whose Homebrew install was run. `brew upgrade` with the full name refuses on a machine that has not added the tap, which is Homebrew's behaviour and not the formula's. The Linux binaries were checked by sha256 and attestation only, not run.

## v0.6.0

**v0.6.0** ([release](https://github.com/Flurit/applygate/releases/tag/v0.6.0), run 42992671970, commit `d6b80d4`; ships the allow-list for every command applygate lets through, the effects oracle as a CI gate, the boundary contract (`doctor --boundary`), guarded hook files at the git root and session directories, git work-tree rewrites asking at repository roots, the Codex `/hooks` trust check in `doctor`, and asks shown as prompts in Claude Code's auto mode) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4 on 2026-11-11: the install.md verify steps with the tag set to v0.6.0 against `release.yml@refs/tags/v0.6.0`, sha256 of all four archives against the signed `checksums.txt`, the SLSA build-provenance attestation of all four archives with `gh attestation verify`, `applygate version` 0.6.0 and `selftest` 163/163 exact (108/108 dangerous) on the released darwin/amd64 binary;

- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.6.0 in 5 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.6.0` through the public proxy and checksum database (`h1:l8KGhyXQ…`, origin `refs/tags/v0.6.0` at `d6b80d4`) reporting 0.6.0
- the Claude Code plugin re-pinned to v0.6.0 with `scripts/pin-plugin-release.sh`, its launcher fetching and running 0.6.0 with no applygate on PATH and blocking the `script`-wrapped destroy
- the four archive sha256 values in `packaging/homebrew/applygate.rb` taken from the signed `checksums.txt`. The live agent tests for this release are in `review/T3_RESULTS.md` (Claude Code 2.1.314 and 2.1.322, Codex 0.166.0). **The release ran without its approval gate:** the `release` environment had no protection rules (no required reviewer, no deployment tag policy), so the run built, signed and published without a person approving it, contrary to [RELEASE.md](RELEASE.md). The signature is still bound to `release.yml@refs/tags/v0.6.0`
- what was missing is the human check that a workflow run cannot sign a release by itself. The gate was set up after the release, on 2026-11-11: a required reviewer and a deployment rule for `v*` tags only (administrators can still bypass it). `brew install` was not run, and the Linux binaries were checked by sha256 and attestation only, not run.

## v0.5.0

**v0.5.0** ([release](https://github.com/Flurit/applygate/releases/tag/v0.5.0), run 41223425518, commit `e650aa7`; ships one-time approvals (`applygate approve`) and the fix for commands hidden behind the BSD form of `script`, which v0.4.0 allowed even in a protected tier) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4: the install.md verify steps with the tag set to v0.5.0 against `release.yml@refs/tags/v0.5.0`, sha256 of all four archives against the signed `checksums.txt`, `applygate version` 0.5.0 and `selftest` 141/141 exact on the released binary, `script -q /dev/null terraform destroy -auto-approve` and `applygate approve 1234abcd` blocked;

- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.5.0 in 4 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.5.0` through the public proxy and checksum database (`h1:zRxsMw0zQ…`) reporting 0.5.0
- the SLSA v1 build-provenance attestation verified with `gh attestation verify` 2.102.0 (signer `release.yml@refs/tags/v0.5.0`)
- the scenario pack replayed against the released binary in all nine hook formats with `--probes --strict-probes`: Claude, Copilot, Gemini, Windsurf, OpenCode and Cline 141/141 exact and 93/93 dangerous, Codex 139/139 and 92/92, Cursor and Devin 136/136 and 90/90 (2 and 5 scenarios not expressible in those formats skipped), 0 bypasses and 0 of 5 fail-open probes proceeding in each
- the same pack against v0.4.0 misses D106 to D108 (90/93)
- the Claude Code plugin re-pinned to v0.5.0 with `scripts/pin-plugin-release.sh`, its launcher fetching and running 0.5.0 with no applygate on PATH and blocking the `script`-wrapped destroy
- the four archive sha256 values in `packaging/homebrew/applygate.rb` and in `Flurit/homebrew-tap` (commit `f2fc602`, "applygate 0.5.0") taken from the signed `checksums.txt`. `applygate approve` was exercised end to end with the Codex hook format before the release (request, refusal without a terminal and on a wrong word, approval, one allowed retry, the next call blocked) but not inside a live agent. `brew install` was not run (the tap is not added on this machine), and the Linux binaries were checked by sha256 only, not run.

## v0.4.0

**v0.4.0** ([release](https://github.com/Flurit/applygate/releases/tag/v0.4.0), run 41156219403, commit `106fccd`; ships the hook adapters for Cursor, Copilot CLI, Gemini CLI, Windsurf, Devin, OpenCode and Cline written from documentation and not tested live, MCP call logging and the Claude Code plugin launcher) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4: README verify steps with the tag set to v0.4.0 against `release.yml@refs/tags/v0.4.0` (the v0.3.2 identity is rejected), sha256 of the darwin/amd64 archive, `applygate version` 0.4.0 and `selftest` 137/137 exact on the released binary, and `applygate hosts` marking the seven new hosts "not tested live";

- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.4.0 (230 s on a slow link, where the archive download alone took 76 s)
- `go install github.com/Flurit/applygate/cmd/applygate@v0.4.0` through the public proxy and checksum database (`h1:KY5874VR…`) reporting 0.4.0
- the SLSA v1 build-provenance attestation verified with `gh attestation verify` 2.102.0 (signer `release.yml@refs/tags/v0.4.0` at `106fccd`, subjects the four archives and `checksums.txt`)
- the scenario pack replayed against the released binary in all nine hook formats with `--probes --strict-probes`: Claude, Copilot, Gemini, Windsurf, OpenCode and Cline 137/137 exact and 90/90 dangerous, Codex 135/135 and 89/89, Cursor and Devin 132/132 and 87/87 (scenarios not expressible in a format are skipped: 2 for Codex, 5 for Cursor and Devin), 0 of 5 fail-open probes proceeding in each
- the Claude Code plugin re-pinned to v0.4.0 with `scripts/pin-plugin-release.sh`, its launcher fetching and running 0.4.0 with no applygate on PATH
- the four archive sha256 values in `packaging/homebrew/applygate.rb` and in `Flurit/homebrew-tap` (commit `7324838`, "applygate 0.4.0") checked by downloading each formula URL. The Linux archives were checked by sha256 only
- the Linux binaries were not run for this release.

## v0.3.2

**v0.3.2** ([release](https://github.com/Flurit/applygate/releases/tag/v0.3.2), run 41064837898, commit `dd14612`; ships the plan-gate fix for the `code-execution` and `exposure` false positives found by the plan-gate false-positive study) was verified on Linux x86-64 with cosign v3.1.4: README verify steps with the tag set to v0.3.2 against `release.yml@refs/tags/v0.3.2` (the v0.3.1 identity is rejected), sha256 of the linux/amd64 archive, `applygate version` 0.3.2 and `selftest` 137/137 exact on the released binary;

- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.3.2 in 3 s
- `go install github.com/Flurit/applygate/cmd/applygate@v0.3.2` through the public proxy and checksum database (`h1:uywCy7Is…`) reporting 0.3.2
- the SLSA v1 build-provenance attestation of the linux/amd64 archive, fetched through the attestations API and verified with `cosign verify-blob-attestation` (builder `release.yml@refs/tags/v0.3.2` at `dd14612`, subjects the four archives and `checksums.txt`)
- the released binary on the study's 212 routine plans per tier: 0 false positives in the protected tier with all 26 expected prompts kept, no prompts in the standard tier, and 63 of 63 destroy plans prompting
- the four archive sha256 values in `packaging/homebrew/applygate.rb` and in `Flurit/homebrew-tap` (commit `4a129c0`, "applygate 0.3.2") checked by downloading each formula URL.

## v0.3.1

**v0.3.1** ([release](https://github.com/Flurit/applygate/releases/tag/v0.3.1), run 41054598366, commit `3631b93`; ships the secrets-runner unwrapping fix and the module version for `go install` builds) was verified on macOS 26.7.1 (Intel) with cosign v3.1.4: README verify steps with the tag set to v0.3.1 against `release.yml@refs/tags/v0.3.1` (the v0.3.0 identity is rejected), sha256 of the darwin/amd64 archive, `applygate version` 0.3.1 and `selftest` 137/137 exact on the released binary, which blocks `dotenvx run -- aws s3 rb …`, `sops exec-env f 'aws s3 rb …'` and `doppler run --command 'terraform destroy'` in a protected directory;

- the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` installing 0.3.1 (3 min 50 s wall time on a slow connection, 0.7 s of CPU)
- `go install github.com/Flurit/applygate/cmd/applygate@v0.3.1` through the public proxy and checksum database (`h1:NbvjvMm4…`, the same from the proxy and from git) reporting 0.3.1
- the SLSA build-provenance attestation of the darwin/amd64 archive with `gh attestation verify` (gh 2.102.0)
- the four archive sha256 values in `Flurit/homebrew-tap` checked by downloading each formula URL. A first `go install` on this machine failed with a checksum mismatch from a stale local module-cache entry: a v0.3.1 fetched at 08:12 UTC from a temporary tag on `aac6d09` during the `go install` version work, never served by the public proxy or checksum database
- after removing that cache entry the install verified.

## v0.2.0

**v0.2.0** ([release](https://github.com/Flurit/applygate/releases/tag/v0.2.0), run 40908360988, commit `4558d7e`; the first release under the applygate name, carrying the rename with its compatibility shim, the host capability matrix, fail-closed resolution of an unknown command directory, the planfile search and user-scope hooks) was verified on Linux x86-64 with cosign v3.1.4: README verify steps against the new identity `Flurit/applygate/.github/workflows/release.yml@refs/tags/v0.2.0` (the old `Flurit/seatbelt` identity is rejected), sha256, the tag's `install.sh` with `APPLYGATE_VERIFY_SIGNATURE=require` in 3 s installing both `applygate` and the `seatbelt` shim, the same installer with the legacy `SEATBELT_*` variables (each warned as deprecated, install succeeded), `applygate version` 0.2.0, `selftest` 133/133 exact, the `seatbelt` shim printing its deprecation line and forwarding to applygate 0.2.0, and the SLSA v1 provenance attestation read through the attestations API (builder `release.yml@refs/tags/v0.2.0`, subjects the four archives and `checksums.txt`).


## v0.1.4

**v0.1.4** ([release](https://github.com/Flurit/seatbelt/releases/tag/v0.1.4), run 40875311466, commit `2d4fbe2`; ships the mismatched-plan tier fix, the file-only interpreter rule, the `non-prod` name-hint fix and Codex workdir parsing) was verified on Linux x86-64 with cosign v3.1.4: README verify steps with the tag set to v0.1.4 (the v0.1.3 identity is rejected), the tag's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require` in 3 s, `selftest` 133/133 exact on the released binary (87/87 dangerous caught; one benign control, the trial edit whose text names `terraform.tfstate`, is expected to ask), the SLSA v1 provenance attestation read through the attestations API (builder `release.yml@refs/tags/v0.1.4`, subjects the four archives and `checksums.txt`; `gh attestation verify` is not available in the local `gh`), and a side-by-side check against v0.1.3 in a protected directory: three of the four trial edit scripts go ask → allow and the fourth stays ask, a `subprocess` body and a by-reference `os.system` body stay ask, `terraform apply -auto-approve` under `non-prod/` goes block → ask (standard tier) and under `envs/prod` stays block.


## v0.1.3

**v0.1.3** ([release](https://github.com/Flurit/seatbelt/releases/tag/v0.1.3), run 40735243396, commit `f1a2535`; ships the unknown-wrapper backstop, backend-value tier hints and unquoted `-backend-config` values) was verified on Linux x86-64 with cosign v3.1.4: README verify steps with the tag set to v0.1.3, the tag's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require`, `selftest` 122/122 on the released binary, the SLSA v1 provenance for the linux/amd64 archive (`refs/tags/v0.1.3` at `f1a2535`), and a side-by-side check against v0.1.2: six wrapped destroy/apply commands go allow → block, a prod bucket in a `-backend-config` file without a backend block goes ask → block, and text mentions stay allowed.


## v0.1.1

**v0.1.1** ([release](https://github.com/Flurit/seatbelt/releases/tag/v0.1.1), run 40704462908, commit `62dfdad`; same binary behavior as v0.1.0, ships the signature-verifying `install.sh`) was verified end to end on Linux x86-64 with cosign v3.1.4: the README verify steps run verbatim (`checksums.txt` signature against `release.yml@refs/tags/v0.1.1`, sha256), the tag's `install.sh` with `SEATBELT_VERIFY_SIGNATURE=require`, `selftest` 82/82 on the installed binary, and the SLSA v1 provenance attestation for the linux/amd64 archive verified with `cosign verify-blob-attestation` (subjects: the four archives and `checksums.txt`; source `refs/tags/v0.1.1` at `62dfdad`).


## v0.1.0

[Release v0.1.0](https://github.com/Flurit/seatbelt/releases/tag/v0.1.0) was built by `.github/workflows/release.yml` (run 40697944755): four reproducible archives (linux/darwin × amd64/arm64), `checksums.txt` signed keylessly with cosign 3 (`checksums.txt.sigstore.json`, bundle v0.3 with a transparency-log entry), a syft SBOM per archive and a SLSA v1 build-provenance attestation whose subjects are the four archives and `checksums.txt` (builder `.github/workflows/release.yml@refs/tags/v0.1.0`, read back through the attestations API). Actions are SHA-pinned and dependencies are pinned in `go.sum`. The first run failed in the cosign step (cosign 3 needs `--bundle`);

- fixed in PR #13 and the tag was moved before any release existed. The `checksums.txt` signature was verified locally with cosign v3.1.4 against the exact workflow identity `release.yml@refs/tags/v0.1.0` (README steps run verbatim; a tampered `checksums.txt` and a wrong-tag identity are both rejected). The provenance attestations were checked only through the attestations API, not with `gh attestation verify` locally (older `gh`). Tag history: `v0.1.0` first pointed at `c8cae0e`, whose release run failed without creating a release
- it was moved to `531a583` (the PR #13 merge) at 13:36:07Z, that run succeeded, and the release was published at 13:37:30Z. Tags of published releases are not moved.
