# v0.6.0 reassessment: can the design carry the promise?

Written after round 11 and its fixes (main at ea1c83c), from the eleven round reports, three independent design reviews (one on the design, one on a default-deny allow-list with a measured cost, one on enforcement below the parser) and two checks the coordinator ran itself. The reviewers did not see each other's reports.

## Verdict

**The parser cannot carry "never allowed" for a protected environment, and the documents should stop saying it does.** What it can honestly deliver is: mistakes and most injected instructions are caught, and in a protected tier only a closed, positively defined set of commands runs without asking. The guarantee that holds whatever the parser misses has to come from boundaries the hook can check but not enforce: the agent's credentials, the cloud's own guards, the host's confinement and a reviewed apply path.

This does not narrow what applygate tries to catch. It changes which layer carries the guarantee, and it makes the conditions something `doctor` verifies instead of something the README assumes.

## Evidence that the loop is not converging

| Round | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|
| Critical | 31 | 4 | 19 | 9 | 17 | 21 | 14 | 17 | 12 | 11 |

155 criticals in ten rounds, about 15 a round since round 4. Round 11 still found 62 issues. Fixes introduce defects (R5-1 was a panic in round-10 code that failed open). A new class appeared in round 11 (zsh, three criticals in constructs the analyzer treats as plain). Eight of round 11's eleven criticals are one design: each program's way of naming a target is a table row, and an unlisted spelling is an allow. Rounds 4, 8, 10 and 11 say the same sentence.

## Four classes, and what closes each

1. **The shell model is bash's and incomplete.** Closable by a positive grammar for protected tiers (one-operand `cd`, literal single redirect targets, a closed charset), not by modelling each shell. Inherent: the hook never observes which shell runs the command.
2. **Deny lists lose to spellings** (options, output files, state writers). Closable by a positive per-call grammar for every program that is not purely read-only, and by deleting the "takes any arguments" shapes (about 60 programs). The table must shrink, not grow.
3. **The hook lacks information** (the real directory on some hosts, what a runner loads, what a program really does). Closable by tracking every value as known or unknown-with-a-reason per invocation and failing closed. Inherent: a swap between verdict and execution, Codex failing open when the hook does not start, processes and tools outside the hook, MCP servers with their own credentials.
4. **A long tail of programs.** Closable only by shrinking the trusted surface. A reviewer verified a live example: `curl -X POST https://app.terraform.io/api/v2/runs … -d @run.json` is allowed in a protected directory (an HCP Terraform run can carry `is-destroy`). The coordinator reproduced it, and `wget --post-data` too. Round 11 blocked only `curl -X DELETE`.

Intrinsic, whatever is done to the parser: an agent can write code and run it, and allowed programs such as `terraform plan`, `make`, `pytest` and `go test` run code with the agent's credentials. A cloud call through any client that is not a recognized CLI is outside the hook.

## The allow-list, measured

A prototype (93 programs, about 1,000 option entries, one matcher that replaces the shapes and the write-target tables) was replayed on the 162 real agent calls in a protected directory:

| Configuration | Asks or blocks, of 162 |
|---|---|
| Strict shapes off | 11 (6.8%) |
| Current strict shapes | 52 (32.1%) |
| Allow-list prototype | 53 (32.7%); 50 (30.9%) with the analyzer's variable tracking; about 43 (26.5%) with loop unrolling |

The ask rate is about the same because program and option shape was never where the asks came from: `python3` and `node` (12), `init` or a file write followed by `plan` (8), loops and subshells (6), `export PATH` (5). Only about 4 of the 39 asks it adds to a shapes-off run are shape. On the curated benign controls about 13% (10 of 68) would newly ask in a protected directory (copies to `/tmp`, state-file backups, `git checkout -b`, `eks update-kubeconfig`, `kubectl port-forward`).

Of the 54 criticals of rounds 8 to 11 it prevents about 44 (11 of 14, 12 of 17, 10 of 12, 11 of 11). The other 10 are Terraform and provider-scan semantics (init and provider execution, `tfquery`, `-backend-config`, module scans, `graph -type=plan`, a config over 1 MiB, an unresolved `-chdir`), which no shell allow-list touches. **Caveat:** the prototype was written knowing the findings, so it shows the mechanism works, not that the table is complete. New attack surface: a wrongly listed option becomes a false allow, GNU and BSD argument parsing can disagree with the matcher, and environment and in-tree config can steer a listed program (`GIT_EXTERNAL_DIFF`, `RIPGREP_CONFIG_PATH`). Fatigue at about 30% asks is real; only the user config can turn strict shapes off.

## Enforcement below the parser

| Layer | Closes | Cannot close | Set up by |
|---|---|---|---|
| Credentials (plan-only agent role, MFA- or OIDC-gated apply role) | every route to the cloud API, any spelling | local state and files; reads of data and secrets; person credentials the same OS user can read | platform admin, each developer |
| Cloud guards (versioned, object-locked state bucket with a deny policy; deletion protection; SCPs) | state surgery and deletes on remote state, recoverably | non-delete harm; what the apply role may legitimately do | platform or org admin |
| Host sandbox (Claude Code sandbox, Codex modes) | every subprocess the Bash tool starts: the local-state, guard-file and cross-directory families by construction | non-Bash tools, MCP, escape hatches (unsandboxed retries, `docker.sock`); network is domain-level only | developer or managed settings |
| Reviewed apply path (plan-only agents, CI plan gate, OIDC-pinned apply role) | semantic review the other layers cannot express | an agent holding direct credentials | platform team |

The managed install is the one place the docs' guarantee holds, because root file ownership enforces it, not parsing. `doctor --creds` exists; it samples 16 actions, has no state-bucket actions and covers only AWS.

## Claims the evidence says are overstated

- The README headline ("Stop coding agents from running `terraform destroy` in production") and "It parses commands the way the shell does".
- "17 / 17" against other guards: a self-authored scenario set and a self-chosen comparison. The 790-scenario attack pack is the reviewers' own finds, so it shows past fixes held, not coverage.
- "Reads cloud credential files": three AWS paths and 15 readers.
- "Tested live" for hosts: the docs themselves list `v0.6.0 as a whole (re-run T3 before the release)` as pending, and the managed-install settings keys are "not yet tested live" while a managed install is called "the guarantee".
- The state-surgery row and the "swaps what will run" claim, for any program not in a table; the plan check-then-apply window (documented from round 11 on).
- Cost understated: ordinary git blocked and unapprovable, the cross-directory asks, and about a third of real agent calls asking in a protected directory.

## Recommendation

1. **Restate the promise** (needs your decision; see below). Proposed text: *applygate is a pre-execution reviewer for coding-agent shell, file and MCP calls. In a protected environment it allows only commands it recognizes in a narrow, fully understood form and asks or blocks everything else. It catches mistakes and most injected instructions; a determined agent with your credentials can still cause damage. Protection that holds regardless of the hook comes from plan-only credentials, a gated apply and remote versioned state, which `applygate doctor` verifies.* Publish assurance levels: L0 hook only; L1 plus a managed, exclusive install; L2 plus verified agent credentials with no write path; L3 plus a host sandbox and a CI apply path.
2. **Close the quick gaps found in the review.** Treat any non-GET/HEAD `curl`, `wget`, `gh` or `httpie` call as not plain in a protected tier (the HCP Terraform POST), and add the missing "Not done" facts to the docs.
3. **Replace the deny-list shapes and the writer tables with one positive per-call grammar,** in the order the allow-list review proposed: writers and output-capable programs; the redirect, builtin, `cd`, assignment and wrapper grammars; `git` and the cloud CLI verbs; the Terraform option table. Keep `make`, build tools and interpreters asking in protected tiers. Add a per-entry conformance test (run each entry under a tracer with a canary config). Expected cost: no worse than today on the trial, about 13% more asks on benign controls.
4. **Build the boundary contract:** `doctor --boundary` (state-bucket actions, the assume-role chain, credential files readable by the agent's user, sandbox settings, branch protection, an environment-pinned OIDC trust), a ready-to-use kit under `examples/boundary/`, and a verified boundary allowed to relax strict shapes (so the asks fall where the damage is bounded). Fix the `credentials.md` MFA example for IAM Identity Center, which may not behave as shown.
5. **Add an effects oracle to testing:** generate commands, run them under real bash, zsh and dash against fake `terraform` and `aws` binaries that log their argv, directory and file writes, and treat an allowed run that destroyed, applied unreviewed or wrote state as a failure. This replaces the AI reviewers as the only discovery mechanism.
6. **Fix tracking at its root** (the 10 criticals no allow-list reaches): per-invocation provenance of unknowns, every recovered panic fails closed, provider and module execution scans by positive rule.
7. **Cut or label what has not been verified:** the seven hosts not run live, the MCP translation tables, the judge and one-time approvals are not part of a security claim.
8. **Exit criterion for review rounds,** replacing "a round with fewer criticals": two consecutive rounds with no class-1 or class-2 critical where the reviewers are not told the family list, plus one external human review and the effects oracle running in CI.

Not covered by any of this: a swap between the hook's verdict and the execution, Codex failing open, and anything that never passes through the hook.

## Decisions for the owner

- Whether the headline promise becomes the conditional one above. The earlier direction was to keep the full adversarial promise and not narrow it. The reviewers read the evidence as saying the full promise cannot be kept by the parser; stating that is not narrowing what is caught, but it does change what the README says.
- Whether the allow-list rewrite (3) or the boundary contract (4) goes first. They are independent; the contract changes the claim sooner, the rewrite closes the finding family.
- Whether `doctor --boundary` may be required (exit non-zero below a declared level) for enforce mode in a protected tier.
