# v0.6.0 round-5 fix plan

This plan fixes the findings of [red-team round 5](2026-11-03-red-team-round-5.md). On 2026-11-03 the user accepted all three of the report's recommendations:

1. **Exact shapes instead of a plain-program list.** Each program on strict shapes' table has a shape: the subcommands and options known not to run another program, or any arguments for a program with no such option. A call outside its shape asks in protected tiers. The cost was to be measured on the agent trial before the decision was final.
2. **Repository state that runs code.** A git command is plain only when its repository has no hooks and no command-running keys in its config; writing either is not plain.
3. **The bounded criticals 5C2, 5C7, 5C8 and 5C9,** with the highs that share their causes.

## Milestones

| Milestone | Covers | Done when |
|---|---|---|
| R5-0 | Attack-pack scenarios for 5C1 to 5C6, 5C8, 5C9, 5H1 to 5H4, 5H9 to 5H12, and benign controls | each fails on the round-4 build and passes after the fixes |
| R5-1 | Exact shapes (`internal/shell/shapes.go`), the variable safe list, recipes checked | 5C1, 5C3, 5C5, 5C6, 5H1 to 5H3 pass; the agent-trial cost is measured |
| R5-2 | Repository git state and writes into a git directory | 5C4 passes |
| R5-3 | `cd` to a missing directory (5C2), parse the hashed bytes (5C7), MCP directories (5C8) and saved plans (5C9) resolved physically | the C findings pass |
| R5-4 | Guard paths for skills, MCP lists and program configs; PATH plants; agent CLI subcommands; `aws` through `plan_gate.engines`; the plugin launcher; no home directory; the nesting guard; unknown-directory relative paths; the MCP walk; full paths for `sudo`; ancestor checks (5H4, 5H5, 5H7 to 5H15) | the listed highs pass |
| Round 6 | A blind red-team round on the same guarantee | no critical finding |

## Measured cost

- **Exact shapes:** on the agent trial's 162 real calls, replayed in the fixture's protected directory, the build with exact shapes and the git state rule asks about 29, the same as the round-4 build. The first draft asked about 4 more: each set a lower-case shell variable (`d=/tmp/…`), which is now local and plain.
- **With every fix:** the replay asks about 7 more in the protected directory. All 7 `cd` into `/work/…`, which exists on the trial machine but not on the one replaying, so the `cd` fix leaves the directory unknown and the git state cannot be checked. On the trial's own machine they would not ask. In the standard and disposable directories nothing new asks or blocks.
- **Latency:** p95 8.3 ms on a normal build (round 4: about 6.5 ms).
- **5C7:** the reviewer's swapping script got an untrusted config read in 91 of 300 checks on the round-4 build, and in none on this one.

## Left open

- **5H6,** a trusted nested config that becomes the repository's when the outer one is removed: trust would have to record a file's place in the chain. Documented in `docs/limits.md`.
- **R3-2,** widening an already-public resource policy on an update.
- **Mediums and lows not listed above:** the judge filter's `tar -P` and `go -C … run` (R4-4, R4-5), redaction misses (R5-8), `install.sh` and a symlinked archive member (R5-9), the step-summary fence (R5-10), the uncapped deny reason (R5-11), the release job's Go cache (R5-12), and the R2-11 group.
