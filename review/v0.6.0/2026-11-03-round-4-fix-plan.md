# v0.6.0 round-4 fix plan

This plan fixes the findings of [red-team round 4](2026-11-03-red-team-round-4.md). On 2026-11-03 the user accepted all three of the report's recommendations:

1. **The managed install is the only documented guarantee.** Without it, self-protection is best-effort: the hook blocks the routes it knows, and the docs no longer claim more. The fixes go to the parts a managed install still shares with the agent's user: the state directory (approvals and the log) and the programs the hook runs from `PATH`.
2. **Strict shapes are on in protected tiers.** A shell command in a protected directory runs without asking only when it is a plain list or pipeline of programs on a known list. Anything else (functions, substitutions, arithmetic, loops, shells, interpreters, wrappers outside the list) asks. Standard and disposable tiers are not changed. The measured cost is about 16% of real agent calls in protected directories.
3. **The bounded criticals 4T1 to 4T4 and 4M1 are fixed,** with the highs that share their causes: 4H1, 4H3, 4H9 to 4H15 and 4H26.

The self-protection criticals (4S1 to 4S10) are covered by decision 1: under a managed install the agent's user cannot write the guard, and without one they are documented as best-effort. The shell criticals (4C1 to 4C4) are covered by decision 2.

## Milestones

| Milestone | Covers | Done when |
|---|---|---|
| R4-0 | Attack-pack scenarios for 4C1 to 4C4, 4T1, 4T3, 4T4, 4M1, 4H1 and 4H26; `reviewgap` lists the open ones | the open list equals the reproduced findings |
| R4-1 | Strict shapes (`strict_shapes`, on by default; asks in protected tiers only) | 4C1 to 4C4 pass; the benign cost is measured and documented |
| R4-2 | Tiers: `-backend-config` files read as HCL or JSON, and unknown when written in the same command or missing (4T3, 4T4, 4H9); `..` resolved after symlinks (4T1, 4T2); state paths, profiles and Terragrunt sources (4H10 to 4H15, 4H26) | the T findings and the listed highs pass |
| R4-3 | MCP: a server-split command is split the way the server splits it (4M1) | 4M1 passes |
| R4-4 | The managed guarantee: engines on `PATH` (4H1), the verdict within the deadline (4H3), redaction before the cut, the judge setting under managed mode, `sudo` in the trust hint; the docs say what is guaranteed and what is best-effort | the docs match; the listed highs pass |
| Round 5 | A blind red-team round, briefed on managed mode and strict shapes | no critical finding |
