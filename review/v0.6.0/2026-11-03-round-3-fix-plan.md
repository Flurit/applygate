# v0.6.0 round-3 fix plan

This plan fixes the findings of [red-team round 3](2026-11-03-red-team-round-3.md). On 2026-11-03 the user accepted all three of the report's recommendations:

1. **Managed mode and the user config (3S2).** Under a managed install the user config may only tighten, like a repository config. Loosening comes from the root-owned system config only.
2. **Reading HCL (3T1).** Backend blocks are parsed with HashiCorp's `hcl/v2` parser. A parse failure is an unknown backend, so protected.
3. **Shell start-up and lookup state (3C1 to 3C5).** These are handled like guard files.
   - A shell started with `BASH_ENV`, `ENV` or `ZDOTDIR` set sources that file, or is unresolved.
   - `CDPATH`, `cdable_vars`, `hash -p` and a `command_not_found_handle` make later directory or program resolution unknown, unless the analyzer can follow them exactly.
   - A tilde form other than `~` and `~/…` makes the directory unknown.

## Milestones

| Milestone | Covers | Done when |
|---|---|---|
| R3-0 | A failing test for every finding that can be expressed as one; `reviewgap` lists them | the open list equals the reproduced findings |
| R3-1 | Trust, managed mode and guard paths: 3S1 to 3S10, 3T2 | the S findings pass; trust in CI is documented |
| R3-2 | The shell (3C1 to 3C8), the HCL parser (3T1) and plan actions (3T3) | the C and T findings pass |
| R3-3 | MCP and the judge (3M1 to 3M3), the log and redaction (3D1 to 3D5), docs (3D6 to 3D12) | the M and D findings pass; docs match |
| Round 4 | A blind red-team round, briefed the same way | no critical finding |
