# Migrating from seatbelt

This project was called seatbelt until 2026-10-29. The word already names Apple's macOS sandbox in the Claude Code and Codex documentation, and other agent-guardrail products use it, so the name was confusing for exactly the people this tool is for. v0.2.0 was the first release as applygate. For an existing install:

- the repository config is `.applygate.yaml` (a `.seatbelt.yaml` is still read, with a note from `doctor`; rename it);
- hook entries become `applygate hook claude` / `applygate hook codex` (`applygate hook install` rewrites them; the `seatbelt` compatibility binary shipped with v0.2 to v0.5 and is gone in v0.6.0, so run `applygate hook install` before upgrading; `applygate doctor` flags a hook entry that still calls it);
- the user config and the decision log move to `~/.config/applygate/` and `~/.local/state/applygate/` (existing files at the old paths are used until a new one exists);
- installer variables are `APPLYGATE_VERSION`, `APPLYGATE_INSTALL_DIR` and `APPLYGATE_VERIFY_SIGNATURE` (the `SEATBELT_*` names were honoured until v0.5; v0.6.0 reads only the `APPLYGATE_*` names).

Release tags v0.1.0 to v0.1.4 and the records under `docs/project/` and `review/` keep the old name where they describe those builds.
