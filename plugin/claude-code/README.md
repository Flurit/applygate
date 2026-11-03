# applygate as a Claude Code plugin

This directory is a Claude Code plugin that registers the applygate PreToolUse hook. A `.applygate.yaml` in the repository tells it which directories are which environment (`applygate init --no-hooks`, or write one by hand: [docs/config.md](../../docs/config.md)). Without one the defaults apply: enforce mode, strict, so every directory is judged as protected.

Try it for one session:

```bash
claude --plugin-dir plugin/claude-code
```

`--plugin-dir` loads the plugin from this checkout, which is an ordinary directory an agent can edit, so it is for trying the plugin, not for relying on it. Install it from the marketplace for that.

Install it from this repository's marketplace (`.claude-plugin/marketplace.json` at the repo root):

```bash
claude plugin marketplace add Flurit/applygate
claude plugin install applygate@applygate --scope project
```

## Where the binary comes from

The hooks run [scripts/applygate-hook](scripts/applygate-hook), which picks the first of:

0. the binary it pinned the first time it found one in 1 or 2, by path and sha256, in `pinned-binary` in its data directory. Later calls run only that file, and only while its sha256 is unchanged; a changed file blocks every call until a person removes `pinned-binary` (after an upgrade, for example);
1. `$APPLYGATE_BIN`, if set;
2. `applygate` on PATH (`install.sh`, `brew install Flurit/tap/applygate`, `go install`);
3. the release named in [scripts/pinned-release.txt](scripts/pinned-release.txt), downloaded once from GitHub, its archive checked against the sha256 in that file, and kept in the plugin's data directory (`${CLAUDE_PLUGIN_DATA}`, which survives plugin updates; `~/.cache/applygate/plugin` when Claude Code does not set it).

A `SessionStart` hook does the download, so the session's first response waits for it rather than a tool call. The sha256 values are committed in the plugin and come from the release's signed `checksums.txt` (`scripts/pin-plugin-release.sh` verifies that signature with cosign before writing them), so a download is checked against values that did not come from the download server. The plugin's version is the pinned release's version, which is what makes Claude Code pick up a new pin.

If no binary can be found (no network, an unsupported platform, a checksum mismatch), the PreToolUse hook exits 2 with the reason and the tool call is blocked. The hook also sets `onFailure: block` (Claude Code v2.1.295 or later), so a crash or a timeout blocks too. The installed plugin's files, its data directory (`$CLAUDE_PLUGIN_DATA`, and `$XDG_CACHE_HOME/applygate` when that is set) and the download cache are guard paths, and an agent that starts a nested session with other values for `APPLYGATE_BIN`, `CLAUDE_PLUGIN_DATA` or `XDG_CACHE_HOME` is blocked: an agent cannot replace the launcher, the pin or the binary by routes the hook sees. A checkout loaded with `--plugin-dir` is not guarded.

`applygate hook install --agent claude` writes an equivalent hook entry into `.claude/settings.json` without a plugin; use one or the other, not both.
