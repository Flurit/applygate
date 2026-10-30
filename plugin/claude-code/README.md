# applygate as a Claude Code plugin

This directory is a Claude Code plugin that registers the applygate PreToolUse hook. It needs a `.applygate.yaml` in the repository (`applygate init --no-hooks`, or write one by hand: [docs/config.md](../../docs/config.md)).

Try it for one session:

```bash
claude --plugin-dir plugin/claude-code
```

Install it from this repository's marketplace (`.claude-plugin/marketplace.json` at the repo root):

```bash
claude plugin marketplace add Flurit/applygate
claude plugin install applygate@applygate --scope project
```

## Where the binary comes from

The hooks run [scripts/applygate-hook](scripts/applygate-hook), which picks the first of:

1. `$APPLYGATE_BIN`, if set;
2. `applygate` on PATH (`install.sh`, `brew install Flurit/tap/applygate`, `go install`);
3. the release named in [scripts/pinned-release.txt](scripts/pinned-release.txt), downloaded once from GitHub, its archive checked against the sha256 in that file, and kept in the plugin's data directory (`${CLAUDE_PLUGIN_DATA}`, which survives plugin updates; `~/.cache/applygate/plugin` when Claude Code does not set it).

A `SessionStart` hook does the download, so the session's first response waits for it rather than a tool call. The sha256 values are committed in the plugin and come from the release's signed `checksums.txt` (`scripts/pin-plugin-release.sh` verifies that signature with cosign before writing them), so a download is checked against values that did not come from the download server. The plugin's version is the pinned release's version, which is what makes Claude Code pick up a new pin.

If no binary can be found (no network, an unsupported platform, a checksum mismatch), the PreToolUse hook exits 2 with the reason and the tool call is blocked. The hook also sets `onFailure: block` (Claude Code v2.1.295 or later), so a crash or a timeout blocks too. The plugin's files, its data directory and the download cache are guard paths: an agent cannot replace the launcher or the binary.

`applygate hook install --agent claude` writes an equivalent hook entry into `.claude/settings.json` without a plugin; use one or the other, not both.
