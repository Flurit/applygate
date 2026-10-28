# seatbelt as a Claude Code plugin

This directory is a Claude Code plugin that registers the seatbelt PreToolUse hook. It carries no binary: install `seatbelt` first (`install.sh` or `go install github.com/Flurit/seatbelt/cmd/seatbelt@latest`) and write a `.seatbelt.yaml` in the repository (`seatbelt init --no-hooks`).

Try it for one session:

```bash
claude --plugin-dir plugin/claude-code
```

Install it from this repository's marketplace (`.claude-plugin/marketplace.json` at the repo root):

```bash
claude plugin marketplace add Flurit/seatbelt
claude plugin install seatbelt@seatbelt --scope project
```

The hook sets `onFailure: block` (Claude Code v2.1.295 or later) so a missing or crashed binary blocks the tool call instead of failing open. `seatbelt hook install --agent claude` writes the same entry into `.claude/settings.json` without a plugin; use one or the other, not both.
