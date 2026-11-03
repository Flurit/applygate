#!/bin/sh
# applygate model judge, command backend: asks Claude through the claude
# CLI's own login, so no API key is needed. Needs claude and jq on PATH.
#
#   judge:
#     enabled: true
#     backend: command
#     command: ["sh", "/path/to/claude-cli.sh"]
#
# applygate writes one request as JSON on stdin ({"system", "prompt",
# "schema", "call"}); this prints {"verdict": ..., "reason": ...}.
#
# claude runs from an empty temporary directory with only the user's
# settings, so the agent's repository (its CLAUDE.md, settings and hooks)
# does not reach the judge. A refusal prints a reason without a verdict, which
# applygate asks about outside a disposable environment, rather than failing,
# which would leave the rule decision.
set -eu
req=$(cat)
system=$(printf '%s' "$req" | jq -r .system)
schema=$(printf '%s' "$req" | jq -c .schema)
tmp=$(mktemp -d)
trap 'rmdir "$tmp"' EXIT
cd "$tmp"
printf '%s' "$req" | jq -r .prompt |
	claude -p --model "${APPLYGATE_JUDGE_MODEL:-claude-haiku-5-5}" --effort low \
		--system-prompt "$system" --tools "" --json-schema "$schema" \
		--setting-sources user --output-format json --no-session-persistence |
	jq -c '.structured_output // {reason: ("no verdict: " + (.result // "no structured answer" | tostring))}'
