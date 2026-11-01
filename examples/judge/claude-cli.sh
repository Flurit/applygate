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
set -eu
req=$(cat)
system=$(printf '%s' "$req" | jq -r .system)
schema=$(printf '%s' "$req" | jq -c .schema)
printf '%s' "$req" | jq -r .prompt |
	claude -p --model "${APPLYGATE_JUDGE_MODEL:-claude-haiku-5-5}" --effort low \
		--system-prompt "$system" --tools "" --json-schema "$schema" \
		--output-format json --no-session-persistence |
	jq -ce '.structured_output // error("no structured answer")'
