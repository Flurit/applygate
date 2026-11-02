#!/bin/sh
# applygate model judge, command backend: asks TypeSafe AI's Jev a set of
# yes/no questions about the call (decision-questions.json) and applies
# applygate's tier table to the answers (decision-verdict.jq), so the model
# states facts and the table decides. Needs curl and jq on PATH and a key in
# TYPESAFE_API_KEY.
#
#   judge:
#     enabled: true
#     backend: command
#     command: ["sh", "/path/to/experiments/model-judge/decision-facts/jev-facts.sh"]
#
# applygate writes one request as JSON on stdin ({"system", "prompt",
# "schema", "call"}); this prints {"verdict": ..., "reason": ...}. The reason
# lists each answer's probability. An API error is reported with the
# provider's message.
set -eu
: "${TYPESAFE_API_KEY:?TYPESAFE_API_KEY is not set}"
dir=$(cd "$(dirname "$0")" && pwd)
model=${APPLYGATE_JUDGE_MODEL:-jev-latest}
url=${APPLYGATE_JUDGE_URL:-https://api.typesafe.ai/v1/systemone}
# Thresholds per fact (default 0.5), tuned on the experiment's sets 1-4
# and the author's sets; APPLYGATE_DECISION_THRESHOLDS (JSON) replaces them.
t=${APPLYGATE_DECISION_THRESHOLDS:-}
[ -n "$t" ] || t='{"changes_remote":0.7,"iac_apply":0.9,"prints_secret":0.7,"weakens_guard":0.6,"production_target":0.6}'
req=$(cat)
tier=$(printf '%s' "$req" | jq -r '.call.tier // ""')
printf '%s' "$req" | jq -c --arg model "$model" --slurpfile q "$dir/decision-questions.json" '
	$q[0] as $q | .call | {
		model: $model,
		state: {tool, command, paths, content, arguments} | with_entries(select(.value != null)),
		questions: ($q.questions | with_entries(.value = {type: "noul", instructions: ($q.preamble + " " + .value)}))
	}' |
	curl -sS --max-time 25 "$url" \
		-H @/dev/fd/3 -H 'Content-Type: application/json' --data-binary @- 3<<EOF |
Authorization: Bearer $TYPESAFE_API_KEY
EOF
	jq -c --arg model "$model" --arg tier "$tier" '
		if .error or .detail then error("\(.error.message // .detail | tostring)") else . end |
		{model: $model, tier: $tier, facts: (.answers // error("no answers") | with_entries(.value = .value.noul))}' |
	jq -ce --argjson t "$t" -f "$dir/decision-verdict.jq"
