#!/bin/sh
# applygate model judge, command backend: asks OpenAI's Decisions API
# (gpt-6-luna) a set of yes/no questions about the call
# (decision-questions.json) and applies applygate's tier table to the answers
# (decision-verdict.jq), so the model states facts and the table decides.
# Needs curl and jq on PATH and a key in OPENAI_API_KEY.
#
#   judge:
#     enabled: true
#     backend: command
#     command: ["sh", "/path/to/openai-decisions-facts.sh"]
#
# applygate writes one request as JSON on stdin ({"system", "prompt",
# "schema", "call"}); this prints {"verdict": ..., "reason": ...}. The reason
# lists each answer's probability; a question the model refuses counts as
# yes. An API error is reported with the provider's message.
set -eu
: "${OPENAI_API_KEY:?OPENAI_API_KEY is not set}"
dir=$(cd "$(dirname "$0")" && pwd)
model=${APPLYGATE_JUDGE_MODEL:-gpt-6-luna}
url=${APPLYGATE_JUDGE_URL:-https://api.openai.com/v1/decisions}
# Thresholds per fact (default 0.5), tuned on experiments/model-judge sets 1-4
# and the author's sets; APPLYGATE_DECISION_THRESHOLDS (JSON) replaces them.
t=${APPLYGATE_DECISION_THRESHOLDS:-}
[ -n "$t" ] || t='{"destroys":0.3,"bulk":0.3,"changes_remote":0.95,"iac_apply":0.9,"weakens_guard":0.8}'
req=$(cat)
tier=$(printf '%s' "$req" | jq -r '.call.tier // ""')
printf '%s' "$req" | jq -c --arg model "$model" --slurpfile q "$dir/decision-questions.json" '
	$q[0] as $q | .call | {
		model: $model,
		input: ({tool, command, paths, content, arguments} | with_entries(select(.value != null)) | tojson),
		questions: [$q.questions | to_entries[] | {type: "predicate", name: .key, instructions: ($q.preamble + " " + .value)}]
	}' |
	curl -sS --max-time 25 "$url" \
		-H @/dev/fd/3 -H 'Content-Type: application/json' --data-binary @- 3<<EOF |
Authorization: Bearer $OPENAI_API_KEY
EOF
	jq -c --arg model "$model" --arg tier "$tier" '
		if .error or .detail then error("\(.error.message // .detail | tostring)") else . end |
		{model: $model, tier: $tier, facts: ([.answers // error("no answers") | .[] | {key: .name, value: (if .type == "refusal" then null else .probability end)}] | from_entries)}' |
	jq -ce --argjson t "$t" -f "$dir/decision-verdict.jq"
