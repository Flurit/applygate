#!/bin/sh
# applygate model judge, command backend: asks OpenAI's Decisions API
# (gpt-6-luna), a decision model. Needs curl and jq on PATH and a key in
# OPENAI_API_KEY.
#
#   judge:
#     enabled: true
#     backend: command
#     command: ["sh", "/path/to/openai-decisions.sh"]
#
# applygate writes one request as JSON on stdin ({"system", "prompt",
# "schema", "call"}); this prints {"verdict": ..., "reason": ...}. The judge's
# instructions become one choice question about the call. The API returns a
# probability per verdict and no explanation, so the reason lists them. An API
# error is an error, reported with its message, which leaves the rule
# decision. A refusal prints a reason without a verdict, which applygate asks
# about outside a disposable environment.
set -eu
: "${OPENAI_API_KEY:?OPENAI_API_KEY is not set}"
model=${APPLYGATE_JUDGE_MODEL:-gpt-6-luna}
url=${APPLYGATE_JUDGE_URL:-https://api.openai.com/v1/decisions}
jq -c --arg model "$model" '{
	model: $model,
	input: .prompt,
	questions: [{
		type: "choice",
		name: "verdict",
		instructions: .system,
		choices: [
			{value: "allow", description: "The call goes ahead without a person."},
			{value: "ask", description: "A person confirms the call before it runs."},
			{value: "block", description: "The call is stopped."}
		]
	}]
}' |
	curl -q -sS --max-time 25 "$url" \
		-H @/dev/fd/3 -H 'Content-Type: application/json' --data-binary @- 3<<EOF |
Authorization: Bearer $OPENAI_API_KEY
EOF
	jq -ce --arg model "$model" 'if .error or .detail then error("\(.error.message // .detail | tostring)") else . end |
		.answers[0] as $a |
		if $a.type != "choice" then {reason: "\($model) gave no answer (\($a.type))"} else
		($a.probabilities | map({key: .value, value: .probability}) | from_entries) as $p |
		{verdict: $a.choice, reason: ("\($model) chose \($a.choice) (allow \($p.allow), ask \($p.ask), block \($p.block)); a decision model gives no explanation.")} end'
