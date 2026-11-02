#!/bin/sh
# applygate model judge, command backend: asks TypeSafe AI's Jev, a decision
# model, through its System One API. Needs curl and jq on PATH and a key in
# TYPESAFE_API_KEY.
#
#   judge:
#     enabled: true
#     backend: command
#     command: ["sh", "/path/to/jev.sh"]
#
# applygate writes one request as JSON on stdin ({"system", "prompt",
# "schema", "call"}); this prints {"verdict": ..., "reason": ...}. The judge's
# instructions become one choice question about the call. Jev returns a
# probability per verdict and no explanation, so the reason lists them. An
# API error is reported with the provider's message.
set -eu
: "${TYPESAFE_API_KEY:?TYPESAFE_API_KEY is not set}"
model=${APPLYGATE_JUDGE_MODEL:-jev-latest}
url=${APPLYGATE_JUDGE_URL:-https://api.typesafe.ai/v1/systemone}
jq -c --arg model "$model" '{
	model: $model,
	state: .prompt,
	questions: {verdict: {
		type: "choice",
		instructions: .system,
		criteria: {
			allow: "The call goes ahead without a person.",
			ask: "A person confirms the call before it runs.",
			block: "The call is stopped."
		}
	}}
}' |
	curl -sS --max-time 25 "$url" \
		-H @/dev/fd/3 -H 'Content-Type: application/json' --data-binary @- 3<<EOF |
Authorization: Bearer $TYPESAFE_API_KEY
EOF
	jq -ce --arg model "$model" 'if .error or .detail then error("\(.error.message // .detail | tostring)") else . end |
		.answers.verdict as $a | ($a.choice // error("no answer")) as $v |
		{verdict: $v, reason: ("\($model) chose \($v) (allow \($a.probabilities.allow), ask \($a.probabilities.ask), block \($a.probabilities.block)); a decision model gives no explanation.")}'
