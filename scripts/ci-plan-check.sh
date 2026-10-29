#!/usr/bin/env bash
# Runs applygate plan-check in CI and turns the verdict into job outputs, a step
# summary and an exit code. Used by action.yml; works on any CI that sets the
# same environment variables:
#   APPLYGATE_BIN  path to the applygate binary (default: applygate on PATH)
#   PLAN           saved planfile or its show -json output (required)
#   TIER           protected|standard|disposable (default: resolved from config)
#   FAIL_ON        block|ask|never (default: block)
#   WORKDIR        directory the plan belongs to (default: .)
#   TF_BIN         terraform or tofu, for show -json on a planfile (default: terraform)
# Exit codes: 0 when the verdict passes FAIL_ON, 1 when it does not, 2 on an error.
set -euo pipefail
bin=${APPLYGATE_BIN:-applygate}
plan=${PLAN:?PLAN is required}
tier=${TIER:-}
fail_on=${FAIL_ON:-block}
workdir=${WORKDIR:-.}
tf=${TF_BIN:-terraform}
case "$fail_on" in block|ask|never) ;; *) echo "FAIL_ON must be block, ask or never, not '$fail_on'" >&2; exit 2 ;; esac

cd "$workdir"
[ -f "$plan" ] || { echo "plan file not found: $plan (in $(pwd))" >&2; exit 2; }
json=$plan
# A saved planfile is a zip; its JSON is produced by show -json.
if [ "$(head -c1 "$plan")" != "{" ]; then
    json=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/applygate-plan.$$.json
    "$tf" show -json "$plan" > "$json" || { echo "$tf show -json failed on $plan" >&2; exit 2; }
fi

set +e
if [ -n "$tier" ]; then
    out=$("$bin" plan-check --cwd . --tier "$tier" "$json" 2>&1)
else
    out=$("$bin" plan-check --cwd . "$json" 2>&1)
fi
code=$?
set -e
[ "$json" != "$plan" ] && rm -f "$json"

case "$code" in
    0) verdict=allow ;;
    4) verdict=ask ;;
    3) verdict=block ;;
    *) verdict=error ;;
esac

printf '%s\n' "$out"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "verdict=$verdict"
        echo "exit-code=$code"
        echo "summary<<APPLYGATE_EOF"
        printf '%s\n' "$out"
        echo "APPLYGATE_EOF"
    } >> "$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### applygate plan-check: $verdict"
        echo
        echo '```'
        printf '%s\n' "$out"
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi

[ "$verdict" = error ] && exit 2
case "$fail_on:$verdict" in
    never:*) exit 0 ;;
    block:block) exit 1 ;;
    ask:block|ask:ask) exit 1 ;;
    *) exit 0 ;;
esac
