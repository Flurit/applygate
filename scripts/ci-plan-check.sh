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
    # A private temp file: the plan JSON holds values, and a predictable
    # name could be created by someone else first.
    json=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/applygate-plan.XXXXXXXX") || { echo "cannot create a temp file" >&2; exit 2; }
    chmod 600 "$json"
    "$tf" show -json "$plan" > "$json" || { rm -f "$json"; echo "$tf show -json failed on $plan" >&2; exit 2; }
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

# The output quotes the plan (resource addresses, values), which whoever
# wrote the configuration controls: drop control characters other than
# newline and tab, and end the multi-line output with a random delimiter
# that the text cannot contain, so it cannot add outputs of its own.
out=$(printf '%s' "$out" | LC_ALL=C tr -d '\000-\010\013-\037\177')
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    # Workflow commands (::add-mask::, ::error::) in the plan text must not
    # run: the runner ignores them between stop-commands markers.
    stop="applygate-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    echo "::stop-commands::$stop"
    printf '%s\n' "$out"
    echo "::$stop::"
else
    printf '%s\n' "$out"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    delim="APPLYGATE_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    while printf '%s' "$out" | grep -qF "$delim"; do
        delim="APPLYGATE_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    done
    {
        echo "verdict=$verdict"
        echo "exit-code=$code"
        echo "summary<<$delim"
        printf '%s\n' "$out"
        echo "$delim"
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
