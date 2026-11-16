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
#   TRUST_CONFIG   true to read the repository config without a trust record (default: false)
#   COMMENT_FILE   file to write the verdict to as the Markdown of a pull-request comment
#                  (default: none). scripts/ci-pr-comment.sh posts it on GitHub; on another
#                  CI, post the file yourself.
#   COMMENT        false to write no comment although COMMENT_FILE is set (default: true)
#   COMMENT_KEY    name the comment shows for what was judged (default: WORKDIR and PLAN,
#                  relative to GITHUB_WORKSPACE)
#   COMMENT_COMMIT commit the plan was made from, shown in the comment (default: none)
#   COMMENT_SCOPE  what tells this job from others of its name, such as its matrix values;
#                  shown in the comment after the workflow and job (default: none)
# Exit codes: 0 when the verdict passes FAIL_ON, 1 when it does not, 2 on an error.
# The comment never changes them. plan-check runs once: with --comment-file it
# writes the comment beside the output it always printed. A release without
# that flag (v0.6.1 and before) is run as before, without a comment.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/ci-comment-key.sh"
bin=${APPLYGATE_BIN:-applygate}
plan=${PLAN:-}
tier=${TIER:-}
fail_on=${FAIL_ON:-block}
workdir=${WORKDIR:-.}
tf=${TF_BIN:-terraform}

comment_file=${COMMENT_FILE:-}
case "${COMMENT:-true}" in
    true) ;;
    false) comment_file="" ;;
    *) echo "COMMENT must be true or false, not '$COMMENT'" >&2; exit 2 ;;
esac
# The arguments that make plan-check write the comment; none when no comment
# is asked for or this applygate cannot write one.
cargs=()
if [ -n "$comment_file" ]; then
    case "$comment_file" in /* | [A-Za-z]:[\\/]*) ;; *) comment_file="$(pwd)/$comment_file" ;; esac
    # A file an earlier step left is not this run's verdict.
    rm -f "$comment_file"
    help=$("$bin" plan-check -h 2>&1 || true)
    case "$help" in
        *-comment-file*)
            cargs=(--comment-file "$comment_file" --comment-key "$(comment_key)")
            if [[ "${COMMENT_COMMIT:-}" =~ ^[0-9a-fA-F]{7,64}$ ]]; then
                cargs+=(--comment-commit "$COMMENT_COMMIT")
            fi
            job=${GITHUB_WORKFLOW:-}${GITHUB_WORKFLOW:+ / }${GITHUB_JOB:-}
            case "${COMMENT_SCOPE:-}" in
                "" | null) ;;
                *) job="$job $(printf '%s' "$COMMENT_SCOPE" | tr -s ' \t\r\n' ' ')" ;;
            esac
            if [ -n "$job" ]; then
                cargs+=(--comment-job "$job")
            fi
            ;;
        *)
            echo "applygate: no pull-request comment: this applygate cannot write one (releases up to v0.6.1); the check runs as usual"
            comment_file=""
            ;;
    esac
fi

json=""
# die MESSAGE: an error before plan-check could judge the plan. The comment
# says so too: one that said allow for an earlier commit must not stay.
die() {
    echo "$1" >&2
    if [ -n "$json" ] && [ "$json" != "$plan" ]; then
        rm -f "$json"
    fi
    if [ -n "$comment_file" ]; then
        "$bin" plan-check "${cargs[@]}" --comment-error "$1" > /dev/null 2>&1 || true
    fi
    exit 2
}

case "$fail_on" in block|ask|never) ;; *) die "FAIL_ON must be block, ask or never, not '$fail_on'" ;; esac
[ -n "$plan" ] || die "PLAN is required"
cd "$workdir" 2> /dev/null || die "working directory not found: $workdir"
[ -f "$plan" ] || die "plan file not found: $plan (in $(pwd))"
json=$plan
# A saved planfile is a zip; its JSON is produced by show -json.
if [ "$(head -c1 "$plan")" != "{" ]; then
    # A private temp file: the plan JSON holds values, and a predictable
    # name could be created by someone else first.
    json=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/applygate-plan.XXXXXXXX") || { json=""; die "cannot create a temp file"; }
    chmod 600 "$json"
    "$tf" show -json "$plan" > "$json" || die "$tf show -json failed on $plan"
fi

set +e
args=(plan-check --cwd .)
[ -n "$tier" ] && args+=(--tier "$tier")
case "${TRUST_CONFIG:-false}" in
    true) args+=(--trust-config) ;;
    false | "") ;;
    *) die "TRUST_CONFIG must be true or false, not '$TRUST_CONFIG'" ;;
esac
# An empty array is an unset variable to the bash 3.2 of macOS.
out=$("$bin" "${args[@]}" ${cargs[@]+"${cargs[@]}"} "$json" 2>&1)
code=$?
set -e
[ "$json" != "$plan" ] && rm -f "$json"

case "$code" in
    0) verdict=allow ;;
    4) verdict=ask ;;
    3) verdict=block ;;
    *) verdict=error ;;
esac
# plan-check writes the comment for an error it reports itself; one it could
# not report (it was killed, or is not there) is written here.
if [ "$verdict" = error ] && [ -n "$comment_file" ] && [ ! -s "$comment_file" ]; then
    "$bin" plan-check "${cargs[@]}" --comment-error "plan-check ended with exit code $code before it gave a verdict" > /dev/null 2>&1 || true
fi
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
