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
#   COMMENT_KEY    name for what is judged; with the Terraform workspace it identifies the
#                  comment, so a later run updates it (default: WORKDIR and PLAN)
#   COMMENT_COMMIT commit the plan was made from, shown in the comment (default: none)
# Exit codes: 0 when the verdict passes FAIL_ON, 1 when it does not, 2 on an error.
# The comment never changes them: it comes from a second run of plan-check that
# only formats, and when that run fails or disagrees no comment is written.
set -euo pipefail
bin=${APPLYGATE_BIN:-applygate}
plan=${PLAN:?PLAN is required}
tier=${TIER:-}
fail_on=${FAIL_ON:-block}
workdir=${WORKDIR:-.}
tf=${TF_BIN:-terraform}
case "$fail_on" in block|ask|never) ;; *) echo "FAIL_ON must be block, ask or never, not '$fail_on'" >&2; exit 2 ;; esac

comment_file=${COMMENT_FILE:-}
case "${COMMENT:-true}" in
    true) ;;
    false) comment_file="" ;;
    *) echo "COMMENT must be true or false, not '$COMMENT'" >&2; exit 2 ;;
esac
if [ -n "$comment_file" ]; then
    case "$comment_file" in /* | [A-Za-z]:[\\/]*) ;; *) comment_file="$(pwd)/$comment_file" ;; esac
    # A file an earlier step left is not this run's verdict.
    rm -f "$comment_file"
fi
comment_key=${COMMENT_KEY:-}
if [ -z "$comment_key" ]; then
    case "$plan" in
        /*) comment_key=$plan ;;
        *) comment_key=${workdir%/}/$plan; comment_key=${comment_key#./} ;;
    esac
fi
comment_commit=${COMMENT_COMMIT:-}
[[ "$comment_commit" =~ ^[0-9a-fA-F]{7,64}$ ]] || comment_commit=""

# write_comment CODE ARGS...: writes COMMENT_FILE with plan-check's comment
# format, run with ARGS. The file is kept only when that run exits with CODE,
# the exit code of the check itself. A release without the comment format, or
# any other failure, leaves no file and a line in the log; the check's own
# result stands either way.
write_comment() {
    [ -n "$comment_file" ] || return 0
    local want=$1 rc=0 tmp="$comment_file.tmp"
    shift
    local cargs=(plan-check --format comment --comment-key "$comment_key")
    [ -n "$comment_commit" ] && cargs+=(--comment-commit "$comment_commit")
    "$bin" "${cargs[@]}" "$@" > "$tmp" 2>/dev/null || rc=$?
    if [ "$rc" = "$want" ] && [ -s "$tmp" ] && mv "$tmp" "$comment_file"; then
        return 0
    fi
    rm -f "$tmp"
    echo "applygate: no pull-request comment written: plan-check --format comment exited $rc where the check exited $want (releases up to v0.6.1 have no comment format)"
}

json=""
# die MESSAGE: an error before plan-check could run. The comment says so too:
# one that said allow for an earlier commit must not stay.
die() {
    echo "$1" >&2
    [ -n "$json" ] && [ "$json" != "$plan" ] && rm -f "$json"
    write_comment 2 --cwd . --comment-error "$1" || true
    exit 2
}

cd "$workdir"
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
out=$("$bin" "${args[@]}" "$json" 2>&1)
code=$?
set -e
write_comment "$code" "${args[@]:1}" "$json" || true
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
