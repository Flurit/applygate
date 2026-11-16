#!/usr/bin/env bash
# Posts the comment scripts/ci-plan-check.sh wrote on a pull request, or
# updates the one an earlier run posted for the same plan. Used by action.yml.
# It never fails the job: when it cannot comment it says why and exits 0.
#   COMMENT_FILE       the Markdown plan-check wrote
#   CHECK_OUTCOME      "skipped" when the plan-check step did not run (applygate was not
#                      installed): a comment an earlier run wrote is then changed to say
#                      the plan was not judged
#   PR_NUMBER          the pull request (empty when the run is not for one)
#   PR_HEAD_REPO       owner/name the pull request comes from (to explain a refusal)
#   GH_TOKEN           a token with pull-requests: write
#   WORKDIR, PLAN, COMMENT_KEY, COMMENT_SCOPE   as for ci-plan-check.sh
#   GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_WORKFLOW, GITHUB_JOB, GITHUB_RUN_ID,
#   GITHUB_RUN_ATTEMPT, GITHUB_WORKSPACE        as GitHub Actions sets them
#
# Which comment. The first line of a comment is a hidden marker, a hash of
# what was judged (COMMENT_KEY, or WORKDIR and PLAN) and of who judged it (the
# workflow, the job, COMMENT_SCOPE and TF_WORKSPACE). Everything in it comes
# from the workflow and its inputs, none of it from the working directory, so
# a run that fails early finds the comment a run that passed wrote. Only a
# comment this workflow's own token wrote (github-actions[bot]) is updated: a
# comment someone else starts with the marker is not taken for it.
#
# Whose verdict stays. The second line records the run that wrote the comment
# and its verdict. A comment written by a later run is left alone, so a slow
# run for an older commit cannot put its verdict over a newer one. When the
# comment was written earlier in this same run, two steps share it (same job,
# directory and plan): the more severe verdict stays, and a notice names
# comment-key. A comment that exists twice (two runs posted at once) is
# updated in both places.
#
# The body goes to gh as a file and is never part of a command line.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/ci-comment-key.sh"
file=${COMMENT_FILE:-}
body=""
errf=""
cleanup() {
    [ -n "$file" ] && rm -f "$file"
    [ -n "$body" ] && rm -f "$body"
    [ -n "$errf" ] && rm -f "$errf"
    return 0
}
skip() {
    echo "applygate: no pull-request comment: $1"
    cleanup
    exit 0
}
# unable MESSAGE DETAIL: the comment was asked for and could not be written.
unable() {
    echo "::notice title=applygate plan check::The pull-request comment was not written: $1"
    [ -n "$2" ] && printf 'applygate: gh said: %s\n' "$(printf '%s' "$2" | LC_ALL=C tr -d '\000-\037\177' | head -c 500)"
    cleanup
    exit 0
}

pr=${PR_NUMBER:-}
[ -n "$pr" ] || skip "this run is not for a pull request"
[[ "$pr" =~ ^[0-9]+$ ]] || skip "the pull request number is not a number"
repo=${GITHUB_REPOSITORY:-}
[[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || skip "GITHUB_REPOSITORY is not owner/name"

# What to post: the file plan-check wrote, whose first line gives the verdict.
# When the plan-check step did not run at all, applygate was not installed
# (a failed download or signature check): the comment says the plan was not
# judged, in fixed words. A step that ran and wrote nothing has said why.
verdict=""
if [ -n "$file" ] && [ -s "$file" ]; then
    [[ "$(head -n 1 "$file")" =~ ^'### applygate plan check: '.*' '(allow|ask|block|error)$ ]] || skip "the comment file is not one plan-check wrote"
    verdict=${BASH_REMATCH[1]}
elif [ "${CHECK_OUTCOME:-}" = skipped ]; then
    verdict=error
else
    skip "plan-check wrote none (see the plan-check step)"
fi

command -v gh > /dev/null || unable "the gh command is not on this runner." ""
[ -n "${GH_TOKEN:-}" ] || unable "the step has no token." ""

sha256() {
    if command -v sha256sum > /dev/null; then
        sha256sum
    elif command -v shasum > /dev/null; then
        shasum -a 256
    else
        openssl dgst -sha256 -r
    fi
}
scope="${GITHUB_WORKFLOW:-}"$'\n'"${GITHUB_JOB:-}"$'\n'"${COMMENT_SCOPE:-}"$'\n'"${TF_WORKSPACE:-}"
id=$(printf '%s\0%s' "$(comment_key)" "$scope" | sha256 2> /dev/null | cut -c1-16)
[[ "$id" =~ ^[0-9a-f]{16}$ ]] || unable "this runner has no sha256sum, shasum or openssl to name the comment with." ""
marker="<!-- applygate:plan-check $id -->"
run=${GITHUB_RUN_ID:-0}
attempt=${GITHUB_RUN_ATTEMPT:-0}
[[ "$run" =~ ^[0-9]{1,18}$ ]] || run=0
[[ "$attempt" =~ ^[0-9]{1,9}$ ]] || attempt=0

tmpdir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
body=$(mktemp "$tmpdir/applygate-comment.XXXXXXXX") && errf=$(mktemp "$tmpdir/applygate-gh.XXXXXXXX") || unable "a temporary file could not be created." ""
{
    echo "$marker"
    echo "<!-- applygate:run $run $attempt $verdict -->"
    if [ -n "$file" ] && [ -s "$file" ]; then
        cat "$file"
    else
        printf '%s\n\n' '### applygate plan check: ❌ error'
        printf '%s\n\n' 'applygate was not installed or could not start, so this plan was not judged. The check fails closed; the job log says why.'
        printf '%s\n' '<sub>applygate · this comment is updated on each run</sub>'
    fi
} > "$body"

host=${GITHUB_SERVER_URL:-https://github.com}
host=${host#*://}
host=${host%%/*}
if [ "$host" != github.com ]; then
    export GH_HOST=$host GH_ENTERPRISE_TOKEN=$GH_TOKEN
fi

why="GitHub refused the request. If the error below is a 403 or a 404, give the job 'permissions: pull-requests: write'."
if [ -n "${PR_HEAD_REPO:-}" ] && [ "$PR_HEAD_REPO" != "$repo" ]; then
    why="GitHub refused the request. The pull request comes from a fork, and GitHub gives its workflow runs a read-only token."
fi

# One line per comment that is ours: its id, then its second line. The marker
# is 16 hex digits between fixed words (checked above), so it is safe inside
# the jq program. gh's stderr is kept apart: a warning it prints on a call
# that worked must not be read as a comment.
jq='.[] | select(.user.login == "github-actions[bot]" and ((.body // "") | startswith("'"$marker"'"))) | "\(.id) \(((.body // "") | split("\n") | .[1] // "") | gsub("\r"; ""))"'
if ! found=$(gh api --paginate "repos/$repo/issues/$pr/comments?per_page=100" --jq "$jq" 2> "$errf"); then
    unable "$why" "$(cat "$errf")"
fi

rank() {
    case "$1" in block) echo 3 ;; error) echo 2 ;; ask) echo 1 ;; *) echo 0 ;; esac
}
ids=()
newer=""
shared=""
shared_rank=-1
while IFS= read -r line; do
    [[ "$line" =~ ^([0-9]+)(' '(.*))?$ ]] || continue
    ids+=("${BASH_REMATCH[1]}")
    meta=${BASH_REMATCH[3]:-}
    # A comment without the line (edited, or from before it existed) is from no run.
    [[ "$meta" =~ ^'<!-- applygate:run '([0-9]{1,18})' '([0-9]{1,9})' '(allow|ask|block|error)' -->'$ ]] || continue
    r=$((10#${BASH_REMATCH[1]}))
    a=$((10#${BASH_REMATCH[2]}))
    v=${BASH_REMATCH[3]}
    if [ "$run" = 0 ]; then
        continue
    elif [ "$r" -gt "$run" ] || { [ "$r" -eq "$run" ] && [ "$a" -gt "$attempt" ]; }; then
        newer=$r
    elif [ "$r" -eq "$run" ] && [ "$a" -eq "$attempt" ]; then
        shared=$v
        [ "$(rank "$v")" -gt "$shared_rank" ] && shared_rank=$(rank "$v")
    fi
done <<< "$found"

if [ "${#ids[@]}" -eq 0 ]; then
    if [ ! -s "${file:-/nonexistent}" ]; then
        # Nothing was judged and no comment says otherwise. Posting one would
        # leave an error that a release without comments could never clear.
        skip "applygate was not installed, and there is no earlier comment to correct"
    fi
    if ! gh api --silent --method POST "repos/$repo/issues/$pr/comments" -F "body=@$body" > /dev/null 2> "$errf"; then
        unable "$why" "$(cat "$errf")"
    fi
    echo "applygate: posted the plan-check comment on pull request #$pr"
    cleanup
    exit 0
fi
if [ -n "$newer" ]; then
    echo "applygate: the plan-check comment on pull request #$pr was written by a later run ($newer) than this one ($run); it is left as it is"
    cleanup
    exit 0
fi
if [ -n "$shared" ]; then
    echo "::notice title=applygate plan check::Two steps of this workflow run write the same pull-request comment (same workflow, job, working-directory and plan). The comment shows the more severe of their verdicts; give each step its own comment-key to get a comment for each."
    if [ "$(rank "$verdict")" -le "$shared_rank" ]; then
        echo "applygate: the plan-check comment on pull request #$pr keeps the verdict of the other step ($shared); this step's is $verdict"
        cleanup
        exit 0
    fi
fi
for cid in "${ids[@]}"; do
    if ! gh api --silent --method PATCH "repos/$repo/issues/comments/$cid" -F "body=@$body" > /dev/null 2> "$errf"; then
        unable "$why" "$(cat "$errf")"
    fi
done
if [ "${#ids[@]}" -gt 1 ]; then
    echo "applygate: updated the plan-check comment on pull request #$pr (it exists ${#ids[@]} times; all were updated)"
else
    echo "applygate: updated the plan-check comment on pull request #$pr"
fi
cleanup
exit 0
