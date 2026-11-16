#!/usr/bin/env bash
# Posts the comment scripts/ci-plan-check.sh wrote on a pull request, or
# updates the one an earlier run posted for the same plan. Used by action.yml.
# It never fails the job: when it cannot comment it says why and exits 0.
#   COMMENT_FILE       the Markdown; its first line is the marker a comment is found by
#   PR_NUMBER          the pull request (empty when the run is not for one)
#   PR_HEAD_REPO       owner/name the pull request comes from (to explain a refusal)
#   GH_TOKEN           a token with pull-requests: write
#   GITHUB_REPOSITORY  owner/name, as GitHub Actions sets it
#   GITHUB_SERVER_URL  as GitHub Actions sets it (GitHub Enterprise Server)
# The body goes to gh as a file and is never part of a command line. Only a
# comment this workflow's own token wrote (github-actions[bot]) is updated, so
# a comment someone else starts with the marker is not taken for it.
set -uo pipefail
file=${COMMENT_FILE:-}
skip() {
    echo "applygate: no pull-request comment: $1"
    [ -n "$file" ] && rm -f "$file"
    exit 0
}
# unable MESSAGE DETAIL: the comment was asked for and could not be written.
unable() {
    echo "::notice title=applygate plan check::The pull-request comment was not written: $1"
    [ -n "$2" ] && printf 'applygate: gh said: %s\n' "$(printf '%s' "$2" | LC_ALL=C tr -d '\000-\037\177' | head -c 500)"
    [ -n "$file" ] && rm -f "$file"
    exit 0
}

[ -n "$file" ] && [ -s "$file" ] || skip "plan-check wrote none (see the plan-check step)"
pr=${PR_NUMBER:-}
[ -n "$pr" ] || skip "this run is not for a pull request"
[[ "$pr" =~ ^[0-9]+$ ]] || skip "the pull request number is not a number"
repo=${GITHUB_REPOSITORY:-}
[[ "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || skip "GITHUB_REPOSITORY is not owner/name"
marker=$(head -n 1 "$file")
[[ "$marker" =~ ^'<!-- applygate:plan-check '[0-9a-f]{16}' -->'$ ]] || skip "the comment does not start with its marker"
command -v gh > /dev/null || unable "the gh command is not on this runner." ""
[ -n "${GH_TOKEN:-}" ] || unable "the step has no token." ""

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

# The marker is 16 hex digits between fixed words (checked above), so it is
# safe inside the jq program.
if ! ids=$(gh api --paginate "repos/$repo/issues/$pr/comments?per_page=100" \
    --jq ".[] | select(.user.login == \"github-actions[bot]\" and ((.body // \"\") | startswith(\"$marker\"))) | .id" 2>&1); then
    unable "$why" "$ids"
fi
id=$(printf '%s\n' "$ids" | head -n 1)
if [[ "$id" =~ ^[0-9]+$ ]]; then
    if ! err=$(gh api --silent --method PATCH "repos/$repo/issues/comments/$id" -F "body=@$file" 2>&1); then
        unable "$why" "$err"
    fi
    echo "applygate: updated the plan-check comment on pull request #$pr"
else
    if ! err=$(gh api --silent --method POST "repos/$repo/issues/$pr/comments" -F "body=@$file" 2>&1); then
        unable "$why" "$err"
    fi
    echo "applygate: posted the plan-check comment on pull request #$pr"
fi
rm -f "$file"
exit 0
