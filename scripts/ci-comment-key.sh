# Sourced by ci-plan-check.sh and ci-pr-comment.sh, so that the comment and
# the step that posts it name a plan the same way.
#
# comment_key prints the name a pull-request comment shows for what was
# judged: COMMENT_KEY, or WORKDIR and PLAN as one path. A path under
# GITHUB_WORKSPACE is written relative to it, so the name does not depend on
# where a runner checked the repository out and does not show that directory.
comment_key() {
    local key=${COMMENT_KEY:-} workdir=${WORKDIR:-.} plan=${PLAN:-} root=${GITHUB_WORKSPACE:-}
    if [ -n "$key" ]; then
        printf '%s' "$key"
        return 0
    fi
    case "$plan" in
        /*) key=$plan ;;
        *) key=${workdir%/}/$plan ;;
    esac
    root=${root%/}
    if [ -n "$root" ]; then
        key=${key#"$root"/}
    fi
    while [ "${key#./}" != "$key" ]; do
        key=${key#./}
    done
    printf '%s' "$key"
}
