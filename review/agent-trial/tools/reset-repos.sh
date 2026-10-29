#!/bin/sh
# Reset the five clones in the trial container to their pinned commits so the
# next agent starts from the same tree as the last one. Keeps the harness
# files (.applygate.yaml and the hook configs, which are git-ignored inside the
# clones), the provider caches and the decision log. Agent edits are lost:
# run collect.sh first, which saves them as raw/diff/<repo>.patch.
#
#   review/agent-trial/tools/reset-repos.sh
#
# Does not touch LocalStack or Terraform state files that an apply left
# behind (examples/simple in terraform-aws-vpc, for instance); destroy those
# against LocalStack from inside the container if a clean sidecar matters.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
repos="$here/../oss-corpus/repos.txt"
pins=$(awk '{split($1, a, "/"); print a[2] "=" $2}' "$repos")
docker compose -f "$here/compose.yaml" run --rm --no-deps -T -e PINS="$pins" trial sh -s <<'INSIDE'
set -eu
status=0
for pin in $PINS; do
    name=${pin%%=*}; sha=${pin#*=}; d=/work/$name
    [ -d "$d/.git" ] || { echo "$name: missing clone"; status=1; continue; }
    git -C "$d" reset -q --hard "$sha"
    git -C "$d" clean -qfd
    tracked=$(git -C "$d" status --porcelain --untracked-files=no | wc -l)
    untracked=$(git -C "$d" status --porcelain --untracked-files=all | grep -c '^??' || true)
    cfg=$([ -f "$d/.applygate.yaml" ] && echo ok || echo MISSING)
    hooks=$([ -f "$d/.claude/settings.json" ] && [ -f "$d/.codex/hooks.json" ] && echo ok || echo MISSING)
    echo "$name: $(git -C "$d" rev-parse --short HEAD) tracked-changes=$tracked untracked=$untracked config=$cfg hooks=$hooks"
    [ "$cfg" = ok ] && [ "$hooks" = ok ] || status=1
done
exit $status
INSIDE
