#!/bin/sh
# Clone every corpus repository at its pinned commit into /study/src.
# Runs inside the runner container. Git hooks are disabled and nothing from the
# repositories is executed here.
#
#   clone.sh [CORPUS]      (default: /home/study/fp/corpus.txt)
set -eu
corpus=${1:-/home/study/fp/corpus.txt}
src=/study/src
mkdir -p "$src"
grep -v '^#' "$corpus" | while read -r repo sha _license _roots; do
    [ -n "$repo" ] || continue
    dir="$src/${repo#*/}"
    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
        git -C "$dir" config core.hooksPath /dev/null
        git -C "$dir" -c core.hooksPath=/dev/null fetch -q --depth 1 "https://github.com/$repo.git" "$sha"
        git -C "$dir" -c core.hooksPath=/dev/null -c advice.detachedHead=false checkout -q FETCH_HEAD
    fi
    got=$(git -C "$dir" rev-parse HEAD)
    [ "$got" = "$sha" ] || { echo "$repo: HEAD $got is not the pinned $sha" >&2; exit 1; }
    echo "$repo at $sha"
done
