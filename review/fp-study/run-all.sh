#!/bin/sh
# Run the false-positive study's plan generation over the whole corpus.
# Runs on the host, from anywhere; needs Docker with Compose v2.
#
#   run-all.sh [JOBS] [REPO...]      (JOBS default 3; REPO filters by name)
#
# Expands each corpus line's root globs against the clones in work/src (run
# `docker compose run --rm -T runner sh /home/study/fp/tools/clone.sh` first),
# keeps directories that hold .tf files, and runs tools/run-root.sh on every
# root inside the runner container. Repositories run in parallel, JOBS at a
# time; roots within one repository run one after another so their LocalStack
# resources never overlap. Output: work/out/<repo>__<root>/.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
jobs=${1:-3}; [ $# -gt 0 ] && shift
cd "$here"
list=$(mktemp)
trap 'rm -f "$list"' EXIT
grep -v '^#' corpus.txt | while read -r repo _sha _license mode roots; do
    [ -n "$repo" ] && [ "$mode" != skip ] || continue
    name=${repo#*/}
    if [ $# -gt 0 ]; then
        keep=no; for f in "$@"; do [ "$f" = "$name" ] && keep=yes; done
        [ $keep = yes ] || continue
    fi
    sel=""
    for g in $(printf '%s' "$roots" | tr ',' ' '); do
        for d in work/src/$name/$g; do
            [ -d "$d" ] && ls "$d"/*.tf >/dev/null 2>&1 || continue
            sel="$sel ${d#work/src/$name/}"
        done
    done
    [ -n "$sel" ] && printf '%s %s%s\n' "$name" "$mode" "$sel"
done > "$list"
echo "$(wc -l < "$list") repositories, $(awk '{n += NF - 2} END {print n}' "$list") roots"
# One container per repository; its roots run in sequence inside it.
tr '\n' '\0' < "$list" | xargs -0 -P "$jobs" -I{} sh -c '
    set -- {}
    name=$1; mode=$2; shift 2
    docker compose run --rm -T runner bash -c "for r in $*; do echo \"[$name] \$r\"; bash /home/study/fp/tools/run-root.sh $name \$r $mode; done" 2>&1 | grep -v " Container "
'
echo "done: $(ls -d work/out/*/ | wc -l) root output directories"
