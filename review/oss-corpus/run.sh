#!/bin/sh
# Reproduce the open-source corpus trial (docs/oss-corpus-trial.md).
#
#   review/oss-corpus/run.sh SEATBELT_BIN WORKDIR
#
# Clones the five repositories at the commits in repos.txt into WORKDIR
# (shallow, no hooks, no submodules), extracts their commands, and replays
# them through `seatbelt check` with and without the trial configs.
# Nothing from the repositories is executed: extract.py only reads files,
# and seatbelt runs with an empty PATH, a fake HOME and no user config.
set -eu
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$2
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$work/repos"
while read -r repo sha _license; do
    name=${repo#*/}
    dir="$work/repos/$name"
    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
        git -C "$dir" -c core.hooksPath=/dev/null fetch -q --depth 1 "https://github.com/$repo.git" "$sha"
        git -C "$dir" -c core.hooksPath=/dev/null -c advice.detachedHead=false checkout -q FETCH_HEAD
    fi
done < "$here/repos.txt"

: > "$work/corpus.jsonl"
for dir in "$work"/repos/*; do
    python3 -I "$here/tools/extract.py" "$dir" "$(basename "$dir")" >> "$work/corpus.jsonl"
done

# With the trial configs, then with no config at all (strict defaults).
for dir in "$work"/repos/*; do cp "$here/configs/$(basename "$dir").seatbelt.yaml" "$dir/.seatbelt.yaml"; done
python3 -I "$here/tools/replay.py" "$bin" "$work/repos" "$work/corpus.jsonl" "$work/config.jsonl" config
for dir in "$work"/repos/*; do rm -f "$dir/.seatbelt.yaml"; done
python3 -I "$here/tools/replay.py" "$bin" "$work/repos" "$work/corpus.jsonl" "$work/default.jsonl" default

for run in config default; do
    python3 -I "$here/tools/label.py" "$work/$run.jsonl" > "$work/$run.summary.json"
    python3 -I -c "import json,sys; s=json.load(open(sys.argv[1]))['summary']['ALL']; print(sys.argv[2], 'commands', s['total'], 'runnable', s['runnable'], 'false positives', s['false_positives'], 'fp%', s['fp_rate'])" "$work/$run.summary.json" "$run"
done
