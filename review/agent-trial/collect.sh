#!/bin/sh
# Collect the trial's evidence from the container volumes into
# review/agent-trial/results/<date>/ and build the review template.
#
#   review/agent-trial/collect.sh [DATE] [--agent "NAME VERSION"]...
#
# DATE defaults to today (UTC). Runs a throwaway container on the trial
# volumes (no agent, no LocalStack needed), so it works whether or not a
# trial session is open. Gathers:
#   decisions.jsonl         the observe-mode decision log (secrets already redacted)
#   report.txt              `seatbelt report` on that log
#   doctor/<repo>.txt       `seatbelt doctor` from each clone
#   diff/<repo>.patch       what the agent changed in each clone (git diff)
#   versions.txt            seatbelt, terraform, Claude Code, Codex, machine
#   plangate/               the plan-gate exercise output, if run
#   summary.md              the review template: counts, every ask and block
#                           with a false-positive column to fill by hand
set -eu
here=$(cd "$(dirname "$0")" && pwd)
date=${1:-$(date -u +%Y-%m-%d)}
case "$date" in -*) date=$(date -u +%Y-%m-%d) ;; *) [ $# -gt 0 ] && shift ;; esac
out="$here/results/$date"
mkdir -p "$out"
command -v docker >/dev/null 2>&1 || { echo "collect.sh: docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "collect.sh: python3 is required" >&2; exit 1; }

docker compose -f "$here/compose.yaml" run --rm --no-deps -T trial sh -s <<'INSIDE' | tar -C "$out" -xf -
set -eu
c=$(mktemp -d)
mkdir -p "$c/doctor" "$c/diff"
log=/home/trial/.local/state/seatbelt/decisions.jsonl
if [ -f "$log" ]; then cp "$log" "$c/decisions.jsonl"; else : > "$c/decisions.jsonl"; fi
seatbelt report --log "$c/decisions.jsonl" > "$c/report.txt" 2>&1 || true
{
    echo "collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "seatbelt: $(seatbelt version)"
    echo "terraform: $(terraform version | head -n 1)"
    echo "claude-code: $(claude --version 2>/dev/null | head -n 1 || echo 'not installed')"
    echo "codex: $(codex --version 2>/dev/null | head -n 1 || echo 'not installed')"
    echo "container: $(uname -srm), $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "localstack: $(curl -fsS "${LOCALSTACK_ENDPOINT:-http://localstack:4566}/_localstack/health" 2>/dev/null | head -c 200 || echo 'not running at collect time')"
} > "$c/versions.txt"
for d in /work/*/; do
    name=$(basename "$d")
    [ -d "$d/.git" ] || continue
    (cd "$d" && seatbelt doctor > "$c/doctor/$name.txt" 2>&1 || true)
    (cd "$d" && { git -c core.hooksPath=/dev/null status --short; echo; git -c core.hooksPath=/dev/null diff; } > "$c/diff/$name.patch" 2>&1 || true)
done
[ -d /work/plangate/out ] && cp -r /work/plangate/out "$c/plangate"
tar -C "$c" -cf - .
INSIDE

python3 -I "$here/tools/summarize.py" "$out" "$@" > "$out/summary.md"
echo "results in $out"
echo "  $(wc -l < "$out/decisions.jsonl") decision(s); review template: $out/summary.md"
