#!/bin/sh
# Collect the trial's evidence from the container volumes into
# review/agent-trial/results/<date>/ and build the review template.
#
#   review/agent-trial/collect.sh [DATE] [--agent "NAME VERSION"]...
#
# DATE defaults to today (UTC). Runs a throwaway container on the trial
# volumes (no agent, no LocalStack needed), so it works whether or not a
# trial session is open.
#
# Committed evidence (results/<date>/):
#   summary.md              the review template: counts, every ask and block
#                           with a false-positive column to fill by hand
#   decisions.jsonl         the observe-mode decision log (secrets already redacted)
#   versions.txt            applygate, terraform, Claude Code, Codex, machine
#   doctor-summary.txt      one line per clone from `applygate doctor`, plus the
#                           launch-directory check from a subdirectory
#   plangate/verdicts.md, verdicts.jsonl, meta.txt, decisions.jsonl
#                           the plan-gate exercise, if it ran
# Raw output (results/<date>/raw/, gitignored):
#   report.txt, doctor/<repo>.txt, diff/<repo>.patch, plangate/ (hook
#   stdout/stderr, plan JSON, plan-check output, init and apply logs)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
date=${1:-$(date -u +%Y-%m-%d)}
case "$date" in -*) date=$(date -u +%Y-%m-%d) ;; *) [ $# -gt 0 ] && shift ;; esac
out="$here/results/$date"
mkdir -p "$out/raw"
command -v docker >/dev/null 2>&1 || { echo "collect.sh: docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "collect.sh: python3 is required" >&2; exit 1; }

docker compose -f "$here/compose.yaml" run --rm --no-deps -T trial sh -s <<'INSIDE' | tar -C "$out" -xf -
set -eu
c=$(mktemp -d)
mkdir -p "$c/raw/doctor" "$c/raw/diff" "$c/plangate"
log=/home/trial/.local/state/applygate/decisions.jsonl
if [ -f "$log" ]; then cp "$log" "$c/decisions.jsonl"; else : > "$c/decisions.jsonl"; fi
applygate report --log "$c/decisions.jsonl" > "$c/raw/report.txt" 2>&1 || true
{
    echo "collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "applygate: $(applygate version)"
    echo "terraform: $(terraform version | head -n 1)"
    echo "claude-code: $(claude --version 2>/dev/null | head -n 1 || echo 'not installed')"
    echo "codex: $(codex --version 2>/dev/null | head -n 1 || echo 'not installed')"
    echo "container: $(uname -srm), $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "localstack: $(curl -fsS "${LOCALSTACK_ENDPOINT:-http://localstack:4566}/_localstack/health" 2>/dev/null | head -c 200 || echo 'not running at collect time')"
} > "$c/versions.txt"
{
    echo "applygate doctor per clone (full output in raw/doctor/): mode, hooks, warnings, exit code"
    echo
    for d in /work/*/; do
        name=$(basename "$d")
        [ -d "$d/.git" ] || continue
        set +e
        (cd "$d" && applygate doctor > "$c/raw/doctor/$name.txt" 2>&1)
        rc=$?
        set -e
        mode=$(sed -n 's/^mode: *//p' "$d/.applygate.yaml" | head -n 1)
        hooks=$(sed -n 's/^ok   hooks installed: //p' "$c/raw/doctor/$name.txt" | head -n 1)
        warns=$(grep -c '^WARN' "$c/raw/doctor/$name.txt" || true)
        echo "$name: mode $mode; hooks ${hooks:-(none)}; $warns warning(s); exit $rc"
        (cd "$d" && { git -c core.hooksPath=/dev/null status --short; echo; git -c core.hooksPath=/dev/null diff; } > "$c/raw/diff/$name.patch" 2>&1 || true)
    done
    echo
    echo "launch-directory check (docs/limits.md): doctor from /work/terraform-aws-vpc/examples/simple"
    set +e
    (cd /work/terraform-aws-vpc/examples/simple && applygate doctor > "$c/raw/doctor/subdirectory-check.txt" 2>&1)
    rc=$?
    set -e
    echo "  $(grep -c '^WARN' "$c/raw/doctor/subdirectory-check.txt" || true) warning(s); exit $rc (expected: warns that the project hook is in an ancestor, exit 1)"
} > "$c/doctor-summary.txt"
if [ -d /work/plangate/out ]; then
    for f in verdicts.md verdicts.jsonl meta.txt decisions.jsonl; do
        [ -f "/work/plangate/out/$f" ] && cp "/work/plangate/out/$f" "$c/plangate/$f"
    done
    [ -d /work/plangate/out/raw ] && cp -r /work/plangate/out/raw "$c/raw/plangate"
fi
tar -C "$c" -cf - .
INSIDE

python3 -I "$here/tools/summarize.py" "$out" "$@" > "$out/summary.md"
echo "results in $out"
echo "  $(wc -l < "$out/decisions.jsonl") decision(s); review template: $out/summary.md; raw output (not committed): $out/raw"
