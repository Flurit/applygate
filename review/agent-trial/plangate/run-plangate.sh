#!/bin/sh
# Plan-gate exercise: saved plans against LocalStack through `applygate
# plan-check` and through the real hook path for `terraform apply <planfile>`.
# Needs no agent. See review/agent-trial/README.md, "Plan-gate exercise".
#
#   run-plangate.sh [OUTDIR]        (default: ./out next to this script)
#
# What it does, per workspace (prod = protected tier, staging = standard):
#   1. plan a fresh create, record the verdicts, apply it to LocalStack;
#   2. plan a no-op, a forced replace of the bucket, versioning suspended,
#      force_destroy on, port 22 open to the internet, and a full destroy;
#      record the verdicts for each without applying any of them;
#   3. with the other workspace selected, send an apply of this workspace's
#      plan through the hook (workspace mismatch);
#   4. apply the destroy plan to LocalStack so the sidecar is clean again.
# Every apply goes to LocalStack only: the provider has hard-coded dummy keys
# and an endpoints block, and this script refuses to start unless the
# environment holds LocalStack's dummy credentials and nothing else.
#
# The hook path is exercised by piping a synthetic Claude Code / Codex
# PreToolUse event for `terraform apply plans/<name>.tfplan` into
# `applygate hook claude|codex`, exactly as the agent would; applygate then runs
# `terraform show -json` on the planfile itself. The decision log for the
# exercise is isolated under OUTDIR/state via XDG_STATE_HOME.
#
# OUTDIR gets the evidence (verdicts.md, verdicts.jsonl, meta.txt,
# decisions.jsonl); everything per case (hook stdout/stderr, plan JSON,
# plan-check output, init and apply logs) goes to OUTDIR/raw/, which is
# never committed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/out}
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac
ep=${LOCALSTACK_ENDPOINT:-http://localstack:4566}

die() { printf 'run-plangate.sh: %s\n' "$*" >&2; exit 1; }

# --- safety guards: LocalStack dummy credentials and nothing else ------------
[ "${AWS_ACCESS_KEY_ID:-}" = test ] || die "AWS_ACCESS_KEY_ID must be LocalStack's dummy value 'test' (got '${AWS_ACCESS_KEY_ID:-unset}')"
[ "${AWS_SECRET_ACCESS_KEY:-}" = test ] || die "AWS_SECRET_ACCESS_KEY must be LocalStack's dummy value 'test'"
[ -z "${AWS_SESSION_TOKEN:-}" ] || die "AWS_SESSION_TOKEN is set; refusing"
[ -z "${AWS_PROFILE:-}" ] || die "AWS_PROFILE is set; refusing"
case "$ep" in
    http://localstack:4566 | http://localhost:4566 | http://127.0.0.1:4566) ;;
    *) die "LOCALSTACK_ENDPOINT '$ep' is not a LocalStack address; refusing" ;;
esac
[ "${AWS_ENDPOINT_URL:-$ep}" = "$ep" ] || die "AWS_ENDPOINT_URL '${AWS_ENDPOINT_URL}' differs from LOCALSTACK_ENDPOINT '$ep'"
grep -q 'access_key = "test"' "$here/main.tf" || die "main.tf no longer pins the dummy access key"
grep -q 'secret_key = "test"' "$here/main.tf" || die "main.tf no longer pins the dummy secret key"
grep -q 'endpoints {' "$here/main.tf" || die "main.tf no longer has an endpoints block"
for t in applygate terraform jq curl; do command -v "$t" >/dev/null 2>&1 || die "$t is required"; done
curl -fsS "$ep/_localstack/health" >/dev/null 2>&1 || die "LocalStack is not reachable at $ep (docker compose up -d localstack)"

raw="$out/raw"
mkdir -p "$raw/plans" "$raw/hook" "$out/state" "$here/plans"
export XDG_STATE_HOME="$out/state"
log="$out/state/applygate/decisions.jsonl"
rm -f "$log"
export TF_VAR_endpoint="$ep"
export TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1
unset TF_WORKSPACE

{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "applygate: $(applygate version)"
    echo "terraform: $(terraform version | head -n 1)"
    echo "localstack: $(curl -fsS "$ep/_localstack/health" | jq -c '{version, s3: .services.s3, ec2: .services.ec2, dynamodb: .services.dynamodb}')"
    echo "machine: $(uname -srm)"
    echo "config: $here/.applygate.yaml (enforce, strict; prod protected, staging standard)"
} > "$out/meta.txt"
cat "$out/meta.txt"

cd "$here"
terraform init -input=false -no-color > "$raw/init.log" 2>&1 || { cat "$raw/init.log"; die "terraform init failed"; }

verdicts="$out/verdicts.md"
jsonl="$out/verdicts.jsonl"
: > "$jsonl"
{
    echo "# Plan-gate exercise verdicts"
    echo
    sed 's/^/    /' "$out/meta.txt"
    echo
    echo "plan-check is given the workspace's tier explicitly (--tier); the hook path resolves the tier itself from the selected workspace. \"decision\" is what the agent receives: the hookSpecificOutput permissionDecision, or allow when the hook prints nothing, or exit 2 (blocked by exit code)."
    echo
    echo "| Workspace | Tier | Plan | Command through the hook | plan-check | Hook verdict | Enforced | Claude decision | Codex decision | Class | Findings |"
    echo "|---|---|---|---|---|---|---|---|---|---|---|"
} > "$verdicts"

# hook AGENT COMMAND LABEL -> writes stdout/stderr files, prints "decision exit"
hook() {
    agent=$1; cmd=$2; label=$3
    ev=$(jq -cn --arg cwd "$here" --arg cmd "$cmd" \
        '{session_id:"plangate-exercise", hook_event_name:"PreToolUse", tool_name:"Bash", permission_mode:"default", cwd:$cwd, tool_input:{command:$cmd}}')
    set +e
    printf '%s' "$ev" | applygate hook "$agent" > "$raw/hook/$label.$agent.stdout" 2> "$raw/hook/$label.$agent.stderr"
    rc=$?
    set -e
    if [ -s "$raw/hook/$label.$agent.stdout" ]; then
        d=$(jq -r '.hookSpecificOutput.permissionDecision // "unparsed"' "$raw/hook/$label.$agent.stdout" 2>/dev/null || echo unparsed)
    else
        d=allow
    fi
    [ "$rc" -eq 2 ] && d="blocked by exit 2"
    printf '%s' "$d"
}

# record WS TIER NAME PLANFILE: plan-check on the JSON, then the hook path for both agents.
record() {
    ws=$1; tier=$2; name=$3; plan=$4
    label="$ws-$name"
    terraform show -json -no-color "$plan" > "$raw/plans/$label.json"
    set +e
    pc=$(applygate plan-check --tier "$tier" --cwd "$here" "$raw/plans/$label.json" 2>&1)
    pcrc=$?
    set -e
    printf '%s\n' "$pc" > "$raw/plans/$label.plan-check.txt"
    pcline=$(printf '%s\n' "$pc" | head -n 1 | sed 's/^tier [a-z]*: //')
    cmd="terraform apply $plan"
    cd_=$(hook claude "$cmd" "$label")
    claude_entry=$(tail -n 1 "$log")
    co_=$(hook codex "$cmd" "$label")
    verdict=$(printf '%s' "$claude_entry" | jq -r '.verdict')
    enforced=$(printf '%s' "$claude_entry" | jq -r '.enforced')
    class=$(printf '%s' "$claude_entry" | jq -r '.actions[0].class // "-"')
    htier=$(printf '%s' "$claude_entry" | jq -r '.actions[0].tier // "-"')
    findings=$(printf '%s' "$claude_entry" | jq -r '[.actions[0].findings[]? | "\(.severity) \(.rule)"] | unique | join("; ")')
    [ -n "$findings" ] || findings="-"
    printf '| %s | %s | %s | `%s` | %s (exit %s) | %s | %s | %s | %s | %s | %s |\n' \
        "$ws" "$htier" "$name" "$cmd" "$pcline" "$pcrc" "$verdict" "$enforced" "$cd_" "$co_" "$class" "$findings" >> "$verdicts"
    jq -cn --arg ws "$ws" --arg tier "$htier" --arg name "$name" --arg cmd "$cmd" --arg pc "$pcline" --argjson pcrc "$pcrc" \
        --arg verdict "$verdict" --arg enforced "$enforced" --arg claude "$cd_" --arg codex "$co_" --arg class "$class" --arg findings "$findings" \
        '{workspace:$ws, tier:$tier, plan:$name, command:$cmd, plan_check:$pc, plan_check_exit:$pcrc, verdict:$verdict, enforced:$enforced, claude:$claude, codex:$codex, class:$class, findings:$findings}' >> "$jsonl"
    echo "  $ws/$name: plan-check '$pcline'; hook $verdict (enforced $enforced; claude $cd_; codex $co_)"
}

plan() { # plan OUTFILE [ARGS...]
    f=$1; shift
    terraform plan -input=false -no-color -out "$f" "$@" > "$f.log" 2>&1 || { cat "$f.log"; die "terraform plan failed for $f"; }
}

for ws in prod staging; do
    case $ws in prod) tier=protected ;; staging) tier=standard ;; esac
    echo "== workspace $ws ($tier)"
    terraform workspace select -or-create -no-color "$ws" >/dev/null
    plan plans/$ws-create.tfplan
    record "$ws" "$tier" create plans/$ws-create.tfplan
    echo "  applying the create plan to LocalStack"
    terraform apply -input=false -no-color plans/$ws-create.tfplan > "$raw/$ws-apply-create.log" 2>&1 || { cat "$raw/$ws-apply-create.log"; die "apply to LocalStack failed"; }
    plan plans/$ws-noop.tfplan
    record "$ws" "$tier" noop plans/$ws-noop.tfplan
    plan plans/$ws-replace-bucket.tfplan -replace=aws_s3_bucket.data
    record "$ws" "$tier" replace-bucket plans/$ws-replace-bucket.tfplan
    plan plans/$ws-versioning-suspended.tfplan -var versioning=Suspended
    record "$ws" "$tier" versioning-suspended plans/$ws-versioning-suspended.tfplan
    plan plans/$ws-force-destroy.tfplan -var force_destroy=true
    record "$ws" "$tier" force-destroy plans/$ws-force-destroy.tfplan
    plan plans/$ws-open-ssh.tfplan -var ingress_port=22
    record "$ws" "$tier" open-ssh plans/$ws-open-ssh.tfplan
    plan plans/$ws-destroy.tfplan -destroy
    record "$ws" "$tier" destroy plans/$ws-destroy.tfplan
done

echo "== workspace mismatch"
terraform workspace select -no-color staging >/dev/null
record staging standard mismatch-prod-plan plans/prod-create.tfplan
terraform workspace select -no-color prod >/dev/null
record prod protected mismatch-staging-plan plans/staging-create.tfplan

echo "== missing and unreadable plans"
rm -f plans/missing.tfplan
printf 'not a plan\n' > plans/garbage.tfplan
for ws in prod staging; do
    case $ws in prod) tier=protected ;; staging) tier=standard ;; esac
    terraform workspace select -no-color "$ws" >/dev/null
    for name in missing garbage; do
        label="$ws-$name"; cmd="terraform apply plans/$name.tfplan"
        cd_=$(hook claude "$cmd" "$label"); e=$(tail -n 1 "$log"); co_=$(hook codex "$cmd" "$label")
        verdict=$(printf '%s' "$e" | jq -r .verdict); enforced=$(printf '%s' "$e" | jq -r .enforced)
        class=$(printf '%s' "$e" | jq -r '.actions[0].class // "-"'); htier=$(printf '%s' "$e" | jq -r '.actions[0].tier // "-"')
        findings=$(printf '%s' "$e" | jq -r '[.actions[0].findings[]? | "\(.severity) \(.rule)"] | unique | join("; ")')
        printf '| %s | %s | %s | `%s` | n/a | %s | %s | %s | %s | %s | %s |\n' "$ws" "$htier" "$name" "$cmd" "$verdict" "$enforced" "$cd_" "$co_" "$class" "$findings" >> "$verdicts"
        jq -cn --arg ws "$ws" --arg tier "$htier" --arg name "$name" --arg cmd "$cmd" --arg verdict "$verdict" --arg enforced "$enforced" --arg claude "$cd_" --arg codex "$co_" --arg class "$class" --arg findings "$findings" \
            '{workspace:$ws, tier:$tier, plan:$name, command:$cmd, plan_check:"n/a", verdict:$verdict, enforced:$enforced, claude:$claude, codex:$codex, class:$class, findings:$findings}' >> "$jsonl"
        echo "  $ws/$name: hook $verdict (enforced $enforced; claude $cd_; codex $co_)"
    done
done
rm -f plans/garbage.tfplan

echo "== cleanup: applying the destroy plans to LocalStack"
for ws in prod staging; do
    terraform workspace select -no-color "$ws" >/dev/null
    terraform apply -input=false -no-color plans/$ws-destroy.tfplan > "$raw/$ws-apply-destroy.log" 2>&1 || { cat "$raw/$ws-apply-destroy.log"; die "destroy apply to LocalStack failed"; }
done
terraform workspace select -no-color default >/dev/null

cp "$log" "$out/decisions.jsonl"
rm -rf "$out/state"
{
    echo
    echo "Decision log entries: $(wc -l < "$out/decisions.jsonl") (two per plan: one Claude, one Codex event). Raw per-case output (hook stdout/stderr, plan JSON, plan-check output, init and apply logs) is written to raw/ next to this file and is not committed; collect.sh copies it to results/<date>/raw/plangate/."
} >> "$verdicts"
echo
echo "wrote $verdicts"
