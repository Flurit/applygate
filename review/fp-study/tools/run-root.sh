#!/bin/bash
# Plan one root module against LocalStack and save the plan JSON.
# Runs inside the runner container (compose.yaml).
#
#   run-root.sh REPO_DIR ROOT MODE
#
# REPO_DIR is the clone under /study/src, ROOT the root module relative to it,
# MODE "apply" or "plan-only". Writes /study/out/<repo>__<root>/:
#   create.json   first plan of the root (empty state)
# and, in apply mode, once the create plan has been applied to LocalStack:
#   noop.json     re-plan with nothing changed
#   tags.json     re-plan after the routine change: the provider default tag
#                 fp_study flipped from v1 to v2
#   destroy.json  plan -destroy, the control: it should prompt
# then applies the destroy plan so LocalStack is clean for the next root.
# status.txt records each step and its exit code; *.log the output.
set -u
repo_dir=$1; root=$2; mode=$3
ep=${LOCALSTACK_ENDPOINT:-http://localstack:4566}
die() { printf 'run-root.sh: %s\n' "$*" >&2; exit 1; }

# --- safety guards: LocalStack dummy credentials and nothing else ------------
[ "${AWS_ACCESS_KEY_ID:-}" = test ] || die "AWS_ACCESS_KEY_ID must be LocalStack's dummy value 'test'"
[ "${AWS_SECRET_ACCESS_KEY:-}" = test ] || die "AWS_SECRET_ACCESS_KEY must be LocalStack's dummy value 'test'"
[ -z "${AWS_SESSION_TOKEN:-}" ] || die "AWS_SESSION_TOKEN is set; refusing"
[ -z "${AWS_PROFILE:-}" ] || die "AWS_PROFILE is set; refusing"
case "$ep" in http://localstack:4566) ;; *) die "LOCALSTACK_ENDPOINT '$ep' is not the sidecar; refusing" ;; esac
[ "${AWS_ENDPOINT_URL:-}" = "$ep" ] || die "AWS_ENDPOINT_URL must be '$ep'"
case "$mode" in apply|plan-only) ;; *) die "MODE must be apply or plan-only" ;; esac

dir=/study/src/$repo_dir/$root
[ -d "$dir" ] || die "no such root: $dir"
slug="${repo_dir}__$(printf '%s' "$root" | tr '/' '_')"
out=/study/out/$slug
rm -rf "$out"; mkdir -p "$out"
status="$out/status.txt"
printf 'repo=%s\nroot=%s\nmode=%s\n' "$repo_dir" "$root" "$mode" > "$status"
step() { printf '%s=%s\n' "$1" "$2" >> "$status"; }
export TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1

cd "$dir" || die "cd $dir"
rm -rf .terraform .terraform.lock.hcl terraform.tfstate terraform.tfstate.backup ./*.tfplan
python3 /home/study/fp/tools/override.py . v1 > "$out/override.log" 2>&1; step override $?

# The provider plugin cache is shared between parallel workers and Terraform
# does not lock it, so provider installs take turns (flock on a file in the
# cache volume).
lock=${TF_PLUGIN_CACHE_DIR:-/tmp}/.fp-study-init.lock
tf() { # tf NAME TIMEOUT ARGS... -> log to $out/NAME.log, records exit code
    name=$1; t=$2; shift 2
    if [ "$name" = init ]; then
        flock "$lock" timeout -k 30 "$t" terraform "$@" -no-color > "$out/$name.log" 2>&1
    else
        timeout -k 30 "$t" terraform "$@" -no-color > "$out/$name.log" 2>&1
    fi
    rc=$?; step "$name" "$rc"; return "$rc"
}
show() { terraform show -json -no-color "$1.tfplan" > "$out/$1.json" 2> "$out/$1.show.log"; step "$1-show" $?; }

# Modules download without the lock (terraform get touches no plugin cache);
# the locked init then only installs providers, mostly from the cache.
tf get 900 get || exit 0
tf init 900 init -input=false || exit 0
tf create 900 plan -input=false -out create.tfplan || exit 0
show create
[ "$mode" = apply ] || exit 0

# A create that LocalStack only partly supports (RDS subnet groups in a VPC
# example, say) still leaves most resources in state; the day-2 plans are
# taken over that state too and the root is marked partial, so the evaluation
# can tell the re-planned creates of what never applied from the change.
tf apply-create 300 apply -input=false create.tfplan; ac=$?
rm -f .terraform.tfstate.lock.info   # left behind when the timeout kills apply
if [ "$ac" -ne 0 ] && terraform state list 2>/dev/null | grep -q .; then
    step partial 1
fi
if [ "$ac" -eq 0 ] || grep -q '^partial=1$' "$status"; then
    tf noop 900 plan -input=false -out noop.tfplan && show noop
    python3 /home/study/fp/tools/override.py . v2 >> "$out/override.log" 2>&1
    tf tags 900 plan -input=false -out tags.tfplan && show tags
fi
# Destroy whatever is in state, also after a partial apply, so LocalStack stays
# clean; the destroy plan is the study's control. Some
# LocalStack deletes never finish (an SQS redrive allow policy waits forever),
# so the destroy apply gets a short timeout; leftovers do not affect the plans.
tf destroy 900 plan -input=false -destroy -out destroy.tfplan && show destroy
tf apply-destroy 180 apply -input=false destroy.tfplan
exit 0
