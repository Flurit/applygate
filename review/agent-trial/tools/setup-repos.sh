#!/bin/sh
# Clone the trial repositories at their pinned commits, drop in the observe-mode
# config and install both agent hooks. Runs at image build time.
#
#   setup-repos.sh WORKDIR REPOS_TXT CONFIGS_DIR
#
# Safety: refuses to run with any AWS credential or profile in the environment,
# clones with hooks disabled, and never runs anything from the repositories.
set -eu
work=$1; repos=$2; configs=$3
for v in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE; do
    if [ -n "$(printenv "$v" 2>/dev/null || true)" ]; then
        echo "setup-repos.sh: $v is set; this trial must run without cloud credentials" >&2
        exit 1
    fi
done
mkdir -p "$work"
while read -r repo sha _license; do
    [ -n "$repo" ] || continue
    name=${repo#*/}
    dir="$work/$name"
    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
        git -C "$dir" -c core.hooksPath=/dev/null fetch -q --depth 1 "https://github.com/$repo.git" "$sha"
        git -C "$dir" -c core.hooksPath=/dev/null -c advice.detachedHead=false checkout -q FETCH_HEAD
        git -C "$dir" config core.hooksPath /dev/null
        git -C "$dir" config user.name trial
        git -C "$dir" config user.email trial@example.invalid
    fi
    got=$(git -C "$dir" rev-parse HEAD)
    [ "$got" = "$sha" ] || { echo "$name: HEAD $got is not the pinned $sha" >&2; exit 1; }
    # Trial config, switched from enforce to observe. Every other line is kept
    # as written for the static corpus trial.
    sed 's/^mode: enforce\b.*/mode: observe/' "$configs/$name.applygate.yaml" > "$dir/.applygate.yaml"
    grep -q '^mode: observe$' "$dir/.applygate.yaml" || { echo "$name: config is not in observe mode" >&2; exit 1; }
    (cd "$dir" && applygate hook install --agent claude --scope project >/dev/null \
               && applygate hook install --agent codex --scope project >/dev/null)
    # Keep the trial's additions out of the agent's diff view.
    printf '.applygate.yaml\n.claude/settings.json\n.codex/hooks.json\n' >> "$dir/.git/info/exclude"
    echo "$name at $sha: observe mode, claude + codex hooks installed"
done < "$repos"
