#!/bin/sh
# bump-version-refs.sh -- point the Action's default and the docs at a release.
#
#   scripts/bump-version-refs.sh --action vX.Y.Z   before the tag
#   scripts/bump-version-refs.sh vX.Y.Z            after the release is published
#
# --action rewrites only action.yml's default version. It goes into the commit
# the tag is made on, so the Action at a release tag (or at that tag's commit
# SHA) installs that release and not the one before it. The release workflow
# and TestActionInstallsTheNewestRelease refuse a mismatch.
#
# Without --action, run it after the release is published, with
# scripts/pin-plugin-release.sh and the Homebrew formula
# (docs/project/RELEASE.md). It rewrites the version in the install and CI
# examples, which can only name a release that exists, sets action.yml's
# default too if --action was skipped, then lists any other mention of the
# previous version so a person can check it.
set -eu

mode=docs
if [ "${1:-}" = "--action" ]; then
    mode=action
    shift
fi
tag=${1:-}
case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "usage: $0 [--action] vX.Y.Z" >&2; exit 2 ;;
esac
case "$tag" in *[!A-Za-z0-9.-]*) echo "invalid tag $tag" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."

# The version input's default, and the example in its error message.
set_action() {
    sed -i.bak \
        -e "s|^    default: v[0-9][0-9.]*\$|    default: $tag|" \
        -e "s|release tag such as v[0-9][0-9.]*\"|release tag such as $tag\"|" \
        action.yml
    rm -f action.yml.bak
    grep -qxF "    default: $tag" action.yml || { echo "no version default in action.yml" >&2; exit 1; }
}

if [ "$mode" = action ]; then
    set_action
    echo "action.yml installs $tag by default"
    exit 0
fi

# The docs name the last published release; docs/install.md's verify steps
# carry it on a line of its own.
old=$(sed -n 's/^tag=\(v[0-9][0-9.]*\)$/\1/p' docs/install.md | head -n 1)
[ -n "$old" ] || { echo "no tag= line in docs/install.md" >&2; exit 1; }
set_action
[ "$old" != "$tag" ] || { echo "already at $tag"; exit 0; }

for f in README.md docs/install.md docs/ci.md; do
    # Only the places that name the release to install or use.
    sed -i.bak \
        -e "s|Flurit/applygate@$old|Flurit/applygate@$tag|g" \
        -e "s|applygate/$old/install.sh|applygate/$tag/install.sh|g" \
        -e "s|cmd/applygate@$old|cmd/applygate@$tag|g" \
        -e "s|^tag=$old\$|tag=$tag|" \
        -e "s|release tag such as $old|release tag such as $tag|" \
        "$f"
    rm -f "$f.bak"
done
echo "bumped $old -> $tag; other mentions of $old to check:"
grep -rn --exclude-dir=review --exclude-dir=.git --exclude=CHANGELOG.md -F "$old" . || true
