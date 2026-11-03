#!/bin/sh
# bump-version-refs.sh -- point the docs and the Action's default at a release.
#
#   scripts/bump-version-refs.sh vX.Y.Z
#
# Run after the release is published, with scripts/pin-plugin-release.sh and
# the Homebrew formula (docs/project/RELEASE.md). It rewrites the version in
# action.yml's default and in the install and CI examples, then lists any
# other mention of the previous version so a person can check it.
set -eu

tag=${1:-}
case "$tag" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "usage: $0 vX.Y.Z" >&2; exit 2 ;;
esac
case "$tag" in *[!A-Za-z0-9.-]*) echo "invalid tag $tag" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."

old=$(sed -n 's/^    default: \(v[0-9][0-9.]*\)$/\1/p' action.yml | head -n 1)
[ -n "$old" ] || { echo "no version default in action.yml" >&2; exit 1; }
[ "$old" != "$tag" ] || { echo "already at $tag"; exit 0; }

for f in action.yml README.md docs/install.md docs/ci.md; do
    # Only the places that name the release to install or use.
    sed -i.bak \
        -e "s|^    default: $old\$|    default: $tag|" \
        -e "s|Flurit/applygate@$old|Flurit/applygate@$tag|g" \
        -e "s|applygate/$old/install.sh|applygate/$tag/install.sh|g" \
        -e "s|cmd/applygate@$old|cmd/applygate@$tag|g" \
        -e "s|^tag=$old\$|tag=$tag|" \
        -e "s|release tag, default $old|release tag, default $tag|" \
        "$f"
    rm -f "$f.bak"
done
echo "bumped $old -> $tag; other mentions of $old to check:"
grep -rn --exclude-dir=review --exclude-dir=.git --exclude=CHANGELOG.md -F "$old" . || true
