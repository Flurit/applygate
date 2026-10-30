#!/bin/sh
# pin-plugin-release.sh -- pin the Claude Code plugin to a published release.
#
#   scripts/pin-plugin-release.sh vX.Y.Z
#
# Run after a release is published, in the same follow-up as the Homebrew
# formula. Downloads the release's checksums.txt, verifies its cosign
# signature against this repository's release workflow for that tag (cosign is
# required), then writes the four archive lines to
# plugin/claude-code/scripts/pinned-release.txt and sets the plugin version in
# plugin/claude-code/.claude-plugin/plugin.json to X.Y.Z. A new plugin version
# is what makes Claude Code pick up the new pin.
set -eu

tag=${1:-}
case "$tag" in
    v[0-9]*) ;;
    *) echo "usage: $0 vX.Y.Z" >&2; exit 2 ;;
esac
case "$tag" in *[!A-Za-z0-9._-]*) echo "invalid tag $tag" >&2; exit 2 ;; esac
version=${tag#v}
command -v cosign >/dev/null 2>&1 || { echo "cosign is required to verify checksums.txt" >&2; exit 1; }

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
base="https://github.com/Flurit/applygate/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"
curl -fsSL -o "$tmp/checksums.txt.sigstore.json" "$base/checksums.txt.sigstore.json"
cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
    --certificate-identity "https://github.com/Flurit/applygate/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$tmp/checksums.txt"

pin="$root/plugin/claude-code/scripts/pinned-release.txt"
{
    printf '# The applygate release the Claude Code plugin downloads when applygate is not\n'
    printf '# on PATH: sha256 and archive name, from the signed checksums.txt of %s.\n' "$tag"
    printf '# Written by scripts/pin-plugin-release.sh; do not edit by hand.\n'
    for p in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
        a="applygate_${version}_${p}.tar.gz"
        l=$(awk -v f="$a" '$2 == f { print $1 "  " $2 }' "$tmp/checksums.txt")
        [ -n "$l" ] || { echo "$a is not in checksums.txt" >&2; exit 1; }
        printf '%s\n' "$l"
    done
} > "$pin.new"
mv "$pin.new" "$pin"

manifest="$root/plugin/claude-code/.claude-plugin/plugin.json"
sed "s/\"version\": \"[^\"]*\"/\"version\": \"$version\"/" "$manifest" > "$manifest.new"
mv "$manifest.new" "$manifest"
echo "pinned the plugin to $tag: $pin, $manifest" >&2
