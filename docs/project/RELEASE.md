# Release checklist

The order matters. The Action's default version goes into the commit the tag is made on, because a workflow that uses the Action at a tag reads `action.yml` from that tag. The plugin pin and the install examples can only name a release that exists, so they are bumped right after it is published.

## Before the tag

- `go test ./...`, `go build -o bin/applygate ./cmd/applygate && bin/applygate selftest`, and `python3 -I harness/run.py --guard bin/applygate --format claude` and `--format codex` pass.
- `CHANGELOG.md` has the release's section, and `docs/limits.md` lists what is still open.
- `scripts/bump-version-refs.sh --action vX.Y.Z`: sets `action.yml`'s default version to the release, in the same pull request as the changelog section. `TestActionInstallsTheNewestRelease` fails until the two agree, and the release workflow refuses a tag whose `action.yml` names another version. Until the release is published, the Action on `main` names a release that does not exist yet and fails closed at the download.
- The `release` environment in the repository settings allows only `v*` tags and has a required reviewer. The release job runs in it, so a workflow run cannot sign a release by itself.

## The tag

- Push the `vX.Y.Z` tag. `.github/workflows/release.yml` runs the tests, then waits for the `release` environment's approval, then builds, signs and attests with the pinned goreleaser.
- Verify the release as `docs/install.md` says, against the exact identity `https://github.com/Flurit/applygate/.github/workflows/release.yml@refs/tags/vX.Y.Z`.

## Right after the release

- `scripts/pin-plugin-release.sh vX.Y.Z`: pins the Claude Code plugin to the release's verified sha256 values and bumps the plugin version.
- `scripts/bump-version-refs.sh vX.Y.Z`: points the install and CI examples at the release, and lists any other mention of the old version.
- Update the Homebrew formula in `packaging/homebrew/applygate.rb` and `Flurit/homebrew-tap` from the signed `checksums.txt`.
- Record the verification in `docs/project/ACCEPTANCE.md`.
