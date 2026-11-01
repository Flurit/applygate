# Install

## Get the binary

Pick one:

```bash
# Installer, from a release tag (never from main). It checks the sha256 and, when cosign is
# installed, the signature; APPLYGATE_VERIFY_SIGNATURE=require makes the signature check mandatory.
curl -fsSL https://raw.githubusercontent.com/Flurit/applygate/v0.5.0/install.sh | APPLYGATE_VERIFY_SIGNATURE=require sh

# Homebrew (checks the sha256 only, not the signature)
brew install Flurit/tap/applygate

# Go
go install github.com/Flurit/applygate/cmd/applygate@v0.5.0

# From source
go build -o bin/applygate ./cmd/applygate
```

The installer takes `APPLYGATE_VERSION` and `APPLYGATE_INSTALL_DIR`. Releases are built for macOS and Linux, amd64 and arm64.

## Set up a repository

```bash
cd your-infra-repo
applygate init                 # .applygate.yaml in observe mode, plus hooks for the agents it finds
$EDITOR .applygate.yaml        # map directories, workspaces, backends, profiles and clusters to tiers
applygate doctor               # check config, hooks and versions
```

- `applygate init --no-hooks` writes the config only.
- `applygate init` installs hooks at **user scope** (`~/.claude/settings.json`, `~/.codex/hooks.json`), because Claude Code and Codex read project settings only from the directory a session starts in. A user-scope hook fires from any directory. Repositories without a `.applygate.yaml` are judged by your user config (`~/.config/applygate/config.yaml`) or the defaults. `--scope project` keeps the hook inside the repository instead; `applygate doctor` tells you when you start a session from a directory that hook does not cover. See [limits.md](limits.md).
- `applygate hook install --agent NAME [--scope user]` installs one agent's hook (project scope by default), and `applygate hook remove --agent NAME` removes it from both scopes. Agent names: `claude`, `codex`, `cursor`, `copilot`, `gemini`, `windsurf`, `devin`, `opencode`, `cline`. Which agents are tested live is in [hosts.md](hosts.md).

After a few days in observe mode, `applygate report` shows what would have been blocked, and `applygate suggest` turns the log into a proposed config. It takes environments from the directories, workspaces, backends and AWS profiles it saw, and guesses tiers from their names. Directories whose names say nothing are left commented out, so they stay protected until you decide. Review it, then set `mode: enforce`. The config format is in [config.md](config.md).

## Claude Code plugin

[plugin/claude-code](../plugin/claude-code) installs the hook as a Claude Code plugin; try it with `claude --plugin-dir plugin/claude-code`. It uses the `applygate` on your PATH. If there is none, it downloads the release it pins, checks the archive against the sha256 committed in the plugin, and keeps it in the plugin's data directory.

## Verify a download

Check the signature before running anything. Set `tag` to the release you want and replace `linux_amd64` with your platform (`linux|darwin` × `amd64|arm64`):

```bash
tag=v0.5.0
base=https://github.com/Flurit/applygate/releases/download/$tag
curl -fsSLO "$base/checksums.txt" -O "$base/checksums.txt.sigstore.json" -O "$base/applygate_${tag#v}_linux_amd64.tar.gz"
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Flurit/applygate/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf "applygate_${tag#v}_linux_amd64.tar.gz" applygate && install -m 755 applygate ~/.local/bin/
```

The signature ties `checksums.txt` to this repository's release workflow for that exact tag, and the checksums tie each archive to `checksums.txt`. Each archive also has a GitHub build-provenance attestation: `gh attestation verify <archive> --repo Flurit/applygate`.

## How releases are built

`.github/workflows/release.yml` builds each release from a tag. Builds are reproducible. `checksums.txt` is signed keylessly with cosign (the Sigstore bundle is `checksums.txt.sigstore.json`), each archive has an SBOM and a build-provenance attestation, and tags of published releases are never moved. Each release's own check is recorded in [project/ACCEPTANCE.md](project/ACCEPTANCE.md).
