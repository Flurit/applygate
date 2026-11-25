# Published as Formula/applygate.rb in Flurit/homebrew-tap (brew install Flurit/tap/applygate).
# Keep the two in step: the tap's copy replaces these first three lines with a one-line source note.
#
# It installs the signed release binaries (macOS and Linux, amd64 and arm64).
# Homebrew checks the sha256 below, which catches corruption; the cosign
# signature on checksums.txt (see the README) is what protects against a
# tampered release, and is not checked by Homebrew.
#
# To update for a release: bump the version in the four URLs, then copy each archive's sha256 from
# the release's checksums.txt.
class Applygate < Formula
  desc "Deterministic local pre-apply gate for Terraform and OpenTofu"
  homepage "https://github.com/Flurit/applygate"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.7.0/applygate_0.7.0_darwin_arm64.tar.gz"
      sha256 "74239fd8f24ce4f67acdf6de23fa4329ac2829653289c74ee935635546377422"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.7.0/applygate_0.7.0_darwin_amd64.tar.gz"
      sha256 "8a9d3d2ffbc06dbf825a6bfb30bdac24be453eb8e93ff6df552a2be6d65fa049"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.7.0/applygate_0.7.0_linux_arm64.tar.gz"
      sha256 "abac90da7a9d17a5d3bab09b0fee1d51527ea3977b34372cdc8c87dfdabca2e5"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.7.0/applygate_0.7.0_linux_amd64.tar.gz"
      sha256 "055c2581e0978ea42a6817d8374a1f7032409d99a43553b55c69b5db29c0ecc8"
    end
  end

  def install
    bin.install "applygate"
  end

  def caveats
    <<~EOS
      Install the hook into your agent with:
        applygate init
      then check it with:
        applygate doctor
      `applygate init` edits ~/.claude/settings.json and ~/.codex/hooks.json
      at user scope; `applygate init --scope project` keeps it in one repository.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/applygate version")
    assert_match "exact expectation", shell_output("#{bin}/applygate selftest")
  end
end
