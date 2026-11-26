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
      url "https://github.com/Flurit/applygate/releases/download/v0.8.0/applygate_0.8.0_darwin_arm64.tar.gz"
      sha256 "4477e8aba3dd6ad3dae17fa14513ad89774813b7614ebe2f1720296f98895560"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.8.0/applygate_0.8.0_darwin_amd64.tar.gz"
      sha256 "6a89cc6b0cd9bf3c6968d66f6ec9beea5c542f46847dfe88434d9cd1feea2b0c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.8.0/applygate_0.8.0_linux_arm64.tar.gz"
      sha256 "ec408121260df531affb9be5e26a4f9a5cd5951b268a8fb9a45df88a450e720d"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.8.0/applygate_0.8.0_linux_amd64.tar.gz"
      sha256 "b4aaa89c6a68ef031f3df8fabb0a4f3051a048e0c931ea4c9359d1eb473b69ad"
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
