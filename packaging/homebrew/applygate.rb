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
      url "https://github.com/Flurit/applygate/releases/download/v0.4.0/applygate_0.4.0_darwin_arm64.tar.gz"
      sha256 "0fb77685ab541ff2c59e25a96b849f758badcffd41a60e27d432030292e470d2"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.4.0/applygate_0.4.0_darwin_amd64.tar.gz"
      sha256 "468f56b309237b57d2a2390a5ba4fd410ce42445e9163c45cfc6409a45c1714c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.4.0/applygate_0.4.0_linux_arm64.tar.gz"
      sha256 "0f6030138af383c08450cbf2fe19cb8b2b44e8995247e2edaa5a681709d281a8"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.4.0/applygate_0.4.0_linux_amd64.tar.gz"
      sha256 "1b879cb290e1bc3af96bbdd6aa4cc906a3cc107ba02e3a28eaab3c50da89b37c"
    end
  end

  def install
    # The archive also carries a `seatbelt` compatibility shim for the old
    # name; new installs get only `applygate`.
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
