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
      url "https://github.com/Flurit/applygate/releases/download/v0.5.0/applygate_0.5.0_darwin_arm64.tar.gz"
      sha256 "0815ed79faca20c738a823a8e70e292f77e59e540b4f8c17d7f9c79e1a5aae90"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.5.0/applygate_0.5.0_darwin_amd64.tar.gz"
      sha256 "e0a7700599adc6f9252f65c90f0b09ab97829f2d5a6d0c45785fbe48436c5bd3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.5.0/applygate_0.5.0_linux_arm64.tar.gz"
      sha256 "10ae6e7a0f8207d521aef2fe45ba39550092f88aeac29aab62ec94cb4f513563"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.5.0/applygate_0.5.0_linux_amd64.tar.gz"
      sha256 "2b7ca1b31ceb51d8fbf0772dd8a1f69909bb4bee2d39a24a4321410ed86bce60"
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
