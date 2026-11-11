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
      url "https://github.com/Flurit/applygate/releases/download/v0.6.0/applygate_0.6.0_darwin_arm64.tar.gz"
      sha256 "ccd114a292a3744c6631d474ebf6f87080c24de986fc173bdc5cb60995a57068"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.0/applygate_0.6.0_darwin_amd64.tar.gz"
      sha256 "ba5805132a8c9b406406c0cdfd498712477283dbaf9ea5df651cb6f92aca26ac"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.0/applygate_0.6.0_linux_arm64.tar.gz"
      sha256 "01c417ccfcb43751d94e50477c3f5916433c589b9f9ee9a639a543d14d948a30"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.0/applygate_0.6.0_linux_amd64.tar.gz"
      sha256 "a719dbecae034517d345003965594437428bb4d4df9a95e571427b57475707a9"
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
