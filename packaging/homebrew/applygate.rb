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
      url "https://github.com/Flurit/applygate/releases/download/v0.6.1/applygate_0.6.1_darwin_arm64.tar.gz"
      sha256 "cac0e9df0d9e2bf9b19714172f625f2512ed21d866f6ca9b7a82000e08de3967"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.1/applygate_0.6.1_darwin_amd64.tar.gz"
      sha256 "f9d12221b4cf94c9457bb166036c45fe5586e1245cd7e930ba01592894b2a9be"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.1/applygate_0.6.1_linux_arm64.tar.gz"
      sha256 "a06e9e1969df69fad3d0d22b821a497a9e23fdd9ef9f446b854ba292259201f9"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.1/applygate_0.6.1_linux_amd64.tar.gz"
      sha256 "a20499d1a5dc56f6cbbe2079193d4484365c963caf663179baf97e60e18f17d9"
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
