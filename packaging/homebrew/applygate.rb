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
      url "https://github.com/Flurit/applygate/releases/download/v0.3.1/applygate_0.3.1_darwin_arm64.tar.gz"
      sha256 "97d525f62f08c0b073566457e1301a7893096919f5bf5da209f51532f59fda1f"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.1/applygate_0.3.1_darwin_amd64.tar.gz"
      sha256 "2a1b8aadd23c72b312137081f007ffba63155f0b4e6626cc120d6751241ee20e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.1/applygate_0.3.1_linux_arm64.tar.gz"
      sha256 "06c1fd8d46a55a5f09783dc51d6428b8bf9d841f6ea1d5df32e36cc65b74d9fd"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.1/applygate_0.3.1_linux_amd64.tar.gz"
      sha256 "a355ad95e3097878a21313b9b380e172ddd37fd7c63db082bb7d5289577e9b7b"
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
