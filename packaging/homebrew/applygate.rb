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
      url "https://github.com/Flurit/applygate/releases/download/v0.6.2/applygate_0.6.2_darwin_arm64.tar.gz"
      sha256 "68fcd58e35706419e99845c1910a1dda658b18bb1111783c3cd616b8f52f2516"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.2/applygate_0.6.2_darwin_amd64.tar.gz"
      sha256 "ed1ca5e4f002fd293b8f97577a738e48150308a6c3ddd03a1d7650fbfcdadf18"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.2/applygate_0.6.2_linux_arm64.tar.gz"
      sha256 "7aef8aa45b306afda92c273b4f8ced01d05dcd0a63cb310bbf202e83e1733db3"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.2/applygate_0.6.2_linux_amd64.tar.gz"
      sha256 "3462896130434e7c40ece7b97888c77ca351bfb2b95bad4aeb8805d1c82e2f5f"
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
