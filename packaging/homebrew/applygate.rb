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
      url "https://github.com/Flurit/applygate/releases/download/v0.6.3/applygate_0.6.3_darwin_arm64.tar.gz"
      sha256 "ddbecaef9c4ea37aed74620d44134c12a0c3a64a40e3b09dcc5877fa415d41c3"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.3/applygate_0.6.3_darwin_amd64.tar.gz"
      sha256 "a30c176a5a45c546cdf63b19f6c099bc3f3fba0f356900275db16be3eda62cc8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.3/applygate_0.6.3_linux_arm64.tar.gz"
      sha256 "77d9c384d86f477202eece45625dd71157ab9c368d7f5e6a648cf0b67289726a"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.6.3/applygate_0.6.3_linux_amd64.tar.gz"
      sha256 "97f50471a9a83ade7fe5acf2db05f04492ee00959408f29a481c965d08eaa425"
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
