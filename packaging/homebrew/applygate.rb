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
      url "https://github.com/Flurit/applygate/releases/download/v0.3.2/applygate_0.3.2_darwin_arm64.tar.gz"
      sha256 "f9fc2dbc13c6d33cb19a983c5bad61fa031c64090d2fa88815de55f3b238e6b8"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.2/applygate_0.3.2_darwin_amd64.tar.gz"
      sha256 "350e793bf4629b4ed42bf32551b095c402051c68b51dc3a591ceadeb12d732fd"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.2/applygate_0.3.2_linux_arm64.tar.gz"
      sha256 "6f447d30d24fe8743865a6dcb44512928b45f10724eb3cd77a430ab5db7c597c"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.2/applygate_0.3.2_linux_amd64.tar.gz"
      sha256 "a6eaa20ea367dd0398d0188ad1678e996a1566ae962ed1b7e19e90db46c6ad80"
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
