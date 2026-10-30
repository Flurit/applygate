# DRAFT, not published. The Flurit tap repository (Flurit/homebrew-tap) does not
# exist yet; this file is meant to live there as Formula/applygate.rb.
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
      url "https://github.com/Flurit/applygate/releases/download/v0.3.0/applygate_0.3.0_darwin_arm64.tar.gz"
      sha256 "db77af050f6c1097a6db8341e5f15c8951f57b2ff4a9b0cadd5d186484c76710"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.0/applygate_0.3.0_darwin_amd64.tar.gz"
      sha256 "bff3b2681ec8129f8fa3b9e8bc8ae095ab44c8e75b5a384993e28104c7182cf5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.0/applygate_0.3.0_linux_arm64.tar.gz"
      sha256 "3fc5b718d396362c820686b8543ad0ed900880ad9e4315397a85d5af81716ae1"
    end
    on_intel do
      url "https://github.com/Flurit/applygate/releases/download/v0.3.0/applygate_0.3.0_linux_amd64.tar.gz"
      sha256 "c8b2ef90866215bbec04093e77a2250f9f179757dee674d0a29425077098b19d"
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
