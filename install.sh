#!/bin/sh
# install.sh -- install the seatbelt binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/Flurit/seatbelt/<tag>/install.sh | sh
#
# Use a release tag, not main, in that URL, so the script you run is the
# reviewed one for that release.
#
# Environment overrides:
#   SEATBELT_VERSION      release tag to install, e.g. v0.3.0 (default: latest release)
#   SEATBELT_INSTALL_DIR  directory to install into (default: $HOME/.local/bin, or
#                         /usr/local/bin when it is writable and $HOME/.local/bin
#                         is not on PATH)
#   SEATBELT_VERIFY_SIGNATURE
#                         auto (default): verify the cosign signature on
#                         checksums.txt when cosign is installed, warn when it
#                         is not; require: refuse to install without cosign
#
# What is verified:
#   1. checksums.txt is signed keylessly with cosign by this repository's
#      release workflow for exactly this tag. With cosign installed the script
#      checks that signature against the Sigstore bundle, the workflow
#      identity and GitHub's OIDC issuer, and refuses to install on failure.
#      This is what protects against a tampered release: a sha256 alone does
#      not, because checksums.txt comes from the same place as the archive.
#   2. The archive's sha256 must match checksums.txt.
# Without cosign only step 2 runs, which catches corruption, not tampering.
#
# Works with curl or wget, POSIX sh only (no bash required).
set -eu

REPO="Flurit/seatbelt"
BASE_URL="https://github.com/${REPO}"
API_URL="https://api.github.com/repos/${REPO}"

log() { printf '%s\n' "$*" >&2; }
die() { log "install.sh: error: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

# --- HTTP helpers: curl preferred, wget as fallback --------------------------
if need curl; then
    fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
    fetch_stdout() { curl -fsSL --retry 3 "$1"; }
    # URL after following redirects (used to resolve releases/latest).
    fetch_final_url() { curl -fsSL -o /dev/null -w '%{url_effective}' "$1"; }
elif need wget; then
    fetch() { wget -q -O "$2" "$1"; }
    fetch_stdout() { wget -q -O - "$1"; }
    fetch_final_url() {
        # wget prints "  Location: <url> [following]"; keep only the URL.
        wget --spider -S "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *\([^ ]*\).*/\1/p' | tail -n 1
    }
else
    die "curl or wget is required"
fi

# --- temp dir, cleaned on exit ----------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t seatbelt) || die "cannot create a temp dir"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- platform ----------------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
    linux | darwin) ;;
    *) die "unsupported OS '$os' (releases are built for linux and darwin)" ;;
esac

arch=$(uname -m)
case "$arch" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported architecture '$arch' (releases are built for amd64 and arm64)" ;;
esac

# --- version -----------------------------------------------------------------
resolve_latest() {
    v=""
    # 1) GitHub API: "tag_name": "vX.Y.Z"
    v=$(fetch_stdout "${API_URL}/releases/latest" 2>/dev/null |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1) || true
    # 2) Fallback: releases/latest redirects to releases/tag/vX.Y.Z
    if [ -z "$v" ]; then
        final=$(fetch_final_url "${BASE_URL}/releases/latest" 2>/dev/null) || true
        v=$(printf '%s\n' "$final" | sed -n 's#.*/releases/tag/\([^/?#]*\).*#\1#p')
    fi
    [ -n "$v" ] || die "could not determine the latest release; set SEATBELT_VERSION=vX.Y.Z"
    printf '%s\n' "$v"
}

verify_mode=${SEATBELT_VERIFY_SIGNATURE:-auto}
case "$verify_mode" in
    auto | require) ;;
    *) die "SEATBELT_VERIFY_SIGNATURE must be auto or require, not '${verify_mode}'" ;;
esac
if [ "$verify_mode" = require ] && ! need cosign; then
    die "cosign is not installed and SEATBELT_VERIFY_SIGNATURE=require (https://docs.sigstore.dev/cosign/system_config/installation/)"
fi

if [ -n "${SEATBELT_VERSION:-}" ]; then
    tag=$SEATBELT_VERSION
    case "$tag" in v*) ;; *) tag="v$tag" ;; esac
else
    tag=$(resolve_latest)
fi
case "$tag" in
    *[!A-Za-z0-9._-]* | "" | v) die "invalid release tag '${tag}'" ;;
esac
version=${tag#v} # goreleaser names archives without the leading v

archive="seatbelt_${version}_${os}_${arch}.tar.gz"
download="${BASE_URL}/releases/download/${tag}"

log "seatbelt ${tag} (${os}/${arch})"

# --- download ----------------------------------------------------------------
log "downloading ${archive}"
fetch "${download}/${archive}" "${tmp}/${archive}" ||
    die "download failed: ${download}/${archive}"
fetch "${download}/checksums.txt" "${tmp}/checksums.txt" ||
    die "download failed: ${download}/checksums.txt"

# --- verify the signature on checksums.txt ----------------------------------
identity="${BASE_URL}/.github/workflows/release.yml@refs/tags/${tag}"
issuer="https://token.actions.githubusercontent.com"
bundle="checksums.txt.sigstore.json"
if need cosign; then
    fetch "${download}/${bundle}" "${tmp}/${bundle}" ||
        die "download failed: ${download}/${bundle} (cannot verify the release signature)"
    if cosign verify-blob \
        --bundle "${tmp}/${bundle}" \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "$issuer" \
        "${tmp}/checksums.txt" >/dev/null 2>"${tmp}/cosign.err"; then
        log "signature verified: checksums.txt was signed by ${identity}"
    else
        sed 's/^/  cosign: /' "${tmp}/cosign.err" >&2
        die "signature verification of checksums.txt failed; refusing to install"
    fi
elif [ "$verify_mode" = require ]; then
    die "cosign is not installed and SEATBELT_VERIFY_SIGNATURE=require (https://docs.sigstore.dev/cosign/system_config/installation/)"
else
    log "WARNING: cosign is not installed, so the release signature is NOT verified."
    log "  The sha256 check below catches a corrupted download, not a tampered release."
    log "  Install cosign and rerun, or set SEATBELT_VERIFY_SIGNATURE=require to make this an error."
fi

# --- verify sha256 -----------------------------------------------------------
if need sha256sum; then
    actual=$(sha256sum "${tmp}/${archive}" | awk '{print $1}')
elif need shasum; then
    actual=$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')
else
    die "sha256sum or shasum is required to verify the download"
fi
expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1 }' "${tmp}/checksums.txt" | head -n 1)
[ -n "$expected" ] || die "${archive} is not listed in checksums.txt; refusing to install"
if [ "$actual" != "$expected" ]; then
    log "sha256 mismatch for ${archive}"
    log "  expected: ${expected}"
    log "  actual:   ${actual}"
    die "checksum verification failed; refusing to install"
fi
log "sha256 verified"

# --- extract only the binary -------------------------------------------------
tar -xzf "${tmp}/${archive}" -C "$tmp" seatbelt || die "could not extract seatbelt from ${archive}"
[ -f "${tmp}/seatbelt" ] || die "archive did not contain a seatbelt binary"
chmod 755 "${tmp}/seatbelt"

# --- install dir -------------------------------------------------------------
on_path() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
    esac
    return 1
}

if [ -n "${SEATBELT_INSTALL_DIR:-}" ]; then
    dir=$SEATBELT_INSTALL_DIR
else
    dir="${HOME}/.local/bin"
    if ! on_path "$dir" && [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        dir=/usr/local/bin
    fi
fi

mkdir -p "$dir" || die "cannot create ${dir}"
[ -w "$dir" ] || die "${dir} is not writable (set SEATBELT_INSTALL_DIR to another directory)"

if need install; then
    install -m 755 "${tmp}/seatbelt" "${dir}/seatbelt"
else
    mv -f "${tmp}/seatbelt" "${dir}/seatbelt"
    chmod 755 "${dir}/seatbelt"
fi

# --- report ------------------------------------------------------------------
log ""
log "installed $("${dir}/seatbelt" version 2>/dev/null || printf 'seatbelt %s' "$tag") to ${dir}/seatbelt"
if on_path "$dir"; then
    log "${dir} is on your PATH"
else
    log "${dir} is NOT on your PATH; add it, for example:"
    log "  export PATH=\"${dir}:\$PATH\""
fi
log ""
log "next steps:"
log "  seatbelt init     # install the hook into your agent config"
log "  seatbelt doctor   # check config, hooks and versions"
