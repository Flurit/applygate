# Agent-driven observe-mode trial container (review/agent-trial/README.md).
#
# Build context is the repository root (see compose.yaml). The image holds:
#   - the applygate v0.1.3 release binary, installed by the repository's
#     install.sh with APPLYGATE_VERIFY_SIGNATURE=require (cosign keyless
#     signature on checksums.txt, then sha256);
#   - Terraform, pinned and checksummed;
#   - Claude Code and Codex from npm, pinned;
#   - the five trial repositories from review/oss-corpus/repos.txt at their
#     pinned commits, each with its trial config as .applygate.yaml switched to
#     mode: observe, and the Claude Code and Codex hooks installed at project
#     scope by `applygate hook install`.
#
# No cloud credentials are baked in or mounted. The only AWS settings are the
# LocalStack dummy values set by compose.yaml at run time.
FROM ubuntu:24.04

ARG TARGETARCH
# v0.2.0 is the first release under the applygate name; the 2026-10-29 results
# in results/ were produced with the seatbelt v0.1.3/v0.1.4 binaries.
ARG APPLYGATE_VERSION=v0.2.0
ARG TERRAFORM_VERSION=1.16.1
ARG COSIGN_VERSION=v3.1.4
ARG CLAUDE_CODE_VERSION=2.1.312
ARG CODEX_VERSION=0.165.0
ARG NODE_MAJOR=22

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git gnupg jq python3 unzip less vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# cosign (needed by install.sh for signature verification), checksummed against
# the release's cosign_checksums.txt which is fetched over TLS from GitHub.
RUN set -eu; \
    case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; esac; \
    base="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}"; \
    curl -fsSL -o /tmp/cosign "${base}/cosign-linux-${TARGETARCH}"; \
    curl -fsSL -o /tmp/cosign_checksums.txt "${base}/cosign_checksums.txt"; \
    (cd /tmp && grep " cosign-linux-${TARGETARCH}\$" cosign_checksums.txt | awk '{print $1 "  cosign"}' | sha256sum -c -); \
    install -m 755 /tmp/cosign /usr/local/bin/cosign; rm -f /tmp/cosign /tmp/cosign_checksums.txt; \
    cosign version

# Terraform, checksummed against HashiCorp's SHA256SUMS for the release.
RUN set -eu; \
    base="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}"; \
    curl -fsSL -o /tmp/tf.zip "${base}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSL -o /tmp/SHA256SUMS "${base}/terraform_${TERRAFORM_VERSION}_SHA256SUMS"; \
    (cd /tmp && grep "terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip\$" SHA256SUMS | awk '{print $1 "  tf.zip"}' | sha256sum -c -); \
    unzip -q /tmp/tf.zip -d /tmp/tf && install -m 755 /tmp/tf/terraform /usr/local/bin/terraform; \
    rm -rf /tmp/tf /tmp/tf.zip /tmp/SHA256SUMS; terraform version

# Node.js (for the agents) from NodeSource, then the two agents, pinned.
RUN set -eu; \
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" -o /tmp/nodesource.sh; \
    bash /tmp/nodesource.sh >/dev/null; rm -f /tmp/nodesource.sh; \
    apt-get install -y --no-install-recommends nodejs; rm -rf /var/lib/apt/lists/*; \
    npm install -g --no-fund --no-audit "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" "@openai/codex@${CODEX_VERSION}"; \
    claude --version; codex --version

# applygate: the repository's install.sh, signature verification required.
COPY install.sh /tmp/install.sh
RUN set -eu; \
    APPLYGATE_VERSION="$APPLYGATE_VERSION" APPLYGATE_VERIFY_SIGNATURE=require APPLYGATE_INSTALL_DIR=/usr/local/bin sh /tmp/install.sh; \
    rm -f /tmp/install.sh; applygate version; applygate selftest

# Unprivileged user; the agents and terraform run as this user.
RUN (userdel -r ubuntu 2>/dev/null || true) && useradd -m -u 1000 -s /bin/bash trial && chown trial:trial /home/trial \
    && mkdir -p /work && chown trial:trial /work
USER trial
WORKDIR /home/trial
ENV PATH=/home/trial/.local/bin:/usr/local/bin:/usr/bin:/bin \
    TF_PLUGIN_CACHE_DIR=/home/trial/.terraform.d/plugin-cache \
    TF_IN_AUTOMATION=1 CHECKPOINT_DISABLE=1
RUN mkdir -p /home/trial/.terraform.d/plugin-cache /home/trial/.local/state/applygate /home/trial/.claude /home/trial/.codex

# The five repositories at pinned commits, each with its observe-mode config
# and both hooks. setup-repos.sh refuses to run if any AWS credential is set.
COPY --chown=trial:trial review/oss-corpus/repos.txt /home/trial/trial/repos.txt
COPY --chown=trial:trial review/oss-corpus/configs/ /home/trial/trial/configs/
COPY --chown=trial:trial review/agent-trial/tools/ /home/trial/trial/tools/
COPY --chown=trial:trial review/agent-trial/plangate/ /work/plangate/
COPY --chown=trial:trial review/agent-trial/tasks.md /home/trial/trial/tasks.md
RUN sh /home/trial/trial/tools/setup-repos.sh /work /home/trial/trial/repos.txt /home/trial/trial/configs

WORKDIR /work
CMD ["bash", "-l"]
