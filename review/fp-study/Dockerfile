# False-positive study runner (review/fp-study/README.md).
#
# Holds only what it takes to clone public Terraform at pinned commits and run
# terraform init/plan/apply/show against the LocalStack sidecar: Terraform,
# pinned and checksummed, plus git, jq, curl and python3 (some modules package
# code with python during plan). No applygate binary: plan-check runs on the
# host against the plan JSON this container writes. No cloud credentials are
# baked in or mounted; the only AWS settings are LocalStack's dummy values set
# by compose.yaml.
FROM ubuntu:24.04

ARG TARGETARCH
ARG TERRAFORM_VERSION=1.16.1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git jq python3 unzip zip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported arch $TARGETARCH" >&2; exit 1 ;; esac; \
    base="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}"; \
    curl -fsSL -o /tmp/tf.zip "${base}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSL -o /tmp/SHA256SUMS "${base}/terraform_${TERRAFORM_VERSION}_SHA256SUMS"; \
    (cd /tmp && grep "terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip\$" SHA256SUMS | awk '{print $1 "  tf.zip"}' | sha256sum -c -); \
    unzip -q /tmp/tf.zip -d /tmp/tf && install -m 755 /tmp/tf/terraform /usr/local/bin/terraform; \
    rm -rf /tmp/tf /tmp/tf.zip /tmp/SHA256SUMS; terraform version

RUN (userdel -r ubuntu 2>/dev/null || true) && useradd -m -u 1000 -s /bin/bash study
USER study
ENV TF_PLUGIN_CACHE_DIR=/home/study/.terraform.d/plugin-cache \
    TF_IN_AUTOMATION=1 TF_INPUT=0 CHECKPOINT_DISABLE=1
RUN mkdir -p /home/study/.terraform.d/plugin-cache
WORKDIR /study
CMD ["bash", "-l"]
