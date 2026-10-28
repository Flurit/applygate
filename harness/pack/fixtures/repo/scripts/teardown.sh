#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../envs/prod"
terraform destroy -auto-approve
