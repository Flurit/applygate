#!/bin/sh
# The Google Cloud side of docs/credentials.md: a read-only agent, and applies
# that only a person can start. Read it, then run it. It prints what it would
# run and runs nothing until APPLY=yes is set, and it stops while a value is
# unset, so an unedited copy changes nothing.
#
#   PROJECT       the production project
#   AGENT_SA      the service account the agent uses (name@PROJECT.iam.gserviceaccount.com)
#   APPLY_SA      the service account that applies
#   PERSON        the person who may apply, as an email
#   STATE_BUCKET  the Terraform state bucket
set -eu
: "${PROJECT:?set PROJECT}" "${AGENT_SA:?set AGENT_SA}" "${APPLY_SA:?set APPLY_SA}" "${PERSON:?set PERSON}" "${STATE_BUCKET:?set STATE_BUCKET}"

run() {
	if [ "${APPLY:-}" = yes ]; then "$@"; else echo "would run: $*"; fi
}

# The agent reads the project and the state, and changes nothing.
run gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$AGENT_SA" --role=roles/viewer --condition=None
run gcloud storage buckets add-iam-policy-binding "gs://$STATE_BUCKET" --member="serviceAccount:$AGENT_SA" --role=roles/storage.objectViewer --condition=None

# Applies go by impersonation, and only the person may impersonate the apply
# account. Never grant the agent this role, or roles/iam.serviceAccountUser,
# on APPLY_SA: the audit reports it as getAccessToken and actAs.
run gcloud iam service-accounts add-iam-policy-binding "$APPLY_SA" --member="user:$PERSON" --role=roles/iam.serviceAccountTokenCreator --condition=None
