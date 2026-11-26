#!/bin/sh
# The Azure side of docs/credentials.md: the agent reads production and changes
# nothing. It prints what it would run and runs nothing until APPLY=yes is set,
# and it stops while a value is unset, so an unedited copy changes nothing.
#
#   SUBSCRIPTION_ID  the production subscription
#   AGENT            the identity the agent uses: object id, sign-in name or service principal name
#
# Contributor or Owner for a person comes through Privileged Identity
# Management activation with MFA, which the person does in the Azure portal.
# It is not a command here: the audit sees a role only while it is active.
set -eu
: "${SUBSCRIPTION_ID:?set SUBSCRIPTION_ID}" "${AGENT:?set AGENT}"

run() {
	if [ "${APPLY:-}" = yes ]; then "$@"; else echo "would run: $*"; fi
}

run az role assignment create --assignee "$AGENT" --role Reader --scope "/subscriptions/$SUBSCRIPTION_ID"
