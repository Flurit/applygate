package config

import (
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewD6BackendGlobCrossesSlash(t *testing.T) {
	ok := backendMatch("s3://acme-state/*", "s3://acme-state/payments/terraform.tfstate")
	reviewgap.Check(t, "D6", ok, "s3://acme-state/* does not match a key containing /")
}

func TestReviewA4ApprovalsOffByDefault(t *testing.T) {
	// No approval channel on one machine is out of the agent's reach until
	// an OS presence check exists, so approvals are off unless turned on.
	reviewgap.Check(t, "A4", !Default().ApprovalsOn(), "approvals are on by default")
}
