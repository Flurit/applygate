package config

import (
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewD6BackendGlobCrossesSlash(t *testing.T) {
	ok := globEq("s3://acme-state/*", "s3://acme-state/payments/terraform.tfstate")
	reviewgap.Check(t, "D6", ok, "s3://acme-state/* does not match a key containing /")
}
