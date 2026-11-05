package judge

import (
	"testing"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/policy"
)

// A recognized action that the rules allow (an aws s3 cp in a standard
// directory) must not take an unrecognized program out of the judge's sight.
func TestResidualForAllowedWriteAction(t *testing.T) {
	d := policy.Decision{Verdict: policy.Allow, Actions: []policy.ActionResult{
		{Class: classify.CloudWrite, Engine: "aws", Verdict: policy.Allow},
	}}
	for cmd, want := range map[string]bool{
		"aws s3 cp x s3://b/x && pulumi destroy --yes": true,
		"aws s3 cp x s3://b/x":                         false,
	} {
		if got := ResidualFor(d, Input{Command: cmd, Cwd: "/repo"}); got != want {
			t.Errorf("%s: residual %v, want %v", cmd, got, want)
		}
	}
}
