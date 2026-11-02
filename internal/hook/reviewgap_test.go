package hook

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewF4OversizedCallIsNotAllowed(t *testing.T) {
	// The call's own size makes the endpoint fail; in a protected tier that
	// must not leave the call allowed.
	root, opt := judgeSetup(t, "enforce", "")
	f := &fakeJudge{err: "openai: 400 Bad Request: request too large"}
	cmd := "pulumi destroy --yes --stack acme/prod # " + strings.Repeat("x", 300_000)
	o, _ := runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": cmd})
	got := decision(t, o)
	reviewgap.Check(t, "F4", got != "allow", "an oversized call the judge could not read was %s", got)
}
