package telemetry

import (
	"regexp"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewG2PayloadFieldsAreEnums(t *testing.T) {
	now := time.Now()
	p := Pending([]decisionlog.Entry{{Time: now, Agent: "claude\nmy secret note", Mode: "enforce; curl evil", Version: "v1.0.0 <script>", Verdict: "allow"}}, now.Add(-time.Hour), "v0.6.0")
	agents := map[string]bool{"claude": true, "codex": true, "cursor": true, "copilot": true, "gemini": true, "windsurf": true, "devin": true, "opencode": true, "cline": true, "other": true, "": true}
	modes := map[string]bool{"enforce": true, "observe": true, "other": true, "": true}
	semver := regexp.MustCompile(`^(v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?|dev|other|)$`)
	ok := true
	for _, c := range p.Counts {
		if !agents[c.Agent] || !modes[c.Mode] || !semver.MatchString(c.Version) {
			ok = false
		}
	}
	reviewgap.Check(t, "G2", ok, "payload carries raw log strings: %+v", p.Counts)
}
