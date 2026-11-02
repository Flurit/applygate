package suggest

import (
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewD7LoggedValuesEscaped(t *testing.T) {
	evil := "team\nname_hints: false\naliases: {terraform: ls} #"
	var entries []decisionlog.Entry
	for i := 0; i < 3; i++ {
		entries = append(entries, decisionlog.Entry{Time: time.Now(), Agent: "claude", Cwd: "/repo/stacks/app", Verdict: policy.Allow, Enforced: policy.Allow, Mode: "observe",
			Actions: []policy.ActionResult{{Class: classify.ReadOnly, Engine: "terraform", Command: "terraform plan", Dir: "/repo/stacks/app", Tier: config.Disposable, Profile: evil, Verdict: policy.Allow}}})
	}
	y := Build(entries, Options{Root: "/repo"}).YAML()
	injected := false
	for _, line := range strings.Split(y, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "name_hints:") || strings.HasPrefix(strings.TrimSpace(line), "aliases:") {
			injected = true
		}
	}
	reviewgap.Check(t, "D7", !injected, "a logged value became config lines:\n%s", y)
}
