// Package reviewgap tracks which findings of the v0.6.0 pre-release review
// (review/v0.6.0/2026-11-02-pre-release-review.md) are not fixed yet, so the
// tests that reproduce them can live in the suite before the fixes do.
//
// A test of an open finding that still fails is skipped and reported. A test
// of an open finding that passes fails, so the finding is taken off the list
// in the same change that fixes it, and a fixed finding cannot regress
// silently. Tests of findings not on the list must pass.
package reviewgap

import (
	"sort"
	"testing"
)

// Open lists the findings not fixed yet, by review ID.
var Open = map[string]string{
	"A13": "the judge cache can be pre-filled with allow entries",
	"D4":  "symlinked directories escape tier path matchers",
	"D5":  "TF_DATA_DIR is ignored for the backend",
	"D6":  "backend pattern s3://bucket/* misses keys containing /",
	"D7":  "suggest writes logged values into its proposal unescaped",
	"D8":  "--kubeconfig and --configuration are ignored for the target",
	"E3":  "replacing a resource is judged more leniently than deleting it",
	"E4":  "protected_resources entries miss count and for_each instances",
	"E5":  "unknown values hide exposure and protection removal",
	"F1":  "the judge filter's local programs can run arbitrary commands",
	"F2":  "shell writes skip the judge and test runners run them",
	"F3":  "the judge filter's outside() ignores cd",
	"F4":  "oversized input, refusals and unreadable answers leave the rule decision",
	"F5":  "create_run destroy flags other than literal true are judged as plan",
	"F6":  "EKS and GKE translations drop the named cluster",
	"F7":  "infrastructure credential reads skip the judge",
	"F8":  "the judge sees no content for Copilot, OpenCode and Cline edits",
	"F9":  "call_aws input that is not an aws command is allowed",
	"G1":  "redaction misses common secret forms",
	"G2":  "telemetry forwards raw strings from the log",
	"I2":  "ci-plan-check.sh outputs can be injected through the plan text",
}

// Check reports one test of finding id. ok is whether the behaviour the
// review asks for holds.
func Check(t testing.TB, id string, ok bool, format string, args ...any) {
	t.Helper()
	_, open := Open[id]
	switch {
	case ok && open:
		t.Errorf("finding %s now passes: remove it from reviewgap.Open", id)
	case !ok && open:
		t.Skipf("open finding %s (%s): "+format, append([]any{id, Open[id]}, args...)...)
	case !ok:
		t.Errorf("finding %s regressed: "+format, append([]any{id}, args...)...)
	}
}

// IDs returns the open finding IDs, sorted.
func IDs() []string {
	var out []string
	for id := range Open {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
