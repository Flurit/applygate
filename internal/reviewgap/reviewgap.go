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
	"I2": "ci-plan-check.sh outputs can be injected through the plan text",
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
