// Package reviewgap tracks which findings of the v0.6.0 reviews
// (review/v0.6.0/2026-11-02-pre-release-review.md, and round 2 in
// review/v0.6.0/2026-11-03-red-team-round-2.md, IDs starting with 2) are not
// fixed yet, so the tests that reproduce them can live in the suite before the
// fixes do.
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
	"2S8":  "package managers remove or replace the hook binary",
	"2S9":  "a fake applygate planted on PATH",
	"2S10": "a renamed copy runs init or hook remove",
	"2S11": "self-approval through tmux command strings",
	"2S12": "nested agent sessions without hooks",
	"2S14": "a nested repository config declares wrappers over runners",
	"2C1":  "trap bodies are judged where they are set",
	"2C2":  "aws s3 cp with a valued flag is read as a download",
	"2C3":  "git options that run programs are missed",
	"2C5":  ".ONESHELL recipes keep no directory across lines",
	"2C6":  "make -C into a symlink made in the same command",
	"2C7":  "PowerShell bodies are parsed as bash",
	"2C9":  "unknown valued flags shift aws and helm positionals",
	"2T1":  "a backend the parser cannot read falls back to the path tier",
	"2T4":  "a symlink to an unmatched directory is judged at the link's tier",
	"2T12": "plan-check treats replaces more leniently than the hook",
	"2T14": "plan-check accepts an unknown tier",
	"2M1":  "wcgw send_ascii is translated to true",
	"2M2":  "decoy arguments reroute MCP calls to a milder rule",
	"2M3":  "a fake workdir picks the tier",
	"2M4":  "shell servers' stdin is ignored",
	"2M6":  "call_kubectl without the kubectl prefix",
	"2M7":  "shell MCP tools outside the table are not judged",
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
