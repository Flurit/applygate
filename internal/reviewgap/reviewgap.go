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
	"B1":  "Monitor and PowerShell tools are never judged",
	"B2":  "apply_patch run from the shell skips the guard check",
	"B3":  "an unreadable Claude or Codex shell command is allowed",
	"B4":  "MCP inputs with non-string command or path fields fail the typed decode",
	"B5":  "text typed into a running process (tmux, screen) is not judged",
	"C1":  "program names are matched case-sensitively",
	"C2":  "word resolution differs from the shell",
	"C3":  "background statements, functions and popd corrupt directory and variable state",
	"C4":  "case words, declaration arguments, C-style loops and trap are not walked",
	"C5":  "read, printf -v, mapfile and declare -n leave stale values",
	"C6":  "xargs -I and parallel placeholders are not modelled",
	"C7":  "interpreter options and missing interpreters",
	"C8":  "programs that run commands through their own options",
	"C9":  "terragrunt working directory and unresolved -chdir",
	"C10": "make flags",
	"C11": "files written earlier in the same command are read as before",
	"C12": "parse failures and exhausted budgets are judged at the current directory",
	"C13": "aliases are split on whitespace and self-referential aliases dropped",
	"C14": "cloud CLI verbs and flags, TF_CLI_ARGS",
	"D1":  "the nearest .applygate.yaml replaces the repository config",
	"D2":  "a repository config can loosen mode, aliases and other fields",
	"D3":  "the config is chosen from the event's directory, not the action's",
	"D4":  "symlinked directories escape tier path matchers",
	"D5":  "TF_DATA_DIR is ignored for the backend",
	"D6":  "backend pattern s3://bucket/* misses keys containing /",
	"D7":  "suggest writes logged values into its proposal unescaped",
	"D8":  "--kubeconfig and --configuration are ignored for the target",
	"E1":  "a planfile written earlier in the same command is judged as it was",
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
