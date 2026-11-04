package judge

import (
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// git accepts any unambiguous prefix of a long option, so --mirr is --mirror;
// a push that rewrites remote history must reach the judge.
func TestPushAbbreviationsReachTheJudge(t *testing.T) {
	for _, cmd := range []string{"git push --mirror origin", "git push --mirr origin", "git push --pru origin x", "git push --delet origin main",
		"git push --force-with origin main", "/usr/bin/env | cat", "env | cat"} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q did not reach the judge", cmd)
		}
	}
	for _, cmd := range []string{"git push origin feature/x", "git push --set-upstream origin feature/x", "git push --dry-run origin"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q reached the judge", cmd)
		}
	}
}

// Strict shapes adds a complex-shape action to a shell command that is not
// plain; it must not keep the judge from seeing an unknown program.
func TestResidualIgnoresComplexShape(t *testing.T) {
	d := policy.Decision{Verdict: policy.Allow, Actions: []policy.ActionResult{{Class: "complex-shape", Engine: "shell"}}}
	if !Residual(d) {
		t.Error("a complex-shape action hid the call from the judge")
	}
	d.Actions = append(d.Actions, policy.ActionResult{Class: "destroy", Engine: "terraform"})
	if Residual(d) {
		t.Error("a classified action reached the judge")
	}
}
