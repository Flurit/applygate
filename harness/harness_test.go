package harness

import "testing"

// TestScenarioPack is the regression test: every scenario must produce one
// of its expected verdicts through the Claude Code hook entry point.
func TestScenarioPack(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Replay(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out {
		if !o.Pass {
			t.Errorf("%s %s (%s): got %s, want %v\n%s", o.Scenario.ID, o.Scenario.Title, o.Scenario.Kind, o.Verdict, o.Scenario.Expect, o.Message)
		}
	}
	s := Score(out)
	t.Logf("dangerous caught %d/%d (exact %d), benign flagged %d/%d", s.DangerousCaught, s.Dangerous, s.DangerousExact, s.BenignFlagged, s.Benign)
}
