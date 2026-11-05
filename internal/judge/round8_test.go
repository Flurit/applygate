package judge

import "testing"

// Four-character abbreviations reach the judge, and so do abbreviated
// options that run a program.
func TestAbbreviationsRound8(t *testing.T) {
	for _, cmd := range []string{"git push --mi origin", "git push --de origin main", "git push --recei=/tmp/x /tmp/b", "git push --ex /tmp/x /tmp/b",
		"git fetch --upl=/tmp/x /tmp/b", "git pull --upl=/tmp/x"} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q did not reach the judge", cmd)
		}
	}
}
