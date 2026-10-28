package harness

import (
	"os"
	"strings"
	"testing"
)

func TestDump(t *testing.T) {
	if os.Getenv("DUMP") == "" {
		t.Skip()
	}
	p, _ := Load()
	out, _ := Replay(p, t.TempDir())
	for _, o := range out {
		m := strings.ReplaceAll(o.Message, "\n", "\n      ")
		t.Logf("%s %-5s %s\n      %s", o.Scenario.ID, o.Verdict, o.Scenario.Title, m)
	}
}
