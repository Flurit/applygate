package hook

import (
	"io"
	"strings"
	"testing"
	"time"
)

// A run that does not finish within its budget is answered by the watchdog
// with a block (6C17): here the input never ends.
func TestWatchdogBlocks(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	start := time.Now()
	o := RunWithin(Codex{}, r, Options{Budget: 200 * time.Millisecond, NoLog: true})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the watchdog took %s", d)
	}
	if !strings.Contains(string(o.Stdout)+o.Stderr, "did not finish") || o.Exit == 0 && !strings.Contains(string(o.Stdout), "deny") {
		t.Fatalf("not a block: exit %d stdout %s stderr %s", o.Exit, o.Stdout, o.Stderr)
	}
}
