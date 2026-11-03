package hook

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewF4OversizedCallIsNotAllowed(t *testing.T) {
	// The call's own size makes the endpoint fail; in a protected tier that
	// must not leave the call allowed.
	root, opt := judgeSetup(t, "enforce", "")
	f := &fakeJudge{err: "openai: 400 Bad Request: request too large"}
	cmd := "pulumi destroy --yes --stack acme/prod # " + strings.Repeat("x", 300_000)
	o, _ := runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": cmd})
	got := decision(t, o)
	reviewgap.Check(t, "F4", got != "allow", "an oversized call the judge could not read was %s", got)
}

// A FIFO at the decision log must not hang the hook (finding 2S18).
func TestReview2S18FifoLogDoesNotHang(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	fifo := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	opt.LogPath, opt.JudgeCache = fifo, "-"
	done := make(chan Output, 1)
	go func() {
		done <- Run(Claude{}, strings.NewReader(event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "terraform destroy -auto-approve"})), opt)
	}()
	var finished bool
	select {
	case <-done:
		finished = true
	case <-time.After(5 * time.Second):
		// Unblock the writer so the goroutine can end.
		if f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			defer f.Close()
		}
	}
	reviewgap.Check(t, "2S18", finished, "the hook was still running after 5 s with a FIFO at the decision log")
}
