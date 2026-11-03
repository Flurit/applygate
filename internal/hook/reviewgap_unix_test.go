//go:build !windows

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
