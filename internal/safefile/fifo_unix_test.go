//go:build !windows

package safefile

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRefusesAFifo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 2)
	go func() { _, err := ReadFile(p); done <- err }()
	go func() { _, err := OpenAppend(p, 0o600); done <- err }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Error("a FIFO was opened")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("blocked on a FIFO")
		}
	}
}
