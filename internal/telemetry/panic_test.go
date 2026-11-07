package telemetry

import (
	"path/filepath"
	"testing"
	"time"
)

// A panic after the verdict is out is dropped: AfterDecision returns, with
// nothing for the caller to change.
func TestAfterDecisionPanicIsContained(t *testing.T) {
	isolate(t)
	PanicHook = func(string) { panic("injected") }
	defer func() { PanicHook = nil }()
	AfterDecision(filepath.Join(t.TempDir(), "log.jsonl"), "test", map[string]string{}, time.Now().Add(time.Second))
}
