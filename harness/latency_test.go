package harness

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/hook"
)

// TestCommandLatency measures in-process decision time for command-only
// scenarios (no plan JSON) against the spec's 50 ms p95 target. It does not
// include process start-up, which the agent pays per hook call.
func TestCommandLatency(t *testing.T) {
	p, _ := Load()
	repo, _, home, err := Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var ds []time.Duration
	for i := 0; i < 20; i++ {
		for _, s := range p.Scenarios {
			if len(s.Plans) > 0 {
				continue
			}
			ev := s.Event(repo, home)
			start := time.Now()
			hook.Run(hook.Claude{}, bytes.NewReader(ev), hook.Options{NoLog: true, NoGit: true, Env: map[string]string{"HOME": home}})
			ds = append(ds, time.Since(start))
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	p50, p95 := ds[len(ds)/2], ds[len(ds)*95/100]
	t.Logf("command decisions: n=%d p50=%s p95=%s max=%s", len(ds), p50, p95, ds[len(ds)-1])
	if p95 > 50*time.Millisecond {
		t.Errorf("p95 %s over the 50ms target", p95)
	}
}
