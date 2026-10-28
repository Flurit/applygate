package shell

import (
	"strings"
	"testing"
	"time"
)

// TestRobustnessBounds checks that pathological inputs found in independent
// review (F5 deep pipelines, F6 nested braces) are analyzed in bounded time
// and that truncation stays fail-closed (a problem is recorded, which the
// policy turns into ask rather than a silent allow).
func TestRobustnessBounds(t *testing.T) {
	opt := Options{Dir: "/r", Env: map[string]string{"HOME": "/h"}, ReadFile: fakeFS(nil), MaxDepth: 8}

	run := func(cmd string) *Result {
		done := make(chan *Result, 1)
		go func() { done <- Analyze(cmd, opt) }()
		select {
		case r := <-done:
			return r
		case <-time.After(5 * time.Second):
			t.Fatalf("Analyze did not finish in 5s for a %d-byte command", len(cmd))
			return nil
		}
	}

	// F5: a very deep pipeline must not blow the budget's time; it truncates
	// with a problem (fail-closed) rather than running for seconds.
	t.Run("deep_pipeline", func(t *testing.T) {
		r := run("echo x" + strings.Repeat(" | cat", 60000))
		if len(r.Problems) == 0 {
			t.Fatalf("expected a truncation problem for a 60k-stage pipeline")
		}
	})

	// A modest pipeline is still fully analyzed: a destroy is still seen.
	t.Run("modest_pipeline_still_detected", func(t *testing.T) {
		r := run("terraform destroy -auto-approve" + strings.Repeat(" | cat", 20))
		if !strings.Contains(strings.Join(render(r), "\n"), "terraform destroy -auto-approve") {
			t.Fatalf("destroy not detected through a 20-stage pipe:\n%s", strings.Join(render(r), "\n"))
		}
	})

	// F6: deeply nested braces must not allocate or run away; completes bounded
	// and yields the echo invocation with the braces left literal.
	t.Run("nested_braces", func(t *testing.T) {
		r := run("echo " + strings.Repeat("{", 20000) + "a" + strings.Repeat("}", 20000))
		if len(r.Invocations) == 0 {
			t.Fatalf("expected an echo invocation for nested braces")
		}
	})

	// Real brace expansion still works.
	t.Run("real_brace_expansion", func(t *testing.T) {
		r := run("terraform -chdir=envs/{dev,prod} version")
		got := strings.Join(render(r), "\n")
		if !strings.Contains(got, "envs/dev") || !strings.Contains(got, "envs/prod") {
			t.Fatalf("brace expansion broken:\n%s", got)
		}
	})
}
