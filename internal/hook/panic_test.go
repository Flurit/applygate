package hook

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// Every recovered panic fails closed where a protected tier is in reach, in
// every on_error setting, whichever stage panicked, and never turns a verdict
// that was a refusal into an allow. Observe mode, which never blocks, is the
// one exception.
func TestInjectedPanicsNeverAllowInProtectedTier(t *testing.T) {
	hookSites := []string{"parse", "policy", "judge", "finish"}
	policySites := []string{"decide", "engine-state"}
	run := func(t *testing.T, site, onErr, mode, dir, command string) string {
		t.Helper()
		root := setup(t, mode, onErr)
		hit := func(s string) {
			if s == site {
				panic("injected at " + s)
			}
		}
		if contains(hookSites, site) {
			PanicHook = hit
			defer func() { PanicHook = nil }()
		} else {
			policy.PanicHook = hit
			defer func() { policy.PanicHook = nil }()
		}
		in := event("Bash", filepath.Join(root, dir), map[string]any{"command": command})
		o := Run(Claude{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{},
			UserConfig: userConfig(t, "mode: "+mode+"\non_error: "+onErr+"\n")})
		return decision(t, o)
	}
	for _, site := range append(append([]string{}, hookSites...), policySites...) {
		for _, onErr := range []string{"auto", "block", "allow"} {
			for _, dir := range []string{"prod", "dev"} {
				// The root holds prod, so a command run from dev could reach it.
				name := site + "/" + onErr + "/" + dir
				t.Run(name, func(t *testing.T) {
					got := run(t, site, onErr, "enforce", dir, "terraform plan")
					if got == "allow" {
						t.Fatalf("a panic at %s allowed the call (on_error %s, %s)", site, onErr, dir)
					}
				})
			}
		}
		t.Run(site+"/observe", func(t *testing.T) {
			// Observe mode never blocks; it must still not crash.
			if got := run(t, site, "auto", "observe", "prod", "terraform plan"); got != "allow" {
				t.Fatalf("observe mode: got %s", got)
			}
		})
	}
	// A panic after the policy refused is still a refusal, in a tier where a
	// failure alone would allow (no protected tier under the root).
	t.Run("panic after a refusal does not allow", func(t *testing.T) {
		got := func() string {
			root := t.TempDir()
			PanicHook = func(s string) {
				if s == "judge" {
					panic("injected")
				}
			}
			defer func() { PanicHook = nil }()
			in := event("Bash", root, map[string]any{"command": "terraform destroy -auto-approve"})
			o := Run(Claude{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{},
				UserConfig: userConfig(t, "mode: enforce\non_error: allow\n")})
			return decision(t, o)
		}()
		if got == "allow" {
			t.Fatal("a panic in the judge turned a refused destroy into an allow")
		}
	})
}

// A panic in the failure path itself (the decision log, rendering) still ends
// in a block, and a panic in the watchdog goroutine's Run does too.
func TestPanicInFailurePathBlocks(t *testing.T) {
	root := setup(t, "enforce", "auto")
	n := 0
	PanicHook = func(s string) {
		if s == "finish" || s == "parse" {
			n++
			panic("again")
		}
	}
	defer func() { PanicHook = nil }()
	in := event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "terraform plan"})
	o := RunWithin(Claude{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{},
		UserConfig: userConfig(t, "mode: enforce\non_error: allow\n")})
	if o.Exit != 2 {
		t.Fatalf("got exit %d, want a block (stderr %q)", o.Exit, o.Stderr)
	}
}
