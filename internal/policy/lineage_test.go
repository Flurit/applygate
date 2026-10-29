package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Flurit/seatbelt/internal/config"
)

// TestLineageCheckWired checks that the opt-in state pull runs when a local
// state file sits next to a remote backend, and that its finding is reported.
func TestLineageCheckWired(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".terraform"), 0o755)
	os.WriteFile(filepath.Join(dir, ".terraform", "terraform.tfstate"),
		[]byte(`{"version":3,"backend":{"type":"s3","config":{"bucket":"b","key":"k"}}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(`{"version":4,"lineage":"old-lineage","serial":2}`), 0o644)
	os.WriteFile(filepath.Join(dir, config.FileName), []byte("mode: enforce\nstrict: false\ndefault_tier: standard\n"), 0o644)
	cfg, err := config.Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	pulled := 0
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent"}, StatePull: func(engine, d string) ([]byte, error) {
		pulled++
		if d != dir {
			t.Errorf("pull in %q, want %q", d, dir)
		}
		return []byte(`{"version":4,"lineage":"new-lineage","serial":7}`), nil
	}}
	d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform plan", Cwd: dir, CanAsk: true, DirKnown: true}, cfg, deps)
	if pulled != 1 {
		t.Fatalf("state pull ran %d times, want 1", pulled)
	}
	rules := map[string]string{}
	for _, a := range d.Actions {
		for _, f := range a.Findings {
			rules[f.Rule] = string(f.Severity)
		}
	}
	if rules["stale-state"] != "high" || rules["state-lineage"] != "high" {
		t.Fatalf("want stale-state and state-lineage high, got %v", rules)
	}
	// Without the opt-in there is no pull and no lineage finding.
	d2 := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform plan", Cwd: dir, CanAsk: true, DirKnown: true}, cfg, Deps{Env: deps.Env})
	for _, a := range d2.Actions {
		for _, f := range a.Findings {
			if f.Rule == "state-lineage" {
				t.Fatal("state-lineage reported without StatePull")
			}
		}
	}
}
