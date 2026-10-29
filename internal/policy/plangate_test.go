package policy

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

// writePlanfile writes a minimal saved plan whose "tfplan" entry records the
// given workspace the way Terraform 1.x does (backend message, field 13, with
// the workspace in field 3).
func writePlanfile(t *testing.T, path, workspace string) {
	t.Helper()
	backend := append([]byte{0x1a, byte(len(workspace))}, workspace...) // field 3, length-delimited
	plan := append([]byte{0x6a, byte(len(backend))}, backend...)        // field 13, length-delimited
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("tfplan")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plan)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// createOnlyPlan is a show -json plan that adds one resource and triggers no
// plan-gate rule, so the verdict comes from the workspace check alone.
func createOnlyPlan(string, string, string) ([]byte, error) {
	return json.Marshal(map[string]any{"format_version": "1.2", "resource_changes": []map[string]any{{
		"address": "aws_s3_bucket.a", "mode": "managed", "type": "aws_s3_bucket", "name": "a",
		"change": map[string]any{"actions": []string{"create"}, "before": nil, "after": map[string]any{"bucket": "a", "force_destroy": false}},
	}}})
}

// TestWorkspaceMismatchJudgedByPlanTier checks that applying a plan made in
// another workspace is judged by the more protected of the two workspaces:
// a prod plan applied from staging blocks just as a staging plan applied
// from prod does.
func TestWorkspaceMismatchJudgedByPlanTier(t *testing.T) {
	cases := []struct {
		name, selected, plan string
		verdict              Verdict
		tier                 config.Tier
		matched              string
	}{
		{"prod plan from staging blocks", "staging", "prod", Block, config.Protected, "plan workspace prod"},
		{"staging plan from prod blocks", "prod", "staging", Block, config.Protected, "workspace prod"},
		{"matching workspaces allow", "staging", "staging", Allow, config.Standard, "workspace staging"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, ".terraform"), 0o755)
			os.WriteFile(filepath.Join(dir, ".terraform", "environment"), []byte(c.selected), 0o644)
			os.WriteFile(filepath.Join(dir, config.FileName), []byte(strings.Join([]string{
				"mode: enforce",
				"strict: false",
				"name_hints: false",
				"default_tier: disposable",
				"environments:",
				"  - name: prod",
				"    tier: protected",
				"    match: {workspaces: [prod]}",
				"  - name: staging",
				"    tier: standard",
				"    match: {workspaces: [staging]}",
				"",
			}, "\n")), 0o644)
			writePlanfile(t, filepath.Join(dir, "tfplan"), c.plan)
			cfg, err := config.Load("", dir)
			if err != nil {
				t.Fatal(err)
			}
			deps := Deps{Env: map[string]string{"PATH": "/nonexistent"}, PlanJSON: createOnlyPlan}
			d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform apply tfplan", Cwd: dir, CanAsk: true, DirKnown: true}, cfg, deps)
			if len(d.Actions) != 1 {
				t.Fatalf("got %d actions, want 1: %+v", len(d.Actions), d.Actions)
			}
			a := d.Actions[0]
			if d.Verdict != c.verdict || a.Verdict != c.verdict {
				t.Errorf("verdict %s (action %s), want %s; findings %+v", d.Verdict, a.Verdict, c.verdict, a.Findings)
			}
			if a.Tier != c.tier {
				t.Errorf("tier %s, want %s", a.Tier, c.tier)
			}
			if !slices.Contains(a.Matched, c.matched) {
				t.Errorf("matched %v, want it to contain %q", a.Matched, c.matched)
			}
			if a.Workspace != c.selected {
				t.Errorf("selected workspace %q, want %q", a.Workspace, c.selected)
			}
			var mismatch bool
			for _, f := range a.Findings {
				if f.Rule == "workspace-mismatch" {
					mismatch = true
				}
			}
			if want := c.selected != c.plan; mismatch != want {
				t.Errorf("workspace-mismatch reported %v, want %v; findings %+v", mismatch, want, a.Findings)
			}
		})
	}
}
