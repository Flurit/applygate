package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/seatbelt/internal/config"
)

// The agent-driven trial of 2026-10-29 found two false-positive sources: a
// file-only Python edit that mentions terraform asked in a protected tier,
// and a directory under non-prod/ was tiered protected by the prod name
// hint. Both are judged here end to end through Decide.
func TestFileOnlyEditAllowedWithNoteAndNonProdIsStandard(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"envs/prod", "non-prod/us-east-1/qa"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, config.FileName), []byte(strings.Join([]string{
		"mode: enforce",
		"strict: true",
		"environments:",
		"  - name: prod",
		"    tier: protected",
		"    match: {paths: [\"envs/prod/**\"]}",
		"  - name: non-prod",
		"    tier: standard",
		"    match: {paths: [\"non-prod/**\"]}",
		"",
	}, "\n")), 0o644)
	cfg, err := config.Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent", "HOME": dir}}
	edit := "python3 -I - <<'EOF'\np='mysql-replica/terragrunt.hcl'\ns=open(p).read()\ni=s.index('# ----', s.index('terraform {'))\ns=s[:i]+'''inputs = {\n  name = \"mysql_replica_${include.envcommon.locals.env}\"\n}\n'''\nopen(p,'w').write(s)\nEOF\ntail -12 mysql-replica/terragrunt.hcl"
	prod := filepath.Join(dir, "envs", "prod")
	nonprod := filepath.Join(dir, "non-prod", "us-east-1", "qa")

	// File-only edit: allowed in the protected tier, with a note that says why.
	d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: edit, Cwd: prod, CanAsk: true}, cfg, deps)
	if d.Verdict != Allow || len(d.Actions) != 0 {
		t.Fatalf("file-only edit in prod: verdict %s, actions %+v", d.Verdict, d.Actions)
	}
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "python3 code mentions") || !strings.Contains(d.Notes[0], "terraform") || !strings.Contains(d.Notes[0], "treated as a file edit") {
		t.Fatalf("file-only edit: want one explanatory note, got %v", d.Notes)
	}

	// The same edit with a process start keeps asking in the protected tier.
	dangerous := strings.Replace(edit, "open(p,'w').write(s)\n", "open(p,'w').write(s)\nimport subprocess\nsubprocess.run(['terraform','destroy','-auto-approve'])\n", 1)
	d = Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: dangerous, Cwd: prod, CanAsk: true}, cfg, deps)
	if d.Verdict != Ask || len(d.Notes) != 0 {
		t.Fatalf("edit plus subprocess in prod: verdict %s, notes %v, actions %+v", d.Verdict, d.Notes, d.Actions)
	}
	if !strings.Contains(d.Message, "uses subprocess") {
		t.Errorf("message should name the construct: %q", d.Message)
	}

	// non-prod/** is the configured standard environment, not "prod (name hint)".
	d = Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform apply -auto-approve", Cwd: nonprod, CanAsk: true}, cfg, deps)
	if len(d.Actions) != 1 {
		t.Fatalf("got %d actions: %+v", len(d.Actions), d.Actions)
	}
	if a := d.Actions[0]; d.Verdict != Ask || a.Tier != config.Standard || a.Env != "non-prod" {
		t.Fatalf("apply under non-prod: verdict %s, tier %s, env %s, matched %v", d.Verdict, a.Tier, a.Env, a.Matched)
	}
	d = Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform apply -auto-approve", Cwd: prod, CanAsk: true}, cfg, deps)
	if d.Verdict != Block {
		t.Fatalf("apply under envs/prod: verdict %s", d.Verdict)
	}
}
