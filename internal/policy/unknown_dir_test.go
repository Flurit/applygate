package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/preflight"
)

// writeRepo writes a repository config and the directories it names.
func writeRepo(t *testing.T, cfg string, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, config.FileName), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func loadCfg(t *testing.T, userYAML, root string) *config.Config {
	t.Helper()
	user := ""
	if userYAML != "" {
		user = filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(user, []byte(userYAML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(user, root)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// codexEvent is a Codex 0.165.0 shell event: the cwd is the session root and
// the command's directory is not reported.
func codexEvent(cmd, root string) Event {
	return Event{Agent: "codex", Tool: "Bash", Kind: KindShell, Command: cmd, Cwd: root, CanAsk: false, DirKnown: false}
}

const mixedRepo = `version: 1
mode: enforce
strict: false
default_tier: standard
name_hints: false
environments:
  - name: examples
    tier: disposable
    match: {paths: ["examples/**"]}
  - name: prod
    tier: protected
    match: {paths: ["envs/prod/**"]}
`

const lowRepo = `version: 1
mode: enforce
strict: false
default_tier: disposable
name_hints: false
environments:
  - name: examples
    tier: disposable
    match: {paths: ["examples/**"]}
  - name: staging
    tier: standard
    match: {paths: ["envs/staging/**"]}
`

func TestUnknownDirMostProtected(t *testing.T) {
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent"}}
	t.Run("protected directory under the root wins", func(t *testing.T) {
		root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod")
		cfg := loadCfg(t, "", root)
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		a := d.Actions[0]
		if d.Verdict != Block || a.Tier != config.Protected || a.Env != "prod" {
			t.Fatalf("verdict %s tier %s env %s, want block/protected/prod: %v", d.Verdict, a.Tier, a.Env, a.Matched)
		}
		want := "command directory not reported by codex; judged at the most protected tier under " + root + " (prod, tier protected)"
		if len(a.Matched) == 0 || a.Matched[0] != want {
			t.Fatalf("matched %v, want first line %q", a.Matched, want)
		}
		if !strings.Contains(d.Message, want) {
			t.Fatalf("message should carry the reason: %s", d.Message)
		}
	})
	t.Run("only lower tiers under the root: the highest present", func(t *testing.T) {
		root := writeRepo(t, lowRepo, "examples/simple", "envs/staging")
		cfg := loadCfg(t, "", root)
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		a := d.Actions[0]
		if d.Verdict != Ask || a.Tier != config.Standard || a.Env != "staging" {
			t.Fatalf("verdict %s tier %s env %s, want ask/standard/staging: %v", d.Verdict, a.Tier, a.Env, a.Matched)
		}
		if d.Enforced != Block {
			t.Fatalf("codex cannot ask: enforced %s", d.Enforced)
		}
	})
	t.Run("strict root with no environments is protected", func(t *testing.T) {
		root := writeRepo(t, "version: 1\nmode: enforce\n", "x")
		cfg := loadCfg(t, "", root)
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		if d.Verdict != Block || d.Actions[0].Tier != config.Protected {
			t.Fatalf("got %s %s", d.Verdict, d.Actions[0].Tier)
		}
	})
	t.Run("session_root switch restores the root's tier", func(t *testing.T) {
		root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod")
		cfg := loadCfg(t, "unknown_dir: session_root\n", root)
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		a := d.Actions[0]
		if d.Verdict != Ask || a.Tier != config.Standard {
			t.Fatalf("verdict %s tier %s, want ask/standard: %v", d.Verdict, a.Tier, a.Matched)
		}
		if len(a.Matched) == 0 || !strings.Contains(a.Matched[0], "judged at the session root") {
			t.Fatalf("matched should say the root was used: %v", a.Matched)
		}
	})
	t.Run("repository config cannot loosen the switch", func(t *testing.T) {
		root := writeRepo(t, mixedRepo+"unknown_dir: session_root\n", "examples/simple", "envs/prod")
		cfg := loadCfg(t, "", root)
		if !cfg.UnknownDirMostProtected() {
			t.Fatal("repository config loosened unknown_dir")
		}
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		if d.Verdict != Block {
			t.Fatalf("got %s", d.Verdict)
		}
		// But it can tighten what the user config loosened.
		cfg = loadCfg(t, "unknown_dir: session_root\n", writeRepo(t, mixedRepo+"unknown_dir: most_protected\n"))
		if !cfg.UnknownDirMostProtected() {
			t.Fatal("repository config could not tighten unknown_dir")
		}
	})
	t.Run("a known directory is judged as itself", func(t *testing.T) {
		root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod")
		cfg := loadCfg(t, "", root)
		ev := codexEvent("terraform destroy -auto-approve", filepath.Join(root, "examples", "simple"))
		ev.DirKnown = true
		if d := Decide(ev, cfg, deps); d.Verdict != Allow || d.Actions[0].Tier != config.Disposable {
			t.Fatalf("got %s %s", d.Verdict, d.Actions[0].Tier)
		}
	})
	t.Run("cd and -chdir in the command establish the directory", func(t *testing.T) {
		root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod")
		cfg := loadCfg(t, "", root)
		for _, cmd := range []string{"cd examples/simple && terraform destroy -auto-approve", "terraform -chdir=examples/simple destroy -auto-approve"} {
			d := Decide(codexEvent(cmd, root), cfg, deps)
			if d.Verdict != Allow || d.Actions[0].Tier != config.Disposable {
				t.Fatalf("%s: got %s %s: %v", cmd, d.Verdict, d.Actions[0].Tier, d.Actions[0].Matched)
			}
		}
		d := Decide(codexEvent("cd envs/prod && terraform destroy -auto-approve", root), cfg, deps)
		if d.Verdict != Block {
			t.Fatalf("cd into prod: got %s", d.Verdict)
		}
	})
	t.Run("workspace and profile matchers count under an unknown directory", func(t *testing.T) {
		root := writeRepo(t, "version: 1\nmode: enforce\nstrict: false\ndefault_tier: disposable\nname_hints: false\nenvironments:\n  - {name: prod, tier: protected, match: {workspaces: [prod]}}\n", "x")
		cfg := loadCfg(t, "", root)
		d := Decide(codexEvent("terraform destroy -auto-approve", root), cfg, deps)
		if d.Verdict != Block || d.Actions[0].Env != "prod" {
			t.Fatalf("got %s %s: %v", d.Verdict, d.Actions[0].Env, d.Actions[0].Matched)
		}
	})
}

// fakeShow returns an empty plan when the planfile exists in dir.
func fakeShow(calls *[]string) func(string, string, string) ([]byte, error) {
	return func(engine, dir, planfile string) ([]byte, error) {
		*calls = append(*calls, dir)
		p := planfile
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, errors.New("show failed: " + err.Error())
		}
		return []byte(`{"format_version":"1.2","resource_changes":[]}`), nil
	}
}

func findings(a ActionResult) []string {
	var out []string
	for _, f := range a.Findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestUnknownDirPlanfileSearch(t *testing.T) {
	t.Run("unique match sets the command directory", func(t *testing.T) {
		root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod", ".terraform/x", ".git/x")
		os.WriteFile(filepath.Join(root, "examples", "simple", "simple.tfplan"), []byte("plan"), 0o644)
		// Copies under .git and .terraform are skipped.
		os.WriteFile(filepath.Join(root, ".git", "x", "simple.tfplan"), []byte("plan"), 0o644)
		os.WriteFile(filepath.Join(root, ".terraform", "x", "simple.tfplan"), []byte("plan"), 0o644)
		cfg := loadCfg(t, "", root)
		var calls []string
		d := Decide(codexEvent("terraform apply simple.tfplan", root), cfg, Deps{Env: map[string]string{}, PlanJSON: fakeShow(&calls)})
		a := d.Actions[0]
		if d.Verdict != Allow || a.Tier != config.Disposable || a.Dir != filepath.Join(root, "examples", "simple") {
			t.Fatalf("verdict %s tier %s dir %s findings %v matched %v", d.Verdict, a.Tier, a.Dir, findings(a), a.Matched)
		}
		if len(calls) != 1 || calls[0] != a.Dir {
			t.Fatalf("show should run in the found directory: %v", calls)
		}
		if a.PlanSHA256 == "" || len(a.Findings) != 0 {
			t.Fatalf("plan not read: sha %q findings %v", a.PlanSHA256, findings(a))
		}
		if !strings.Contains(strings.Join(a.Matched, "; "), "found once under it at "+filepath.Join(a.Dir, "simple.tfplan")) {
			t.Fatalf("matched should say how the planfile was found: %v", a.Matched)
		}
	})
	t.Run("several matches fail closed", func(t *testing.T) {
		root := writeRepo(t, lowRepo, "examples/simple", "envs/staging")
		os.WriteFile(filepath.Join(root, "examples", "simple", "tfplan"), []byte("plan"), 0o644)
		os.WriteFile(filepath.Join(root, "envs", "staging", "tfplan"), []byte("plan"), 0o644)
		cfg := loadCfg(t, "", root)
		var calls []string
		d := Decide(codexEvent("terraform apply tfplan", root), cfg, Deps{Env: map[string]string{}, PlanJSON: fakeShow(&calls)})
		a := d.Actions[0]
		var amb *preflight.Finding
		for i := range a.Findings {
			if a.Findings[i].Rule == "plan-ambiguous" {
				amb = &a.Findings[i]
			}
		}
		if amb == nil || amb.Severity != preflight.Critical || len(amb.Evidence) != 2 {
			t.Fatalf("want a critical plan-ambiguous finding with two candidates: %+v", a.Findings)
		}
		// The directory stays unknown (standard here), so critical asks,
		// which Codex enforces as a block. show never ran.
		if a.Tier != config.Standard || d.Verdict != Ask || d.Enforced != Block || len(calls) != 0 {
			t.Fatalf("tier %s verdict %s enforced %s show calls %v", a.Tier, d.Verdict, d.Enforced, calls)
		}
	})
	t.Run("no match keeps plan-missing", func(t *testing.T) {
		root := writeRepo(t, lowRepo, "examples/simple", "envs/staging")
		cfg := loadCfg(t, "", root)
		var calls []string
		d := Decide(codexEvent("terraform apply tfplan", root), cfg, Deps{Env: map[string]string{}, PlanJSON: fakeShow(&calls)})
		if fs := findings(d.Actions[0]); len(fs) != 1 || fs[0] != "plan-missing" {
			t.Fatalf("findings %v", fs)
		}
	})
	t.Run("a known directory is never searched", func(t *testing.T) {
		root := writeRepo(t, lowRepo, "examples/simple")
		os.WriteFile(filepath.Join(root, "examples", "simple", "tfplan"), []byte("plan"), 0o644)
		cfg := loadCfg(t, "", root)
		ev := codexEvent("terraform apply tfplan", root)
		ev.DirKnown = true
		d := Decide(ev, cfg, Deps{Env: map[string]string{}, PlanJSON: fakeShow(new([]string))})
		if fs := findings(d.Actions[0]); len(fs) != 1 || fs[0] != "plan-missing" {
			t.Fatalf("findings %v", fs)
		}
	})
	t.Run("search limits", func(t *testing.T) {
		root := t.TempDir()
		deep := root
		for i := 0; i < planSearchMaxDepth+2; i++ {
			deep = filepath.Join(deep, "d")
		}
		os.MkdirAll(deep, 0o755)
		os.WriteFile(filepath.Join(deep, "tfplan"), []byte("plan"), 0o644)
		if m, tr := findPlanfile(root, "tfplan"); len(m) != 0 || tr {
			t.Fatalf("beyond the depth cap: %v %v", m, tr)
		}
		os.MkdirAll(filepath.Join(root, "plans"), 0o755)
		os.WriteFile(filepath.Join(root, "plans", "tfplan"), []byte("plan"), 0o644)
		// A planfile with a directory part is matched as a whole.
		if m, _ := findPlanfile(root, filepath.Join("plans", "tfplan")); len(m) != 0 {
			t.Fatalf("root itself is not a candidate: %v", m)
		}
		os.MkdirAll(filepath.Join(root, "a", "plans"), 0o755)
		os.WriteFile(filepath.Join(root, "a", "plans", "tfplan"), []byte("plan"), 0o644)
		if m, _ := findPlanfile(root, filepath.Join("plans", "tfplan")); len(m) != 1 || m[0] != filepath.Join(root, "a", "plans", "tfplan") {
			t.Fatalf("planfile with a directory part: %v", m)
		}
	})
}
