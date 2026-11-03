package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Flurit/applygate/internal/config"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/hook"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// AttackScenario is one reproduction from the v0.6.0 pre-release review
// (pack_attack/scenarios.json). Strings may use {repo}, {home} and {self} (the
// running binary).
type AttackScenario struct {
	Scenario
	Finding  string            `json:"finding"` // review ID, or "control" for benign calls the fixes must keep allowed
	Files    map[string]string `json:"files"`   // written before the call; keys relative to the repo or starting with {home}
	Symlinks map[string]string `json:"symlinks"`
	GOOS     []string          `json:"goos"`    // only on these systems (case-insensitive file systems)
	Formats  []string          `json:"formats"` // claude, codex (default both)
}

func TestAttackPack(t *testing.T) {
	config.TrustAll = false
	defer func() { config.TrustAll = true }()
	b, err := os.ReadFile("pack_attack/scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Scenarios []AttackScenario `json:"scenarios"`
	}
	if err := json.Unmarshal(b, &pack); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	byFinding := map[string][]AttackScenario{}
	seen := map[string]bool{}
	for _, s := range pack.Scenarios {
		if seen[s.ID] {
			t.Fatalf("duplicate scenario id %s", s.ID)
		}
		seen[s.ID] = true
		if s.Finding == "" {
			t.Fatalf("%s has no finding", s.ID)
		}
		byFinding[s.Finding] = append(byFinding[s.Finding], s)
	}
	var findings []string
	for f := range byFinding {
		findings = append(findings, f)
	}
	sort.Strings(findings)
	for _, f := range findings {
		t.Run(f, func(t *testing.T) {
			var failed []string
			ran := 0
			for _, s := range byFinding[f] {
				if len(s.GOOS) > 0 && !contains(s.GOOS, runtime.GOOS) {
					continue
				}
				formats := s.Formats
				if len(formats) == 0 {
					formats = []string{"claude", "codex"}
				}
				for _, format := range formats {
					ran++
					if v, msg, ok := runAttack(t, s, format, self); !ok {
						failed = append(failed, fmt.Sprintf("%s/%s got %s (want %s)%s", s.ID, format, v, strings.Join(s.Expect, "|"), firstLine(msg)))
					}
				}
			}
			if ran == 0 {
				t.Skipf("no scenario of %s runs on %s", f, runtime.GOOS)
			}
			detail := strings.Join(failed, "; ")
			if f == "control" {
				if len(failed) > 0 {
					t.Errorf("benign controls changed: %s", detail)
				}
				return
			}
			reviewgap.Check(t, f, len(failed) == 0, "%d of %d replays fail: %s", len(failed), ran, detail)
		})
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return " [" + s + "]"
}

// runAttack replays one scenario in a fresh copy of the fixtures.
func runAttack(t *testing.T, s AttackScenario, format, self string) (string, string, bool) {
	t.Helper()
	dir := t.TempDir()
	repo, plans, home, err := Materialize(dir)
	if err != nil {
		t.Fatal(err)
	}
	sub := strings.NewReplacer("{repo}", repo, "{home}", home, "{self}", self).Replace
	// The person trusted the fixture's own configs; a config a scenario
	// plants or rewrites is not trusted.
	original := map[string][]byte{}
	filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (d.Name() == ".applygate.yaml" || d.Name() == ".seatbelt.yaml") {
			if b, err := os.ReadFile(p); err == nil {
				original[p] = b
			}
		}
		return nil
	})
	place := func(p string) string {
		p = sub(p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(repo, p)
		}
		return p
	}
	for p, content := range s.Files {
		p = place(p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(sub(content)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range s.Symlinks {
		link = place(link)
		os.MkdirAll(filepath.Dir(link), 0o755)
		if err := os.Symlink(sub(target), link); err != nil {
			t.Fatal(err)
		}
	}
	// The guard paths and the user config follow the process environment.
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	env := map[string]string{"HOME": home, "USER": "agent", "PATH": "/nonexistent"}
	for k, v := range s.Env {
		v = sub(v)
		env[k] = v
		if strings.HasPrefix(k, "XDG_") || k == "CLAUDE_CONFIG_DIR" || k == "CODEX_HOME" || k == "COPILOT_HOME" {
			t.Setenv(k, v)
		}
	}
	// The trust store follows the environment just set.
	if err := config.TrustContent(original); err != nil {
		t.Fatal(err)
	}
	in := map[string]any{}
	for k, v := range s.ToolInput {
		if str, ok := v.(string); ok {
			v = sub(str)
		}
		in[k] = v
	}
	cwd := sub(s.Cwd)
	if !filepath.IsAbs(cwd) {
		cwd = filepath.Join(repo, cwd)
	}
	mode := s.PermissionMode
	if mode == "" {
		mode = "default"
	}
	ev := map[string]any{"session_id": "attack-" + s.ID, "transcript_path": "/dev/null", "cwd": cwd, "permission_mode": mode,
		"hook_event_name": "PreToolUse", "tool_name": s.Tool, "tool_input": in, "tool_use_id": "toolu_attack_" + s.ID}
	if _, ok := s.ToolInput["__no_tool_input"]; ok {
		delete(ev, "tool_input")
	}
	b, _ := json.Marshal(ev)
	opt := hook.Options{NoLog: true, NoGit: true, Env: env,
		PlanJSON: func(engine, d, planfile string) ([]byte, error) {
			f, ok := s.Plans[planfile]
			if !ok {
				return nil, fmt.Errorf("no plan fixture for %s", planfile)
			}
			if rest, ok := strings.CutPrefix(f, "attack/"); ok {
				return os.ReadFile(filepath.Join("pack_attack", "plans", rest))
			}
			return os.ReadFile(filepath.Join(plans, f))
		}}
	var a hook.Adapter = hook.Claude{}
	if format == "codex" {
		a = hook.Codex{}
	}
	v, msg := ParseClaudeOutput(hook.Run(a, bytes.NewReader(b), opt))
	ok := contains(s.Expect, v)
	for _, m := range s.MustMention {
		if !strings.Contains(msg, m) {
			ok = false
		}
	}
	return v, msg, ok
}
