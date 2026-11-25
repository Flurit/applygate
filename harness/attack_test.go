package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
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
				if len(s.GOOS) > 0 && !slices.Contains(s.GOOS, runtime.GOOS) {
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

// TestAttackPackWithoutConfig pins what the rule for a repository with no
// config costs. There, strict shapes ask about a command that is not plain
// only when it names an infrastructure tool or a guard file
// (config.ShapesByWord), so some reproductions the full rule stops are
// allowed. testdata/no_config_allowed.txt lists them; docs/limits.md gives
// the count. A reproduction that becomes allowed and is not listed fails
// this test, and so does a listed one that is stopped again.
func TestAttackPackWithoutConfig(t *testing.T) {
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
	listed := map[string]bool{}
	lb, err := os.ReadFile("testdata/no_config_allowed.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(lb), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			listed[strings.Fields(line)[0]] = true
		}
	}
	self, _ := os.Executable()
	ran := map[string]bool{}
	var allowed, dangerous int
	var unlisted, stopped []string
	for _, s := range pack.Scenarios {
		if s.Kind != "dangerous" || len(s.GOOS) > 0 && !slices.Contains(s.GOOS, runtime.GOOS) || len(s.Formats) > 0 && !slices.Contains(s.Formats, "claude") {
			continue
		}
		dangerous++
		ran[s.ID] = true
		v, _, _ := runAttackIn(t, s, "claude", self, true)
		if v != "allow" {
			if listed[s.ID] {
				stopped = append(stopped, s.ID)
			}
			continue
		}
		allowed++
		if !listed[s.ID] {
			unlisted = append(unlisted, fmt.Sprintf("%s  %s", s.ID, firstLine(fmt.Sprint(s.ToolInput["command"]))))
		}
	}
	t.Logf("no repository config: %d of %d dangerous reproductions are allowed on %s", allowed, dangerous, runtime.GOOS)
	if len(unlisted) > 0 {
		t.Errorf("%d reproductions are allowed in a repository with no config and are not in testdata/no_config_allowed.txt.\n"+
			"Each is a way past the check there: fix it, or add its id to the list and correct the count in docs/limits.md.\n%s",
			len(unlisted), strings.Join(unlisted, "\n"))
	}
	if len(stopped) > 0 {
		t.Errorf("%d listed reproductions are no longer allowed in a repository with no config: remove them from testdata/no_config_allowed.txt and correct the count in docs/limits.md: %s",
			len(stopped), strings.Join(stopped, " "))
	}
	for id := range listed {
		if !ran[id] && !goosOnly(pack.Scenarios, id) {
			t.Errorf("testdata/no_config_allowed.txt lists %s, which is not a dangerous scenario of the attack pack", id)
		}
	}
}

// goosOnly reports whether id is a scenario that runs on other systems only.
func goosOnly(scs []AttackScenario, id string) bool {
	for _, s := range scs {
		if s.ID == id {
			return len(s.GOOS) > 0 && !slices.Contains(s.GOOS, runtime.GOOS)
		}
	}
	return false
}

// padRe finds {pad:N} in a planted file: N bytes of HCL comment, so a
// scenario can plant a configuration file past the size cap without
// carrying a megabyte in the pack.
var padRe = regexp.MustCompile(`\{pad:(\d+)\}`)

func padOf(m string) string {
	n, _ := strconv.Atoi(padRe.FindStringSubmatch(m)[1])
	line := "# padding padding padding padding padding padding padding\n"
	return strings.Repeat(line, n/len(line)+1)[:n]
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
	return runAttackIn(t, s, format, self, false)
}

// runAttackIn is runAttack; with noConfig the scenario runs in a repository
// that has no config and whose directory names say nothing: the fixture's
// own repository configs are removed (one a scenario plants is still there,
// and untrusted) and envs/prod* becomes envs/main*, in the fixtures and in
// the scenario, because a directory named prod is protected by its name.
func runAttackIn(t *testing.T, s AttackScenario, format, self string, noConfig bool) (string, string, bool) {
	t.Helper()
	dir := t.TempDir()
	repo, plans, home, err := Materialize(dir)
	if err != nil {
		t.Fatal(err)
	}
	sub := strings.NewReplacer("{repo}", repo, "{home}", home, "{self}", self).Replace
	if noConfig {
		filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (d.Name() == ".applygate.yaml" || d.Name() == ".seatbelt.yaml") {
				os.Remove(p)
			}
			return nil
		})
		envs, _ := os.ReadDir(filepath.Join(repo, "envs"))
		for _, e := range envs {
			if rest, ok := strings.CutPrefix(e.Name(), "prod"); ok {
				if err := os.Rename(filepath.Join(repo, "envs", e.Name()), filepath.Join(repo, "envs", "main"+rest)); err != nil {
					t.Fatal(err)
				}
			}
		}
		placeholders := sub
		sub = func(v string) string { return strings.ReplaceAll(placeholders(v), "envs/prod", "envs/main") }
	}
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
		if err := os.WriteFile(p, []byte(padRe.ReplaceAllStringFunc(sub(content), padOf)), 0o644); err != nil {
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
		if strings.HasPrefix(k, "XDG_") || k == "CLAUDE_CONFIG_DIR" || k == "CODEX_HOME" || k == "COPILOT_HOME" || k == "PATH" {
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
	ok := slices.Contains(s.Expect, v)
	for _, m := range s.MustMention {
		if !strings.Contains(msg, m) {
			ok = false
		}
	}
	return v, msg, ok
}
