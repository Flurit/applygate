// Package harness holds the scenario pack and replays it through the
// seatbelt's hook entry point. Replay builds synthetic hook events and never
// executes the commands in them.
package harness

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/flurit-ai/seatbelt/internal/hook"
	"github.com/flurit-ai/seatbelt/internal/policy"
)

//go:embed all:pack
var packFS embed.FS

// Scenario is one replay case.
type Scenario struct {
	ID             string            `json:"id"`
	Spec           string            `json:"spec"`
	Kind           string            `json:"kind"` // dangerous | benign
	Title          string            `json:"title"`
	Cwd            string            `json:"cwd"` // relative to the fixture repo
	Tool           string            `json:"tool"`
	ToolInput      map[string]any    `json:"tool_input"`
	Expect         []string          `json:"expect"`
	Plans          map[string]string `json:"plans"` // planfile -> plans/<file>
	Env            map[string]string `json:"env"`
	PermissionMode string            `json:"permission_mode"`
	Note           string            `json:"note"`
	// MustMention lists substrings the decision message must contain, so a
	// right verdict for the wrong reason fails.
	MustMention []string `json:"must_mention"`
	Origin      string   `json:"origin"`
}

// Pack is the scenario file.
type Pack struct {
	Version   int        `json:"version"`
	Note      string     `json:"note"`
	Scenarios []Scenario `json:"scenarios"`
}

// Load reads the embedded pack.
func Load() (*Pack, error) {
	b, err := packFS.ReadFile("pack/scenarios.json")
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Materialize writes the fixtures and plans under dir and returns the paths
// of the fixture repo, the plans directory and a fake HOME.
func Materialize(dir string) (repo, plans, home string, err error) {
	err = fs.WalkDir(packFS, "pack", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, strings.TrimPrefix(p, "pack"))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := packFS.ReadFile(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, ".sh") {
			mode = 0o755
		}
		return os.WriteFile(dst, b, mode)
	})
	home = filepath.Join(dir, "home")
	if err == nil {
		err = os.MkdirAll(filepath.Join(home, ".aws"), 0o755)
	}
	return filepath.Join(dir, "fixtures", "repo"), filepath.Join(dir, "plans"), home, err
}

// Event builds the Claude Code PreToolUse event for a scenario.
func (s Scenario) Event(repo, home string) []byte {
	sub := func(v string) string {
		return strings.NewReplacer("{repo}", repo, "{home}", home).Replace(v)
	}
	in := map[string]any{}
	for k, v := range s.ToolInput {
		if str, ok := v.(string); ok {
			v = sub(str)
		}
		in[k] = v
	}
	mode := s.PermissionMode
	if mode == "" {
		mode = "default"
	}
	ev := map[string]any{
		"session_id": "replay-" + s.ID, "transcript_path": "/dev/null", "cwd": filepath.Join(repo, s.Cwd),
		"permission_mode": mode, "hook_event_name": "PreToolUse", "tool_name": s.Tool, "tool_input": in,
		"tool_use_id": "toolu_replay_" + s.ID,
	}
	b, _ := json.Marshal(ev)
	return b
}

// Outcome is the replay result for one scenario.
type Outcome struct {
	Scenario Scenario
	Verdict  string // allow | ask | block | error
	Message  string
	Pass     bool
}

// Replay runs every scenario through the Claude Code hook adapter in-process.
func Replay(p *Pack, dir string) ([]Outcome, error) {
	repo, plans, home, err := Materialize(dir)
	if err != nil {
		return nil, err
	}
	var out []Outcome
	for _, s := range p.Scenarios {
		env := map[string]string{"HOME": home, "USER": "agent", "PATH": "/nonexistent"}
		for k, v := range s.Env {
			env[k] = v
		}
		planMap := s.Plans
		opt := hook.Options{
			NoLog: true, NoGit: true, Env: env,
			PlanJSON: func(engine, d, planfile string) ([]byte, error) {
				f, ok := planMap[planfile]
				if !ok {
					return nil, fmt.Errorf("no plan fixture for %s", planfile)
				}
				return os.ReadFile(filepath.Join(plans, f))
			},
		}
		o := hook.Run(hook.Claude{}, bytes.NewReader(s.Event(repo, home)), opt)
		v, msg := ParseClaudeOutput(o)
		pass := contains(s.Expect, v)
		for _, m := range s.MustMention {
			if !strings.Contains(msg, m) {
				pass = false
				msg += "\n[harness] missing expected mention: " + m
			}
		}
		out = append(out, Outcome{Scenario: s, Verdict: v, Message: msg, Pass: pass})
	}
	return out, nil
}

// ParseClaudeOutput turns a Claude Code hook result into a verdict.
func ParseClaudeOutput(o hook.Output) (string, string) {
	if o.Exit == 2 {
		return string(policy.Block), o.Stderr
	}
	if o.Exit != 0 {
		return "error", o.Stderr
	}
	if len(bytes.TrimSpace(o.Stdout)) == 0 {
		return string(policy.Allow), ""
	}
	var r struct {
		HSO struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(o.Stdout, &r); err != nil {
		return "error", string(o.Stdout)
	}
	switch r.HSO.Decision {
	case "deny":
		return string(policy.Block), r.HSO.Reason
	case "ask":
		return string(policy.Ask), r.HSO.Reason
	case "allow", "":
		return string(policy.Allow), r.HSO.Reason
	}
	return "error", r.HSO.Reason
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Summary scores outcomes the way the v0 spec does: dangerous pass on block
// or ask, benign pass on allow (or what the scenario lists).
type Summary struct {
	Dangerous, DangerousCaught, DangerousExact int
	Benign, BenignFlagged, BenignExact         int
}

// Score computes the summary.
func Score(out []Outcome) Summary {
	var s Summary
	for _, o := range out {
		if o.Scenario.Kind == "dangerous" {
			s.Dangerous++
			if o.Verdict == "block" || o.Verdict == "ask" {
				s.DangerousCaught++
			}
			if o.Pass {
				s.DangerousExact++
			}
		} else {
			s.Benign++
			if o.Verdict != "allow" {
				s.BenignFlagged++
			}
			if o.Pass {
				s.BenignExact++
			}
		}
	}
	return s
}
