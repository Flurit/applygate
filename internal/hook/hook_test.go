package hook

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/seatbelt/internal/decisionlog"
)

const prodConfig = `version: 1
mode: %MODE%
on_error: %ONERR%
environments:
  - name: prod
    tier: protected
    match: {paths: ["prod/**"]}
  - name: dev
    tier: disposable
    match: {paths: ["dev/**"]}
`

func setup(t *testing.T, mode, onErr string) string {
	t.Helper()
	root := t.TempDir()
	cfg := strings.NewReplacer("%MODE%", mode, "%ONERR%", onErr).Replace(prodConfig)
	if err := os.WriteFile(filepath.Join(root, ".seatbelt.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"prod", "dev"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	return root
}

func event(tool, cwd string, input map[string]any) string {
	b, _ := json.Marshal(map[string]any{"session_id": "s1", "cwd": cwd, "permission_mode": "default",
		"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input})
	return string(b)
}

func decision(t *testing.T, o Output) string {
	t.Helper()
	if o.Exit == 2 {
		return "block(exit2)"
	}
	if len(o.Stdout) == 0 {
		return "allow"
	}
	var r struct {
		H struct {
			D string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(o.Stdout, &r); err != nil {
		t.Fatalf("bad output %q", o.Stdout)
	}
	return r.H.D
}

func TestFailureBehavior(t *testing.T) {
	slow := func(string, string, string) ([]byte, error) { time.Sleep(2 * time.Second); return nil, nil }
	boom := func(string, string, string) ([]byte, error) { panic("boom") }
	cases := []struct {
		name, mode, onErr, dir, input string
		plan                          func(string, string, string) ([]byte, error)
		want                          string
	}{
		{"malformed JSON fails closed", "enforce", "auto", "prod", "{not json", nil, "block(exit2)"},
		{"missing tool_name fails closed", "enforce", "auto", "prod", `{"hook_event_name":"PreToolUse","cwd":"/"}`, nil, "block(exit2)"},
		{"panic in protected tier blocks", "enforce", "auto", "prod", "", boom, "block(exit2)"},
		{"panic in disposable tier allows (auto)", "enforce", "auto", "dev", "", boom, "allow"},
		{"panic with on_error block blocks in dev", "enforce", "block", "dev", "", boom, "block(exit2)"},
		{"panic with on_error allow allows in prod", "enforce", "allow", "prod", "", boom, "allow"},
		{"timeout in protected tier blocks", "enforce", "auto", "prod", "", slow, "block(exit2)"},
		{"observe mode never blocks on error", "observe", "auto", "prod", "", boom, "allow"},
		{"other hook events are ignored", "enforce", "auto", "prod", `{"hook_event_name":"PostToolUse","tool_name":"Bash"}`, nil, "allow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := setup(t, c.mode, c.onErr)
			in := c.input
			if in == "" {
				in = event("Bash", filepath.Join(root, c.dir), map[string]any{"command": "terraform apply tfplan"})
			}
			log := filepath.Join(t.TempDir(), "log.jsonl")
			o := Run(Claude{}, strings.NewReader(in), Options{LogPath: log, NoGit: true, Env: map[string]string{}, PlanJSON: c.plan, Timeout: 200 * time.Millisecond})
			if got := decision(t, o); got != c.want {
				t.Fatalf("got %s, want %s (stderr %q)", got, c.want, o.Stderr)
			}
		})
	}
}

func TestTimeoutFailsClosedEveryTier(t *testing.T) {
	// A fake slow `show`: the plan gate hangs, the internal deadline fires. The
	// decision must then block in EVERY tier, including disposable, where an
	// apply of a saved plan would otherwise be allowed.
	slow := func(string, string, string) ([]byte, error) { time.Sleep(2 * time.Second); return nil, nil }
	for _, dir := range []string{"prod", "dev"} { // protected, disposable
		t.Run(dir, func(t *testing.T) {
			root := setup(t, "enforce", "auto")
			in := event("Bash", filepath.Join(root, dir), map[string]any{"command": "terraform apply tfplan"})
			o := Run(Claude{}, strings.NewReader(in), Options{NoLog: true, NoGit: true,
				Env: map[string]string{}, PlanJSON: slow, Timeout: 200 * time.Millisecond})
			if o.Exit != 2 {
				t.Fatalf("%s tier: timeout must fail closed (exit 2), got exit %d stderr %q", dir, o.Exit, o.Stderr)
			}
			if !strings.Contains(o.Stderr, "timed out") {
				t.Fatalf("%s tier: reason should mention the timeout: %q", dir, o.Stderr)
			}
		})
	}
}

func TestShowPlanCancelledByContext(t *testing.T) {
	// A fake `terraform` that sleeps far past the deadline. Cancelling the
	// parent context must kill the subprocess promptly, not wait out show_timeout.
	bindir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bindir, "terraform"), []byte("#!/bin/sh\nexec sleep 10\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bindir+":"+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := ShowPlan(ctx, 30*time.Second)("terraform", t.TempDir(), "tfplan")
	if err == nil {
		t.Fatal("expected an error when the context is cancelled")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("subprocess was not cancelled by context: took %s", d)
	}
}

func TestBrokenRepoConfigFailsClosed(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".seatbelt.yaml"), []byte("mode: enforce\nunknown_key: 1\n"), 0o644)
	o := Run(Claude{}, strings.NewReader(event("Bash", root, map[string]any{"command": "ls"})), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if o.Exit != 2 || !strings.Contains(o.Stderr, "config error") {
		t.Fatalf("got exit %d stderr %q", o.Exit, o.Stderr)
	}
}

func TestObserveModeLogsWouldBlock(t *testing.T) {
	root := setup(t, "observe", "auto")
	log := filepath.Join(t.TempDir(), "log.jsonl")
	in := event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "AWS_SECRET_ACCESS_KEY=abcd1234secret terraform destroy -auto-approve"})
	o := Run(Claude{}, strings.NewReader(in), Options{LogPath: log, NoGit: true, Env: map[string]string{}})
	if decision(t, o) != "allow" {
		t.Fatalf("observe mode must allow, got %s", decision(t, o))
	}
	f, err := os.Open(log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, bad := decisionlog.Read(f)
	if bad != 0 || len(entries) != 1 {
		t.Fatalf("entries %d bad %d", len(entries), bad)
	}
	e := entries[0]
	if e.Verdict != "block" || e.Enforced != "allow" || e.Mode != "observe" {
		t.Fatalf("entry %+v", e)
	}
	raw, _ := os.ReadFile(log)
	if strings.Contains(string(raw), "abcd1234secret") {
		t.Fatal("secret was not redacted from the log")
	}
	if fi, _ := os.Stat(log); fi.Mode().Perm() != 0o600 {
		t.Fatalf("log permissions %v", fi.Mode().Perm())
	}
}

func TestAllowProducesNoOutput(t *testing.T) {
	// A hook "allow" would skip Claude Code's own permission prompt, so
	// seatbelt must stay silent when it has no objection.
	root := setup(t, "enforce", "auto")
	o := Run(Claude{}, strings.NewReader(event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "terraform plan"})), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if len(o.Stdout) != 0 || o.Exit != 0 {
		t.Fatalf("got stdout %q exit %d", o.Stdout, o.Exit)
	}
}

func TestCodexAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	run := func(tool string, input map[string]any) string {
		o := Run(Codex{}, strings.NewReader(event(tool, filepath.Join(root, "prod"), input)), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
		return decision(t, o)
	}
	if got := run("Bash", map[string]any{"command": "terraform destroy"}); got != "deny" {
		t.Fatalf("destroy: %s", got)
	}
	// Codex does not support ask: a dynamic command (ask) must be denied.
	if got := run("Bash", map[string]any{"command": `sh -c "$X"`}); got != "deny" {
		t.Fatalf("dynamic: %s", got)
	}
	if got := run("Bash", map[string]any{"command": []string{"bash", "-lc", "terraform state rm aws_s3_bucket.x"}}); got != "deny" {
		t.Fatalf("argv form: %s", got)
	}
	patch := "*** Begin Patch\n*** Update File: ../.codex/hooks.json\n@@\n-x\n+y\n*** End Patch\n"
	if got := run("apply_patch", map[string]any{"command": patch}); got != "deny" {
		t.Fatalf("apply_patch on hooks: %s", got)
	}
	if got := run("Bash", map[string]any{"command": "terraform plan"}); got != "allow" {
		t.Fatalf("plan: %s", got)
	}
}
