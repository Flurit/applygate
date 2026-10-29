package hook

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/seatbelt/internal/decisionlog"
	"github.com/Flurit/seatbelt/internal/policy"
)

// panicOnRender parses like Codex but panics while rendering, to exercise the
// top-level panic recovery in Run (a case policy.Run's own recover does not
// cover).
type panicOnRender struct{ Codex }

func (panicOnRender) Render(policy.Decision) Output { panic("render boom") }

// panicOnParse panics during Parse, before any config for the event is loaded.
type panicOnParse struct{ Codex }

func (panicOnParse) Parse([]byte) (policy.Event, bool, error) { panic("parse boom") }

func TestPanicRecoveryFailsClosed(t *testing.T) {
	// A panic outside policy.Run (here, in the adapter) must still block, so a
	// Codex hook that panics does not fail open.
	root := setup(t, "enforce", "auto")
	in := event("Bash", filepath.Join(root, "dev"), map[string]any{"command": "ls"})
	for _, a := range []Adapter{panicOnRender{}, panicOnParse{}} {
		o := Run(a, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
		if o.Exit != 2 {
			t.Fatalf("%T: panic must fail closed (exit 2), got exit %d stderr %q", a, o.Exit, o.Stderr)
		}
	}
}

func TestPanicRecoveryObserveAllows(t *testing.T) {
	// Observe mode never blocks, even on a panic.
	root := setup(t, "observe", "auto")
	in := event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "ls"})
	o := Run(panicOnRender{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if o.Exit != 0 {
		t.Fatalf("observe mode must not block on panic, got exit %d stderr %q", o.Exit, o.Stderr)
	}
}

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

func TestMissingPlanFileAsksNotBlocks(t *testing.T) {
	// F10: applying a plan whose file does not exist is a High "plan-missing"
	// finding, so in a protected tier it asks (nothing to apply) rather than
	// blocking as an unreadable plan.
	root := setup(t, "enforce", "auto")
	noPlan := func(string, string, string) ([]byte, error) { return nil, errors.New("show: no such file") }
	o := Run(Claude{}, strings.NewReader(event("Bash", filepath.Join(root, "prod"),
		map[string]any{"command": "terraform apply tfplan"})),
		Options{NoLog: true, NoGit: true, Env: map[string]string{}, PlanJSON: noPlan})
	if got := decision(t, o); got != "ask" {
		t.Fatalf("missing plan file in protected tier should ask, got %s (exit %d)", got, o.Exit)
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

func TestClaudeCanAsk(t *testing.T) {
	// Only dontAsk suppresses the ask prompt on Claude Code. bypassPermissions
	// still shows it (observed on Claude Code 2.1.312, test T3.2).
	cases := []struct {
		mode string
		want bool
	}{
		{"default", true},
		{"acceptEdits", true},
		{"plan", true},
		{"bypassPermissions", true},
		{"dontAsk", false},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
				"permission_mode": c.mode, "tool_input": map[string]any{"command": "terraform state rm x"}})
			ev, ok, err := Claude{}.Parse(raw)
			if err != nil || !ok {
				t.Fatalf("parse: ok=%v err=%v", ok, err)
			}
			if ev.CanAsk != c.want {
				t.Fatalf("mode %q: CanAsk=%v, want %v", c.mode, ev.CanAsk, c.want)
			}
		})
	}
}

func TestCodexCannotAsk(t *testing.T) {
	// Codex has no "ask", so every mode must leave CanAsk false.
	for _, mode := range []string{"default", "bypassPermissions", "dontAsk"} {
		raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
			"permission_mode": mode, "tool_input": map[string]any{"command": "terraform state rm x"}})
		ev, ok, err := Codex{}.Parse(raw)
		if err != nil || !ok {
			t.Fatalf("parse: ok=%v err=%v", ok, err)
		}
		if ev.CanAsk {
			t.Fatalf("codex mode %q: CanAsk must be false", mode)
		}
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
	// An edit event that names the file directly (file_path) is guarded too.
	if got := run("Edit", map[string]any{"file_path": filepath.Join(root, ".codex", "hooks.json")}); got != "deny" {
		t.Fatalf("Edit with file_path on hooks: %s", got)
	}
}

// rootStandardConfig has a standard-tier root (strict off) with a protected
// and a disposable subdirectory, so the tier of a command depends on whether
// the adapter resolves it against the session root or the command's workdir.
const rootStandardConfig = `version: 1
mode: enforce
strict: false
default_tier: standard
environments:
  - name: prod
    tier: protected
    match: {paths: ["prod/**"]}
  - name: dev
    tier: disposable
    match: {paths: ["dev/**"]}
`

func setupRootStandard(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".seatbelt.yaml"), []byte(rootStandardConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"prod", "dev"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	return root
}

func TestCodexWorkdirField(t *testing.T) {
	// The directory a Codex shell command runs in comes from tool_input
	// (workdir, working_directory or cwd; relative values resolve against the
	// top-level cwd) and falls back to the top-level cwd when none is sent,
	// which is what Codex 0.165.0 does (see the Codex adapter comment).
	cases := []struct {
		name  string
		tool  string
		input map[string]any
		want  string
	}{
		{"absolute workdir", "Bash", map[string]any{"command": "pwd", "workdir": "/work/repo/examples/simple"}, "/work/repo/examples/simple"},
		{"relative workdir", "Bash", map[string]any{"command": "pwd", "workdir": "examples/simple"}, "/work/repo/examples/simple"},
		{"relative workdir with dot segments", "Bash", map[string]any{"command": "pwd", "workdir": "./examples/../examples/simple/"}, "/work/repo/examples/simple"},
		{"working_directory", "Bash", map[string]any{"command": "pwd", "working_directory": "/work/repo/envs/prod"}, "/work/repo/envs/prod"},
		{"cwd inside tool_input", "Bash", map[string]any{"command": "pwd", "cwd": "envs/prod"}, "/work/repo/envs/prod"},
		{"workdir wins over the others", "Bash", map[string]any{"command": "pwd", "workdir": "a", "working_directory": "b", "cwd": "c"}, "/work/repo/a"},
		{"missing falls back to cwd", "Bash", map[string]any{"command": "pwd"}, "/work/repo"},
		{"empty string falls back to cwd", "Bash", map[string]any{"command": "pwd", "workdir": ""}, "/work/repo"},
		{"non-string is ignored", "Bash", map[string]any{"command": "pwd", "workdir": 7}, "/work/repo"},
		{"exec_command tool name", "exec_command", map[string]any{"command": "pwd", "workdir": "examples/simple"}, "/work/repo/examples/simple"},
		{"apply_patch keeps the top-level cwd", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: x\n*** End Patch\n", "workdir": "examples/simple"}, "/work/repo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok, err := Codex{}.Parse([]byte(event(c.tool, "/work/repo", c.input)))
			if err != nil || !ok {
				t.Fatalf("parse: ok=%v err=%v", ok, err)
			}
			if ev.Cwd != c.want {
				t.Fatalf("cwd %q, want %q", ev.Cwd, c.want)
			}
		})
	}
	// Without a top-level cwd a relative workdir is kept as given.
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_input": map[string]any{"command": "pwd", "workdir": "examples/simple"}})
	ev, _, err := Codex{}.Parse(raw)
	if err != nil || ev.Cwd != "examples/simple" {
		t.Fatalf("no top-level cwd: got %q err %v", ev.Cwd, err)
	}
}

// readLog returns the single decision-log entry written to path.
func readLog(t *testing.T, path string) decisionlog.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, bad := decisionlog.Read(f)
	if bad != 0 || len(entries) != 1 {
		t.Fatalf("entries %d bad %d", len(entries), bad)
	}
	return entries[0]
}

func TestCodexWorkdirDecidesTier(t *testing.T) {
	// The trial case: a Codex session rooted in a standard-tier repository
	// runs commands in a subdirectory. With the workdir in the event, the
	// tier and the plan gate follow the subdirectory; without it, the root.
	root := setupRootStandard(t)
	run := func(cwd string, input map[string]any, plan func(string, string, string) ([]byte, error)) (string, decisionlog.Entry) {
		log := filepath.Join(t.TempDir(), "log.jsonl")
		o := Run(Codex{}, strings.NewReader(event("Bash", cwd, input)),
			Options{LogPath: log, NoGit: true, Env: map[string]string{}, PlanJSON: plan})
		return decision(t, o), readLog(t, log)
	}

	// Disposable workdir under the standard root: destroy is allowed there.
	got, e := run(root, map[string]any{"command": "terraform destroy -auto-approve", "workdir": "dev"}, nil)
	if got != "allow" {
		t.Fatalf("destroy in disposable workdir: got %s, want allow", got)
	}
	if e.Cwd != filepath.Join(root, "dev") || len(e.Actions) != 1 || e.Actions[0].Dir != filepath.Join(root, "dev") || e.Actions[0].Tier != "disposable" {
		t.Fatalf("log should record the workdir and the disposable tier: cwd %q actions %+v", e.Cwd, e.Actions)
	}
	// The same command without a workdir has an unknown directory: it is
	// judged at the most protected tier under the root (prod/** is
	// protected), so the destroy is denied and the reason says why.
	got, e = run(root, map[string]any{"command": "terraform destroy -auto-approve"}, nil)
	if got != "deny" || e.Actions[0].Dir != root || e.Actions[0].Tier != "protected" {
		t.Fatalf("destroy without a workdir: got %s dir %q tier %q, want deny at %q as protected", got, e.Actions[0].Dir, e.Actions[0].Tier, root)
	}
	if !strings.Contains(strings.Join(e.Actions[0].Matched, "; "), "command directory not reported by codex") {
		t.Fatalf("matched should say the directory was not reported: %v", e.Actions[0].Matched)
	}

	// A relative planfile resolves against the workdir, so the plan gate reads
	// the file Codex is about to apply instead of reporting it missing.
	if err := os.WriteFile(filepath.Join(root, "dev", "simple.tfplan"), []byte("not a real planfile"), 0o644); err != nil {
		t.Fatal(err)
	}
	var showDir, showPlan string
	show := func(engine, dir, planfile string) ([]byte, error) {
		showDir, showPlan = dir, planfile
		p := planfile
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, errors.New("terraform show failed: " + err.Error())
		}
		return []byte(`{"format_version":"1.2","terraform_version":"1.16.1","resource_changes":[]}`), nil
	}
	got, e = run(root, map[string]any{"command": "terraform apply simple.tfplan", "workdir": "dev"}, show)
	if got != "allow" {
		t.Fatalf("apply of a saved plan in the disposable workdir: got %s", got)
	}
	if showDir != filepath.Join(root, "dev") || showPlan != "simple.tfplan" {
		t.Fatalf("show ran in %q on %q, want %q and simple.tfplan", showDir, showPlan, filepath.Join(root, "dev"))
	}
	a := e.Actions[0]
	if a.PlanSHA256 == "" {
		t.Fatalf("the planfile was not read: %+v", a)
	}
	for _, f := range a.Findings {
		if f.Rule == "plan-missing" || f.Rule == "plan-unreadable" {
			t.Fatalf("plan gate did not read the planfile: %+v", a.Findings)
		}
	}
	// The same apply without the workdir: the planfile is not in the root,
	// but exactly one copy exists under it, so that copy's directory becomes
	// the command directory and the plan gate reads it there.
	got, e = run(root, map[string]any{"command": "terraform apply simple.tfplan"}, show)
	if got != "allow" {
		t.Fatalf("apply without a workdir, unique planfile under the root: got %s, want allow: %+v", got, e.Actions[0])
	}
	a = e.Actions[0]
	if a.Dir != filepath.Join(root, "dev") || a.Tier != "disposable" || a.PlanSHA256 == "" || showDir != filepath.Join(root, "dev") {
		t.Fatalf("planfile search should set the command directory: dir %q tier %q sha %q show in %q", a.Dir, a.Tier, a.PlanSHA256, showDir)
	}
	if !strings.Contains(strings.Join(a.Matched, "; "), "found once under it") {
		t.Fatalf("matched should say how the planfile was found: %v", a.Matched)
	}
}

func TestCodexDirKnown(t *testing.T) {
	// A Codex shell event knows its directory only when the hook input
	// names a workdir; file edits are resolved against the turn's cwd by
	// Codex itself, so they are always known. Claude Code's cwd follows the
	// shell, so it is always known.
	cases := []struct {
		name  string
		tool  string
		input map[string]any
		want  bool
	}{
		{"bare command", "Bash", map[string]any{"command": "pwd"}, false},
		{"empty workdir", "Bash", map[string]any{"command": "pwd", "workdir": ""}, false},
		{"workdir", "Bash", map[string]any{"command": "pwd", "workdir": "examples/simple"}, true},
		{"working_directory", "Bash", map[string]any{"command": "pwd", "working_directory": "/work/repo/x"}, true},
		{"cwd in tool_input", "exec_command", map[string]any{"command": "pwd", "cwd": "x"}, true},
		{"apply_patch", "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: x\n*** End Patch\n"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok, err := Codex{}.Parse([]byte(event(c.tool, "/work/repo", c.input)))
			if err != nil || !ok {
				t.Fatalf("parse: ok=%v err=%v", ok, err)
			}
			if ev.DirKnown != c.want {
				t.Fatalf("DirKnown=%v, want %v", ev.DirKnown, c.want)
			}
		})
	}
	ev, _, err := Claude{}.Parse([]byte(event("Bash", "/work/repo/examples", map[string]any{"command": "pwd"})))
	if err != nil || !ev.DirKnown {
		t.Fatalf("claude: DirKnown=%v err=%v", ev.DirKnown, err)
	}
}

func TestCodexUnknownDirFailsClosed(t *testing.T) {
	// The user decision: a Codex command without a workdir under a root that
	// holds a protected directory is judged as protected, whatever the root
	// itself would be; with unknown_dir: session_root in the USER config it
	// is judged at the root; a repository config cannot loosen it.
	root := setupRootStandard(t)
	run := func(userCfg string, cwd string) (string, decisionlog.Entry) {
		log := filepath.Join(t.TempDir(), "log.jsonl")
		opt := Options{LogPath: log, NoGit: true, Env: map[string]string{}}
		if userCfg != "" {
			opt.UserConfig = filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(opt.UserConfig, []byte(userCfg), 0o644)
		}
		o := Run(Codex{}, strings.NewReader(event("Bash", cwd, map[string]any{"command": "terraform destroy -auto-approve"})), opt)
		return decision(t, o), readLog(t, log)
	}
	if got, e := run("", root); got != "deny" || e.Actions[0].Tier != "protected" || e.Actions[0].Env != "prod" {
		t.Fatalf("default: got %s tier %q env %q, want deny/protected/prod", got, e.Actions[0].Tier, e.Actions[0].Env)
	}
	// session_root from the user config: the root is standard, so a destroy
	// asks, which Codex enforces as deny, but the tier is the root's.
	if got, e := run("unknown_dir: session_root\n", root); got != "deny" || e.Actions[0].Tier != "standard" {
		t.Fatalf("session_root: got %s tier %q, want deny/standard", got, e.Actions[0].Tier)
	}
	if got, e := run("unknown_dir: session_root\n", filepath.Join(root, "dev")); got != "allow" || e.Actions[0].Tier != "disposable" {
		t.Fatalf("session_root in dev: got %s tier %q, want allow/disposable", got, e.Actions[0].Tier)
	}
	// A repository config that says session_root is ignored.
	os.WriteFile(filepath.Join(root, ".seatbelt.yaml"), []byte(rootStandardConfig+"unknown_dir: session_root\n"), 0o644)
	if got, e := run("", root); got != "deny" || e.Actions[0].Tier != "protected" {
		t.Fatalf("repo config must not loosen unknown_dir: got %s tier %q", got, e.Actions[0].Tier)
	}
	// A cd inside the command establishes the directory.
	o := Run(Codex{}, strings.NewReader(event("Bash", root, map[string]any{"command": "cd dev && terraform destroy -auto-approve"})), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if got := decision(t, o); got != "allow" {
		t.Fatalf("cd inside the command should make the directory known: got %s (%s)", got, o.Stdout)
	}
}

func TestCodexProtectedWorkdirUnderDisposableRoot(t *testing.T) {
	// The reverse safety case: the session is rooted in a disposable
	// directory but the command runs in a protected one. The workdir must
	// win, so the destroy blocks.
	root := setupRootStandard(t)
	dev := filepath.Join(root, "dev")
	for _, wd := range []string{filepath.Join(root, "prod"), "../prod"} {
		log := filepath.Join(t.TempDir(), "log.jsonl")
		o := Run(Codex{}, strings.NewReader(event("Bash", dev, map[string]any{"command": "terraform destroy -auto-approve", "workdir": wd})),
			Options{LogPath: log, NoGit: true, Env: map[string]string{}})
		if got := decision(t, o); got != "deny" {
			t.Fatalf("workdir %q: destroy in a protected workdir must be denied, got %s", wd, got)
		}
		e := readLog(t, log)
		if e.Cwd != filepath.Join(root, "prod") || e.Actions[0].Tier != "protected" {
			t.Fatalf("workdir %q: log cwd %q tier %q", wd, e.Cwd, e.Actions[0].Tier)
		}
	}
	// And without a workdir the disposable root allows it, which is what
	// makes the workdir the safety-relevant signal.
	o := Run(Codex{}, strings.NewReader(event("Bash", dev, map[string]any{"command": "terraform destroy -auto-approve"})),
		Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if got := decision(t, o); got != "allow" {
		t.Fatalf("destroy at a disposable root: got %s", got)
	}
}
