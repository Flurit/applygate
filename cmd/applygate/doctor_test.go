package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const applygateSettings = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/usr/bin/applygate\" hook claude"}]}
    ]
  }
}`

func TestLaunchDirWarnings(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(applygateSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "envs", "prod")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	none := map[string]bool{}
	// Launched from the directory holding the hook: nothing to report.
	if c := launchDirChecks(root, none); len(c) != 0 {
		t.Fatalf("expected nothing from the hook directory, got %v", c)
	}

	// Launched from a subdirectory with no user-scope hook: Claude Code
	// would not load the ancestor project hook, so doctor must fail, name
	// the hook directory and give the exact fix.
	c := launchDirChecks(sub, none)
	if len(c) != 1 || !c[0].fail {
		t.Fatalf("expected one failure from a subdirectory, got %v", c)
	}
	if !strings.Contains(c[0].msg, "claude") || !strings.Contains(c[0].msg, root) || !strings.Contains(c[0].msg, "applygate hook install --agent claude --scope user") {
		t.Fatalf("failure should name the agent, the hook directory and the fix: %q", c[0].msg)
	}

	// With a user-scope hook the subdirectory is covered: ok, not a failure.
	c = launchDirChecks(sub, map[string]bool{"claude": true})
	if len(c) != 1 || c[0].fail || !strings.Contains(c[0].msg, "user-scope hook covers") {
		t.Fatalf("user scope should cover the subdirectory: %v", c)
	}

	// Project hook here plus a user-scope hook: runs twice, a warning with
	// the remove command.
	c = launchDirChecks(root, map[string]bool{"claude": true})
	if len(c) != 1 || c[0].fail || !strings.Contains(c[0].msg, "applygate hook remove --agent claude --scope project") {
		t.Fatalf("double install should warn: %v", c)
	}
}

func TestDoctorFailsFromSubdirectoryWithoutUserHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".claude"), 0o755)
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(applygateSettings), 0o644)
	os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte("version: 1\nmode: observe\nenvironments:\n  - {name: prod, tier: protected, match: {paths: [\"envs/prod/**\"]}}\n"), 0o644)
	sub := filepath.Join(root, "envs", "prod")
	os.MkdirAll(sub, 0o755)
	t.Chdir(sub)
	var out, errb bytes.Buffer
	if rc := cmdDoctor(&out, &errb); rc != 1 || !strings.Contains(out.String(), "FAIL claude: the project hook is in "+root) {
		t.Fatalf("doctor from a subdirectory without a user hook: rc %d\n%s", rc, out.String())
	}
	if !strings.Contains(out.String(), "Fix: applygate hook install --agent claude --scope user") {
		t.Fatalf("doctor should print the fix:\n%s", out.String())
	}
	// Install the user-scope hook: the failure goes away.
	var ib bytes.Buffer
	if rc := cmdInstall("install", []string{"--agent", "claude", "--scope", "user"}, &ib, &errb); rc != 0 {
		t.Fatalf("install: %d %s", rc, errb.String())
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err != nil || !settingsHasApplygate(b) {
		t.Fatalf("user-scope install did not write ~/.claude/settings.json: %v", err)
	}
	out.Reset()
	cmdDoctor(&out, &errb)
	if strings.Contains(out.String(), "FAIL") {
		t.Fatalf("doctor should not fail once a user-scope hook exists:\n%s", out.String())
	}
	// remove without --scope cleans both scopes.
	var rb bytes.Buffer
	if rc := cmdInstall("remove", []string{"--agent", "claude"}, &rb, &errb); rc != 0 {
		t.Fatalf("remove: %d %s", rc, errb.String())
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); settingsHasApplygate(b) {
		t.Fatal("remove did not clean the user scope")
	}
	if !strings.Contains(rb.String(), "removed 1 applygate hook entry from "+filepath.Join(home, ".claude", "settings.json")) {
		t.Fatalf("remove output: %s", rb.String())
	}
}

func TestApplygateHookDirIgnoresNonApplygate(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".claude"), 0o755)
	// A settings file with an unrelated hook must not be treated as applygate's.
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`), 0o644)
	if dir := applygateHookDir(root, filepath.Join(".claude", "settings.json")); dir != "" {
		t.Fatalf("non-applygate hook should not match, got %q", dir)
	}
}

func TestScanHooks(t *testing.T) {
	doc := `{"hooks":{"PreToolUse":[
		{"matcher":"Bash","hooks":[{"type":"command","command":"\"/usr/bin/applygate\" hook codex"}]},
		{"matcher":"*","hooks":[{"type":"command","command":"my-own-logger --flag"}]}
	]}}`
	s, ok := scanHooks([]byte(doc))
	if !ok {
		t.Fatal("valid JSON reported invalid")
	}
	if len(s.applygateBins) != 1 || s.applygateBins[0] != "/usr/bin/applygate" {
		t.Fatalf("applygate bins: %v", s.applygateBins)
	}
	if len(s.unrecognised) != 1 || !strings.Contains(s.unrecognised[0], "my-own-logger") {
		t.Fatalf("unrecognised: %v", s.unrecognised)
	}
	if _, ok := scanHooks([]byte("{not json")); ok {
		t.Fatal("invalid JSON reported valid")
	}
}

func TestBinExecutable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "run")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, why := binExecutable(exe); !ok {
		t.Fatalf("executable file reported bad: %s", why)
	}
	noexe := filepath.Join(dir, "data")
	os.WriteFile(noexe, []byte("x"), 0o644)
	if ok, why := binExecutable(noexe); ok || why != "not executable" {
		t.Fatalf("non-executable: ok=%v why=%q", ok, why)
	}
	if ok, why := binExecutable(filepath.Join(dir, "missing")); ok || why != "not found" {
		t.Fatalf("missing: ok=%v why=%q", ok, why)
	}
	if ok, why := binExecutable(dir); ok || why != "is a directory" {
		t.Fatalf("directory: ok=%v why=%q", ok, why)
	}
}

func TestCodexInstallPreservesEntries(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.MkdirAll(".codex", 0o755); err != nil {
		t.Fatal(err)
	}
	// A pre-existing, unrelated Codex hook and an unrelated top-level key.
	orig := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-own-logger"}]}]},"model":"gpt-x"}`
	if err := os.WriteFile(".codex/hooks.json", []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := cmdInstall("install", []string{"--agent", "codex"}, &out, &errb); rc != 0 {
		t.Fatalf("install rc=%d stderr=%s", rc, errb.String())
	}
	b, _ := os.ReadFile(".codex/hooks.json")
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["model"] != "gpt-x" {
		t.Fatalf("unrelated top-level key dropped: %v", doc["model"])
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	var sawOwn, sawApplygate bool
	for _, e := range pre {
		if isApplygateEntry(e) {
			sawApplygate = true
			continue
		}
		if strings.Contains(entrySummary(e), "my-own-logger") {
			sawOwn = true
		}
	}
	if !sawApplygate {
		t.Fatal("applygate entry was not installed")
	}
	if !sawOwn {
		t.Fatal("unrelated hook entry was dropped by install")
	}
}

func TestDetectAgents(t *testing.T) {
	home := t.TempDir()
	wd := t.TempDir()
	none := func(string) (string, error) { return "", os.ErrNotExist }
	if got := detectAgents(home, wd, none); len(got) != 0 {
		t.Fatalf("nothing installed, got %v", got)
	}
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	if got := detectAgents(home, wd, none); len(got) != 1 || got[0] != "claude" {
		t.Fatalf("user .claude dir should detect claude, got %v", got)
	}
	os.MkdirAll(filepath.Join(wd, ".codex"), 0o755)
	if got := detectAgents(home, wd, none); len(got) != 2 || got[1] != "codex" {
		t.Fatalf("project .codex dir should add codex, got %v", got)
	}
	onPath := func(bin string) (string, error) {
		if bin == "codex" {
			return "/usr/bin/codex", nil
		}
		return "", os.ErrNotExist
	}
	if got := detectAgents(t.TempDir(), t.TempDir(), onPath); len(got) != 1 || got[0] != "codex" {
		t.Fatalf("codex on PATH should detect codex, got %v", got)
	}
}

func TestInitInstallsHooksForDetectedAgents(t *testing.T) {
	wd := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(wd, ".claude"), 0o755)
	old, _ := os.Getwd()
	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	var out, errb bytes.Buffer
	if rc := cmdInit(nil, &out, &errb); rc != 0 {
		t.Fatalf("init rc %d: %s %s", rc, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "detected agents: claude") {
		t.Fatalf("init should report the detected agent: %s", out.String())
	}
	// init installs at user scope, so the hook fires from any directory.
	b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil || !settingsHasApplygate(b) {
		t.Fatalf("init should install the claude user-scope hook: %v %s", err, b)
	}
	if _, err := os.Stat(filepath.Join(wd, ".claude", "settings.json")); err == nil {
		t.Fatal("init should not write a project-scope hook by default")
	}
	if !strings.Contains(out.String(), "user scope") {
		t.Fatalf("init should explain the scope choice: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(wd, ".applygate.yaml")); err != nil {
		t.Fatal("config not written")
	}
	// --scope project keeps the old behaviour.
	wd3 := t.TempDir()
	os.MkdirAll(filepath.Join(wd3, ".claude"), 0o755)
	os.Chdir(wd3)
	out.Reset()
	if rc := cmdInit([]string{"--scope", "project"}, &out, &errb); rc != 0 {
		t.Fatalf("init --scope project rc %d", rc)
	}
	if b, err := os.ReadFile(filepath.Join(wd3, ".claude", "settings.json")); err != nil || !settingsHasApplygate(b) {
		t.Fatalf("init --scope project should write the project hook: %v", err)
	}
	os.Chdir(wd)
	// --no-hooks writes the config only.
	wd2 := t.TempDir()
	os.MkdirAll(filepath.Join(wd2, ".claude"), 0o755)
	os.Chdir(wd2)
	out.Reset()
	if rc := cmdInit([]string{"--no-hooks"}, &out, &errb); rc != 0 {
		t.Fatalf("init --no-hooks rc %d", rc)
	}
	if _, err := os.Stat(filepath.Join(wd2, ".claude", "settings.json")); err == nil {
		t.Fatal("--no-hooks must not install hooks")
	}
}

// Hook entries written before the rename call the seatbelt binary; they are
// still recognised as ours (so doctor sees them and hook install replaces
// them rather than adding a second entry).
func TestLegacySeatbeltHookEntryRecognised(t *testing.T) {
	legacy := `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/usr/local/bin/seatbelt\" hook claude"}]}]}}`
	if !settingsHasApplygate([]byte(legacy)) {
		t.Fatal("a seatbelt hook entry should be recognised as ours")
	}
	other := `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "guardfall hook claude"}]}]}}`
	if settingsHasApplygate([]byte(other)) {
		t.Fatal("a third-party hook entry must not be recognised as ours")
	}
}
