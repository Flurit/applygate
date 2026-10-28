package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const seatbeltSettings = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/usr/bin/seatbelt\" hook claude"}]}
    ]
  }
}`

func TestLaunchDirWarnings(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(seatbeltSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "envs", "prod")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	// Launched from the directory holding the hook: no warning.
	if w := launchDirWarnings(root); len(w) != 0 {
		t.Fatalf("expected no warning from the hook directory, got %v", w)
	}

	// Launched from a subdirectory: Claude Code would not load the ancestor
	// project hook, so doctor must warn and name the hook directory.
	w := launchDirWarnings(sub)
	if len(w) != 1 {
		t.Fatalf("expected one warning from a subdirectory, got %v", w)
	}
	if !strings.Contains(w[0], "claude") || !strings.Contains(w[0], root) {
		t.Fatalf("warning should name the agent and the hook directory: %q", w[0])
	}
}

func TestSeatbeltHookDirIgnoresNonSeatbelt(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".claude"), 0o755)
	// A settings file with an unrelated hook must not be treated as seatbelt's.
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`), 0o644)
	if dir := seatbeltHookDir(root, filepath.Join(".claude", "settings.json")); dir != "" {
		t.Fatalf("non-seatbelt hook should not match, got %q", dir)
	}
}

func TestScanHooks(t *testing.T) {
	doc := `{"hooks":{"PreToolUse":[
		{"matcher":"Bash","hooks":[{"type":"command","command":"\"/usr/bin/seatbelt\" hook codex"}]},
		{"matcher":"*","hooks":[{"type":"command","command":"my-own-logger --flag"}]}
	]}}`
	s, ok := scanHooks([]byte(doc))
	if !ok {
		t.Fatal("valid JSON reported invalid")
	}
	if len(s.seatbeltBins) != 1 || s.seatbeltBins[0] != "/usr/bin/seatbelt" {
		t.Fatalf("seatbelt bins: %v", s.seatbeltBins)
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
	var sawOwn, sawSeatbelt bool
	for _, e := range pre {
		if isSeatbeltEntry(e) {
			sawSeatbelt = true
			continue
		}
		if strings.Contains(entrySummary(e), "my-own-logger") {
			sawOwn = true
		}
	}
	if !sawSeatbelt {
		t.Fatal("seatbelt entry was not installed")
	}
	if !sawOwn {
		t.Fatal("unrelated hook entry was dropped by install")
	}
}
