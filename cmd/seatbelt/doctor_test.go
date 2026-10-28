package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
