package main

import (
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
