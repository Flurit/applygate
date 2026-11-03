package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// On macOS a directory's NFD and NFC spellings are the same directory, so
// both match an environment written either way (finding 2T20).
func TestNFDAndNFCMatch(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("APFS ignores normalization; other file systems keep both names")
	}
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, FileName), []byte("version: 1\nenvironments:\n  - {name: cafe, tier: protected, match: {paths: [\"envs/café/**\"]}}\n  - {name: rest, tier: disposable, match: {paths: [\"envs/**\"]}}\n"), 0o644)
	nfd := filepath.Join(repo, "envs", "café")
	os.MkdirAll(nfd, 0o755)
	cfg, err := Load("", repo)
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.Resolve(Signals{Dir: nfd}); r.Tier != Protected {
		t.Fatalf("NFD spelling resolved to %s %s: %v", r.Tier, r.Env, r.Matched)
	}
}
