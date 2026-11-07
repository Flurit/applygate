package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

// A repository config that is not trusted is not read, but the repository's
// hook settings beside it are still guard files: removing, extracting into or
// copying into its .claude directory is tampering, as it is under a trusted
// config. Removing an ordinary directory is not.
func TestUntrustedConfigStillGuardsRepoHookDir(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		config.TrustAll = trusted
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
		t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".state"))
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte("version: 1\nenvironments:\n  - {name: dev, tier: disposable, match: {paths: [\"envs/dev/**\"]}}\n"), 0o644)
		os.MkdirAll(filepath.Join(root, ".claude"), 0o755)
		os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte("{}\n"), 0o644)
		dev := filepath.Join(root, "envs", "dev")
		os.MkdirAll(filepath.Join(dev, "build"), 0o755)
		for _, c := range []string{
			"rm -rf ../../.claude",
			"tar -xf a.tar -C ../../.claude",
			"unzip a.zip -d ../../.claude",
			"cp x ../../.claude",
			"cp /dev/null ../../.claude/settings.json",
		} {
			var out, errb bytes.Buffer
			if rc := run([]string{"check", "--no-judge", "--cwd", dev, "--", c}, nil, &out, &errb); rc == 0 {
				t.Errorf("trusted=%v: %q allowed:\n%s", trusted, c, out.String())
			}
		}
		var out, errb bytes.Buffer
		if rc := run([]string{"check", "--no-judge", "--cwd", dev, "--", "rm -rf build"}, nil, &out, &errb); rc != 0 {
			t.Errorf("trusted=%v: rm -rf build: rc %d\n%s", trusted, rc, out.String())
		}
	}
	config.TrustAll = true
}
