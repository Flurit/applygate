package preflight

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Round-2 reproductions; see internal/reviewgap.

// The checks the hook runs must not start programs the repository's git
// config names: an agent can set core.fsmonitor (finding 2S13).
func TestReview2S13GitConfigDoesNotRunInTheHook(t *testing.T) {
	dir := gitRepo(t, map[string]string{"main.tf": "", ".terraform.lock.hcl": ""})
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "fsmonitor.sh")
	os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)
	cmd := exec.Command("git", "config", "core.fsmonitor", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("changed\n"), 0o644)
	// The same git invocations the lock-file and provider checks make, without
	// their timeout, so a slow machine cannot hide the hook.
	_ = gitCommand(context.Background(), dir, "--no-optional-locks", "diff", "HEAD", "--", ".terraform.lock.hcl", "*.tf").Run()
	_ = gitCommand(context.Background(), dir, "cat-file", "-p", "HEAD:./.terraform.lock.hcl").Run()
	_, err := os.Stat(marker)
	reviewgap.Check(t, "2S13", os.IsNotExist(err), "a program from the repository's git config ran inside the hook")
}
