package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Terragrunt's own show is never run (review finding E2): the saved plan is
// found in the Terragrunt cache and shown there with terraform.
func TestTerragruntCacheDir(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touch := func(p string) {
		if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	work := ".terragrunt-cache/abc/def/modules/app"
	mk(work + "/.terraform")
	touch(work + "/tfplan")
	got, err := terragruntCacheDir(root, "tfplan")
	if err != nil || got != filepath.Join(root, work) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := terragruntCacheDir(root, "other.tfplan"); err == nil || !strings.Contains(err.Error(), "terragrunt show is not run") {
		t.Fatalf("missing plan: %v", err)
	}
	mk(".terragrunt-cache/x/y/.terraform")
	touch(".terragrunt-cache/x/y/tfplan")
	if _, err := terragruntCacheDir(root, "tfplan"); err == nil || !strings.Contains(err.Error(), "2 Terragrunt cache directories") {
		t.Fatalf("two copies: %v", err)
	}
}
