package preflight

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// staging.tfplan was produced by Terraform 1.16.1 from a terraform_data-only
// configuration with a local backend in workspace "staging".
func TestPlanWorkspace(t *testing.T) {
	ws, ok := PlanWorkspace("testdata/staging.tfplan")
	if !ok || ws != "staging" {
		t.Fatalf("PlanWorkspace = %q, %v; want staging", ws, ok)
	}
	if _, ok := PlanWorkspace("preflight.go"); ok {
		t.Fatal("non-plan file should not parse")
	}
}

func TestLockfileDrift(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write(".terraform.lock.hcl", "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"5.0.0\"\n}\n")
	write("main.tf", "module \"db\" {\n  source = \"./modules/db\"\n}\n")
	git("add", ".")
	git("commit", "-q", "-m", "init")
	if f := LockfileDrift(dir); f != nil {
		t.Fatalf("clean tree flagged: %+v", f)
	}
	write("main.tf", "module \"db\" {\n  source = \"git::https://example.invalid/db.git\"\n}\n")
	if f := LockfileDrift(dir); f == nil || f.Rule != "lockfile-drift" {
		t.Fatalf("module source change not flagged: %+v", f)
	}
	git("checkout", "-q", "--", "main.tf")
	write(".terraform.lock.hcl", "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"6.0.0\"\n}\n")
	if f := LockfileDrift(dir); f == nil {
		t.Fatal("lock file change not flagged")
	}
	if f := LockfileDrift(t.TempDir()); f != nil {
		t.Fatal("non-repository flagged")
	}
}

func TestStaleStateAndBackend(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("terraform {\n  backend \"s3\" {\n    bucket = \"b\"\n    key    = \"new\"\n  }\n}\n"), 0o644)
	declared := DeclaredBackend(dir)
	if declared == nil || declared.Type != "s3" || declared.Config["key"] != "new" {
		t.Fatalf("declared %+v", declared)
	}
	if StaleState(dir, declared) != nil {
		t.Fatal("clean dir flagged")
	}
	os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte("{}"), 0o644)
	if f := StaleState(dir, declared); f == nil {
		t.Fatal("local state beside remote backend not flagged")
	}
	if f := StaleState(dir, &Backend{Type: "local"}); f != nil {
		t.Fatal("local state with local backend flagged")
	}
	if f := BackendChanged(declared, &Backend{Type: "s3", Config: map[string]string{"bucket": "b", "key": "old"}}); f == nil {
		t.Fatal("key change not flagged")
	}
}
