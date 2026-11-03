package preflight

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

const provDir = ".terraform/providers/registry.terraform.io/hashicorp/aws/6.0.0/linux_amd64"

func lockFor(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h, err := hash1(d)
	if err != nil {
		t.Fatal(err)
	}
	return "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"6.0.0\"\n  hashes = [\n    \"" + h + "\",\n    \"zh:00\",\n  ]\n}\n"
}

func TestVerifyProviders(t *testing.T) {
	pkg := map[string]string{"terraform-provider-aws_v6.0.0": "binary", "LICENSE": "text"}
	lock := lockFor(t, pkg)
	files := map[string]string{".terraform.lock.hcl": lock, "main.tf": ""}
	for n, b := range pkg {
		files[provDir+"/"+n] = b
	}
	dir := gitRepo(t, files)
	ctx := context.Background()
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err != nil {
		t.Fatalf("matching provider rejected: %v", err)
	}
	// A provider replaced in the working tree does not match.
	bin := filepath.Join(dir, provDir, "terraform-provider-aws_v6.0.0")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nterraform destroy\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("replaced provider: %v", err)
	}
	// Editing the lock file to match is not enough: git HEAD's copy counts.
	if err := os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(lockFor(t, map[string]string{"terraform-provider-aws_v6.0.0": "#!/bin/sh\nterraform destroy\n", "LICENSE": "text"})), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err == nil {
		t.Fatal("a lock file edited in the working tree was trusted")
	}
	// An unlisted provider fails.
	extra := filepath.Join(dir, ".terraform/providers/registry.terraform.io/acme/evil/1.0.0/linux_amd64")
	_ = os.MkdirAll(extra, 0o755)
	_ = os.WriteFile(filepath.Join(extra, "p"), []byte("x"), 0o755)
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err == nil {
		t.Fatal("an unlisted provider was accepted")
	}
}

func TestVerifyProvidersWithoutLockOrProviders(t *testing.T) {
	ctx := context.Background()
	dir := gitRepo(t, map[string]string{"main.tf": ""})
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err != nil {
		t.Fatalf("no providers: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(dir, provDir), 0o755)
	_ = os.WriteFile(filepath.Join(dir, provDir, "p"), []byte("x"), 0o755)
	if err := VerifyProviders(ctx, dir, filepath.Join(dir, ".terraform")); err == nil || !strings.Contains(err.Error(), "no .terraform.lock.hcl committed") {
		t.Fatalf("no lock file: %v", err)
	}
}

func TestRunsPrograms(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"null_resource\" \"x\" {}\nmodule \"m\" {\n  source = \"./m\"\n}\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "m"), 0o755)
	if why := RunsPrograms(dir, filepath.Join(dir, ".terraform")); why != "" {
		t.Fatalf("a configuration without external data: %s", why)
	}
	os.WriteFile(filepath.Join(dir, "m", "x.tf"), []byte("data \"external\" \"x\" {\n  program = [\"sh\"]\n}\n"), 0o644)
	if why := RunsPrograms(dir, filepath.Join(dir, ".terraform")); why == "" {
		t.Fatal("external data in a local module was not found")
	}
	os.Remove(filepath.Join(dir, "m", "x.tf"))
	os.MkdirAll(filepath.Join(dir, ".terraform", "modules", "r"), 0o755)
	os.WriteFile(filepath.Join(dir, ".terraform", "modules", "r", "a.tf.json"), []byte(`{"data":{"external":{"x":{"program":["sh"]}}}}`), 0o644)
	if why := RunsPrograms(dir, filepath.Join(dir, ".terraform")); why == "" {
		t.Fatal("external data in a downloaded JSON module was not found")
	}
}
