package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A configuration file the hook cannot read in full hides every signal in it:
// padded past the cap, it must make the target unknown, not absent.
func TestConfigUnreadableOversize(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.tf")
	body := "provider \"aws\" {\n  profile = \"prod-admin\"\n}\n"
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := ConfigUnreadable(dir); why != "" {
		t.Fatalf("readable file: %q", why)
	}
	pad := strings.Repeat("#", MaxConfigFile+1-len(body)) + "\n"
	if err := os.WriteFile(main, []byte(body+pad), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := ConfigUnreadable(dir); why == "" {
		t.Fatal("a file over the cap must be unreadable")
	}
	// A file that does not parse, an oversize tfvars and a deep module chain too.
	if err := os.WriteFile(main, []byte("provider \"aws\" {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := ConfigUnreadable(dir); why == "" {
		t.Fatal("a file that does not parse must be unreadable")
	}
	_ = os.WriteFile(main, []byte(body), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "terraform.tfvars"), []byte(strings.Repeat("#", MaxConfigFile+10)), 0o644)
	if why := ConfigUnreadable(dir); why == "" {
		t.Fatal("an oversize tfvars file must be unreadable")
	}
}

func TestProgramScanReadsQueryTestAndEncryption(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data := filepath.Join(dir, ".terraform")
	write("main.tf", "terraform {}\n")
	if why := RunsPrograms(dir, data); why != "" {
		t.Fatalf("clean config: %q", why)
	}
	write("x.tfquery.hcl", "provider \"kubernetes\" {\n  exec {\n    command = \"sh\"\n  }\n}\n")
	if why := RunsPrograms(dir, data); why == "" {
		t.Error(".tfquery.hcl provider exec not found")
	}
	os.Remove(filepath.Join(dir, "x.tfquery.hcl"))
	write("tests/y.tftest.hcl", "provider \"kubernetes\" {\n  exec {\n    command = \"sh\"\n  }\n}\n")
	if why := RunsPrograms(dir, data); why == "" {
		t.Error("tests/*.tftest.hcl provider exec not found")
	}
	os.Remove(filepath.Join(dir, "tests", "y.tftest.hcl"))
	write("enc.tf", "terraform {\n  encryption {\n    key_provider \"external\" \"x\" {\n      command = [\"./k\"]\n    }\n  }\n}\n")
	if why := RunsPrograms(dir, data); why == "" {
		t.Error("external key provider not found")
	}
	if why := RunsBackendPrograms(dir); why == "" {
		t.Error("external key provider not found by the backend scan")
	}
}

func TestBackendConfigRunsPrograms(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil.hcl"), []byte("bucket = \"x\"\nshared_config_files = [\"./aws.cfg\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := RunsBackendConfig(dir, []string{"evil.hcl"}); why == "" {
		t.Error("a -backend-config file naming shared_config_files must be found")
	}
	if why := RunsBackendConfig(dir, []string{`shared_config_files=["./aws.cfg"]`}); why == "" {
		t.Error("a -backend-config pair naming shared_config_files must be found")
	}
	if why := RunsBackendConfig(dir, []string{"bucket=x", `shared_config_files=["~/.aws/config"]`}); why != "" {
		t.Errorf("the user's own AWS config is not a finding: %q", why)
	}
}
