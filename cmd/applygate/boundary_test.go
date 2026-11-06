package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

func TestReachedLevel(t *testing.T) {
	ok := func(l int) boundaryCheck { return boundaryCheck{l, "ok", ""} }
	for _, c := range []struct {
		name   string
		checks []boundaryCheck
		want   int
	}{
		{"nothing is L0", nil, 0},
		{"L1 only", []boundaryCheck{ok(1), {2, "not verified", ""}}, 1},
		{"a failed L1 check stops everything above", []boundaryCheck{{1, "FAIL", ""}, ok(2), ok(3)}, 0},
		{"L3 without L2 is L1", []boundaryCheck{ok(1), {2, "FAIL", ""}, ok(3)}, 1},
		{"attested counts", []boundaryCheck{ok(1), ok(2), {3, "attested", ""}}, 3},
		{"not verified does not count", []boundaryCheck{ok(1), ok(2), {3, "not verified", ""}}, 2},
		{"optional checks (level 0) never count", []boundaryCheck{ok(1), {0, "not verified", ""}}, 1},
		{"a level with no checks is not reached", []boundaryCheck{ok(1), ok(3)}, 1},
	} {
		if got := reachedLevel(c.checks); got != c.want {
			t.Errorf("%s: level %d, want %d", c.name, got, c.want)
		}
	}
}

func boundaryHome(t *testing.T, userConfig string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("PATH", t.TempDir()) // no aws, no kubectl: nothing to audit
	if err := os.MkdirAll(filepath.Join(home, ".config", "applygate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.UserPath(), []byte(userConfig), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorBoundaryWithoutAnyBoundaryIsL0(t *testing.T) {
	boundaryHome(t, "version: 1\n")
	var out, errb bytes.Buffer
	if rc := cmdDoctorBoundary(nil, &out, &errb); rc != 0 {
		t.Fatalf("no requirement, rc %d: %s %s", rc, out.String(), errb.String())
	}
	for _, want := range []string{"Assurance level reached: L0", "no managed install", "nothing shows the agent's credentials cannot change production"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestDoctorBoundaryRequireExitsBelowTheLevel(t *testing.T) {
	boundaryHome(t, "version: 1\nboundary:\n  require: L1\n")
	var out, errb bytes.Buffer
	if rc := cmdDoctorBoundary(nil, &out, &errb); rc != 1 || !strings.Contains(out.String(), "Required level L1 not reached") {
		t.Fatalf("rc %d, want 1:\n%s", rc, out.String())
	}
	out.Reset()
	if rc := cmdDoctorBoundary([]string{"--require", "L0"}, &out, &errb); rc != 0 {
		t.Fatalf("--require L0 must pass, rc %d", rc)
	}
	if rc := cmdDoctorBoundary([]string{"--require", "L9"}, &out, &errb); rc != 2 {
		t.Fatalf("a bad level is a usage error, rc %d", rc)
	}
	if rc := cmdDoctorBoundary([]string{"--bogus"}, &out, &errb); rc != 2 {
		t.Fatalf("an unknown option is a usage error, rc %d", rc)
	}
}

func TestDoctorBoundaryAttestation(t *testing.T) {
	boundaryHome(t, "version: 1\nboundary:\n  attest: [ci_apply, state_guards, made_up]\n")
	var out, errb bytes.Buffer
	cmdDoctorBoundary(nil, &out, &errb)
	s := out.String()
	for _, want := range []string{"attested     ci_apply", "attested     state_guards", `"made_up", which is not one of`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "Assurance level reached: L3") {
		t.Error("attestation alone must not reach L3")
	}
}

func TestBoundaryIsUserConfigOnly(t *testing.T) {
	boundaryHome(t, "version: 1\n")
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".applygate.yaml"), []byte("version: 1\nboundary:\n  require: L0\n  attest: [ci_apply, state_guards]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPLYGATE_TRUST_ALL", "1")
	cfg, err := config.Load(config.UserPath(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Boundary.Require != "" || len(cfg.Boundary.Attest) != 0 {
		t.Errorf("a repository config set the boundary: %+v", cfg.Boundary)
	}
}

func TestSandboxStateNeedsManagedSettingsWithoutEscape(t *testing.T) {
	dir := t.TempDir()
	old := config.ClaudeManagedDir
	config.ClaudeManagedDir = dir
	defer func() { config.ClaudeManagedDir = old }()
	t.Setenv("HOME", t.TempDir())
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "managed-settings.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"sandbox":{"enabled":true}}`)
	if s, why := sandboxState(); s != "none" || !strings.Contains(why, "allowUnsandboxedCommands") {
		t.Errorf("an unsandboxed retry must not count: %s %s", s, why)
	}
	write(`{"sandbox":{"enabled":false}}`)
	if s, _ := sandboxState(); s != "none" {
		t.Errorf("sandbox off counted: %s", s)
	}
	// Owned by the test's user, not root: the file is one the agent could change.
	write(`{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}`)
	if s, why := sandboxState(); s != "none" || !strings.Contains(why, "sets the sandbox, but") {
		t.Errorf("a user-owned managed file must not count: %s %s", s, why)
	}
}
