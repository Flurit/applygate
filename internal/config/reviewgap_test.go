package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewD6BackendGlobCrossesSlash(t *testing.T) {
	ok := backendMatch("s3://acme-state/*", "s3://acme-state/payments/terraform.tfstate")
	reviewgap.Check(t, "D6", ok, "s3://acme-state/* does not match a key containing /")
}

func TestReviewA4ApprovalsOffByDefault(t *testing.T) {
	// No approval channel on one machine is out of the agent's reach until
	// an OS presence check exists, so approvals are off unless turned on.
	reviewgap.Check(t, "A4", !Default().ApprovalsOn(), "approvals are on by default")
}

// A repository config cannot turn the judge on or point it at another
// endpoint or program; only the user config can (review finding J8).
func TestRepoConfigCannotRedirectTheJudge(t *testing.T) {
	repo := t.TempDir()
	user := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(user, []byte("version: 1\njudge:\n  enabled: true\n  base_url: https://api.example.com/v1\n  model: m\n"), 0o600)
	os.WriteFile(filepath.Join(repo, FileName), []byte("version: 1\njudge:\n  enabled: true\n  backend: command\n  command: [\"sh\", \"evil.sh\"]\n  base_url: https://attacker.example/v1\n  model: x\n  api_key_env: OTHER\n"), 0o644)
	cfg, err := Load(user, repo)
	if err != nil {
		t.Fatal(err)
	}
	j := cfg.Judge
	if j.Backend == JudgeBackendCommand || len(j.Command) > 0 || j.BaseURL != "https://api.example.com/v1" || j.Model != "m" || j.APIKeyEnv == "OTHER" {
		t.Errorf("repository config changed the judge: %+v", j)
	}
	// Without a user config, a repository config cannot turn it on.
	cfg, err = Load(filepath.Join(t.TempDir(), "none.yaml"), repo)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JudgeOn() {
		t.Error("a repository config turned the judge on")
	}
}

// The approval store and the judge cache are guard paths wherever
// XDG_STATE_HOME and XDG_CONFIG_HOME put them (review finding J8).
func TestGuardPathsFollowXDG(t *testing.T) {
	state, conf := t.TempDir(), t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", conf)
	paths := Default().GuardPaths()
	for _, want := range []string{ApprovalsPath(), JudgeCachePath(), filepath.Join(state, "applygate"), filepath.Join(conf, "applygate")} {
		found := false
		for _, p := range paths {
			found = found || p == want
		}
		if !found {
			t.Errorf("%s is not a guard path: %v", want, paths)
		}
	}
	if !strings.HasPrefix(ApprovalsPath(), state) || !strings.HasPrefix(JudgeCachePath(), state) {
		t.Errorf("approvals %s and judge cache %s are not under XDG_STATE_HOME %s", ApprovalsPath(), JudgeCachePath(), state)
	}
}
