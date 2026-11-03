package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

// A cd into another repository is judged by that repository's config too
// (finding 2T11): its protected environment is not lost to the session
// repository's default tier.
func TestOtherRepositoryConfig(t *testing.T) {
	user := "version: 1\nstrict: false\ndefault_tier: disposable\n"
	here := writeRepo(t, "version: 1\nenvironments:\n  - {name: dev, tier: disposable, match: {paths: [\"dev/**\"]}}\n", "dev")
	other := writeRepo(t, "version: 1\nenvironments:\n  - {name: core, tier: protected, match: {paths: [\"core/**\"]}}\n", "core")
	cfg := loadCfg(t, user, here)
	userPath := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(userPath, []byte(user), 0o644)
	ev := Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "cd " + filepath.Join(other, "core") + " && terraform destroy -auto-approve",
		Cwd: filepath.Join(here, "dev"), CanAsk: true, DirKnown: true}

	deps := Deps{Env: map[string]string{}}
	if d := Decide(ev, cfg, deps); d.Verdict != Allow {
		t.Fatalf("without the loader the session config's default tier decides: %s", d.Verdict)
	}
	deps.LoadConfig = func(dir string) (*config.Config, error) { return config.Load(userPath, dir) }
	if d := Decide(ev, cfg, deps); d.Verdict != Block || d.Actions[0].Env != "core" {
		t.Fatalf("got %s %s: %v", d.Verdict, d.Actions[0].Env, d.Actions[0].Matched)
	}
}
