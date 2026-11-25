package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
)

// In a repository with no config, a directory nothing names is protected
// only by the strict default. Strict shapes then ask about a command that is
// not plain only when it names an infrastructure tool or a guard file.
func TestUnconfiguredShapes(t *testing.T) {
	base := t.TempDir()
	mk := func(parts ...string) string {
		d := filepath.Join(append([]string{base}, parts...)...)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	write := func(path string, lines ...string) string {
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	home := mk("home")
	bare := mk("work", "app")    // no config at or above it
	bare2 := mk("work", "other") // another directory with no config
	named := mk("work", "prod")  // no config, but the name says production
	covered := mk("team", "svc") // a repository with a config that names nothing
	write(filepath.Join(mk("team"), config.FileName), "mode: enforce")
	strictUser := write(filepath.Join(base, "strict.yaml"), "strict_shapes: true")
	looseUser := write(filepath.Join(base, "loose.yaml"), "strict: false", "default_tier: standard")
	envUser := write(filepath.Join(base, "env.yaml"), "environments:", "  - name: payments", "    tier: protected",
		"    match: {paths: ['"+bare+"', '"+bare+"/**']}")
	profileUser := write(filepath.Join(base, "profile.yaml"), "environments:", "  - name: payments", "    tier: protected",
		"    match: {aws_profiles: [payments-admin]}")

	const (
		variable = `D=/tmp/x; ls "$D"`
		loop     = `for f in a b; do wc -l "$f"; done`
		script   = `python3 tools/report.py`
		tests    = `go test ./...`
		hidden   = `MANPAGER='terraform destroy -auto-approve' man ls`
		cluster  = `for n in a b; do kubectl -n "$n" delete pods --all; done`
		cdk      = `npx cdk destroy`
		guard    = `for f in a; do echo "$f"; done; ls .claude/settings.json`
		unseen   = `rg --pre sh x main.tf`
	)
	cases := []struct {
		name, user, dir, command string
		noLoad                   bool
		want                     Verdict
	}{
		{"a variable", "", bare, variable, false, Allow},
		{"a loop", "", bare, loop, false, Allow},
		{"a script", "", bare, script, false, Allow},
		{"the project's tests", "", bare, tests, false, Allow},
		{"a program that runs another, naming nothing", "", bare, unseen, false, Allow},
		{"a tool hidden in a variable", "", bare, hidden, false, Ask},
		{"a tool in a loop", "", bare, cluster, false, Block},
		{"a tool with no rules", "", bare, cdk, false, Ask},
		{"a guard file", "", bare, guard, false, Ask},
		{"a recognised command is judged as before", "", bare, "terraform destroy -auto-approve", false, Block},

		{"strict_shapes: true in the user config", strictUser, bare, variable, false, Ask},
		{"unknown directories are standard", looseUser, bare, variable, false, Allow},
		{"the user config names this directory", envUser, bare, variable, false, Ask},
		// A protected environment the user config names by profile could be
		// reached from any directory, so a command that is not plain is
		// asked about as before.
		{"the user config names an environment by profile", profileUser, bare, unseen, false, Ask},
		{"the user config names an environment by profile, a variable", profileUser, bare, variable, false, Ask},
		{"a name hint", "", named, variable, false, Ask},
		{"a repository with a config, directory not named", "", covered, variable, false, Ask},

		{"cd into another directory with no config", "", bare, "cd " + bare2 + " && " + variable, false, Allow},
		{"cd into a repository with a config", "", bare, "cd " + covered + " && " + variable, false, Ask},
		{"cd into a repository with a config that cannot be loaded here", "", bare, "cd " + covered + " && " + variable, true, Ask},
		{"from a repository with a config into one without", "", covered, "cd " + bare + " && " + variable, false, Ask},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.Load(c.user, c.dir)
			if err != nil {
				t.Fatal(err)
			}
			deps := Deps{Env: map[string]string{"PATH": "/nonexistent", "HOME": home}}
			if !c.noLoad {
				deps.LoadConfig = func(dir string) (*config.Config, error) { return config.Load(c.user, dir) }
			}
			d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: c.command, Cwd: c.dir, CanAsk: true, DirKnown: true}, cfg, deps)
			if d.Verdict != c.want {
				t.Errorf("%s in %s: got %s, want %s\n%s", c.command, strings.TrimPrefix(c.dir, base), d.Verdict, c.want, describe(d))
			}
			for _, a := range d.Actions {
				// The relaxed action stays visible: its class and tier are
				// kept and the reason is given.
				if a.Class == classify.ComplexShape && a.Verdict == Allow && a.Tier == config.Protected &&
					!strings.Contains(strings.Join(a.Matched, "; "), "names no infrastructure tool or guard file") {
					t.Errorf("an allowed strict-shapes action in a protected tier does not say why: %+v", a)
				}
			}
		})
	}
}

// Input typed into a shell that keeps running between calls is judged
// without knowing its directory, so the full rule holds there.
func TestUnconfiguredShapesNotInAPersistentShell(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "work", "app")
	os.MkdirAll(dir, 0o755)
	cfg, err := config.Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	ev := Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: `D=/tmp/x; ls "$D"`, Cwd: dir, CanAsk: true, DirKnown: true}
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent", "HOME": filepath.Join(base, "home")}}
	if d := Decide(ev, cfg, deps); d.Verdict != Allow {
		t.Fatalf("one call: got %s, want allow\n%s", d.Verdict, describe(d))
	}
	ev.Persistent = true
	if d := Decide(ev, cfg, deps); d.Verdict == Allow {
		t.Errorf("typed into a persistent shell: got allow, want an ask or a block\n%s", describe(d))
	}
}

// A config that is there but not trusted decides nothing, and every
// directory under it stays protected with full strict shapes: an agent
// cannot reach the looser rule by changing or planting a config.
func TestUnconfiguredShapesNeedNoConfigAtAll(t *testing.T) {
	config.TrustAll = false
	defer func() { config.TrustAll = true }()
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg"))
	dir := filepath.Join(base, "work", "app")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(base, "work", config.FileName), []byte("mode: enforce\n"), 0o600)
	cfg, err := config.Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Untrusted) != 1 || cfg.ShapesByWord() {
		t.Fatalf("untrusted %v, ShapesByWord %v; want one untrusted config and the full rule", cfg.Untrusted, cfg.ShapesByWord())
	}
	d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: `D=/tmp/x; ls "$D"`, Cwd: dir, CanAsk: true, DirKnown: true},
		cfg, Deps{Env: map[string]string{"PATH": "/nonexistent", "HOME": filepath.Join(base, "home")}})
	if d.Verdict != Ask {
		t.Errorf("got %s, want ask\n%s", d.Verdict, describe(d))
	}
}

func describe(d Decision) string {
	var b strings.Builder
	for _, a := range d.Actions {
		b.WriteString("  " + string(a.Verdict) + " " + string(a.Class) + " tier " + string(a.Tier) + ": " + a.Why + " [" + strings.Join(a.Matched, "; ") + "]\n")
	}
	return b.String()
}
