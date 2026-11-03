package shell

import (
	"os"
	"path/filepath"
	"testing"
)

// A CDPATH from the person's environment is followed as bash follows it;
// one the command sets makes a bare cd unknown.
func TestCDPATH(t *testing.T) {
	cwd, other := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(other, "app"), 0o755)
	os.MkdirAll(filepath.Join(cwd, "local"), 0o755)
	dirOf := func(cmd string, env map[string]string) string {
		res := Analyze(cmd, Options{Dir: cwd, Env: env, ReadFile: os.ReadFile})
		for _, inv := range res.Invocations {
			if inv.Name() == "terraform" {
				return inv.Dir
			}
		}
		t.Fatalf("%s: no terraform invocation", cmd)
		return ""
	}
	env := map[string]string{"CDPATH": ".:" + other}
	if d := dirOf("cd app && terraform plan", env); d != filepath.Join(other, "app") {
		t.Errorf("environment CDPATH: %q", d)
	}
	if d := dirOf("cd local && terraform plan", env); d != filepath.Join(cwd, "local") {
		t.Errorf("environment CDPATH, current directory first: %q", d)
	}
	if d := dirOf("CDPATH="+other+"; cd app && terraform plan", nil); d != "" {
		t.Errorf("CDPATH set by the command: %q, want unknown", d)
	}
	if d := dirOf("cd ./local && terraform plan", map[string]string{"CDPATH": other}); d != filepath.Join(cwd, "local") {
		t.Errorf("./ is not searched: %q", d)
	}
}
