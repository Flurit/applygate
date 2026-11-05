package policy

import (
	"path/filepath"
	"testing"

	"github.com/Flurit/applygate/internal/classify"
)

// The null device is empty: a sandbox that points AWS_CONFIG_FILE at it names
// no program. Any other file the CLI cannot read stays unknown.
func TestCredFileRunsNullDevice(t *testing.T) {
	a := classify.Action{Env: map[string]string{"AWS_CONFIG_FILE": "/dev/null"}}
	if got := credFileRuns(a); got != "" {
		t.Errorf("/dev/null asked: %s", got)
	}
	dir := t.TempDir()
	a = classify.Action{Dir: dir, Env: map[string]string{"AWS_CONFIG_FILE": filepath.Join(dir)}}
	if got := credFileRuns(a); got == "" {
		t.Errorf("a directory named as the config file did not ask")
	}
}
