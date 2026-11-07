package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// A panic inside check's analysis is a block (exit 2), never a clean exit, so
// a gate that runs check cannot proceed on it.
func TestCheckPanicFailsClosed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	policy.PanicHook = func(site string) {
		if site == "decide" {
			panic("injected")
		}
	}
	defer func() { policy.PanicHook = nil }()
	var out, errb bytes.Buffer
	code := run([]string{"check", "--cwd", t.TempDir(), "terraform destroy -auto-approve"}, strings.NewReader(""), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "fails closed") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}
