package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every value is known or unknown with a reason, and an unknown that reaches a
// decision in a protected tier is never an allow. Each position of a terraform
// command an unknown can take (an option before the subcommand, the -chdir
// value, the subcommand, a flag after it) is checked in a protected directory.
func TestUnknownReachingADecisionFailsClosedWithItsReason(t *testing.T) {
	root := writeRepo(t, mixedRepo, "envs/prod", "envs/dev")
	if err := os.WriteFile(filepath.Join(root, "envs/prod/main.tf"), []byte("resource \"terraform_data\" \"x\" {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := loadCfg(t, "", root)
	prod := filepath.Join(root, "envs/prod")
	cases := []struct{ name, cmd, reason string }{
		{"unknown option before the subcommand", `read x <<< "-chdir=/tmp"; terraform $x plan`, ""},
		{"unknown -chdir value", `terraform -chdir=$NOPE plan`, "NOPE"},
		{"unknown subcommand", `terraform $NOPE`, "NOPE"},
		{"unknown from a command substitution", `terraform -chdir=$(ls -d /tmp) plan`, "ls -d /tmp"},
		{"unknown from a glob", `terraform -chdir=../p* plan`, ""},
		{"unknown from a positional parameter", `f() { terraform -chdir=$1 plan; }; f "$(date)"`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: c.cmd, Cwd: prod, DirKnown: true, CanAsk: true}, cfg, Deps{})
			if d.Enforced == Allow {
				t.Fatalf("an unknown in a protected directory was allowed: %q", c.cmd)
			}
			if c.reason != "" && !strings.Contains(d.Message, c.reason) {
				t.Fatalf("the decision does not say why the value is unknown (%q): %s", c.reason, d.Message)
			}
		})
	}
}

// A panic inside the engine check is recovered by Run as ErrPanic, which the
// hook treats as a failure of the analysis.
func TestRunWrapsPanicAsErrPanic(t *testing.T) {
	PanicHook = func(string) { panic("injected") }
	defer func() { PanicHook = nil }()
	_, err := Run(5*time.Second, func(context.Context) Decision { panicPoint("decide"); return Decision{} })
	if err == nil || !errors.Is(err, ErrPanic) {
		t.Fatalf("got %v", err)
	}
}
