package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// applyRepo writes a repository with protected, standard and disposable
// directories, an empty saved plan in each (the plan's JSON comes from
// --plan-json), and returns the root.
func applyRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cfg := "mode: enforce\nstrict: true\nenvironments:\n" +
		"  - name: prod\n    tier: protected\n    match: {paths: [\"envs/prod/**\"]}\n" +
		"  - name: stage\n    tier: standard\n    match: {paths: [\"envs/stage/**\"]}\n" +
		"  - name: dev\n    tier: disposable\n    match: {paths: [\"envs/dev/**\"]}\n"
	if err := os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"envs/prod", "envs/stage", "envs/dev"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
		os.WriteFile(filepath.Join(root, d, "tfplan"), nil, 0o644)
	}
	return root
}

type fakeExec struct {
	calls [][]string
	dir   string
	code  int
}

func (f *fakeExec) run(bin string, args []string, dir string, _ io.Reader, _, _ io.Writer) int {
	f.calls = append(f.calls, append([]string{bin}, args...))
	f.dir = dir
	return f.code
}

func TestApplyJudgesThePlanBeforeRunningTheEngine(t *testing.T) {
	root := applyRepo(t)
	destroy, _ := filepath.Abs("../../review/real_plan/delete_real_shape.show.json")
	create, _ := filepath.Abs("../../review/real_plan/create.show.json")
	fe := &fakeExec{code: 7}
	oldExec, oldTTY := applyExec, isTerminal
	applyExec, isTerminal = fe.run, func(io.Reader) bool { return false }
	defer func() { applyExec, isTerminal = oldExec, oldTTY }()
	run := func(dir string, planJSON string, extra ...string) (int, string) {
		var out, errb bytes.Buffer
		args := append([]string{"--no-log", "--cwd", filepath.Join(root, dir), "--plan-json", "tfplan=" + planJSON}, extra...)
		args = append(args, "tfplan")
		rc := cmdApply(args, &bytes.Buffer{}, &out, &errb)
		return rc, out.String() + errb.String()
	}

	// A destructive plan in a protected directory blocks and never runs the engine.
	rc, text := run("envs/prod", destroy)
	if rc != 3 || len(fe.calls) != 0 || !strings.Contains(text, "stateful-destroyed") {
		t.Fatalf("protected destroy: rc %d calls %v text %q", rc, fe.calls, text)
	}
	// The same plan in a disposable directory is applied; the engine's exit code is returned.
	rc, _ = run("envs/dev", destroy)
	if rc != 7 || len(fe.calls) != 1 || strings.Join(fe.calls[0], " ") != "terraform apply tfplan" || fe.dir != filepath.Join(root, "envs/dev") {
		t.Fatalf("disposable destroy: rc %d calls %v dir %s", rc, fe.calls, fe.dir)
	}
	// Standard tier asks; without a terminal and without --yes it is refused.
	fe.calls = nil
	rc, text = run("envs/stage", destroy)
	if rc != 4 || len(fe.calls) != 0 || !strings.Contains(text, "interactive confirmation") {
		t.Fatalf("standard destroy, no tty: rc %d calls %v text %q", rc, fe.calls, text)
	}
	// --yes approves outside protected tiers and forwards extra engine arguments.
	rc, _ = run("envs/stage", destroy, "--yes", "--engine", "tofu")
	if rc != 7 || len(fe.calls) != 1 || strings.Join(fe.calls[0], " ") != "tofu apply tfplan" {
		t.Fatalf("standard destroy --yes: rc %d calls %v", rc, fe.calls)
	}
	// --yes never approves a protected ask (a create plan asks in protected here because of the exposure rule).
	fe.calls = nil
	rc, text = run("envs/prod", create, "--yes")
	if rc != 4 || len(fe.calls) != 0 || !strings.Contains(text, "protected tier") {
		t.Fatalf("protected ask --yes: rc %d calls %v text %q", rc, fe.calls, text)
	}
	// A clean plan in a standard directory applies without a prompt.
	fe.calls = nil
	rc, _ = run("envs/stage", create)
	if rc != 7 || len(fe.calls) != 1 {
		t.Fatalf("standard create: rc %d calls %v", rc, fe.calls)
	}
}

func TestApplyTypedConfirmationAtTheTerminal(t *testing.T) {
	root := applyRepo(t)
	destroy, _ := filepath.Abs("../../review/real_plan/delete_real_shape.show.json")
	fe := &fakeExec{}
	oldExec, oldTTY := applyExec, isTerminal
	applyExec, isTerminal = fe.run, func(io.Reader) bool { return true }
	defer func() { applyExec, isTerminal = oldExec, oldTTY }()
	run := func(typed string) (int, string) {
		var out, errb bytes.Buffer
		rc := cmdApply([]string{"--no-log", "--cwd", filepath.Join(root, "envs/stage"), "--plan-json", "tfplan=" + destroy, "tfplan"},
			strings.NewReader(typed), &out, &errb)
		return rc, errb.String()
	}
	rc, text := run("no\n")
	if rc != 4 || len(fe.calls) != 0 || !strings.Contains(text, `Type the environment name "stage"`) || !strings.Contains(text, "not confirmed") {
		t.Fatalf("wrong word: rc %d calls %v text %q", rc, fe.calls, text)
	}
	rc, _ = run("stage\n")
	if rc != 0 || len(fe.calls) != 1 {
		t.Fatalf("typed environment name: rc %d calls %v", rc, fe.calls)
	}
}

func TestQuoteCommand(t *testing.T) {
	got := quoteCommand([]string{"terraform", "apply", "my plan.tfplan", "-var=x='y'"})
	want := `terraform apply 'my plan.tfplan' '-var=x='\''y'\'''`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
