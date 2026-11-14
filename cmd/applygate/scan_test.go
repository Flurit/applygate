package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scanHome builds a home directory with one Claude Code session and one
// Codex session, and returns it with the repository the calls ran in.
func scanHome(t *testing.T) (home, repo string) {
	t.Helper()
	home = t.TempDir()
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	t.Setenv("HOME", home)
	for _, k := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "CLAUDE_PROJECT_DIR"} {
		t.Setenv(k, "")
	}
	repo = filepath.Join(home, "infra")
	prod := filepath.Join(repo, "envs", "prod")
	for _, d := range []string{filepath.Join(repo, ".git"), prod} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A terraform on PATH that leaves a mark if anything starts it.
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(home, "terraform-ran")
	if err := os.WriteFile(filepath.Join(bin, "terraform"), []byte("#!/bin/sh\necho ran >> "+mark+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	now := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	use := func(id, cwd, tool string, input any) string {
		in, _ := json.Marshal(input)
		return fmt.Sprintf(`{"type":"assistant","cwd":%q,"sessionId":"s1","timestamp":%q,"message":{"content":[{"type":"tool_use","id":%q,"name":%q,"input":%s}]}}`+"\n", cwd, now, id, tool, in)
	}
	cmd := func(c string) map[string]string { return map[string]string{"command": c} }
	claude := use("t1", prod, "Bash", cmd("terraform destroy -auto-approve")) +
		use("t2", prod, "Bash", cmd("terraform destroy -auto-approve")) +
		use("t3", repo, "Bash", cmd("git status")) +
		use("t4", repo, "Bash", cmd("for f in a b; do echo $f; done")) +
		use("t5", prod, "Bash", cmd("terraform apply tfplan")) +
		use("t6", filepath.Join(home, "gone"), "Bash", cmd("terraform destroy")) +
		use("t7", repo, "TodoWrite", map[string]any{"todos": []string{}}) +
		use("t8", repo, "Edit", map[string]string{"file_path": filepath.Join(repo, "main.tf")}) +
		use("t9", repo, "Bash", cmd("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY; terraform destroy"))
	codex := fmt.Sprintf(`{"timestamp":%[1]q,"type":"session_meta","payload":{"id":"c1","cwd":%[2]q}}
{"timestamp":%[1]q,"type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-1","command":["/bin/zsh","-lc","kubectl delete namespace payments"],"cwd":%[3]q}}}
`, now, repo, "file://"+repo)
	for p, body := range map[string]string{
		".claude/projects/-infra/s1.jsonl":            claude,
		".codex/sessions/2026/11/12/rollout-c1.jsonl": codex,
	} {
		p = filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home, repo
}

func TestScanReportsWhatPastCallsWouldGet(t *testing.T) {
	home, _ := scanHome(t)
	var out, errb bytes.Buffer
	if code := run([]string{"scan"}, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"sessions read  2 from the last 30 days (claude 1, codex 1)",
		"tool calls     10, of which 9 are",
		"not judged     1 made in a directory that no longer exists",
		// Three destroys and the Codex delete; the plan apply is counted apart.
		"Infrastructure commands: 5\n  would block  4\n  would ask    0\n  allowed      0\n  saved plans  1 applied",
		"claude  ~/infra/envs/prod, 2 times\n        terraform destroy -auto-approve\n",
		"codex  ~/infra\n        kubectl delete namespace payments\n",
		"Other shell commands: 2\n  would ask    1 (50%)\n  allowed      1\n",
		"a loop or conditional",
		"1 of them ran where no trusted .applygate.yaml covers the directory",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "wJalrXUtnFEMI") {
		t.Errorf("a secret from a past command is printed:\n%s", got)
	}
	// A scan runs nothing and leaves nothing behind.
	if _, err := os.Stat(filepath.Join(home, "terraform-ran")); err == nil {
		t.Error("scan started terraform")
	}
	for _, p := range []string{".local/state/applygate", ".config/applygate"} {
		if _, err := os.Stat(filepath.Join(home, p)); err == nil {
			t.Errorf("scan wrote %s", p)
		}
	}
}

func TestScanJSONDirAndWindow(t *testing.T) {
	home, repo := scanHome(t)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--json", "--dir", filepath.Join(repo, "envs")}, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var verdicts []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r struct {
			Agent, Dir, Repo, Command, Verdict, Group, Kind string
			NoConfig                                        bool `json:"no_config"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if r.Dir != filepath.Join(repo, "envs", "prod") || r.Repo != repo || r.Kind != "shell" || !r.NoConfig || r.Command == "" {
			t.Errorf("row: %+v", r)
		}
		verdicts = append(verdicts, r.Group+":"+r.Verdict)
	}
	// A saved plan that is not there to read is an ask (plan-missing), as in a live call.
	if got := strings.Join(verdicts, " "); got != "infrastructure:block infrastructure:block plan:ask" {
		t.Errorf("rows under envs/, in the order they were made: %q", got)
	}

	// Session files older than the window are not read.
	old := time.Now().AddDate(0, 0, -10)
	for _, p := range []string{".claude/projects/-infra/s1.jsonl", ".codex/sessions/2026/11/12/rollout-c1.jsonl"} {
		if err := os.Chtimes(filepath.Join(home, p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if code := run([]string{"scan", "--days", "7"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "No Claude Code or Codex session with a tool call was found in the last 7 days.") {
		t.Errorf("exit %d:\n%s", code, out.String())
	}
	if code := run([]string{"scan", "extra"}, nil, &out, &errb); code != 2 {
		t.Errorf("an argument: exit %d", code)
	}
}

// noCloud fails the test when anything asks a cloud CLI.
func noCloud(t *testing.T) {
	t.Helper()
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI = func(_ context.Context, bin string, args ...string) ([]byte, error) {
		t.Errorf("scan ran %s %s", bin, strings.Join(args, " "))
		return nil, errors.New("not allowed in this test")
	}
	gcpTestPermissions = func(context.Context, string, string, []string) ([]string, error) {
		t.Error("scan asked Google Cloud")
		return nil, errors.New("not allowed in this test")
	}
	t.Cleanup(func() { runCLI, gcpTestPermissions = old, oldHTTP })
}

func TestScanOpensWithWhatAgentsCanReachAndAsksNoCloud(t *testing.T) {
	home, _ := scanHome(t)
	noCloud(t)
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte("[default]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"scan"}, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"credentials  not audited: this report contacts nothing. applygate scan --boundary asks",
		"boundary     L0 of L3, as far as this machine shows without the audit",
		"L1 not verified no managed install",
		"L2 not verified credentials not audited",
		"L2 not verified ~/.aws/credentials is readable by this user",
		// Three destroys, the Codex delete and the plan apply.
		"your agents issued 5 commands that change infrastructure",
		"Nothing was run, written, or sent to a model or a cloud account.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// What the agents can reach comes before what would have been decided.
	if reach, infra := strings.Index(got, "What your agents can reach"), strings.Index(got, "Infrastructure commands"); reach < 0 || reach > infra {
		t.Errorf("the report does not open with the boundary:\n%s", got)
	}
}

func TestScanBoundaryAuditsTheCredentials(t *testing.T) {
	scanHome(t)
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI, gcpTestPermissions = fakeCloud(t), fakeGCPPermissions(t)
	defer func() { runCLI, gcpTestPermissions = old, oldHTTP }()
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--boundary"}, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"can change production without a person\n  boundary     L0 of L3: the hook is the only check",
		"L2 FAIL         aws profile prod-admin",
		"A wrong verdict, or a call the hook never sees, reaches whatever these credentials allow.",
		"The credential audit asked AWS,",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not audited: this report contacts nothing") || strings.Contains(got, "sent to a model or a cloud account") {
		t.Errorf("an audited report says it contacted nothing:\n%s", got)
	}
}

func TestScanShareHoldsCountsOnly(t *testing.T) {
	home, _ := scanHome(t)
	noCloud(t)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--share"}, nil, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"Counts only: no command, path, repository, account or program name is in this text.",
		"sessions           2 (claude 1, codex 1)",
		"repositories       1, 0 with a trusted config",
		"infrastructure     5: block 4, ask 0, allow 0, saved plans 1",
		"changes issued   5, 5 in a protected or unnamed environment",
		"other shell        2: ask 1 (50%), allow 1",
		"       1  shell syntax beyond a plain command",
		"boundary           L0 of L3; credentials not audited",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, leak := range []string{home, "/infra", "terraform", "kubectl", "payments", "envs", "~/", ".aws"} {
		if strings.Contains(got, leak) {
			t.Errorf("the summary to share holds %q:\n%s", leak, got)
		}
	}
	// --json is the judged calls and takes neither option.
	if code := run([]string{"scan", "--json", "--share"}, nil, &out, &errb); code != 2 {
		t.Errorf("--json with --share: exit %d, want 2", code)
	}
	if code := run([]string{"scan", "--json", "--boundary"}, nil, &out, &errb); code != 2 {
		t.Errorf("--json with --boundary: exit %d, want 2", code)
	}
}
