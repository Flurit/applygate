package scan

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

func entry(cmd string, v policy.Verdict, acts ...policy.ActionResult) decisionlog.Entry {
	return decisionlog.Entry{Tool: "Bash", Command: cmd, Verdict: v, Actions: acts}
}

func act(c classify.Class, v policy.Verdict, why string) policy.ActionResult {
	return policy.ActionResult{Class: c, Verdict: v, Why: why, Tier: "protected"}
}

const shapeWhy = shapePrefix + "the program npm)"

func TestNewRowGroups(t *testing.T) {
	call := Call{Agent: "claude", Cwd: "/repo"}
	for _, tc := range []struct {
		name  string
		e     decisionlog.Entry
		group string
		why   string
	}{
		{"a destroy is an infrastructure block",
			entry("terraform destroy", policy.Block, act(classify.Destroy, policy.Block, "terraform destroy"), act(classify.ComplexShape, policy.Ask, shapeWhy)),
			GroupInfra, "terraform destroy"},
		{"the recognized action gives the reason, not the shape beside it",
			entry("for x in a; do aws s3 cp f s3://b; done", policy.Ask, act(classify.ComplexShape, policy.Ask, shapeWhy), act(classify.CloudWrite, policy.Ask, "aws s3 cp changes resources")),
			GroupInfra, "aws s3 cp changes resources"},
		{"an allowed plan is an infrastructure command",
			entry("terraform plan", policy.Allow, act(classify.ReadOnly, policy.Allow, "plan")),
			GroupInfra, ""},
		{"a settings edit is a guard-file call",
			entry("echo x > .claude/settings.json", policy.Block, act(classify.Tampering, policy.Block, "redirect writes to guard file")),
			GroupGuard, "redirect writes to guard file"},
		{"a shape ask names no infrastructure",
			entry("npm test", policy.Ask, act(classify.ComplexShape, policy.Ask, shapeWhy)),
			GroupGeneral, shapeWhy},
		{"an unresolved command is general too",
			entry("source env.sh", policy.Ask, act(classify.Dynamic, policy.Ask, "source of a file that cannot be read: stat env.sh"), act(classify.ComplexShape, policy.Ask, shapeWhy)),
			GroupGeneral, "source of a file that cannot be read: stat env.sh"},
		{"a saved plan cannot be judged afterwards",
			entry("terraform apply tfplan", policy.Block, act(classify.ApplySavedPlan, policy.Block, "the plan could not be read")),
			GroupPlan, "the plan could not be read"},
		{"an allowed command with nothing recognized",
			entry("git status", policy.Allow),
			GroupOther, ""},
		{"an action below the verdict does not decide the group",
			entry("ls; echo hi > x", policy.Ask, act(classify.Destroy, policy.Allow, "allowed in a disposable tier"), act(classify.ComplexShape, policy.Ask, shapeWhy)),
			GroupGeneral, shapeWhy},
		{"a failed decision",
			decisionlog.Entry{Tool: "Bash", Command: "ls", Verdict: policy.Block, Error: "config error: bad yaml"},
			GroupFailed, ""},
	} {
		r := NewRow(call, tc.e, "/repo", true, false)
		if r.Group != tc.group || r.Why != tc.why {
			t.Errorf("%s: group %q why %q, want %q %q", tc.name, r.Group, r.Why, tc.group, tc.why)
		}
		if r.Kind != "shell" || r.Repo != "/repo" || !r.NoConfig {
			t.Errorf("%s: row %+v", tc.name, r)
		}
	}
}

func TestNewRowKeepsTextOnlyWhereItIsShown(t *testing.T) {
	secret := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	call := Call{Agent: "claude", Cwd: "/repo"}
	// A counted row keeps no command.
	for _, e := range []decisionlog.Entry{
		entry(secret+" npm test", policy.Ask, act(classify.ComplexShape, policy.Ask, shapeWhy)),
		entry(secret+" git status", policy.Allow),
	} {
		if r := NewRow(call, e, "", false, false); r.Command != "" {
			t.Errorf("a counted row kept its command: %q", r.Command)
		}
	}
	// A listed row, and every row of --json, keeps it with secrets redacted.
	listed := entry(secret+" terraform destroy", policy.Block, act(classify.Destroy, policy.Block, "terraform destroy"))
	counted := entry(secret+" git status", policy.Allow)
	for _, r := range []Row{NewRow(call, listed, "", false, false), NewRow(call, counted, "", false, true)} {
		if r.Command == "" || strings.Contains(r.Command, "wJalrXUtnFEMI") {
			t.Errorf("command not kept or not redacted: %q", r.Command)
		}
	}
	// A file edit is a file call.
	if r := NewRow(call, decisionlog.Entry{Tool: "Edit", Paths: []string{"/repo/main.tf"}, Verdict: policy.Allow}, "", false, true); r.Kind != "file" || r.what() != "Edit /repo/main.tf" {
		t.Errorf("file row: %+v", r)
	}
	if r := NewRow(call, decisionlog.Entry{Tool: "mcp__aws__call_aws", Command: `{"x":1}`, Verdict: policy.Allow}, "", false, true); r.Kind != "mcp" {
		t.Errorf("mcp row: %+v", r)
	}
}

func TestReason(t *testing.T) {
	for why, want := range map[string]string{
		shapePrefix + "the variable D)":                 "a variable set in the command (X=... cmd)",
		shapePrefix + "the program python3)":            "the program python3",
		shapePrefix + "the subcommand build ./...)":     "a subcommand that is not listed (build)",
		shapePrefix + "a loop or conditional)":          "a loop or conditional",
		"source of a file that cannot be read: stat /x": "source of a file that cannot be read",
		shapePrefix + "a part the analyzer cannot resolve (source of a file that cannot be read: stat /x))": "source of a file that cannot be read",
		"program name cannot be resolved statically":                                                        "program name cannot be resolved statically",
	} {
		if got := Reason(why); got != want {
			t.Errorf("Reason(%q) = %q, want %q", why, got, want)
		}
	}
}

func TestRender(t *testing.T) {
	day := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	call := func(agent, dir string, d int) Call {
		return Call{Agent: agent, Cwd: dir, Time: day.AddDate(0, 0, d)}
	}
	destroy := entry("terraform destroy -auto-approve", policy.Block, act(classify.Destroy, policy.Block, "terraform destroy"))
	var s Summary
	add := func(c Call, e decisionlog.Entry, repo string, noConfig bool) {
		s.Rows = append(s.Rows, NewRow(c, e, repo, noConfig, false))
	}
	add(call("claude", "/home/u/infra/envs/prod", 0), destroy, "/home/u/infra", false)
	add(call("claude", "/home/u/infra/envs/prod", 1), destroy, "/home/u/infra", false)
	add(call("codex", "/home/u/infra", 0), entry("aws s3 cp f s3://b", policy.Ask, act(classify.CloudWrite, policy.Ask, "aws s3 cp changes resources")), "/home/u/infra", false)
	add(call("claude", "/home/u/infra", 0), entry("terraform plan", policy.Allow, act(classify.ReadOnly, policy.Allow, "plan")), "/home/u/infra", false)
	add(call("claude", "/home/u/infra", 0), entry("terraform apply tfplan", policy.Block, act(classify.ApplySavedPlan, policy.Block, "unreadable")), "/home/u/infra", false)
	add(call("claude", "/home/u/web", 0), entry("echo x > .claude/settings.json", policy.Block, act(classify.Tampering, policy.Block, "redirect writes to guard file")), "/home/u/web", true)
	add(call("claude", "/home/u/web", 0), entry("npm test", policy.Ask, act(classify.ComplexShape, policy.Ask, shapeWhy)), "/home/u/web", true)
	add(call("claude", "/home/u/web", 0), entry("D=1 make", policy.Ask, act(classify.ComplexShape, policy.Ask, shapePrefix+"the variable D)")), "/home/u/web", true)
	add(call("claude", "/home/u/web", 0), entry("git status", policy.Allow), "/home/u/web", true)
	add(call("claude", "/home/u/web", 0), entry("ls", policy.Allow), "/home/u/web", true)
	add(call("claude", "/home/u/web", 0), decisionlog.Entry{Tool: "Read", Paths: []string{"/home/u/web/a.js"}, Verdict: policy.Allow}, "/home/u/web", true)
	s.Gone = 3
	s.Stats = Stats{Sessions: map[string]int{"claude": 4, "codex": 1}, Calls: 1240, Compressed: 2}

	var b bytes.Buffer
	s.Render(&b, RenderOptions{Version: "0.6.0", Days: 30, Home: "/home/u"})
	out := b.String()
	for _, want := range []string{
		"sessions read  5 from the last 30 days (claude 4, codex 1)",
		"tool calls     1,240, of which 14 are",
		"not judged     3 made in a directory that no longer exists",
		"Infrastructure commands: 5\n  would block  2\n  would ask    1\n  allowed      1\n  saved plans  1 applied",
		// The same command in the same directory is one entry, dated by its last use.
		"2026-11-11  claude  ~/infra/envs/prod, 2 times\n        terraform destroy -auto-approve\n        terraform destroy\n",
		"aws s3 cp changes resources",
		"Changes to agent settings and applygate's own files: 1\n  would block  1\n  would ask    0\n",
		"Other shell commands: 4\n  would ask    2 (50%)\n  allowed      2\n",
		"2 of them ran where no trusted .applygate.yaml covers the directory",
		"         1  a variable set in the command (X=... cmd)\n         1  the program npm\n",
		"By repository",
		"         6       1       0           2  none     ~/web",
		"         5       2       1           0  trusted  ~/infra",
		"Codex cannot show an ask prompt: its 1 asked call would have been blocked.",
		"2 archived session files are compressed and not read.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "git status") || strings.Contains(out, "npm test") {
		t.Errorf("a counted command is printed:\n%s", out)
	}

	// With no session, the report says so and nothing else.
	b.Reset()
	Summary{Stats: Stats{Sessions: map[string]int{}, Compressed: 1}}.Render(&b, RenderOptions{Version: "0.6.0", Days: 7})
	if out := b.String(); !strings.Contains(out, "No Claude Code or Codex session with a tool call was found in the last 7 days.") || !strings.Contains(out, "1 archived session file is compressed") || strings.Contains(out, "Infrastructure") {
		t.Errorf("empty report:\n%s", out)
	}
}
