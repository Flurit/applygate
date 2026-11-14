package scan

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
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

func TestNewRowMarksChangesWithTheTierTheyAimAt(t *testing.T) {
	call := Call{Agent: "claude", Cwd: "/repo"}
	tiered := func(c classify.Class, v policy.Verdict, tier string) policy.ActionResult {
		a := act(c, v, "why")
		a.Tier = config.Tier(tier)
		return a
	}
	for _, tc := range []struct {
		name string
		e    decisionlog.Entry
		want string
	}{
		{"a destroy in production", entry("terraform destroy", policy.Block, tiered(classify.Destroy, policy.Block, "protected")), "protected"},
		{"an apply allowed in a disposable environment is still a change", entry("terraform apply", policy.Allow, tiered(classify.Mutating, policy.Allow, "disposable")), "disposable"},
		{"the most protected of several", entry("a; b", policy.Ask, tiered(classify.CloudWrite, policy.Allow, "disposable"), tiered(classify.CloudWrite, policy.Ask, "standard")), "standard"},
		{"no tier recorded", entry("aws s3 rm s3://b/k", policy.Ask, tiered(classify.CloudDestructive, policy.Ask, "")), "unknown"},
		{"a plan changes nothing", entry("terraform plan", policy.Allow, tiered(classify.ReadOnly, policy.Allow, "protected")), ""},
		{"a loop changes nothing", entry("for x in a; do echo; done", policy.Ask, tiered(classify.ComplexShape, policy.Ask, "protected")), ""},
	} {
		if r := NewRow(call, tc.e, "/repo", false, false); r.Change != tc.want {
			t.Errorf("%s: change %q, want %q", tc.name, r.Change, tc.want)
		}
	}
}

func TestRenderOpensWithExposure(t *testing.T) {
	call := Call{Agent: "claude", Cwd: "/home/u/infra", Time: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	rows := []Row{
		NewRow(call, entry("terraform destroy", policy.Block, act(classify.Destroy, policy.Block, "terraform destroy")), "/home/u/infra", false, false),
		NewRow(call, entry("terraform plan", policy.Allow, act(classify.ReadOnly, policy.Allow, "plan")), "/home/u/infra", false, false),
	}
	stats := Stats{Sessions: map[string]int{"claude": 1}, Calls: 2}
	checks := []Check{
		{1, "not verified", "no managed install"},
		{2, "FAIL", "aws profile prod-admin: allowed without MFA: ec2:TerminateInstances"},
		{2, "not verified", "/home/u/.aws/credentials is readable by this user"},
		{0, "not verified", "oidc_pinned is not attested (optional)"},
	}
	render := func(x *Exposure, st Stats) string {
		var b bytes.Buffer
		Summary{Stats: st, Rows: rows, Exposure: x}.Render(&b, RenderOptions{Version: "0.6.0", Days: 30, Home: "/home/u"})
		return b.String()
	}
	for _, tc := range []struct {
		name      string
		x         *Exposure
		want, not []string
	}{
		{"not audited", &Exposure{Checks: checks},
			[]string{"credentials  not audited: this report contacts nothing", "boundary     L0 of L3, as far as this machine shows without the audit: the hook is the only check",
				"    L2 not verified ~/.aws/credentials is readable by this user\n", "your agents issued 1 command that changes infrastructure", "1 of them aimed at",
				"Nothing was run, written, or sent to a model or a cloud account."},
			[]string{"oidc_pinned", "you do not need the hook", "A wrong verdict"}},
		{"a credential that can change production", &Exposure{Audited: true, CredsOK: 2, CredsFail: 1, Checks: checks},
			[]string{"credentials  1 can change production without a person; 2 audited with no destructive path to production\n  boundary     L0 of L3: the hook", "    L2 FAIL         aws profile prod-admin",
				"A wrong verdict, or a call the hook never sees, reaches whatever these credentials allow.", "The credential audit asked AWS,"},
			[]string{"you do not need the hook", "contacts nothing", "or a cloud account"}},
		{"every credential audited and harmless", &Exposure{Audited: true, Level: 2, CredsOK: 3, Checks: checks[:1]},
			[]string{"credentials  none of the 3 audited can change production without a person", "boundary     L2 of L3: a managed install, and credentials",
				"you do not need the hook to protect production", "plan check in your pipeline (docs/ci.md)"},
			[]string{"A wrong verdict", "Until every credential"}},
		{"a sign-in has expired", &Exposure{Audited: true, CredsOK: 1, CredsUnchecked: 4, Checks: checks[:1]},
			[]string{"credentials  1 audited with no destructive path to production; 4 could not be checked\n", "This does not show that production is out of reach.",
				"- 4 could not be checked: the lines above say why", "Sign in again, then run it again."},
			[]string{"you do not need the hook", "Name your environments"}},
		{"a credential in no named environment", &Exposure{Audited: true, CredsOK: 3, CredsUnplaced: 1, Checks: checks[:1]},
			[]string{"3 audited with no destructive path to production; 1 can make destructive changes in an environment no config names",
				"- 1 can make destructive changes and matches no environment in the config", "Name your environments in .applygate.yaml"},
			[]string{"you do not need the hook", "Sign in again"}},
		{"nothing could be audited", &Exposure{Audited: true, CredsUnchecked: 2, CredsUnplaced: 2, Checks: checks[:1]},
			[]string{"credentials  0 audited with no destructive path to production; 2 could not be checked; 2 can make destructive changes",
				"Sign in again", "- 2 can make destructive changes and match no environment"},
			[]string{"you do not need the hook"}},
		{"no credential on the machine", &Exposure{Audited: true, Checks: checks[:1]},
			[]string{"credentials  0 audited with no destructive path to production\n", "No credential was found to audit."},
			[]string{"you do not need the hook", "Sign in again", "Name your environments"}},
		{"the checks could not be made", &Exposure{Error: "config: bad yaml"},
			[]string{"What your agents can reach\n  not checked: config: bad yaml\n", "Infrastructure commands: 2"},
			[]string{"boundary     L"}},
	} {
		out := render(tc.x, stats)
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in:\n%s", tc.name, w, out)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(out, n) {
				t.Errorf("%s: unexpected %q in:\n%s", tc.name, n, out)
			}
		}
		if strings.Index(out, "What your agents can reach") > strings.Index(out, "sessions read") {
			t.Errorf("%s: the boundary does not come first:\n%s", tc.name, out)
		}
	}
	// With no session the boundary is still reported, without a line about sessions.
	out := render(&Exposure{Checks: checks}, Stats{Sessions: map[string]int{}})
	if !strings.Contains(out, "boundary     L0 of L3") || !strings.Contains(out, "No Claude Code or Codex session") || strings.Contains(out, "In the sessions read") {
		t.Errorf("no sessions:\n%s", out)
	}
}

func TestShareReasonNamesNothing(t *testing.T) {
	for why, want := range map[string]string{
		shapePrefix + "the variable DEPLOY_ENV)":                                           "a variable set in the command (X=... cmd)",
		shapePrefix + "the program acme-deploy)":                                           "a program with no option list",
		shapePrefix + "the subcommand build ./...)":                                        "a subcommand or option that is not listed",
		shapePrefix + "the gh run subcommand rerun)":                                       "a subcommand or option that is not listed",
		shapePrefix + "the option -w of gofmt)":                                            "a subcommand or option that is not listed",
		shapePrefix + "a loop or conditional)":                                             "shell syntax beyond a plain command",
		"source of a file that cannot be read: stat /srv/secret/env.sh":                    "a sourced file or script that cannot be read",
		"script cannot be read: open /srv/deploy.sh":                                       "a sourced file or script that cannot be read",
		"python3 runs /srv/internal/tool.py, which cannot be read":                         "code that an interpreter runs",
		"python3 code mentions infrastructure tools, an AWS SDK or guard files":            "code that an interpreter runs",
		"a program named by a path outside the system directories (/srv/bin/acme)":         "a program or file named by something that cannot be resolved",
		"rm removes or overwrites a file it names with a word the analysis cannot resolve": "a program or file named by something that cannot be resolved",
		"git push moves the upstream branch the provider lock check trusts":                "git state or configuration",
		"make reads a makefile that is written by an earlier step (/srv/Makefile)":         "another reason",
		"something new about /srv/secret":                                                  "another reason",
	} {
		got := ShareReason(why)
		if got != want {
			t.Errorf("ShareReason(%q) = %q, want %q", why, got, want)
		}
		for _, leak := range []string{"/srv", "acme", "DEPLOY_ENV", "gofmt", "rerun"} {
			if strings.Contains(got, leak) {
				t.Errorf("ShareReason(%q) = %q holds %q", why, got, leak)
			}
		}
	}
}

func TestRenderShareHoldsCountsOnly(t *testing.T) {
	day := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	var s Summary
	add := func(agent, dir, repo string, noConfig bool, e decisionlog.Entry) {
		s.Rows = append(s.Rows, NewRow(Call{Agent: agent, Cwd: dir, Time: day}, e, repo, noConfig, false))
	}
	add("claude", "/home/u/acme-infra/envs/prod", "/home/u/acme-infra", false, entry("terraform destroy -target=aws_db_instance.billing", policy.Block, act(classify.Destroy, policy.Block, "terraform destroy")))
	add("codex", "/home/u/acme-infra", "/home/u/acme-infra", false, entry("aws s3 cp f s3://acme-billing", policy.Ask, act(classify.CloudWrite, policy.Ask, "aws s3 cp changes resources")))
	add("claude", "/home/u/acme-infra", "/home/u/acme-infra", false, entry("terraform apply tfplan", policy.Ask, act(classify.ApplySavedPlan, policy.Ask, "the plan could not be read")))
	add("claude", "/home/u/acme-web", "/home/u/acme-web", true, entry("echo x > .claude/settings.json", policy.Block, act(classify.Tampering, policy.Block, "redirect writes to guard file")))
	add("claude", "/home/u/acme-web", "/home/u/acme-web", true, entry("acme-deploy --all", policy.Ask, act(classify.ComplexShape, policy.Ask, shapePrefix+"the program acme-deploy)")))
	add("codex", "/home/u/acme-web", "/home/u/acme-web", true, entry("BILLING=1 make", policy.Ask, act(classify.ComplexShape, policy.Ask, shapePrefix+"the variable BILLING)")))
	add("claude", "/home/u/acme-web", "/home/u/acme-web", true, entry("git status", policy.Allow))
	add("claude", "/home/u/acme-web", "/home/u/acme-web", true, decisionlog.Entry{Tool: "Read", Paths: []string{"/home/u/acme-web/a.js"}, Verdict: policy.Allow})
	s.Gone = 2
	s.Stats = Stats{Sessions: map[string]int{"claude": 3, "codex": 1}, Calls: 40}
	s.Exposure = &Exposure{Audited: true, Level: 1, CredsOK: 2, CredsFail: 1, CredsUnchecked: 1, CredsUnplaced: 3, Checks: []Check{
		{1, "ok", "managed install checked"},
		{2, "FAIL", "aws profile acme-prod-admin: arn:aws:iam::111111111111:user/admin: allowed without MFA"},
		{2, "ok", "2 credential(s) audited"},
		{3, "attested", "ci_apply"},
		{3, "not verified", "no host sandbox"},
	}}
	var b bytes.Buffer
	s.RenderShare(&b, RenderOptions{Version: "0.6.0", Days: 30, Home: "/home/u"})
	out := b.String()
	for _, want := range []string{
		"applygate 0.6.0 scan summary, the last 30 days\nCounts only:",
		"sessions           4 (claude 3, codex 1)",
		"tool calls         40; judged 8; directory gone 2; decision failed 0",
		"repositories       2, 1 with a trusted config",
		"infrastructure     3: block 1, ask 1, allow 0, saved plans 1",
		"changes issued   3, 3 in a protected or unnamed environment",
		"guard files        1: block 1, ask 0",
		"other shell        3: ask 2 (66%), allow 1",
		"asks, no config  2",
		"asks by agent    claude 1, codex 1 (an ask is a block on Codex)",
		"       1  a program with no option list\n",
		"       1  a variable set in the command (X=... cmd)\n",
		"boundary           L1 of L3; credentials audited: 2 with no destructive path to production, 1 with one, 1 not checked, 3 in no named environment",
		"L1 checks        ok 1, attested 0, failed 0, not verified 0",
		"L2 checks        ok 1, attested 0, failed 1, not verified 0",
		"L3 checks        ok 0, attested 1, failed 0, not verified 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, leak := range []string{"acme", "billing", "BILLING", "/home", "~", "terraform", "aws ", "arn:", "111111111111", "settings.json", "git status", "make"} {
		if strings.Contains(out, leak) {
			t.Errorf("the summary to share holds %q:\n%s", leak, out)
		}
	}
}
