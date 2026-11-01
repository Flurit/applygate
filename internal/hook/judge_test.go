package hook

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/approval"
	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/policy"
)

// fakeJudge answers with a fixed verdict and records what it was asked.
type fakeJudge struct {
	verdict policy.Verdict
	err     string
	asked   []judge.Input
}

func (f *fakeJudge) Name() string { return "fake-model" }
func (f *fakeJudge) Judge(_ context.Context, in judge.Input) judge.Result {
	f.asked = append(f.asked, in)
	if f.err != "" {
		return judge.Result{Model: "fake-model", Err: f.err}
	}
	return judge.Result{Model: "fake-model", Verdict: f.verdict, Reason: "it " + string(f.verdict) + "s."}
}

// judgeSetup is the hook test repository plus a user config that turns the
// judge on (unless userCfg says otherwise).
func judgeSetup(t *testing.T, mode, userCfg string) (string, Options) {
	t.Helper()
	root := setup(t, mode, "auto")
	user := filepath.Join(t.TempDir(), "config.yaml")
	if userCfg == "" {
		userCfg = "version: 1\njudge:\n  enabled: true\n  skip_mcp: [\"mcp__browser__*\"]\n"
	}
	os.WriteFile(user, []byte(userCfg), 0o644)
	return root, Options{UserConfig: user, NoGit: true, Env: map[string]string{}, JudgeCache: "-"}
}

func runJudged(t *testing.T, a Adapter, opt Options, f *fakeJudge, tool, cwd string, input map[string]any) (Output, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "log.jsonl")
	opt.LogPath, opt.Judge = log, f
	o := Run(a, strings.NewReader(event(tool, cwd, input)), opt)
	return o, log
}

func TestJudgeEscalatesResidualCall(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	f := &fakeJudge{verdict: policy.Ask}
	o, log := runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "pulumi destroy --yes --stack acme/prod"})
	if decision(t, o) != "ask" || !strings.Contains(string(o.Stdout), "model judge (fake-model)") {
		t.Fatalf("want ask naming the judge, got %s %s", decision(t, o), o.Stdout)
	}
	if len(f.asked) != 1 || f.asked[0].Tier != "protected" || f.asked[0].Env != "prod" {
		t.Fatalf("judge input %+v", f.asked)
	}
	e := readLog(t, log)
	if e.Judge == nil || e.Judge.Model != "fake-model" || e.Judge.Verdict != policy.Ask || e.Verdict != policy.Ask {
		t.Fatalf("log entry %+v judge %+v", e, e.Judge)
	}
	if len(e.Actions) != 1 || string(e.Actions[0].Class) != judge.Class {
		t.Fatalf("actions %+v", e.Actions)
	}
}

func TestJudgeCannotLower(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	for _, f := range []*fakeJudge{{verdict: policy.Allow}, {err: "timeout"}} {
		o, log := runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "pulumi destroy --yes"})
		if decision(t, o) != "allow" {
			t.Fatalf("%+v: got %s", f, decision(t, o))
		}
		if e := readLog(t, log); e.Judge == nil || (f.err != "" && !strings.Contains(e.Judge.Error, "timeout")) {
			t.Fatalf("%+v: judge record %+v", f, e.Judge)
		}
		// A call the rules stop stays stopped whatever the judge would say.
		o, _ = runJudged(t, Codex{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "terraform destroy -auto-approve"})
		if decision(t, o) == "allow" {
			t.Fatal("rule block lowered")
		}
	}
}

func TestJudgeNotAsked(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	cases := map[string]struct {
		tool  string
		input map[string]any
	}{
		"rules decide":   {"Bash", map[string]any{"command": "terraform plan"}},
		"local work":     {"Bash", map[string]any{"command": "go test ./... && git status"}},
		"file read":      {"Read", map[string]any{"file_path": "main.tf"}},
		"skipped MCP":    {"mcp__browser__get_page_text", map[string]any{"tab": 1}},
		"known MCP tool": {"mcp__terraform__ExecuteTerraformCommand", map[string]any{"command": "plan", "working_directory": filepath.Join(root, "prod")}},
	}
	for name, c := range cases {
		f := &fakeJudge{verdict: policy.Block}
		runJudged(t, Claude{}, opt, f, c.tool, filepath.Join(root, "prod"), c.input)
		if len(f.asked) != 0 {
			t.Errorf("%s: judge asked %+v", name, f.asked)
		}
	}
	// Off unless the user config turns it on; a repository cannot.
	_, off := judgeSetup(t, "enforce", "version: 1\n")
	cfg := filepath.Join(root, ".applygate.yaml")
	b, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(b, []byte("judge:\n  enabled: true\n")...), 0o644)
	f := &fakeJudge{verdict: policy.Block}
	runJudged(t, Claude{}, off, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "pulumi destroy --yes"})
	if len(f.asked) != 0 {
		t.Fatal("a repository config turned the judge on")
	}
	// A repository may turn it off.
	os.WriteFile(cfg, append(b, []byte("judge:\n  enabled: false\n")...), 0o644)
	runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "pulumi destroy --yes"})
	if len(f.asked) != 0 {
		t.Fatal("judge asked although the repository config turned it off")
	}
}

func TestJudgeSeesMCPAndWrites(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	f := &fakeJudge{verdict: policy.Block}
	o, _ := runJudged(t, Claude{}, opt, f, "mcp__neon__delete_project", filepath.Join(root, "prod"), map[string]any{"projectId": "acme-prod", "api_key": "sk-live-123"})
	if decision(t, o) != "deny" || len(f.asked) != 1 || !strings.Contains(string(f.asked[0].Args), "acme-prod") {
		t.Fatalf("unknown MCP call: %s %+v", decision(t, o), f.asked)
	}
	if strings.Contains(string(f.asked[0].Args), "sk-live-123") {
		t.Fatalf("secret sent to the judge: %s", f.asked[0].Args)
	}
	f = &fakeJudge{verdict: policy.Ask}
	runJudged(t, Claude{}, opt, f, "Edit", filepath.Join(root, "prod"), map[string]any{"file_path": "deploy/values-prod.yaml", "old_string": "replicaCount: 6", "new_string": "replicaCount: 0"})
	if len(f.asked) != 1 || !f.asked[0].Write || !strings.Contains(f.asked[0].Content, "replicaCount: 0") {
		t.Fatalf("write: %+v", f.asked)
	}
	f = &fakeJudge{verdict: policy.Ask}
	runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "curl -H 'Authorization: Bearer abc123def' -X DELETE https://api.acme.io/v1/tenants/42"})
	if len(f.asked) != 1 || strings.Contains(f.asked[0].Command, "abc123def") {
		t.Fatalf("secret in command sent to the judge: %+v", f.asked)
	}
}

func TestJudgeCache(t *testing.T) {
	root, opt := judgeSetup(t, "enforce", "")
	opt.JudgeCache = filepath.Join(t.TempDir(), "judge-cache.json")
	f := &fakeJudge{verdict: policy.Ask}
	in := map[string]any{"command": "pulumi destroy --yes"}
	runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), in)
	o, log := runJudged(t, Claude{}, opt, f, "Bash", filepath.Join(root, "prod"), in)
	if len(f.asked) != 1 || decision(t, o) != "ask" {
		t.Fatalf("second call: asked %d times, %s", len(f.asked), decision(t, o))
	}
	if e := readLog(t, log); e.Judge == nil || !e.Judge.Cached {
		t.Fatalf("cached call not marked: %+v", e.Judge)
	}
}

func TestJudgeBlockIsApprovable(t *testing.T) {
	// A block from the judge is a model's opinion, so a person can allow the
	// exact call once, unlike a rule's block.
	root, opt := judgeSetup(t, "enforce", "")
	store := filepath.Join(t.TempDir(), "approvals.json")
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	opt.Approvals, opt.Now = store, func() time.Time { return now }
	f := &fakeJudge{verdict: policy.Block}
	in := map[string]any{"command": "pulumi destroy --yes --stack acme/prod"}
	o, _ := runJudged(t, Codex{}, opt, f, "Bash", filepath.Join(root, "prod"), in)
	if decision(t, o) == "allow" || !strings.Contains(string(o.Stdout)+o.Stderr, "applygate approve ") {
		t.Fatalf("want a block naming an approval: %s%s", o.Stdout, o.Stderr)
	}
	recs, _ := approval.List(store, now)
	if len(recs) != 1 || recs[0].Token != "prod" {
		t.Fatalf("request %+v", recs)
	}
	approval.Approve(store, recs[0].ID, now)
	if o, _ := runJudged(t, Codex{}, opt, f, "Bash", filepath.Join(root, "prod"), in); decision(t, o) != "allow" {
		t.Fatalf("approved retry: %s", decision(t, o))
	}
}

func TestJudgeObserveMode(t *testing.T) {
	root, opt := judgeSetup(t, "observe", "")
	o, log := runJudged(t, Claude{}, opt, &fakeJudge{verdict: policy.Block}, "Bash", filepath.Join(root, "prod"), map[string]any{"command": "pulumi destroy --yes"})
	if decision(t, o) != "allow" {
		t.Fatalf("observe mode: %s", decision(t, o))
	}
	if e := readLog(t, log); e.Verdict != policy.Block || e.Enforced != policy.Allow {
		t.Fatalf("observe entry %+v", e)
	}
}
