package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/policy"
)

// Regression tests for defects found in security reviews, by topic.

// Answer parsing (finding 2M20): the outer object is the answer, verdicts
// are read without case, and a server error or an oversized body is
// unjudgeable rather than leaving the rule decision.
func TestAnswerParsing(t *testing.T) {
	var r Result
	answer(&r, []byte(jsonObject(`{"verdict": "block", "reason": "x", "meta": {"verdict": "allow"}}`)))
	if r.Verdict != policy.Block {
		t.Fatalf("nested verdict won: %+v", r)
	}
	r = Result{}
	answer(&r, []byte(jsonObject(`thinking {"verdict":"allow"} ... final: {"verdict":"ask","reason":"y"}`)))
	if r.Verdict != policy.Ask {
		t.Fatalf("the last answer did not win: %+v", r)
	}
	r = Result{}
	answer(&r, []byte(`{"verdict": " BLOCK ", "reason": "x"}`))
	if r.Verdict != policy.Block {
		t.Fatalf("BLOCK: %+v", r)
	}
	for name, h := range map[string]http.HandlerFunc{
		"5xx": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusBadGateway) },
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"choices":[{"message":{"content":"` + strings.Repeat("a", maxAnswer) + `"}}]}`))
		},
	} {
		srv := httptest.NewServer(h)
		r := OpenAI{Model: "m", BaseURL: srv.URL}.Judge(context.Background(), testInput)
		srv.Close()
		if !r.Unjudgeable {
			t.Errorf("%s: not unjudgeable: %+v", name, r.Err)
		}
	}
}

// Only an escalation is read back from the cache (6C3): a planted "Allow"
// or any other string is a miss, so the judge is asked.
func TestCacheReadsOnlyEscalations(t *testing.T) {
	now := time.Now()
	c := DefaultCache(filepath.Join(t.TempDir(), "judge-cache.json"))
	for _, v := range []policy.Verdict{"Allow", "ALLOW", "x", policy.Allow, ""} {
		os.WriteFile(c.Path, []byte(`{"k":{"verdict":"`+string(v)+`","reason":"r","at":"`+now.Format(time.RFC3339)+`"}}`), 0o600)
		if r, hit := c.Get("k", now); hit {
			t.Errorf("verdict %q was a cache hit: %+v", v, r)
		}
	}
	for _, v := range []policy.Verdict{policy.Ask, policy.Block} {
		os.WriteFile(c.Path, []byte(`{"k":{"verdict":"`+string(v)+`","reason":"r","at":"`+now.Format(time.RFC3339)+`"}}`), 0o600)
		if r, hit := c.Get("k", now); !hit || r.Verdict != v {
			t.Errorf("verdict %q was not read back: %+v %v", v, r, hit)
		}
	}
}

// A managed judge gets a fixed PATH and only the variables a judge needs
// (6C4): BASH_ENV and the user's PATH do not reach it.
func TestManagedJudgeEnv(t *testing.T) {
	env := judgeEnv(map[string]string{"PATH": "/home/u/.local/bin:/usr/bin", "BASH_ENV": "/tmp/x", "OPENAI_API_KEY": "k",
		"APPLYGATE_JUDGE_URL": "u", "HOME": "/home/u", "LD_PRELOAD": "/tmp/l.so", "GH_TOKEN": "t", "LC_ALL": "C"})
	got := strings.Join(env, " ")
	if env[0] != "PATH=/usr/bin:/bin:/usr/sbin:/sbin" || strings.Contains(got, "BASH_ENV") || strings.Contains(got, "LD_PRELOAD") || strings.Contains(got, ".local/bin") {
		t.Fatalf("env: %v", env)
	}
	for _, want := range []string{"OPENAI_API_KEY=k", "HOME=/var/empty", "PYTHONNOUSERSITE=1", "GH_TOKEN=t", "LC_ALL=C"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %v", want, env)
		}
	}
	// The agent's user would choose who answers through these (7C19).
	for _, bad := range []string{"APPLYGATE_JUDGE_URL", "HOME=/home/u", "HTTP_PROXY"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s reached the managed judge: %v", bad, env)
		}
	}
}

// A managed openai judge needs HTTPS and uses no proxy.
func TestManagedOpenAIJudge(t *testing.T) {
	dir := t.TempDir()
	old := config.SystemDir
	config.SystemDir = dir
	defer func() { config.SystemDir = old }()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mode: enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Judge: config.Judge{Backend: config.JudgeBackendOpenAI, BaseURL: "http://localhost:11434/v1", Model: "m"}}
	if _, err := New(cfg, nil); err == nil {
		t.Error("a plain-HTTP managed judge was accepted")
	}
	cfg.Judge.BaseURL = "https://judge.example/v1"
	j, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := j.(OpenAI)
	if o.Client == nil || o.Client.Transport.(*http.Transport).Proxy != nil {
		t.Error("a managed openai judge may use a proxy")
	}
}

// git accepts any unambiguous prefix of a long option, so --mirr is --mirror;
// a push that rewrites remote history must reach the judge.
func TestPushAbbreviationsReachTheJudge(t *testing.T) {
	for _, cmd := range []string{"git push --mirror origin", "git push --mirr origin", "git push --pru origin x", "git push --delet origin main",
		"git push --force-with origin main", "/usr/bin/env | cat", "env | cat"} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q did not reach the judge", cmd)
		}
	}
	for _, cmd := range []string{"git push origin feature/x", "git push --set-upstream origin feature/x", "git push --dry-run origin"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q reached the judge", cmd)
		}
	}
}

// Strict shapes adds a complex-shape action to a shell command that is not
// plain; it must not keep the judge from seeing an unknown program.
func TestResidualIgnoresComplexShape(t *testing.T) {
	d := policy.Decision{Verdict: policy.Allow, Actions: []policy.ActionResult{{Class: "complex-shape", Engine: "shell"}}}
	if !Residual(d) {
		t.Error("a complex-shape action hid the call from the judge")
	}
	d.Actions = append(d.Actions, policy.ActionResult{Class: "destroy", Engine: "terraform"})
	if Residual(d) {
		t.Error("a classified action reached the judge")
	}
}

// Four-character abbreviations reach the judge, and so do abbreviated
// options that run a program.
func TestAbbreviatedOptionsReachTheJudge(t *testing.T) {
	for _, cmd := range []string{"git push --mi origin", "git push --de origin main", "git push --recei=/tmp/x /tmp/b", "git push --ex /tmp/x /tmp/b",
		"git fetch --upl=/tmp/x /tmp/b", "git pull --upl=/tmp/x"} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%q did not reach the judge", cmd)
		}
	}
}

// A recognized action that the rules allow (an aws s3 cp in a standard
// directory) must not take an unrecognized program out of the judge's sight.
func TestResidualForAllowedWriteAction(t *testing.T) {
	d := policy.Decision{Verdict: policy.Allow, Actions: []policy.ActionResult{
		{Class: classify.CloudWrite, Engine: "aws", Verdict: policy.Allow},
	}}
	for cmd, want := range map[string]bool{
		"aws s3 cp x s3://b/x && pulumi destroy --yes": true,
		"aws s3 cp x s3://b/x":                         false,
	} {
		if got := ResidualFor(d, Input{Command: cmd, Cwd: "/repo"}); got != want {
			t.Errorf("%s: residual %v, want %v", cmd, got, want)
		}
	}
}

func TestGitCommandOptionInACluster(t *testing.T) {
	for _, cmd := range []string{"git rebase -qx 'pulumi destroy --yes' HEAD~2", "git difftool -yx 'x' HEAD", "git rebase --exe 'x' HEAD~1", "git grep -qO'x' y"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) != true {
			t.Errorf("%s is not judged", cmd)
		}
	}
	if Relevant(Input{Tool: "Bash", Command: "git rebase -q main", Cwd: "/repo"}) {
		t.Errorf("an ordinary rebase is judged")
	}
}

func TestOutsideTreeWritesByLocalPrograms(t *testing.T) {
	for _, cmd := range []string{
		"uniq /tmp/p ~/.claude/CLAUDE.md", "sort -o ~/AGENTS.md /tmp/p", "gofmt -w /Users/x/.zshrc", "go build -o /opt/homebrew/bin/aws ./cmd/x",
		"cargo build --target-dir /usr/local/bin", "find . -fprint /Users/x/out", "docker build --output type=local,dest=/Users/x/out .",
	} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%s is not judged", cmd)
		}
	}
	for _, cmd := range []string{"sort -o out.txt in.txt", "gofmt -w ./main.go", "go build -o bin/x ./cmd/x", "uniq in.txt out.txt"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%s is judged", cmd)
		}
	}
}

func TestWriteContentShowsADeletion(t *testing.T) {
	in := json.RawMessage(`{"file_path":"w.yml","old_string":"if: github.ref != 'refs/heads/prod'","new_string":""}`)
	if got := WriteContent(in); !strings.Contains(got, "github.ref") {
		t.Errorf("a deletion shows nothing: %q", got)
	}
	multi := json.RawMessage(`{"edits":[{"old_string":"guard: on","new_string":""}]}`)
	if got := WriteContent(multi); !strings.Contains(got, "guard: on") {
		t.Errorf("a MultiEdit deletion shows nothing: %q", got)
	}
}
