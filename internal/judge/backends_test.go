package judge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/policy"
)

var testInput = Input{Agent: "claude", Tool: "Bash", Command: "pulumi destroy --yes --stack acme/prod", Cwd: "/repo/envs/prod", Env: "prod", Tier: config.Protected}

func TestOpenAIRequestAndAnswer(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("request %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		// Some servers wrap the JSON in a code fence.
		io.WriteString(w, `{"choices":[{"message":{"content":"`+"```json\\n"+`{\"verdict\":\"ask\",\"reason\":\"deploys\"}`+"\\n```"+`"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()
	r := OpenAI{Model: "some-model", BaseURL: srv.URL + "/v1/", Key: "sk-test"}.Judge(context.Background(), testInput)
	if r.Err != "" || r.Verdict != policy.Ask || r.Reason != "deploys" {
		t.Fatalf("result %+v", r)
	}
	rf, _ := got["response_format"].(map[string]any)
	msgs, _ := got["messages"].([]any)
	if got["model"] != "some-model" || rf["type"] != "json_schema" || len(msgs) != 2 {
		t.Fatalf("request %v", got)
	}
}

func TestOpenAIErrors(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"Incorrect API key"}}`)
		},
		"length": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[{"message":{"content":"{\"verdict\":"},"finish_reason":"length"}]}`)
		},
		"verdict": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[{"message":{"content":"{\"verdict\":\"maybe\",\"reason\":\"x\"}"},"finish_reason":"stop"}]}`)
		},
	} {
		srv := httptest.NewServer(h)
		r := OpenAI{Model: "m", BaseURL: srv.URL}.Judge(context.Background(), testInput)
		srv.Close()
		if r.Err == "" || r.Verdict != "" {
			t.Errorf("%s: result %+v", name, r)
		}
	}
}

func TestCommandBackend(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "judge.sh")
	// The request arrives on stdin; this judge answers by what it finds.
	os.WriteFile(script, []byte("#!/bin/sh\nif grep -q 'pulumi destroy' && true; then echo '{\"verdict\":\"block\",\"reason\":\"stack destroy\"}'; fi\n"), 0o755)
	r := Command{Argv: []string{script}}.Judge(context.Background(), testInput)
	if r.Err != "" || r.Verdict != policy.Block {
		t.Fatalf("result %+v", r)
	}
	if n := (Command{Argv: []string{"sh", script}}).Name(); n != "judge.sh" {
		t.Fatalf("name %q", n)
	}
	slow := filepath.Join(dir, "slow.sh")
	os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o755)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if r := (Command{Argv: []string{slow}}).Judge(ctx, testInput); r.Err == "" || r.Verdict != "" {
		t.Fatalf("timeout result %+v", r)
	}
}

func TestNew(t *testing.T) {
	cfg := config.Default()
	if _, err := New(cfg, map[string]string{}); err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Fatalf("missing key: %v", err)
	}
	j, err := New(cfg, map[string]string{"ANTHROPIC_API_KEY": "k"})
	if o, ok := j.(OpenAI); err != nil || !ok || o.BaseURL != config.DefaultJudgeBaseURL || o.Model != config.DefaultJudgeModel || o.Key != "k" {
		t.Fatalf("default: %+v %v", j, err)
	}
	// A local server without a key.
	cfg.Judge = config.Judge{BaseURL: "http://localhost:11434/v1", Model: "m"}
	if j, err := New(cfg, map[string]string{"ANTHROPIC_API_KEY": "k"}); err != nil || j.(OpenAI).Key != "" {
		t.Fatalf("local: %+v %v", j, err)
	}
	cfg.Judge.APIKeyEnv = "OPENAI_API_KEY"
	if _, err := New(cfg, map[string]string{}); err == nil {
		t.Fatal("configured key env not set: no error")
	}
}

func TestOpenAIReasoningEffort(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"verdict\":\"allow\",\"reason\":\"reads\"}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()
	OpenAI{Model: "m", BaseURL: srv.URL}.Judge(context.Background(), testInput)
	if _, sent := got["reasoning_effort"]; sent {
		t.Fatal("reasoning_effort sent when not configured")
	}
	OpenAI{Model: "m", BaseURL: srv.URL, ReasoningEffort: "low"}.Judge(context.Background(), testInput)
	if got["reasoning_effort"] != "low" {
		t.Fatalf("reasoning_effort %v", got["reasoning_effort"])
	}
}

func TestCache(t *testing.T) {
	c := DefaultCache(filepath.Join(t.TempDir(), "sub", "judge-cache.json"))
	now := time.Now()
	c.Put("a", Result{Verdict: policy.Ask, Reason: "r", Model: "m"}, now)
	c.Put("e", Result{Err: "boom"}, now)
	if r, ok := c.Get("a", now.Add(time.Hour)); !ok || r.Verdict != policy.Ask || !r.Cached {
		t.Fatalf("hit %+v %v", r, ok)
	}
	if _, ok := c.Get("a", now.Add(25*time.Hour)); ok {
		t.Fatal("expired entry returned")
	}
	if _, ok := c.Get("e", now); ok {
		t.Fatal("error cached")
	}
	c.Max = 1
	c.Put("b", Result{Verdict: policy.Allow}, now.Add(time.Minute))
	if _, ok := c.Get("a", now.Add(2*time.Minute)); ok {
		t.Fatal("oldest entry kept beyond Max")
	}
}
