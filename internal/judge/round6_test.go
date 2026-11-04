package judge

import (
	"github.com/Flurit/applygate/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/policy"
)

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
