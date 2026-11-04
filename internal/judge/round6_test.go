package judge

import (
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
	for _, want := range []string{"OPENAI_API_KEY=k", "APPLYGATE_JUDGE_URL=u", "HOME=/home/u", "GH_TOKEN=t", "LC_ALL=C"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %v", want, env)
		}
	}
}
