package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/config"
)

// New returns the judge the config describes. env is the hook's process
// environment, where the API key is read.
func New(cfg *config.Config, env map[string]string) (Judge, error) {
	j := cfg.Judge
	switch j.Backend {
	case config.JudgeBackendCommand:
		if !config.Managed() {
			return Command{Argv: j.Command}, nil
		}
		// Under a managed install the judge is the system config's, so the
		// program and the scripts it is given must be root's alone, and it
		// runs with a fixed PATH and only the variables a judge needs: one
		// found on the user's PATH, or started with the user's BASH_ENV,
		// could answer allow for every call.
		argv, err := config.SystemProgram(j.Command)
		if err != nil {
			return nil, err
		}
		return Command{Argv: argv, Env: judgeEnv(env), Dir: "/"}, nil
	case "", config.JudgeBackendOpenAI:
		// No provider or model is chosen for the user (docs/judge.md).
		if j.BaseURL == "" || j.Model == "" {
			return nil, errors.New("no endpoint chosen: set judge.base_url and judge.model, or use backend: command (docs/judge.md compares the options)")
		}
		o := OpenAI{BaseURL: j.BaseURL, Model: j.Model, ReasoningEffort: j.ReasoningEffort}
		if config.Managed() {
			// The agent's user can answer on a plain-HTTP or local port, and
			// sets the proxy variables: a managed judge talks HTTPS to the
			// endpoint itself.
			if !strings.HasPrefix(strings.ToLower(j.BaseURL), "https://") {
				return nil, errors.New("under a managed install the judge's base_url must be https://, which the agent's user cannot answer for")
			}
			o.Client = &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}}
		}
		if j.APIKeyEnv != "" {
			// A local server may need no key; a configured key must exist.
			if o.Key = env[j.APIKeyEnv]; o.Key == "" {
				return nil, fmt.Errorf("%s is not set", j.APIKeyEnv)
			}
		}
		return o, nil
	}
	return nil, fmt.Errorf("unknown judge backend %q", j.Backend)
}

// Command judges through a program the user names: it gets one request as
// JSON on stdin ({"system", "prompt", "schema", "call"}) and writes
// {"verdict": "allow"|"ask"|"block", "reason": "..."} on stdout. This is how
// a local model, another gateway or the claude CLI's own login is used.
type Command struct {
	Argv []string
	// Env, when set, is the program's whole environment.
	Env []string
	// Dir, when set, is the directory the program runs in.
	Dir string
}

// judgeEnv is the environment a managed judge program gets: a fixed PATH,
// a home and temporary directory the agent's user cannot write (so no
// start-up file of theirs is read: .curlrc, Python's user site, a shell
// rc, Claude Code's user settings), Python's user site turned off, the
// locale, and the variables named like credentials (*_API_KEY, *_TOKEN).
// The judge's own settings (APPLYGATE_JUDGE_*) and the proxy variables
// are not passed: the agent's user would choose who answers.
func judgeEnv(env map[string]string) []string {
	out := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + judgeHome, "TMPDIR=" + judgeHome, "PYTHONNOUSERSITE=1",
		"PYTHONDONTWRITEBYTECODE=1", "CURL_HOME=" + judgeHome, "XDG_CONFIG_HOME=" + judgeHome}
	for k, v := range env {
		switch {
		case k == "USER", k == "LOGNAME", k == "LANG", k == "TZ", strings.HasPrefix(k, "LC_"),
			strings.HasSuffix(k, "_API_KEY"), strings.HasSuffix(k, "_TOKEN"):
			out = append(out, k+"="+v)
		}
	}
	sort.Strings(out[7:]) // after the fixed entries
	return out
}

// judgeHome is a directory root owns on every supported system.
const judgeHome = "/var/empty"

// Name is the program's file name, or the script's when the program is an
// interpreter ("sh judge.sh" is "judge.sh").
func (c Command) Name() string {
	name := filepath.Base(c.Argv[0])
	if interpreters[name] && len(c.Argv) > 1 {
		name = filepath.Base(c.Argv[len(c.Argv)-1])
	}
	return name
}

var interpreters = map[string]bool{"sh": true, "bash": true, "zsh": true, "python": true, "python3": true, "node": true, "ruby": true, "perl": true, "deno": true, "bun": true, "uv": true}

func (c Command) Judge(ctx context.Context, in Input) Result {
	r := Result{Model: c.Name()}
	req, _ := json.Marshal(map[string]any{"system": System, "prompt": Prompt(in), "schema": Schema, "call": in})
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Stdin = bytes.NewReader(req)
	if c.Env != nil {
		cmd.Env = c.Env
	}
	if c.Dir != "" {
		cmd.Dir = c.Dir
	}
	cmd.WaitDelay = time.Second
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	r.WallMS = float64(time.Since(start).Milliseconds())
	r.APIms = r.WallMS
	if ctx.Err() != nil {
		r.Err = "judge command: " + ctx.Err().Error()
		return r
	}
	if err != nil {
		r.Err = fmt.Sprintf("judge command: %v: %s", err, firstLine(errb.String()))
		return r
	}
	answer(&r, []byte(jsonObject(out.String())))
	return r
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
