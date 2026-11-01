package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
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
		return Command{Argv: j.Command}, nil
	case "", config.JudgeBackendOpenAI:
		o := OpenAI{BaseURL: j.BaseURL, Model: j.Model, ReasoningEffort: j.ReasoningEffort}
		keyEnv := j.APIKeyEnv
		if o.BaseURL == "" {
			o.BaseURL = config.DefaultJudgeBaseURL
			if keyEnv == "" {
				keyEnv = config.DefaultJudgeKeyEnv
			}
		}
		if o.Model == "" {
			o.Model = config.DefaultJudgeModel
		}
		if keyEnv != "" {
			// A local server may need no key; a configured key must exist.
			if o.Key = env[keyEnv]; o.Key == "" {
				return nil, fmt.Errorf("%s is not set", keyEnv)
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
}

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
	answer(&r, out.Bytes())
	return r
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
