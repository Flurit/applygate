package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/policy"
)

// CLI judges through the claude CLI in print mode: no tools, the judge's own
// system prompt, a JSON schema for the answer. It uses the CLI's login, so
// the experiment needs no API key; APIms is the CLI's API time, which is the
// figure an SDK call would see.
type CLI struct {
	Model  string
	Effort string // low | medium | high; "" leaves the model default
}

func (c CLI) Name() string { return c.Model + "/" + c.Effort }

func (c CLI) Judge(ctx context.Context, in judge.Input) judge.Result {
	r := judge.Result{Model: c.Model}
	args := []string{"-p", "--model", c.Model, "--system-prompt", judge.System, "--tools", "", "--json-schema", judge.SchemaJSON,
		"--output-format", "json", "--no-session-persistence"}
	if c.Effort != "" {
		args = append(args, "--effort", c.Effort)
	}
	cmd := exec.CommandContext(ctx, "claude", args...)
	cmd.Stdin = strings.NewReader(judge.Prompt(in))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	r.WallMS = float64(time.Since(start).Milliseconds())
	if err != nil {
		r.Err = fmt.Sprintf("claude: %v: %s", err, strings.TrimSpace(errb.String()))
		return r
	}
	var resp struct {
		IsError    bool    `json:"is_error"`
		Result     string  `json:"result"`
		DurationMS float64 `json:"duration_api_ms"`
		Cost       float64 `json:"total_cost_usd"`
		Structured *struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
		} `json:"structured_output"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		r.Err = "unreadable CLI output: " + err.Error()
		return r
	}
	r.APIms, r.CostUSD = resp.DurationMS, resp.Cost
	if resp.IsError || resp.Structured == nil {
		r.Err = "no structured answer: " + resp.Result
		return r
	}
	switch v := policy.Verdict(resp.Structured.Verdict); v {
	case policy.Allow, policy.Ask, policy.Block:
		r.Verdict, r.Reason = v, resp.Structured.Reason
	default:
		r.Err = "unknown verdict " + resp.Structured.Verdict
	}
	return r
}
