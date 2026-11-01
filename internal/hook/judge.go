package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/policy"
)

// Judge asks the model judge about a call the rules let through without
// recognizing anything, when the user turned the judge on (docs/judge.md).
// The verdict can only rise: an answer of allow, an error or a timeout
// leaves the rule decision as it is. It returns the decision and the record
// for the log (nil when the judge was not asked).
func Judge(ctx context.Context, ev policy.Event, d policy.Decision, cfg *config.Config, opt Options) (policy.Decision, *decisionlog.Judge) {
	if !cfg.JudgeOn() || !judge.Residual(d) {
		return d, nil
	}
	if ev.Kind == policy.KindMCP && cfg.JudgeSkips(ev.Tool) {
		return d, nil
	}
	in := judgeInput(ev, cfg)
	if !judge.Relevant(in) {
		return d, nil
	}
	j := opt.Judge
	if j == nil {
		var err error
		if j, err = judge.New(cfg, opt.Env); err != nil {
			return d, &decisionlog.Judge{Error: "model judge not asked: " + err.Error()}
		}
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	cache := judge.DefaultCache(opt.JudgeCache)
	if opt.JudgeCache == "" {
		cache = judge.DefaultCache(config.JudgeCachePath())
	}
	if opt.JudgeCache == "-" {
		cache.Path = ""
	}
	key := judge.Key(j.Name(), in)
	r, hit := cache.Get(key, now())
	if !hit {
		ctx, cancel := context.WithTimeout(ctx, cfg.JudgeTimeout())
		r = j.Judge(ctx, in)
		cancel()
		if r.Err == "" {
			_ = cache.Put(key, r, now())
		}
	}
	rec := &decisionlog.Judge{Model: j.Name(), Verdict: r.Verdict, Reason: r.Reason, MS: r.APIms, Cached: r.Cached, Error: r.Err}
	merged := judge.Merge(d.Verdict, r)
	if merged == d.Verdict {
		return d, rec
	}
	d.Actions = append(d.Actions, policy.ActionResult{
		Class:   classify.Class(judge.Class),
		Command: in.Command,
		Why:     fmt.Sprintf("the model judge (%s) says: %s The rules do not recognize this call; the judge is a language model the user turned on for such calls, and it can be wrong.", j.Name(), r.Reason),
		Dir:     ev.Cwd,
		Tier:    in.Tier,
		Env:     in.Env,
		Matched: []string{"the environment of the working directory"},
		Verdict: merged,
	})
	d.Verdict = merged
	policy.Settle(&d, ev, cfg)
	return d, rec
}

// judgeInput is the call as the judge sees it, secrets redacted.
func judgeInput(ev policy.Event, cfg *config.Config) judge.Input {
	in := judge.Input{Agent: ev.Agent, Tool: ev.Tool, Paths: ev.Paths, Cwd: ev.Cwd,
		Content: decisionlog.Redact(ev.Content), Write: ev.Kind == policy.KindWrite}
	switch ev.Kind {
	case policy.KindShell:
		in.Command = decisionlog.Redact(ev.Command)
	case policy.KindMCP:
		args := decisionlog.Redact(string(ev.Args))
		if !json.Valid([]byte(args)) {
			b, _ := json.Marshal(args)
			args = string(b)
		}
		in.Args = json.RawMessage(args)
	}
	res := cfg.Resolve(config.Signals{Dir: ev.Cwd})
	if !ev.DirKnown && cfg.UnknownDirMostProtected() {
		res = cfg.ResolveUnknownDir(ev.Agent, ev.Cwd, config.Signals{})
	}
	in.Env, in.Tier = res.Env, res.Tier
	if in.Env == "" {
		in.Env = "unknown"
	}
	return in
}
