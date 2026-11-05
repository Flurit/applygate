package hook

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/shell"
)

// Judge asks the model judge about a call the rules let through without
// recognizing anything, when the user turned the judge on (docs/judge.md).
// The verdict can only rise: an answer of allow, an error or a timeout
// leaves the rule decision as it is. It returns the decision and the record
// for the log (nil when the judge was not asked).
func Judge(ctx context.Context, ev policy.Event, d policy.Decision, cfg *config.Config, opt Options) (policy.Decision, *decisionlog.Judge) {
	if !cfg.JudgeOn() {
		return d, nil
	}
	if ev.Kind == policy.KindMCP && cfg.JudgeSkips(ev.Tool) {
		return d, nil
	}
	// The filter sees the call as it is; the judge gets a copy with
	// secrets redacted.
	raw := judgeInput(ev, cfg, false)
	if !judge.ResidualFor(d, raw) {
		return d, nil
	}
	if !judge.Relevant(raw) {
		return d, nil
	}
	in := judgeInput(ev, cfg, true)
	j := opt.Judge
	if j == nil {
		var err error
		if j, err = judge.New(cfg, opt.Env); err != nil {
			if config.Managed() {
				// The system config's judge cannot run (a program the agent's
				// user owns, say): the call is unjudgeable, not unjudged.
				j = brokenJudge{err}
			} else {
				return d, &decisionlog.Judge{Error: "model judge not asked: " + err.Error()}
			}
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
	if opt.JudgeCache == "-" || config.Managed() {
		// Under a managed install the cache is in the agent's user's state
		// directory, so an entry there could answer for the judge.
		cache.Path = ""
	}
	key := judge.Key(judge.Identity(j), in)
	r, hit := cache.Get(key, now())
	switch {
	case max(len(in.Command), len(in.Args)) > judge.MaxCall:
		r, hit = judge.Result{Model: j.Name(), Err: fmt.Sprintf("the call is %d bytes, more than the %d the judge is sent", max(len(in.Command), len(in.Args)), judge.MaxCall), Unjudgeable: true}, true
	case len(in.Content) > judge.MaxContent:
		r, hit = judge.Result{Model: j.Name(), Err: fmt.Sprintf("the content written is %d bytes, more than the %d the judge is sent", len(in.Content), judge.MaxContent), Unjudgeable: true}, true
	case decisionlog.UnclosedKeyMarker(raw.Command) || decisionlog.UnclosedKeyMarker(raw.Content) || decisionlog.UnclosedKeyMarker(string(raw.Args)):
		// A private-key header with no end marker: redaction removed everything
		// after it, which may be commands, file text or arguments.
		r, hit = judge.Result{Model: j.Name(), Err: "text after a private-key marker with no end marker was redacted", Unjudgeable: true}, true
	case judge.HiddenByRedaction(raw.Command, in.Command, raw.Cwd):
		// What redaction hid starts programs, so the judge would not see
		// what the call runs.
		r, hit = judge.Result{Model: j.Name(), Err: "text redacted as a secret holds commands", Unjudgeable: true}, true
	}
	if !hit {
		ctx, cancel := context.WithTimeout(ctx, cfg.JudgeTimeout())
		r = j.Judge(ctx, in)
		cancel()
		if r.Err != "" && config.Managed() {
			// The agent's user decides whether a judge answers (a local
			// server, a proxy, a slow call), so under a managed install a
			// judge that fails is one the call could not get past.
			r.Unjudgeable = true
		}
		if r.Err == "" {
			_ = cache.Put(key, r, now())
		}
	}
	rec := &decisionlog.Judge{Model: j.Name(), Verdict: r.Verdict, Reason: r.Reason, MS: r.APIms, Cached: r.Cached, Error: r.Err}
	merged := judge.Merge(d.Verdict, r)
	// In a disposable directory an unjudgeable call that names production (a
	// padded command, text hidden by redaction) is still an ask: the tier
	// the judge was told is the directory's, not the target's.
	if r.Unjudgeable && (in.Tier != config.Disposable || config.LooksProd(raw.Command) || config.LooksProd(string(raw.Args))) {
		// The call kept the judge from answering (too large, refused, no
		// verdict in the answer): outside a disposable tier that is an ask,
		// so a call cannot get past the judge by breaking it.
		merged = policy.Max(merged, policy.Ask)
		r.Reason = "it could not judge this call (" + r.Err + "), and outside a disposable environment, or where it names production, that is an ask."
	}
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

// judgeInput is the call as the judge sees it, with secrets redacted when
// redact is set.
func judgeInput(ev policy.Event, cfg *config.Config, redact bool) judge.Input {
	r := func(s string) string {
		if redact {
			return decisionlog.Redact(s)
		}
		return s
	}
	in := judge.Input{Agent: ev.Agent, Tool: ev.Tool, Paths: ev.Paths, Cwd: ev.Cwd,
		Content: r(ev.Content), Write: ev.Kind == policy.KindWrite}
	if ev.Kind == policy.KindShell {
		in.Command = r(ev.Command)
	}
	// A known MCP tool is judged as its command, and the judge sees the
	// arguments the server gets too.
	if len(ev.Args) > 0 && (ev.Kind == policy.KindMCP || ev.Kind == policy.KindShell) {
		args := r(string(ev.Args))
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
	// A cd inside the command moves it: the judge's tier is the most
	// protected of the directories its programs run in.
	if ev.Kind == policy.KindShell {
		for _, d := range judge.Dirs(ev.Command, ev.Cwd) {
			alt := cfg.Resolve(config.Signals{Dir: d})
			if d == "" {
				alt = cfg.ResolveUnknownDir(ev.Agent, ev.Cwd, config.Signals{})
			}
			if alt.Tier.Rank() > res.Tier.Rank() {
				res = alt
			}
		}
	}
	// The targets the command itself names (a profile, a context, a project,
	// a workspace, a stack) decide the tier too, whatever the directory.
	if ev.Kind == policy.KindShell {
		for _, sig := range commandSignals(ev.Command, ev.Cwd) {
			if alt := cfg.Resolve(sig); alt.Tier.Rank() > res.Tier.Rank() && !alt.Unknown {
				res = alt
			}
		}
	}
	in.Env, in.Tier = res.Env, res.Tier
	if in.Env == "" {
		in.Env = "unknown"
	}
	return in
}

// brokenJudge stands for a judge that cannot be started.
type brokenJudge struct{ err error }

func (b brokenJudge) Name() string { return "judge" }

func (b brokenJudge) Judge(context.Context, judge.Input) judge.Result {
	return judge.Result{Model: "judge", Err: "the judge cannot run: " + b.err.Error(), Unjudgeable: true}
}

// commandSignals are the tier signals a shell command carries: tier
// environment variables set for a program, and the options that name a
// profile, context, project, subscription, workspace or stack.
func commandSignals(cmd, cwd string) []config.Signals {
	res := shell.Analyze(cmd, shell.Options{Dir: cwd, ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	var out []config.Signals
	for _, inv := range res.Invocations {
		sig := config.Signals{Dir: cwd}
		if inv.Dir != "" {
			sig.Dir = inv.Dir
		}
		set := false
		env := func(name string, f func(string)) {
			if v := inv.Env[name]; v != "" {
				f(v)
				set = true
			}
		}
		env("AWS_PROFILE", func(v string) { sig.AWSProfile = v })
		env("AWS_DEFAULT_PROFILE", func(v string) { sig.AWSProfile = v })
		env("TF_WORKSPACE", func(v string) { sig.Workspace = v })
		for _, k := range []string{"GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT"} {
			env(k, func(v string) { sig.GCPProject = v })
		}
		for _, k := range []string{"ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"} {
			env(k, func(v string) { sig.AzureSubscription = v })
		}
		env("KUBE_CTX", func(v string) { sig.KubeContext = v })
		for i, w := range inv.Args {
			t, v, eq := strings.Cut(w.Text, "=")
			if !eq && i+1 < len(inv.Args) {
				v = inv.Args[i+1].Text
			}
			if v == "" {
				continue
			}
			switch t {
			case "--profile":
				sig.AWSProfile, set = v, true
			case "--context", "--kube-context":
				sig.KubeContext, set = v, true
			case "--project":
				sig.GCPProject, set = v, true
			case "--subscription":
				sig.AzureSubscription, set = v, true
			case "--stack", "-s", "--workspace":
				if t != "-s" || shell.ProgName(inv.Args[0].Text) == "pulumi" {
					sig.Backend, set = v, true
				}
			}
		}
		if set {
			out = append(out, sig)
		}
	}
	return out
}
