// Package policy combines command class, environment tier, preflight and
// plan-gate findings into one verdict. It is the seatbelt's decision function.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/flurit-ai/seatbelt/internal/classify"
	"github.com/flurit-ai/seatbelt/internal/config"
	"github.com/flurit-ai/seatbelt/internal/plangate"
	"github.com/flurit-ai/seatbelt/internal/preflight"
	"github.com/flurit-ai/seatbelt/internal/shell"
)

// Verdict is allow, ask or block.
type Verdict string

const (
	Allow Verdict = "allow"
	Ask   Verdict = "ask"
	Block Verdict = "block"
)

func (v Verdict) rank() int {
	switch v {
	case Block:
		return 2
	case Ask:
		return 1
	}
	return 0
}

// Max returns the stricter verdict.
func Max(a, b Verdict) Verdict {
	if b.rank() > a.rank() {
		return b
	}
	if a == "" {
		return Allow
	}
	return a
}

// Table is the v1 verdict table: class x tier. ApplySavedPlan is decided by
// the plan gate and starts at allow.
var Table = map[classify.Class]map[config.Tier]Verdict{
	classify.ReadOnly:         {config.Protected: Allow, config.Standard: Allow, config.Disposable: Allow},
	classify.ApplySavedPlan:   {config.Protected: Allow, config.Standard: Allow, config.Disposable: Allow},
	classify.UnreviewedApply:  {config.Protected: Block, config.Standard: Ask, config.Disposable: Allow},
	classify.Destroy:          {config.Protected: Block, config.Standard: Ask, config.Disposable: Allow},
	classify.StateSurgery:     {config.Protected: Block, config.Standard: Ask, config.Disposable: Ask},
	classify.CloudDestructive: {config.Protected: Block, config.Standard: Ask, config.Disposable: Ask},
	classify.Tampering:        {config.Protected: Block, config.Standard: Block, config.Disposable: Block},
	classify.Dynamic:          {config.Protected: Ask, config.Standard: Ask, config.Disposable: Allow},
	// Not in the spec table; chosen here and documented in docs/policy.md.
	classify.UnknownWrapper:   {config.Protected: Ask, config.Standard: Allow, config.Disposable: Allow},
	classify.Mutating:         {config.Protected: Ask, config.Standard: Allow, config.Disposable: Allow},
	classify.CloudWrite:       {config.Protected: Ask, config.Standard: Allow, config.Disposable: Allow},
	classify.CredentialAccess: {config.Protected: Ask, config.Standard: Ask, config.Disposable: Ask},
}

// FindingVerdict maps a finding severity to a verdict for a tier: protected
// blocks critical and asks on high; standard asks on critical and logs high;
// disposable logs everything.
func FindingVerdict(s preflight.Severity, t config.Tier) Verdict {
	switch t {
	case config.Protected:
		switch s {
		case preflight.Critical:
			return Block
		case preflight.High:
			return Ask
		}
	case config.Standard:
		if s == preflight.Critical {
			return Ask
		}
	}
	return Allow
}

// EventKind is what kind of tool call an event is.
type EventKind string

const (
	KindShell EventKind = "shell"
	KindWrite EventKind = "write"
	KindRead  EventKind = "read"
	KindOther EventKind = "other"
)

// Event is the agent-neutral form of a tool call.
type Event struct {
	Agent          string    `json:"agent"`
	Tool           string    `json:"tool"`
	Kind           EventKind `json:"kind"`
	Command        string    `json:"command,omitempty"`
	Paths          []string  `json:"paths,omitempty"`
	Cwd            string    `json:"cwd"`
	Session        string    `json:"session,omitempty"`
	PermissionMode string    `json:"permission_mode,omitempty"`
	// CanAsk is false when the host cannot show an ask prompt; ask then
	// becomes block.
	CanAsk bool `json:"can_ask"`
}

// Deps are the effects Decide may use. Tests replace them.
type Deps struct {
	Env      map[string]string // process environment of the hook
	ReadFile func(string) ([]byte, error)
	// PlanJSON returns "show -json" output for a saved plan.
	PlanJSON func(engine, dir, planfile string) ([]byte, error)
	// Lockfile runs the git lockfile check; nil disables it.
	Lockfile func(dir string) *preflight.Finding
	// Account resolves the AWS account for a profile (live check); nil
	// disables it.
	Account func(profile string) (string, error)
	Rules   *plangate.Rules
}

// ActionResult is the decision for one classified action.
type ActionResult struct {
	Class      classify.Class      `json:"class"`
	Engine     string              `json:"engine,omitempty"`
	Command    string              `json:"command"`
	Why        string              `json:"why"`
	Via        []string            `json:"via,omitempty"`
	Dir        string              `json:"dir,omitempty"`
	Tier       config.Tier         `json:"tier,omitempty"`
	Env        string              `json:"environment,omitempty"`
	Matched    []string            `json:"matched,omitempty"`
	Workspace  string              `json:"workspace,omitempty"`
	Backend    string              `json:"backend,omitempty"`
	Profile    string              `json:"aws_profile,omitempty"`
	PlanFile   string              `json:"plan_file,omitempty"`
	PlanSHA256 string              `json:"plan_sha256,omitempty"`
	Findings   []preflight.Finding `json:"findings,omitempty"`
	Verdict    Verdict             `json:"verdict"`
	NextStep   string              `json:"next_step,omitempty"`
}

// Decision is the outcome for one event.
type Decision struct {
	Verdict  Verdict        `json:"verdict"`  // what the policy decided
	Enforced Verdict        `json:"enforced"` // what is returned to the agent
	Mode     string         `json:"mode"`
	Actions  []ActionResult `json:"actions,omitempty"`
	Message  string         `json:"message,omitempty"`
	Notes    []string       `json:"notes,omitempty"`
}

// Decide evaluates an event. It does not write the log.
func Decide(ev Event, cfg *config.Config, deps Deps) Decision {
	if deps.ReadFile == nil {
		deps.ReadFile = shell.DefaultReadFile
	}
	if deps.Rules == nil {
		deps.Rules = plangate.DefaultRules()
	}
	copt := classify.Options{ProtectedPaths: cfg.GuardPaths(), Home: deps.Env["HOME"]}
	var actions []classify.Action
	switch ev.Kind {
	case KindShell:
		res := shell.Analyze(ev.Command, shell.Options{Dir: ev.Cwd, Env: deps.Env, Aliases: cfg.Aliases, ReadFile: deps.ReadFile})
		actions = classify.Invocations(res, copt)
	case KindWrite:
		for _, p := range ev.Paths {
			actions = append(actions, classify.FileWrite(ev.Tool, p, ev.Cwd, copt)...)
		}
	case KindRead:
		for _, p := range ev.Paths {
			actions = append(actions, classify.FileRead(ev.Tool, p, ev.Cwd, copt)...)
		}
	}

	d := Decision{Verdict: Allow, Mode: cfg.Mode}
	selected := map[string]string{} // dir -> workspace selected earlier in this command
	for _, a := range actions {
		if ws, ok := selected[a.Dir]; ok && a.Env["TF_WORKSPACE"] == "" {
			env := map[string]string{"TF_WORKSPACE": ws}
			for k, v := range a.Env {
				if v != "" {
					env[k] = v
				}
			}
			a.Env = env
		}
		if a.SelectWorkspace != "" {
			selected[a.Dir] = a.SelectWorkspace
		}
		r := evaluate(a, ev, cfg, deps)
		d.Actions = append(d.Actions, r)
		d.Verdict = Max(d.Verdict, r.Verdict)
	}
	d.Enforced = d.Verdict
	if d.Enforced == Ask && !ev.CanAsk {
		d.Enforced = Block
		d.Notes = append(d.Notes, "this agent cannot show an approval prompt here, so ask is enforced as block")
	}
	if d.Enforced != Allow {
		d.Message = message(d)
	}
	if cfg.Observe() && d.Enforced != Allow {
		d.Notes = append(d.Notes, "observe mode: would have returned "+string(d.Enforced)+"; allowed")
		d.Enforced = Allow
	}
	return d
}

func mergeEnv(base, over map[string]string) map[string]string {
	env := map[string]string{}
	for k, v := range base {
		env[k] = v
	}
	for k, v := range over {
		if v != "" {
			env[k] = v
		}
	}
	return env
}

func evaluate(a classify.Action, ev Event, cfg *config.Config, deps Deps) ActionResult {
	r := ActionResult{Class: a.Class, Engine: a.Engine, Command: a.Command, Why: a.Why, Via: a.Via, Dir: a.Dir, PlanFile: a.PlanFile}
	if a.Class == classify.Tampering || a.Class == classify.CredentialAccess {
		// Tier does not matter: these are about the guard and credentials,
		// not about one environment.
		r.Verdict = Table[a.Class][config.Protected]
		r.NextStep = nextStep(a.Class, "")
		return r
	}
	env := mergeEnv(deps.Env, a.Env)
	sig := config.Signals{Dir: a.Dir}
	tf := a.Engine == "terraform" || a.Engine == "tofu" || a.Engine == "terragrunt"
	var recorded, declared *preflight.Backend
	if tf && a.Dir != "" {
		r.Workspace = preflight.Workspace(a.Dir, env)
		sig.Workspace = r.Workspace
		recorded = preflight.InitBackend(a.Dir)
		declared = preflight.DeclaredBackend(a.Dir)
		be := recorded
		if be == nil {
			be = declared
		}
		if be != nil {
			r.Backend = be.URL()
			sig.Backend = r.Backend
			if p := be.Config["profile"]; p != "" && env["AWS_PROFILE"] == "" {
				sig.AWSProfile = p
			}
		}
	}
	if a.Profile != "" {
		sig.AWSProfile = a.Profile
	} else if p := env["AWS_PROFILE"]; p != "" {
		sig.AWSProfile = p
	}
	r.Profile = sig.AWSProfile
	if deps.Account != nil && (tf || a.Engine == "aws") && a.Class != classify.ReadOnly {
		if acct, err := deps.Account(sig.AWSProfile); err == nil {
			sig.AWSAccount = acct
		} else {
			r.Findings = append(r.Findings, preflight.Finding{Rule: "live-identity", Severity: preflight.Info, Message: "STS identity check failed: " + err.Error()})
		}
	}
	res := cfg.Resolve(sig)
	r.Tier, r.Env, r.Matched = res.Tier, res.Env, res.Matched
	if a.Dir == "" && tf {
		r.Matched = append(r.Matched, "working directory could not be resolved statically")
	}

	if tf && a.Dir != "" {
		if a.TouchesState && cfg.BackendCheck() {
			if f := preflight.BackendChanged(declared, recorded); f != nil {
				r.Findings = append(r.Findings, *f)
			}
		}
		if a.TouchesState && cfg.StaleStateCheck() {
			be := recorded
			if be == nil {
				be = declared
			}
			if f := preflight.StaleState(a.Dir, be); f != nil {
				r.Findings = append(r.Findings, *f)
			}
		}
		if deps.Lockfile != nil && cfg.LockfileCheck() && (a.Class == classify.ApplySavedPlan || a.Class == classify.UnreviewedApply || a.Class == classify.Destroy) {
			if f := deps.Lockfile(a.Dir); f != nil {
				r.Findings = append(r.Findings, *f)
			}
		}
	}

	class := a.Class
	if class == classify.ApplySavedPlan {
		class = planGate(&r, a, cfg, deps, recorded, declared)
	}
	r.Class = class
	v := Table[class][res.Tier]
	for _, f := range r.Findings {
		v = Max(v, FindingVerdict(f.Severity, res.Tier))
	}
	r.Verdict = v
	if v != Allow {
		r.NextStep = nextStep(class, a.Engine)
		if class == classify.ApplySavedPlan || class == classify.ReadOnly || class == classify.Mutating {
			r.NextStep = "Show the findings above to the user. A human should review the plan and apply it outside the agent, or change the configuration so the plan no longer triggers them."
		}
	}
	return r
}

// planGate runs the saved-plan checks and returns the effective class
// (Destroy when the plan deletes resources).
func planGate(r *ActionResult, a classify.Action, cfg *config.Config, deps Deps, recorded, declared *preflight.Backend) classify.Class {
	planPath := a.PlanFile
	if !filepath.IsAbs(planPath) && a.Dir != "" {
		planPath = filepath.Join(a.Dir, planPath)
	}
	if b, err := deps.ReadFile(planPath); err == nil {
		sum := sha256.Sum256(b)
		r.PlanSHA256 = hex.EncodeToString(sum[:])
	} else if fi, serr := os.Stat(planPath); serr == nil && fi.Size() > 0 {
		// Larger than the read cap: hash by streaming.
		if f, err := os.Open(planPath); err == nil {
			h := sha256.New()
			_, _ = io.Copy(h, f)
			f.Close()
			r.PlanSHA256 = hex.EncodeToString(h.Sum(nil))
		}
	}
	if ws, ok := preflight.PlanWorkspace(planPath); ok && r.Workspace != "" && ws != r.Workspace {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "workspace-mismatch", Severity: preflight.Critical,
			Message:  fmt.Sprintf("the plan was made in workspace %q but workspace %q is selected; applying it would change the wrong environment", ws, r.Workspace),
			Evidence: []string{"plan workspace: " + ws, "selected workspace: " + r.Workspace}})
		// The plan's own workspace may be more protected than the selected one.
		alt := cfg.Resolve(config.Signals{Dir: a.Dir, Workspace: ws, Backend: r.Backend, AWSProfile: r.Profile})
		if alt.Tier.Rank() > r.Tier.Rank() {
			r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "plan workspace "+ws)
		}
	}
	if deps.PlanJSON == nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: "reading saved plans is disabled (plan_gate.run_show: false), so the plan cannot be checked"})
		return classify.ApplySavedPlan
	}
	js, err := deps.PlanJSON(a.Engine, a.Dir, a.PlanFile)
	if err != nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical,
			Message: "could not read the saved plan with show -json: " + err.Error()})
		return classify.ApplySavedPlan
	}
	be := recorded
	if be == nil {
		be = declared
	}
	gres, err := plangate.Evaluate(plangate.Input{PlanJSON: js, MaxDestroy: cfg.MaxDestroy(r.Tier), Scope: cfg.PlanGate.Scope, Backend: be}, deps.Rules)
	if err != nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: err.Error()})
		return classify.ApplySavedPlan
	}
	if r.PlanSHA256 == "" {
		sum := sha256.Sum256(js)
		r.PlanSHA256 = "json:" + hex.EncodeToString(sum[:])
	}
	r.Findings = append(r.Findings, gres.Findings...)
	if len(gres.Deletes) > 0 {
		r.Why = fmt.Sprintf("applies saved plan %s, which destroys %d resource(s): %s", a.PlanFile, len(gres.Deletes), strings.Join(first(gres.Deletes, 5), ", "))
		return classify.Destroy
	}
	r.Why = fmt.Sprintf("applies saved plan %s (%d change(s))", a.PlanFile, gres.Changes)
	return classify.ApplySavedPlan
}

func first(ss []string, n int) []string {
	if len(ss) > n {
		return append(ss[:n:n], fmt.Sprintf("and %d more", len(ss)-n))
	}
	return ss
}

func nextStep(c classify.Class, engine string) string {
	tf := engine
	if tf == "" || tf == "terragrunt" {
		tf = "terraform"
	}
	switch c {
	case classify.UnreviewedApply:
		return fmt.Sprintf("Run `%s plan -out=tfplan`, show the plan to the user, then apply the saved plan with `%s apply tfplan`.", tf, tf)
	case classify.Destroy:
		return "Do not retry or rephrase this. Destroying resources here needs a human: tell the user what you intended and let them run it outside the agent."
	case classify.StateSurgery:
		return "State surgery must be done by a human. Tell the user what you intended and why."
	case classify.CloudDestructive:
		return "Deleting cloud resources directly needs a human. Tell the user which resource and why; prefer changing the Terraform configuration and planning."
	case classify.Tampering:
		return "The agent may not change its own guardrails, hook configuration or seatbelt's config and log. Ask the user to make this change themselves."
	case classify.Dynamic:
		return "Write the command out literally, without eval, variables for subcommands, encoded text, or piping generated or fetched text into a shell, so it can be checked."
	case classify.UnknownWrapper:
		return "Run the underlying commands directly so they can be checked, or ask the user to run this wrapper."
	case classify.CredentialAccess:
		return "Do not read credentials. Use the configured profile through the CLI instead, and ask the user if access is really needed."
	case classify.Mutating, classify.CloudWrite:
		return "This changes a protected environment. Confirm with the user first."
	}
	return ""
}

func message(d Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seatbelt: %s.", strings.ToUpper(string(d.Enforced)))
	if d.Enforced != d.Verdict {
		fmt.Fprintf(&b, " (policy verdict: %s)", d.Verdict)
	}
	var rs []ActionResult
	for _, a := range d.Actions {
		if a.Verdict != Allow {
			rs = append(rs, a)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Verdict.rank() > rs[j].Verdict.rank() })
	steps := map[string]bool{}
	for _, a := range rs {
		fmt.Fprintf(&b, "\n- [%s] %s: %s", a.Verdict, a.Class, a.Why)
		if a.Tier != "" {
			fmt.Fprintf(&b, "\n  environment: %s (tier %s; %s)", a.Env, a.Tier, strings.Join(a.Matched, "; "))
		}
		if a.Command != "" && !strings.Contains(a.Why, a.Command) {
			fmt.Fprintf(&b, "\n  command: %s", a.Command)
		}
		if len(a.Via) > 0 {
			fmt.Fprintf(&b, "\n  reached via: %s", strings.Join(a.Via, " > "))
		}
		for _, f := range a.Findings {
			if f.Severity == preflight.Info {
				continue
			}
			fmt.Fprintf(&b, "\n  finding (%s, %s): %s", f.Severity, f.Rule, f.Message)
			for _, e := range first(f.Evidence, 5) {
				fmt.Fprintf(&b, "\n    - %s", e)
			}
		}
		if a.PlanSHA256 != "" {
			fmt.Fprintf(&b, "\n  plan sha256: %s", a.PlanSHA256)
		}
	}
	for _, a := range rs {
		if a.NextStep != "" && !steps[a.NextStep] {
			steps[a.NextStep] = true
			fmt.Fprintf(&b, "\nNext step: %s", a.NextStep)
		}
	}
	for _, n := range d.Notes {
		fmt.Fprintf(&b, "\nNote: %s", n)
	}
	return b.String()
}

// ErrTimeout is returned by Run when the decision took too long.
var ErrTimeout = errors.New("decision timed out")

// Run calls f with a time limit and converts a panic into an error, so the
// caller can apply the configured error behavior instead of crashing.
func Run(timeout time.Duration, f func() Decision) (d Decision, err error) {
	type result struct {
		d   Decision
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: fmt.Errorf("internal error: %v", p)}
			}
		}()
		ch <- result{d: f()}
	}()
	select {
	case r := <-ch:
		return r.d, r.err
	case <-time.After(timeout):
		return Decision{}, ErrTimeout
	}
}
