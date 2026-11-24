// Package policy combines command class, environment tier, preflight and
// plan-gate findings into one verdict. It is the applygate's decision function.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
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
	classify.HookRewrite:      {config.Protected: Ask, config.Standard: Ask, config.Disposable: Ask},
	classify.Dynamic:          {config.Protected: Ask, config.Standard: Ask, config.Disposable: Allow},
	// Not in the spec table; chosen here and documented in docs/policy.md.
	classify.UnknownWrapper:   {config.Protected: Ask, config.Standard: Allow, config.Disposable: Allow},
	classify.ComplexShape:     {config.Protected: Ask, config.Standard: Allow, config.Disposable: Allow},
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
	// KindMCP is a call to an MCP server's tool (mcp__<server>__<tool>). It
	// is logged with its arguments and never judged: the verdict is allow.
	KindMCP   EventKind = "mcp"
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
	// DirKnown is true when Cwd is the directory the command runs in. When
	// the host reports only the session root (Codex 0.165.0 sends no
	// workdir), it is false and the command is judged at the most protected
	// tier it could be in under Cwd, unless unknown_dir is session_root. A
	// cd or -chdir inside the command establishes the directory for that
	// invocation. The zero value fails closed on purpose.
	DirKnown bool `json:"dir_known"`
	// Persistent is set for input typed into a shell that keeps running
	// between calls (an MCP terminal tool).
	Persistent bool `json:"persistent,omitempty"`
	// Args are an MCP call's raw arguments (KindMCP); Command then holds
	// the compact copy kept in the log.
	Args json.RawMessage `json:"-"`
	// Content is what a write puts in the file (an edit's replacement, a
	// patch), for the model judge. It is never logged.
	Content string `json:"-"`
}

// Deps are the effects Decide may use. Tests replace them.
type Deps struct {
	// Ctx bounds the subprocesses a decision runs (git for the lock file);
	// nil means context.Background.
	Ctx      context.Context
	Env      map[string]string // process environment of the hook
	ReadFile func(string) ([]byte, error)
	// PlanJSON returns "show -json" output for a saved plan.
	PlanJSON func(engine, dir, planfile string) ([]byte, error)
	// Lockfile runs the git lockfile check; nil disables it.
	Lockfile func(dir string) *preflight.Finding
	// Account resolves the AWS account for a profile (live check); nil
	// disables it.
	Account func(profile string) (string, error)
	// StatePull returns the remote state ("<engine> state pull"); nil
	// disables the opt-in lineage and serial comparison.
	StatePull func(engine, dir string) ([]byte, error)
	Rules     *plangate.Rules
	// LoadConfig loads the configuration for another directory, for a
	// command that runs in a repository the session's config did not
	// read; nil keeps the session's config.
	LoadConfig func(dir string) (*config.Config, error)
}

// ActionResult is the decision for one classified action.
type ActionResult struct {
	Class     classify.Class `json:"class"`
	Engine    string         `json:"engine,omitempty"`
	Command   string         `json:"command"`
	Why       string         `json:"why"`
	Via       []string       `json:"via,omitempty"`
	Dir       string         `json:"dir,omitempty"`
	Tier      config.Tier    `json:"tier,omitempty"`
	Env       string         `json:"environment,omitempty"`
	Matched   []string       `json:"matched,omitempty"`
	Workspace string         `json:"workspace,omitempty"`
	Backend   string         `json:"backend,omitempty"`
	Profile   string         `json:"aws_profile,omitempty"`
	// The cluster or cloud a kubectl, helm, gcloud or az command targets.
	KubeContext       string              `json:"kube_context,omitempty"`
	GCPProject        string              `json:"gcp_project,omitempty"`
	AzureSubscription string              `json:"azure_subscription,omitempty"`
	PlanFile          string              `json:"plan_file,omitempty"`
	PlanSHA256        string              `json:"plan_sha256,omitempty"`
	Findings          []preflight.Finding `json:"findings,omitempty"`
	Verdict           Verdict             `json:"verdict"`
	NextStep          string              `json:"next_step,omitempty"`
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

// GuardOptions returns the guard for a decision. The session directories the
// hook's environment names (SessionRoots) are guard roots as the repository
// root is. A host's event cwd is not one: Codex 0.166.0 sends the command's
// directory there, not the session's.
func GuardOptions(cfg *config.Config, env map[string]string) classify.Options {
	home := env["HOME"]
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	paths := cfg.GuardPaths()
	roots := SessionRoots(env)
	g := guard.New(paths, cfg.GuardTargets(home, roots...)).Programs(config.PathDirs(home), config.PathPrograms()).
		PlantOnly(cfg.PlantOnlyPaths(), cfg.PlantOnlyTargets(home, roots...)).Soft(cfg.SoftTargets(home, roots...))
	return classify.Options{ProtectedPaths: paths, Guard: g, Home: home}
}

// sessionRootVars are the variables hosts set in a hook's environment to
// the directory the session was started in, whose hook settings they load:
// Claude Code's, Gemini CLI's and Devin's (docs/hosts.md).
var sessionRootVars = []string{"CLAUDE_PROJECT_DIR", "GEMINI_PROJECT_DIR", "DEVIN_PROJECT_DIR"}

// SessionRoots returns the session directories the hook's environment
// names. A session started in a subdirectory of a repository loads that
// subdirectory's .claude/settings.json, so its hook files are guarded there
// as at the repository root.
func SessionRoots(env map[string]string) []string {
	var out []string
	for _, k := range sessionRootVars {
		if v := env[k]; v != "" && filepath.IsAbs(v) {
			out = append(out, v)
		}
	}
	return out
}

// ShellOptions returns the analyzer options for a command run in dir.
func ShellOptions(cfg *config.Config, copt classify.Options, dir string, env map[string]string, read func(string) ([]byte, error)) shell.Options {
	return shell.Options{Dir: dir, Env: env, Aliases: cfg.Aliases, Wrappers: cfg.ShellWrappers(), ReadFile: read, IsDir: isDir,
		UnknownBase: copt.UnknownCwd && cfg.UnknownDirMostProtected(), ProtectedPaths: copt.ProtectedPaths, ProtectedPath: copt.Guard.Protected, GuardNeedles: copt.Guard.Needles(copt.Home)}
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Decide evaluates an event. It does not write the log.
func Decide(ev Event, cfg *config.Config, deps Deps) Decision {
	panicPoint("decide")
	if deps.ReadFile == nil {
		deps.ReadFile = shell.DefaultReadFile
	}
	if deps.Rules == nil {
		deps.Rules = plangate.DefaultRules()
	}
	copt := GuardOptions(cfg, deps.Env)
	copt.UnknownCwd, copt.Cwd = !ev.DirKnown, ev.Cwd
	var actions []classify.Action
	var notes []string
	switch ev.Kind {
	case KindShell:
		res := shell.Analyze(ev.Command, ShellOptions(cfg, copt, ev.Cwd, deps.Env, deps.ReadFile))
		actions = classify.Invocations(res, copt)
		notes = res.Notes
		for _, a := range actions {
			// A credentials file the command points a CLI at that names a
			// program runs it whatever the verb is, and whatever the tier.
			why := ""
			if a.Engine != "" {
				env := mergeEnv(deps.Env, a.Env)
				for k, v := range a.TargetEnv {
					env[k] = v
				}
				a.Env, a.TargetEnv = env, nil
				why = credFileRuns(a)
				if why == "" && strings.Contains(a.TargetUnknown, "names a file an earlier step") {
					why = a.TargetUnknown
				}
			}
			if why != "" {
				actions = append(actions, classify.Action{Class: classify.CredentialAccess, Engine: "file", Command: ev.Command, Dir: a.Dir, Why: why})
				break
			}
		}
		if why := classify.UnknownGuardChange(res, ev.Command, ev.Cwd, copt); why != "" {
			actions = append(actions, classify.Action{Class: classify.Tampering, Engine: "file", Command: ev.Command, Dir: ev.Cwd, Why: why})
		}
		if cfg.StrictShapesOn() {
			actions = append(actions, shapeActions(ev, res, deps, actions)...)
		}
		if ev.Persistent {
			// Each call is judged on its own, so state one call leaves in
			// the shell (an alias for git, a function, an exported
			// profile) would change what a later, plain-looking call runs.
			if why := shell.DefinesState(ev.Command); why != "" {
				actions = append(actions, classify.Action{Class: classify.Tampering, Engine: "shell", Command: ev.Command, Dir: ev.Cwd,
					Why: "typed into a shell that keeps running between calls: " + why + " stays for later calls, which are judged on their own"})
			}
		}
		// apply_patch run from the shell (Codex puts it on PATH) edits the
		// files its patch names, like the apply_patch tool.
		if strings.Contains(ev.Command, "apply_patch") || strings.Contains(ev.Command, "applypatch") {
			for _, p := range classify.PatchPaths(ev.Command) {
				actions = append(actions, classify.FileWrite("apply_patch", p, ev.Cwd, copt)...)
			}
		}
	case KindWrite:
		for _, p := range ev.Paths {
			actions = append(actions, classify.FileWrite(ev.Tool, p, ev.Cwd, copt)...)
		}
	case KindRead:
		for _, p := range ev.Paths {
			actions = append(actions, classify.FileRead(ev.Tool, p, ev.Cwd, copt)...)
		}
	}

	d := Decision{Verdict: Allow, Mode: cfg.Mode, Notes: notes}
	selected := map[string]string{}            // dir -> workspace selected earlier in this command
	backendCfg := map[string]classify.Action{} // dir -> an earlier init in this command with -backend-config
	unknownBackend := map[string]bool{}        // dir -> an earlier init whose -backend-config cannot be resolved
	for _, a := range actions {
		if len(a.BackendConfig) > 0 {
			backendCfg[a.Dir] = a
			delete(unknownBackend, a.Dir)
		} else if a.BackendConfigUnknown {
			unknownBackend[a.Dir] = true
			delete(backendCfg, a.Dir)
		} else if init, ok := backendCfg[a.Dir]; ok && isTerraform(a.Engine) {
			a.BackendConfig, a.BackendConfigWritten = init.BackendConfig, init.BackendConfigWritten
		} else if unknownBackend[a.Dir] && isTerraform(a.Engine) {
			a.BackendConfigUnknown = true
		}
		if ws, ok := selected[a.Dir]; ok && ws == classify.UnknownWorkspace && a.Env["TF_WORKSPACE"] == "" {
			a.WorkspaceUnknown = true
		} else if ok && a.Env["TF_WORKSPACE"] == "" {
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
	Settle(&d, ev, cfg)
	return d
}

// Settle derives what is returned to the agent from d.Verdict: ask becomes
// block on an agent that cannot ask, the message is written, and observe
// mode allows. The model judge calls it again after raising the verdict.
func Settle(d *Decision, ev Event, cfg *config.Config) {
	d.Enforced = d.Verdict
	if d.Enforced == Ask && !ev.CanAsk {
		d.Enforced = Block
		d.Notes = append(d.Notes, "this agent cannot show an approval prompt here, so ask is enforced as block")
	}
	d.Message = ""
	if d.Enforced != Allow {
		d.Message = message(*d)
	}
	if cfg.Observe() && d.Enforced != Allow {
		d.Notes = append(d.Notes, "observe mode: would have returned "+string(d.Enforced)+"; allowed")
		d.Enforced = Allow
	}
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
	for k, v := range a.TargetEnv {
		env[k] = v
	}
	absEnvPaths(env, a.Dir)
	tf := a.Engine == "terraform" || a.Engine == "tofu" || a.Engine == "terragrunt"
	// The directory is known when the host reported it or the command
	// itself moved there (cd, pushd, -chdir); a.Dir then differs from the
	// event's cwd. A relative cd is resolved against the session root, which
	// is the host's best information.
	dirKnown := ev.DirKnown || (a.Dir != "" && a.Dir != ev.Cwd)
	var dirNotes []string
	if !dirKnown && tf && a.Dir != "" && a.Class == classify.ApplySavedPlan && a.PlanFile != "" && !filepath.IsAbs(a.PlanFile) {
		// A relative planfile that is not in the reported directory may sit
		// in the directory the command really runs in. One copy under the
		// root identifies that directory; several cannot be told apart.
		if _, err := os.Stat(filepath.Join(a.Dir, a.PlanFile)); errors.Is(err, os.ErrNotExist) {
			matches, truncated := findPlanfile(a.Dir, a.PlanFile)
			switch {
			case len(matches) == 1 && !truncated:
				dir := filepath.Dir(matches[0])
				if rel := filepath.Dir(a.PlanFile); rel != "." {
					dir = strings.TrimSuffix(matches[0], string(filepath.Separator)+a.PlanFile)
				}
				dirNotes = append(dirNotes, fmt.Sprintf("planfile %s is not in %s; found once under it at %s, whose directory is taken as the command directory", a.PlanFile, a.Dir, matches[0]))
				a.Dir, r.Dir, dirKnown = dir, dir, true
			case len(matches) > 1 || truncated:
				msg := fmt.Sprintf("the saved plan file %s is not in %s and %d copies exist under it; the command directory is not known, so the plan that would be applied cannot be identified", a.PlanFile, a.Dir, len(matches))
				if truncated {
					msg = fmt.Sprintf("the saved plan file %s is not in %s and the search under it was cut short (%d found before the limit); the command directory is not known, so the plan that would be applied cannot be identified", a.PlanFile, a.Dir, len(matches))
				}
				r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-ambiguous", Severity: preflight.Critical, Message: msg, Evidence: matches})
			}
		}
	}
	sig := config.Signals{Dir: a.Dir}
	var recorded, declared *preflight.Backend
	if tf && a.Dir != "" {
		r.Workspace = preflight.Workspace(a.Dir, env)
		sig.Workspace = r.Workspace
		if a.WorkspaceUnknown {
			sig.WorkspaceUnknown = "the workspace selected earlier in this command cannot be resolved"
		}
		recorded = preflight.InitBackendEnv(a.Dir, env)
		declared = preflight.DeclaredBackend(a.Dir)
		sig.ProviderProfiles, sig.ProviderRoles, sig.ProviderUnknown = preflight.ProviderAWS(a.Dir, preflight.Vars{Values: a.Vars, Files: a.VarFiles, Env: env, Unknown: a.VarsUnknown})
		addProviderTargets(&sig, a.Dir, env, deps.ReadFile)
		if why := preflight.ConfigUnreadable(a.Dir); why != "" && sig.ProviderUnknown == "" {
			sig.ProviderUnknown = why
		}
		if len(a.BackendConfig) > 0 {
			// An init in this command re-points the directory: judge this
			// command against the backend it will use, not the old one.
			sig.BackendConfig = strings.Join(a.BackendConfig, " ")
			target, err := preflight.BackendFromConfig(a.Dir, declared, recorded, a.BackendConfig, deps.ReadFile)
			if err == nil && a.BackendConfigWritten {
				err = errors.New("an earlier step of this command writes it")
			}
			// The init itself changes no state; an unknown target only matters
			// for commands that read or write state after it.
			if err != nil && a.Class != classify.ReadOnly {
				r.Findings = append(r.Findings, preflight.Finding{Rule: "backend-config-unreadable", Severity: preflight.High,
					Message: "the -backend-config given to init cannot be read, so the backend this command uses is unknown: " + err.Error()})
				sig.BackendUnknown = "the -backend-config given to init cannot be read (" + err.Error() + ")"
			}
			recorded = target
		}
		be := recorded
		if be == nil && len(a.BackendConfig) == 0 {
			// With -backend-config the declared block alone is not the
			// backend in use; if the config could not be read the backend
			// is unknown rather than the old declared one.
			be = declared
		}
		if be != nil && be.Unreadable != "" {
			sig.BackendUnknown = be.Unreadable
		}
		for _, f := range a.StateFiles {
			sig.StateDirs = append(sig.StateDirs, filepath.Dir(f))
		}
		if be != nil && be.Type == "local" && be.Config["path"] != "" {
			sig.StateDirs = append(sig.StateDirs, filepath.Dir(shell.PhysicalJoin(a.Dir, be.Config["path"])))
		}
		if be != nil && be.Type == "local" && be.Config["workspace_dir"] != "" {
			sig.StateDirs = append(sig.StateDirs, filepath.Dir(shell.PhysicalJoin(a.Dir, be.Config["workspace_dir"])))
		}
		// The implicit local state files are where they resolve to: a link
		// to another environment's state is that environment's.
		for _, n := range []string{"terraform.tfstate", "terraform.tfstate.d", "terraform.tfstate.backup"} {
			p := filepath.Join(a.Dir, n)
			if r, err := filepath.EvalSymlinks(p); err == nil && filepath.Clean(r) != filepath.Clean(p) {
				sig.StateDirs = append(sig.StateDirs, filepath.Dir(r))
			}
		}
		if a.StateUnknown {
			sig.BackendUnknown = "a -state path cannot be resolved statically"
		}
		if a.BackendConfigUnknown && a.Sub != "init" {
			sig.BackendUnknown = "an earlier init in this command has a -backend-config that cannot be resolved statically"
		}
		if a.Engine == "terragrunt" {
			terragruntSignals(&sig, a, be)
		}
		if be != nil {
			r.Backend = be.URL()
			sig.Backend = r.Backend
			sig.BackendValues = be.Config
			if p := be.Config["profile"]; p != "" && awsProfileEnv(env) == "" {
				sig.AWSProfile = p
			}
		}
	}
	if a.Profile != "" {
		sig.AWSProfile = a.Profile
	} else if p := awsProfileEnv(env); p != "" {
		sig.AWSProfile = p
	}
	r.Profile = sig.AWSProfile
	// A kubectl, helm, gcloud or az command targets the cluster, project or
	// subscription its command line names, else the one the CLI's own local
	// configuration selects.
	switch a.Engine {
	case "kubectl", "helm":
		if sig.KubeContext = a.Target; sig.KubeContext == "" && a.Engine == "helm" {
			sig.KubeContext = env["HELM_KUBECONTEXT"]
		}
		if sig.KubeContext == "" {
			sig.KubeContext = preflight.KubeContext(env, deps.ReadFile)
		}
	case "gcloud":
		if sig.GCPProject = a.Target; sig.GCPProject == "" {
			sig.GCPProject = preflight.GCPProject(env, deps.ReadFile)
		}
	case "az":
		if sig.AzureSubscription = a.Target; sig.AzureSubscription == "" {
			sig.AzureSubscription, sig.AzureSubscriptionID = preflight.AzureSubscription(env, deps.ReadFile)
		}
	}
	r.KubeContext, r.GCPProject, r.AzureSubscription = sig.KubeContext, sig.GCPProject, sig.AzureSubscription
	if deps.Account != nil && (tf || a.Engine == "aws") && a.Class != classify.ReadOnly {
		if acct, err := deps.Account(sig.AWSProfile); err == nil {
			sig.AWSAccount = acct
		} else {
			r.Findings = append(r.Findings, preflight.Finding{Rule: "live-identity", Severity: preflight.Info, Message: "STS identity check failed: " + err.Error()})
		}
	}
	if a.S3Object != "" && sig.Backend == "" {
		// aws s3 cp/mv/rm/sync and s3api writes name a bucket: one that holds
		// an environment's state (backends: in the config) is that
		// environment's, whatever directory the command runs in.
		sig.Backend = a.S3Object
	}
	var res config.Resolution
	switch {
	case a.Subtree && a.Dir != "" && a.UnitsUnknown:
		res = cfg.ResolveUnder(a.Dir, sig, "terragrunt stack run runs units generated from terragrunt.stack.hcl, which cannot be listed before it runs")
	case a.Subtree && a.Dir != "":
		res = subtreeResolve(cfg, a.Dir, sig, deps.Env)
	case a.AnyDir && rootOf(cfg, ev) != "":
		why := "the directory this command runs in could not be followed statically"
		if a.Dir != "" {
			why = "the analysis of this command stopped early, so what it did not see may run in any directory"
		}
		if a.AnyDirWhy != "" {
			why = a.AnyDirWhy
		}
		res = cfg.ResolveUnder(rootOf(cfg, ev), sig, why)
	case dirKnown || a.Dir == "" || a.Class == classify.ComplexShape:
		// Strict shapes is judged where the command is known to run: on a
		// host that does not report the directory, at the session
		// directory. The command's own actions keep the unknown-directory
		// rule.
		res = cfg.Resolve(sig)
	case cfg.UnknownDirMostProtected():
		res = cfg.ResolveUnknownDir(ev.Agent, a.Dir, sig)
	default:
		res = cfg.Resolve(sig)
		res.Matched = append([]string{fmt.Sprintf("command directory not reported by %s; judged at the session root %s (unknown_dir: session_root)", orHost(ev.Agent), a.Dir)}, res.Matched...)
	}
	r.Tier, r.Env, r.Matched = res.Tier, res.Env, res.Matched
	if deps.LoadConfig != nil && a.Dir != "" && !a.AnyDir && otherRepo(cfg, a.Dir) {
		// A cd or -chdir into another repository: its own config decides
		// too, and the stricter tier wins.
		if c2, err := deps.LoadConfig(a.Dir); err != nil {
			r.Tier, r.Env = config.Protected, "unknown"
			r.Matched = append(r.Matched, "the config of the repository "+a.Dir+" is in cannot be read ("+err.Error()+"); judged as protected")
		} else if alt := c2.Resolve(sig); alt.Tier.Rank() > r.Tier.Rank() {
			r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "by the config of the repository "+a.Dir+" is in")
		}
	}
	if v, set := a.Env["TF_DATA_DIR"]; tf && set && v == "" && r.Tier.Rank() < config.Protected.Rank() {
		// TF_DATA_DIR is exported with a value that cannot be resolved: the
		// workspace and backend it records are unknown.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "TF_DATA_DIR cannot be resolved statically, so the workspace and backend it selects are unknown; judged as protected")
	}
	if ev.Persistent && r.Tier.Rank() < config.Protected.Rank() {
		// A shell that keeps running between calls keeps its directory: a
		// cd typed in one call moves the next, which is judged on its own.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "typed into a shell that keeps running between calls, whose directory an earlier call may have changed; judged as protected")
	}
	if why := unknownSignal(a); why != "" && r.Tier.Rank() < config.Protected.Rank() {
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, why+"; judged as protected")
	}
	if a.ConfigWritten && tf && r.Tier.Rank() < config.Protected.Rank() {
		// The configuration, providers, lock file or state the hook read
		// are rewritten by an earlier step, so they cannot tell the target.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "an earlier step of this command writes the configuration or state in "+a.Dir+", so what this call uses is unknown; judged as protected")
	}
	if a.DataDirWritten && r.Tier.Rank() < config.Protected.Rank() {
		// The workspace and backend this directory records are rewritten by
		// an earlier step of the command, so they cannot tell the target.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "an earlier step of this command rewrites "+filepath.Join(a.Dir, ".terraform")+", so the workspace and backend it selects are unknown; judged as protected")
	}
	r.Matched = append(r.Matched, dirNotes...)
	if a.Dir == "" && tf {
		r.Matched = append(r.Matched, "working directory could not be resolved statically")
	}

	if tf && a.Dir != "" {
		if a.TouchesState && cfg.BackendCheck() {
			if f := preflight.BackendChanged(declared, recorded); f != nil && len(a.BackendConfig) == 0 {
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
				if deps.StatePull != nil && be.Remote() {
					if lf := lineageCheck(a, be, *f, deps); lf != nil {
						r.Findings = append(r.Findings, *lf)
					}
				}
			}
		}
		if deps.Lockfile != nil && cfg.LockfileCheck() && (a.Class == classify.ApplySavedPlan || a.Class == classify.UnreviewedApply || a.Class == classify.Destroy) {
			if f := deps.Lockfile(a.Dir); f != nil {
				r.Findings = append(r.Findings, *f)
			}
		}
	}

	class := a.Class
	if a.S3Object != "" && class != classify.StateSurgery {
		for _, m := range r.Matched {
			if m == "backend "+sig.Backend {
				class = classify.StateSurgery
				r.Matched = append(r.Matched, "aws changes "+a.S3Object+", an object in a bucket that holds an environment's Terraform state")
				break
			}
		}
	}
	if class == classify.ApplySavedPlan {
		class = planGate(&r, a, cfg, deps, recorded, declared)
	}
	r.Class = class
	v := Table[class][r.Tier]
	for _, f := range r.Findings {
		v = Max(v, FindingVerdict(f.Severity, r.Tier))
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

// ErrTimeout is returned by Run when the decision took too long.
var ErrTimeout = errors.New("decision timed out")

// ErrPanic is wrapped by the error Run returns when f panicked. A caller
// must treat it as a failure of the analysis, not as a configured error: a
// panic that is recovered never allows in a protected tier, whatever
// on_error says.
var ErrPanic = errors.New("internal error")

// PanicHook is called at named points of a decision; a test sets it to inject
// a panic and prove that the recovery fails closed. It is nil in the binary.
var PanicHook func(site string)

func panicPoint(site string) {
	if h := PanicHook; h != nil {
		h(site)
	}
}

// Run calls f with a time limit and converts a panic into an error, so the
// caller can apply the configured error behavior instead of crashing.
//
// f receives a context that is cancelled when the deadline fires (or when Run
// returns). f must thread it into any in-flight work it starts — the plan
// gate's `show -json` subprocess in particular — so that work is cancelled on
// deadline rather than left running after Run has already returned ErrTimeout.
func Run(timeout time.Duration, f func(context.Context) Decision) (d Decision, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		d   Decision
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: fmt.Errorf("%w: %v", ErrPanic, p)}
			}
		}()
		ch <- result{d: f(ctx)}
	}()
	select {
	case r := <-ch:
		return r.d, r.err
	case <-ctx.Done():
		return Decision{}, ErrTimeout
	}
}

func ctxOf(deps Deps) context.Context {
	if deps.Ctx != nil {
		return deps.Ctx
	}
	return context.Background()
}
