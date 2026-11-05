// Package policy combines command class, environment tier, preflight and
// plan-gate findings into one verdict. It is the applygate's decision function.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/safefile"
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

// GuardOptions returns the classifier options for cfg in env: the guard
// patterns, and the guard set that also knows where guard files live under
// the user's home and the repository root.
// MCPGuardPath returns a guard path that a call to an MCP tool outside the
// known-tool table names in its arguments, or "". Any string argument that
// resolves to a guard file, or to a directory that holds one, counts, unless
// the tool's name says it only reads (read_file, list_directory).
// readOnlyToolName reports whether an MCP tool's name says it only reads:
// every word of it (split at _, -, . and case changes) is a read verb or a
// noun, and at least one is a read verb. Any other word (replace, sync,
// apply, and words applygate does not know) may write, which is the
// default for a call that names a guard file.
func readOnlyToolName(tool string) bool {
	if i := strings.LastIndex(tool, "__"); i >= 0 {
		tool = tool[i+2:]
	}
	verb := false
	for _, w := range toolWords(tool) {
		switch {
		case readVerbs[w]:
			verb = true
		case !readNouns[w]:
			return false
		}
	}
	return verb
}

var (
	readVerbs = toSet("read", "get", "list", "search", "view", "stat", "info", "find", "show", "describe", "tree", "cat", "head", "tail", "grep", "glob", "inspect", "query", "fetch", "lookup", "ls", "exists", "count", "diff", "check", "validate", "preview")
	readNouns = toSet("file", "files", "dir", "dirs", "directory", "directories", "text", "content", "contents", "multiple", "many", "path", "paths", "metadata", "details", "status", "by", "name", "in", "of", "all", "recent", "project", "workspace", "symbols", "symbol", "definition", "references", "lines", "range", "tree", "entries", "info")
)

func toSet(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// toolWords splits a tool name into lower-case words at _, -, . and case
// changes: searchAndReplace and search_and_replace are the same words.
func toolWords(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || i+1 < len(rs) && unicode.IsLower(rs[i+1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

func MCPGuardPath(cfg *config.Config, env map[string]string, tool, cwd string, args json.RawMessage) string {
	name := strings.ToLower(tool)
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if readOnlyToolName(tool) {
		return ""
	}
	var v any
	if json.Unmarshal(args, &v) != nil {
		return ""
	}
	copt := GuardOptions(cfg, env)
	var found string
	n, overflow := 0, false
	var walk func(any, int)
	walk = func(x any, depth int) {
		if found != "" {
			return
		}
		if depth > 8 || n > 500 {
			overflow = true
			return
		}
		n++
		switch t := x.(type) {
		case string:
			if t == "" || !strings.ContainsAny(t, "/.~") {
				return
			}
			p := t
			if strings.HasPrefix(p, "~/") {
				p = filepath.Join(copt.Home, p[2:])
			} else if !filepath.IsAbs(p) {
				p = filepath.Join(cwd, p)
			}
			// Cleaned first: ./ and // pad a path past any length.
			if p = filepath.Clean(p); len(p) > 4096 {
				overflow = true
				return
			}
			if copt.Guard.Touches(p) {
				found = p
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
	if found == "" && overflow {
		// Arguments too large or deep to walk: the call names a guard file
		// when its text does, once padding is taken out.
		found = guardInText(copt, cwd, string(args))
	}
	return found
}

// guardInText returns the guard path a text names, by the guard set's
// needles, with ./ and // collapsed; "" when it names none.
func guardInText(copt classify.Options, cwd, text string) string {
	t := strings.ToLower(text)
	for {
		u := strings.ReplaceAll(strings.ReplaceAll(t, "/./", "/"), "//", "/")
		if u == t {
			break
		}
		t = u
	}
	for _, nd := range copt.Guard.Needles(copt.Home) {
		if !strings.Contains(t, nd) {
			continue
		}
		var cands []string
		switch {
		case strings.HasPrefix(nd, "/"):
			cands = []string{nd}
		case strings.HasPrefix(nd, "~/"), strings.HasPrefix(nd, "$home/"), strings.HasPrefix(nd, "${home}/"):
			_, rel, _ := strings.Cut(nd, "/")
			cands = []string{filepath.Join(copt.Home, rel)}
		default:
			cands = []string{filepath.Join(copt.Home, nd), filepath.Join(cwd, nd)}
		}
		for _, c := range cands {
			if copt.Guard.Touches(c) {
				return c
			}
		}
		return cands[0]
	}
	return ""
}

func GuardOptions(cfg *config.Config, env map[string]string) classify.Options {
	home := env["HOME"]
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	paths := cfg.GuardPaths()
	g := guard.New(paths, cfg.GuardTargets(home)).Programs(config.PathDirs(home), config.PathPrograms())
	return classify.Options{ProtectedPaths: paths, Guard: g, Home: home}
}

// ShellOptions returns the analyzer options for a command run in dir.
func ShellOptions(cfg *config.Config, copt classify.Options, dir string, env map[string]string, read func(string) ([]byte, error)) shell.Options {
	return shell.Options{Dir: dir, Env: env, Aliases: cfg.Aliases, Wrappers: cfg.ShellWrappers(), ReadFile: read, IsDir: isDir,
		ProtectedPaths: copt.ProtectedPaths, ProtectedPath: copt.Guard.Protected, GuardNeedles: copt.Guard.Needles(copt.Home)}
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Decide evaluates an event. It does not write the log.
func Decide(ev Event, cfg *config.Config, deps Deps) Decision {
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

// lineageCheck runs the opt-in state pull and compares the local state files
// named in the stale-state finding with the remote state.
func lineageCheck(a classify.Action, be *preflight.Backend, stale preflight.Finding, deps Deps) *preflight.Finding {
	var states []string
	for _, e := range stale.Evidence {
		if strings.HasSuffix(e, ".tfstate") || strings.HasSuffix(e, ".tfstate.backup") {
			states = append(states, e)
		}
	}
	if len(states) == 0 {
		return nil
	}
	remote, err := deps.StatePull(a.Engine, a.Dir)
	if err != nil {
		return &preflight.Finding{Rule: "state-lineage", Severity: preflight.Info, Message: "live state check failed: " + err.Error()}
	}
	return preflight.LineageMismatch(a.Dir, states, remote)
}

// terraformDir reports whether dir holds Terraform configuration or working
// data.
func terraformDir(dir string) bool {
	for _, pat := range []string{"*.tf", "*.tf.json", ".terraform", "terragrunt.hcl"} {
		if m, _ := filepath.Glob(filepath.Join(dir, pat)); len(m) > 0 {
			return true
		}
	}
	return false
}

// otherRepo reports whether dir is under a repository config the session's
// config did not read.
func otherRepo(cfg *config.Config, dir string) bool {
	if dir == cfg.LoadedFor {
		// Load looked up this directory's configs: none is unread.
		return false
	}
	read := map[string]bool{}
	for _, p := range append(append([]string(nil), cfg.Sources...), cfg.Untrusted...) {
		read[p] = true
	}
	for _, p := range config.RepoConfigs(dir) {
		if !read[p] {
			return true
		}
	}
	return false
}

// SavedPlanVerdict is the verdict applying a saved plan with this plan-gate
// result gets in tier t, as planGate and the decision table judge it: a
// replace counts as a destroy.
func SavedPlanVerdict(res *plangate.Result, t config.Tier) Verdict {
	class := classify.ApplySavedPlan
	if len(res.Deletes)+len(res.Replaces) > 0 {
		class = classify.Destroy
	}
	v := Table[class][t]
	for _, f := range res.Findings {
		v = Max(v, FindingVerdict(f.Severity, t))
	}
	return v
}

// DirSignals are the tier signals of a Terraform directory as the hook reads
// them: the path, the selected workspace, and the recorded backend, else the
// declared one.
func DirSignals(dir string, env map[string]string) (config.Signals, *preflight.Backend) {
	sig := config.Signals{Dir: dir, Workspace: preflight.Workspace(dir, env)}
	sig.ProviderProfiles, sig.ProviderRoles, sig.ProviderUnknown = preflight.ProviderAWS(dir, preflight.Vars{Env: env})
	addProviderTargets(&sig, dir, env, nil)
	if why := preflight.ConfigUnreadable(dir); why != "" && sig.ProviderUnknown == "" {
		sig.ProviderUnknown = why
	}
	be := preflight.InitBackendEnv(dir, env)
	if be == nil {
		be = preflight.DeclaredBackend(dir)
	}
	if be != nil {
		if be.Unreadable != "" {
			sig.BackendUnknown = be.Unreadable
		}
		sig.Backend, sig.BackendValues = be.URL(), be.Config
		if p := be.Config["profile"]; p != "" && awsProfileEnv(env) == "" {
			sig.AWSProfile = p
		}
	}
	if p := awsProfileEnv(env); p != "" {
		sig.AWSProfile = p
	}
	// Where the state is: a local backend's path or workspace_dir, and local
	// state files that are links into another directory.
	if be != nil && be.Type == "local" {
		for _, k := range []string{"path", "workspace_dir"} {
			if be.Config[k] != "" {
				sig.StateDirs = append(sig.StateDirs, filepath.Dir(shell.PhysicalJoin(dir, be.Config[k])))
			}
		}
	}
	for _, n := range []string{"terraform.tfstate", "terraform.tfstate.d", "terraform.tfstate.backup"} {
		p := filepath.Join(dir, n)
		if r, err := filepath.EvalSymlinks(p); err == nil && filepath.Clean(r) != filepath.Clean(p) {
			sig.StateDirs = append(sig.StateDirs, filepath.Dir(r))
		}
	}
	for _, n := range []string{"terragrunt.hcl", "terragrunt.hcl.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			// A Terragrunt unit: its remote_state and local source are
			// signals too (terragrunt run --all, plan-check in a unit).
			terragruntSignals(&sig, classify.Action{Dir: dir, Engine: "terragrunt"}, be)
			break
		}
	}
	return sig, be
}

// terragruntSignals adds what the unit's terragrunt.hcl and --source say:
// remote_state values as name hints, and a local source's directory.
func terragruntSignals(sig *config.Signals, a classify.Action, be *preflight.Backend) {
	tg := preflight.ReadTerragrunt(a.Dir)
	source := a.Source
	if tg != nil {
		vals := map[string]string{}
		if be != nil {
			maps.Copy(vals, be.Config)
		}
		for k, v := range tg.Backend {
			if vals[k] == "" {
				vals[k] = v
			}
		}
		sig.BackendValues = vals
		if tg.Unknown != "" && sig.BackendUnknown == "" {
			sig.BackendUnknown = tg.Unknown
		}
		if source == "" {
			source = tg.Source
		}
	}
	if a.SourceUnknown {
		sig.BackendUnknown = "the terragrunt --source cannot be resolved statically"
	}
	// A local path: not a URL, a go-getter forced source (git::, s3::) or a
	// registry address (tfr:).
	if source != "" && !strings.Contains(source, "://") && !strings.Contains(source, "::") && !strings.HasPrefix(source, "tfr:") && !strings.HasPrefix(source, "git@") {
		p, _, _ := strings.Cut(source, "?")
		p = strings.Replace(p, "//", "/", 1)
		sig.SourceDirs = append(sig.SourceDirs, shell.PhysicalJoin(a.Dir, p))
	}
}

// awsProfileEnv is the profile the AWS CLI and SDKs pick from the
// environment: AWS_PROFILE, else AWS_DEFAULT_PROFILE.
func awsProfileEnv(env map[string]string) string {
	if p := env["AWS_PROFILE"]; p != "" {
		return p
	}
	return env["AWS_DEFAULT_PROFILE"]
}

// planGate runs the saved-plan checks and returns the effective class
// (Destroy when the plan deletes resources).
func planGate(r *ActionResult, a classify.Action, cfg *config.Config, deps Deps, recorded, declared *preflight.Backend) classify.Class {
	if a.PlanWritten {
		// The plan on disk now is not the one that will be applied: an
		// earlier step of this command writes it (plan -out, cp, a download).
		// It was made where its plan -out ran; written by anything else, it
		// could have been made anywhere.
		if a.PlanOrigin == "" {
			r.Tier, r.Env = config.Protected, "unknown"
			r.Matched = append(r.Matched, "an earlier step writes the saved plan "+a.PlanFile+" by a means other than plan -out, so where it was made is not known; judged as protected")
		} else if filepath.Clean(a.PlanOrigin) != filepath.Clean(a.Dir) {
			sig, _ := DirSignals(a.PlanOrigin, deps.Env)
			if alt := cfg.Resolve(sig); alt.Tier.Rank() > r.Tier.Rank() {
				r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is made in "+a.PlanOrigin)
			}
		}
		for _, d := range a.PlanStateDirs {
			// plan -state=FILE -out=p: p changes the resources in FILE.
			if alt := cfg.Resolve(config.Signals{Dir: d, StateDirs: []string{d}}); alt.Unknown || alt.Tier.Rank() > r.Tier.Rank() {
				t, e := alt.Tier, alt.Env
				if alt.Unknown && t.Rank() < r.Tier.Rank() {
					t, e = r.Tier, r.Env
				}
				r.Tier, r.Env, r.Matched = t, e, append(r.Matched, "the saved plan is made from the state in "+d)
			}
		}
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unverifiable", Severity: preflight.Critical,
			Message: "an earlier step of this command writes the saved plan " + a.PlanFile + ", so the plan that would be applied cannot be checked; run the steps separately"})
		return classify.ApplySavedPlan
	}
	planPath := a.PlanFile
	if !filepath.IsAbs(planPath) && a.Dir != "" {
		// Physically, as Terraform opens it: m/../tfplan through a link m
		// is in the directory the link's parent is.
		planPath = shell.PhysicalJoin(a.Dir, planPath)
	}
	if streamPath(planPath) {
		// A plan read from stdin or a descriptor (apply /dev/stdin <
		// ../prod/tfplan) has no directory.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "the saved plan "+a.PlanFile+" is read from a stream, so where it was made is not known; judged as protected")
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
	// A plan saved in another directory was made against that directory's
	// state: its tier joins the command's. A plan reached through a
	// symlink is in the directory the link leads to.
	// Only a Terraform working directory says where a plan was made: a plan
	// file kept in /tmp says nothing.
	planDirs := []string{filepath.Dir(planPath)}
	if real, err := filepath.EvalSymlinks(planPath); err == nil {
		planDirs = append(planDirs, filepath.Dir(real))
	}
	for _, pd := range planDirs {
		if a.Dir == "" || !filepath.IsAbs(pd) || filepath.Clean(pd) == filepath.Clean(a.Dir) {
			continue
		}
		if terraformDir(pd) {
			sig, _ := DirSignals(pd, deps.Env)
			if alt := cfg.Resolve(sig); alt.Tier.Rank() > r.Tier.Rank() {
				r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is in "+pd)
			}
			continue
		}
		// Elsewhere only a configured environment's path counts (a plan in
		// envs/prod/out is prod's); an unmatched place such as /tmp says
		// nothing.
		if alt := cfg.Resolve(config.Signals{Dir: pd}); !alt.Unknown && alt.Tier.Rank() > r.Tier.Rank() {
			r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is in "+pd)
		}
	}
	if fi, err := os.Stat(planPath); err == nil && hardLinked(fi) && r.Tier.Rank() < config.Protected.Rank() {
		// A hard link is the same file under another name, in a directory
		// that cannot be found from here.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "the saved plan "+a.PlanFile+" is a hard link, so the directory it was made in is not known; judged as protected")
	}
	for _, f := range r.Findings {
		if f.Rule == "plan-ambiguous" {
			// Several candidate planfiles: nothing to show, and reading one
			// of them would check the wrong plan.
			return classify.ApplySavedPlan
		}
	}
	if deps.PlanJSON == nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: "reading saved plans is disabled (plan_gate.run_show: false), so the plan cannot be checked"})
		return classify.ApplySavedPlan
	}
	js, err := deps.PlanJSON(a.Engine, a.Dir, a.PlanFile)
	if err != nil {
		// F10: distinguish a plan file that simply does not exist from one that
		// exists but cannot be read. A missing file means there is nothing to
		// apply, so it is High (protected tier asks) rather than Critical
		// (block). An existing-but-unreadable plan stays Critical: applygate
		// cannot verify a real plan, so it must fail closed.
		if _, serr := os.Stat(planPath); errors.Is(serr, os.ErrNotExist) {
			r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-missing", Severity: preflight.High,
				Message: "the saved plan file " + a.PlanFile + " does not exist, so there is nothing to apply; check the path"})
			return classify.ApplySavedPlan
		}
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical,
			Message: "could not read the saved plan with show -json: " + err.Error()})
		return classify.ApplySavedPlan
	}
	be := recorded
	if be == nil {
		be = declared
	}
	gres, err := plangate.Evaluate(plangate.Input{PlanJSON: js, MaxDestroy: cfg.MaxDestroy(r.Tier), Scope: cfg.PlanGate.Scope, Protected: cfg.ProtectedResources, Backend: be}, deps.Rules)
	if err != nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: err.Error()})
		return classify.ApplySavedPlan
	}
	if r.PlanSHA256 == "" {
		sum := sha256.Sum256(js)
		r.PlanSHA256 = "json:" + hex.EncodeToString(sum[:])
	}
	r.Findings = append(r.Findings, gres.Findings...)
	// Replacing a resource destroys it first (or after its successor is
	// created): it is judged like deleting it.
	if gone := append(append([]string(nil), gres.Deletes...), gres.Replaces...); len(gone) > 0 {
		verb := "destroys"
		switch {
		case len(gres.Deletes) == 0:
			verb = "replaces"
		case len(gres.Replaces) > 0:
			verb = "destroys or replaces"
		}
		r.Why = fmt.Sprintf("applies saved plan %s, which %s %d resource(s): %s", a.PlanFile, verb, len(gone), strings.Join(first(gone, 5), ", "))
		return classify.Destroy
	}
	r.Why = fmt.Sprintf("applies saved plan %s (%d change(s))", a.PlanFile, gres.Changes)
	return classify.ApplySavedPlan
}

func orHost(agent string) string {
	if agent == "" {
		return "the host"
	}
	return agent
}

// Limits of the planfile search under the session root.
const (
	planSearchMaxDepth   = 8
	planSearchMaxEntries = 20000
	planSearchMaxMatches = 5
)

// findPlanfile looks for rel (a relative planfile path) in every directory
// under root, bounded by depth and by the number of directory entries
// visited; .git and .terraform are skipped and symbolic links are not
// followed. truncated is true when a limit stopped the walk before it
// finished, so the matches may be incomplete.
func findPlanfile(root, rel string) (matches []string, truncated bool) {
	entries := 0
	stop := errors.New("stop")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if d.Type()&os.ModeSymlink != 0 {
				// A link to a directory leads somewhere the search does not
				// go: a copy of the plan there would be missed.
				if fi, err := os.Stat(p); err != nil || fi.IsDir() {
					truncated = true
				}
			}
			return nil
		}
		if p != root {
			switch d.Name() {
			case ".git", ".terraform":
				return filepath.SkipDir
			}
			if r, err := filepath.Rel(root, p); err == nil && strings.Count(r, string(filepath.Separator)) >= planSearchMaxDepth {
				// Deeper directories are not searched, so a copy there would
				// be missed.
				truncated = true
				return filepath.SkipDir
			}
		}
		entries++
		if entries > planSearchMaxEntries {
			truncated = true
			return stop
		}
		if p == root {
			return nil
		}
		if fi, err := os.Stat(filepath.Join(p, rel)); err == nil && fi.Mode().IsRegular() {
			matches = append(matches, filepath.Join(p, rel))
			if len(matches) >= planSearchMaxMatches {
				truncated = true
				return stop
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		truncated = true
	}
	return matches, truncated
}

// rootOf is the directory a command whose directory is not known is
// assumed to run under: the repository config's directory, else the
// event's.
func rootOf(cfg *config.Config, ev Event) string {
	if cfg.Root != "" {
		return cfg.Root
	}
	return ev.Cwd
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
		return "The agent may not change its own guardrails, hook configuration or applygate's config and log. Ask the user to make this change themselves."
	case classify.Dynamic:
		return "Write the command out literally, without eval, variables for subcommands, encoded text, or piping generated or fetched text into a shell, so it can be checked."
	case classify.UnknownWrapper:
		return "Run the underlying commands directly so they can be checked, or ask the user to run this wrapper."
	case classify.ComplexShape:
		return "In a protected environment only plain commands run without asking: a list or pipeline of known programs, without functions, loops, substitutions or other shells. Split the command into plain steps, or ask the user."
	case classify.CredentialAccess:
		return "Do not read credentials. Use the configured profile through the CLI instead, and ask the user if access is really needed."
	case classify.Mutating, classify.CloudWrite:
		return "This changes a protected environment. Confirm with the user first."
	}
	return ""
}

func message(d Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "applygate: %s.", strings.ToUpper(string(d.Enforced)))
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
	// An enforced "ask" is shown to a human as a permission prompt, so the
	// closing guidance is human-facing. A block is read by the agent (including
	// when an ask was converted to a block because the agent cannot prompt), so
	// it keeps the agent-facing "Next step" instructions. The verdict itself is
	// unchanged either way; only the wording differs by audience.
	if d.Enforced == Ask {
		b.WriteString("\nThis needs your approval. Approve only if you asked for this and the effect above is what you intend; otherwise deny.")
	} else {
		for _, a := range rs {
			if a.NextStep != "" && !steps[a.NextStep] {
				steps[a.NextStep] = true
				fmt.Fprintf(&b, "\nNext step: %s", a.NextStep)
			}
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
				ch <- result{err: fmt.Errorf("internal error: %v", p)}
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

func isTerraform(engine string) bool {
	return engine == "terraform" || engine == "tofu" || engine == "terragrunt"
}

// shapeActions are the strict-shapes actions of a shell command that is not
// plain: one per directory its programs are known to run in, each judged at
// that directory's tier: ask in protected, allow elsewhere. A part the
// analysis lost is judged by the command's own actions.
func shapeActions(ev Event, res *shell.Result, deps Deps, acts []classify.Action) []classify.Action {
	ok, why, unseen := shell.PlainShapeUnseen(ev.Command, res)
	if ok {
		// The provider, lock-file and data-source checks read the disk
		// before the command runs; a step that rewrites what they read
		// comes first.
		for _, a := range acts {
			if isTerraform(a.Engine) && (a.InstalledEarlier || a.InitEarlier && !preflight.InitSafe(ctxOf(deps), a.Dir)) && startsProviders(a.Sub, nil) {
				why = "an earlier step installs providers or modules in " + a.Dir + " that " + a.Engine + " then runs, from somewhere the committed lock file does not vouch for"
				ok, unseen = false, why
				break
			}
			if isTerraform(a.Engine) && (a.ConfigWritten || a.DataDirWritten) && startsProviders(a.Sub, nil) {
				why = "an earlier step writes the configuration or .terraform in " + a.Dir + " that " + a.Engine + " then reads"
				ok, unseen = false, why
				break
			}
			if isTerraform(a.Engine) && ev.Persistent && startsProviders(a.Sub, nil) {
				// The provider check needs the directory, which a shell that
				// keeps running between calls may have left.
				why = a.Engine + " typed into a shell that keeps running between calls, whose directory the hook cannot follow"
				ok, unseen = false, why
				break
			}
		}
	}
	if ok {
		ctx := deps.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if why = engineState(ctx, res, deps.Env); why == "" {
			return nil
		}
		unseen = why
	}
	dirs := map[string]bool{ev.Cwd: true}
	for _, inv := range res.Invocations {
		if inv.Dir != "" {
			dirs[inv.Dir] = true
		}
	}
	var out []classify.Action
	for d := range dirs {
		out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, Dir: d,
			Why: "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	// A command that can run code the analysis does not see (a program with
	// no shape, python3, perl -e, awk, a name or part it could not resolve)
	// can reach any directory, a cd or -chdir to a protected sibling
	// included: it is judged at the most protected tier under the root too.
	if unseen != "" {
		out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, AnyDir: true,
			AnyDirWhy: "the command is not plain and can run code the analysis does not follow (" + unseen + "), which can reach any directory under the root",
			Why:       "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
	}
	// A command run over every unit under a directory (terragrunt
	// --all) runs what each unit's configuration names: the shape is
	// judged at the most protected unit's tier too.
	for _, a := range acts {
		if a.Subtree && a.Dir != "" {
			out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, Dir: a.Dir,
				Subtree: true, UnitsUnknown: a.UnitsUnknown,
				Why: "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
		}
	}
	return out
}

// subtreeResolve is the tier of a command that runs in every Terragrunt unit
// under dir: the most protected of dir and each unit's own signals. When
// the units cannot all be listed (too many, unreadable), it is the most
// protected tier anything under dir could have.
func subtreeResolve(cfg *config.Config, dir string, sig config.Signals, env map[string]string) config.Resolution {
	best := cfg.Resolve(sig)
	n, complete := 0, true
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			complete = false
			return filepath.SkipDir
		}
		if d.IsDir() {
			if n++; n > 2000 {
				complete = false
				return filepath.SkipAll
			}
			if name := d.Name(); p != dir && (name == ".git" || name == ".terraform" || name == ".terragrunt-cache") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// A linked unit or directory could lead anywhere.
			complete = false
			return nil
		}
		if d.Name() != "terragrunt.hcl" && d.Name() != "terragrunt.hcl.json" {
			return nil
		}
		usig, _ := DirSignals(filepath.Dir(p), env)
		if r := cfg.Resolve(usig); r.Tier.Rank() > best.Tier.Rank() {
			best = config.Resolution{Tier: r.Tier, Env: r.Env, Matched: append([]string{"terragrunt runs the unit in " + filepath.Dir(p)}, r.Matched...)}
		}
		return nil
	})
	if !complete {
		return cfg.ResolveUnder(dir, sig, "terragrunt runs every unit under "+dir+", and they could not all be listed")
	}
	return best
}

// unknownSignal says why the target of a cloud or Terraform action cannot
// be told ("" when it can).
func unknownSignal(a classify.Action) string {
	if a.Engine == "" {
		return ""
	}
	if why := credFileRuns(a); why != "" {
		return why
	}
	if a.TargetUnknown != "" {
		return a.TargetUnknown
	}
	for _, k := range shell.TierEnv {
		if v, set := a.Env[k]; set && v == "" {
			return k + " is set to a value that cannot be resolved statically, so what it selects is unknown"
		}
	}
	for k, v := range a.Env {
		if strings.HasPrefix(k, "TF_CLI_ARGS_") && v == "" && a.Engine != "" {
			return k + " is set to a value that cannot be resolved statically"
		}
	}
	return ""
}

// absEnvPaths makes the relative config paths in env absolute against the
// command's directory, where the program resolves them.
func absEnvPaths(env map[string]string, dir string) {
	if dir == "" {
		return
	}
	for _, k := range []string{"KUBECONFIG", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		v := env[k]
		if v == "" {
			continue
		}
		parts := filepath.SplitList(v)
		for i, p := range parts {
			if p != "" && !filepath.IsAbs(p) && !strings.HasPrefix(p, "~") {
				parts[i] = shell.PhysicalJoin(dir, p)
			}
		}
		env[k] = strings.Join(parts, string(filepath.ListSeparator))
	}
}

// streamPath reports a planfile path that is not a regular file on disk: a
// device, a pipe or a descriptor, by any spelling (//dev/stdin, /./dev/fd/3)
// or through a link.
func streamPath(p string) bool {
	c := filepath.ToSlash(filepath.Clean(p))
	if r, err := filepath.EvalSymlinks(p); err == nil {
		c = filepath.ToSlash(r)
	}
	if strings.HasPrefix(c, "/dev/") || strings.HasPrefix(c, "/proc/") {
		return true
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.Mode().IsRegular()
}

// addProviderTargets adds what the google, kubernetes and azurerm provider
// blocks in dir name to sig.
func addProviderTargets(sig *config.Signals, dir string, env map[string]string, read func(string) ([]byte, error)) {
	t := preflight.ProviderTargets(dir)
	if read == nil {
		read = os.ReadFile
	}
	// What the providers read from the environment when the block names
	// nothing: the project, the subscription, the kube context.
	if sig.GCPProject == "" {
		for _, k := range []string{"GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT"} {
			if v := env[k]; v != "" {
				t.GCPProjects = append(t.GCPProjects, v)
			}
		}
	}
	for _, k := range []string{"ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"} {
		if v := env[k]; v != "" {
			t.AzureSubscriptions = append(t.AzureSubscriptions, v)
		}
	}
	if v := env["KUBE_CTX"]; v != "" {
		t.KubeContexts = append(t.KubeContexts, v)
	}
	// config_path names a kubeconfig, whose current context is the one the
	// provider uses when it names none; KUBE_CONFIG_PATH(S) does the same
	// from the environment.
	kc := append([]string(nil), t.KubeConfigs...)
	for _, k := range []string{"KUBE_CONFIG_PATH", "KUBE_CONFIG_PATHS"} {
		if v := env[k]; v != "" {
			kc = append(kc, filepath.SplitList(v)...)
			t.UsesKube = true
		}
	}
	for _, p := range kc {
		if !filepath.IsAbs(p) {
			p = shell.PhysicalJoin(dir, p)
		}
		if c := preflight.KubeContext(map[string]string{"KUBECONFIG": p}, read); c != "" {
			t.KubeContexts = append(t.KubeContexts, c)
		} else if t.Unknown == "" {
			t.Unknown = "the kubeconfig " + p + " names no current context applygate can read"
		}
	}
	if t.UsesKube && len(t.KubeContexts) == 0 && env["KUBE_CTX"] == "" {
		if c := preflight.KubeContext(env, read); c != "" {
			t.KubeContexts = append(t.KubeContexts, c)
		}
	}
	sig.ProviderProjects, sig.ProviderContexts, sig.ProviderSubscriptions = t.GCPProjects, t.KubeContexts, t.AzureSubscriptions
	if t.Unknown != "" && sig.ProviderUnknown == "" {
		sig.ProviderUnknown = t.Unknown
	}
}

var (
	credProcessRe = regexp.MustCompile(`(?mi)^\s*(credential_process|credentials_process)\s*=|^\s*exec\s*:|^\s*auth-provider\s*:|^\s*command\s*:`)
)

// credFileRuns reports a credentials or kube config file the command points
// the CLI at, other than the user's own (a guard file), that names a
// program to run: credential_process in an AWS config, exec or
// auth-provider in a kubeconfig. An unreadable file is not a finding: it
// runs nothing.
func credFileRuns(a classify.Action) string {
	for _, k := range classify.CredFileEnv() {
		v := a.Env[k]
		if tv := a.TargetEnv[k]; tv != "" {
			v = tv
		}
		if v == "" {
			continue
		}
		for _, p := range filepath.SplitList(v) {
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) && a.Dir != "" {
				p = shell.PhysicalJoin(a.Dir, p)
			}
			if p == os.DevNull || p == "/dev/null" {
				// The null device is empty by definition: pointing a CLI at it
				// (as sandboxes do) names no program, and no content can
				// arrive through it.
				continue
			}
			b, err := safefile.ReadFileMax(p, 1<<20)
			if err != nil {
				if !os.IsNotExist(err) {
					return k + " names " + p + ", which cannot be read, so what it runs is unknown"
				}
				continue
			}
			if credProcessRe.Match(b) {
				return k + " names " + p + ", which names a program to run (credential_process, exec)"
			}
		}
	}
	return ""
}

func ctxOf(deps Deps) context.Context {
	if deps.Ctx != nil {
		return deps.Ctx
	}
	return context.Background()
}
