// Package classify maps analyzed invocations and tool calls to command classes.
package classify

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/shell"
)

// Class is a command class from the v1 verdict table.
type Class string

const (
	ReadOnly        Class = "read-only"
	Mutating        Class = "mutating"    // import, refresh, test: changes state, not in the spec table
	CloudWrite      Class = "cloud-write" // cloud create/update calls: not in the spec table
	ApplySavedPlan  Class = "apply-saved-plan"
	UnreviewedApply Class = "unreviewed-apply"
	Destroy         Class = "destroy"
	// RoutineReplace is a saved plan whose only deletes and replaces are
	// replaces the plan gate found routine (plangate.Result.RoutineReplaces):
	// allowed outside a protected tier, where every replace needs a person.
	RoutineReplace   Class = "routine-replace"
	StateSurgery     Class = "state-surgery"
	CloudDestructive Class = "cloud-destructive"
	CredentialAccess Class = "credential-access" // not in the spec table
	UnknownWrapper   Class = "unknown-wrapper"
	// ComplexShape is a shell command in a protected tier that is not a
	// plain list or pipeline of known programs (strict shapes).
	ComplexShape Class = "complex-shape"
	Dynamic      Class = "dynamic"
	Tampering    Class = "guard-tampering"
	// HookRewrite is a git command that rewrites the work tree of a
	// repository or session directory where hook settings or the repository
	// config may be: it asks in every tier (guard.Set.Soft).
	HookRewrite Class = "hook-rewrite"
)

// Action is one classified, policy-relevant operation.
type Action struct {
	Class   Class
	Engine  string // terraform, tofu, terragrunt, aws, kubectl, agent, file, ""
	Command string // the resolved command, for messages
	Why     string
	Dir     string
	// S3Object is the s3://bucket/key an aws s3 or s3api call writes, moves
	// or deletes. A bucket that holds a protected environment's state
	// (backends: in the config) makes the call state surgery.
	S3Object string
	// ApproxDir is set when Dir is only the session directory (the host
	// does not report the command's own), so a relative -chdir is unknown.
	ApproxDir bool
	Env       map[string]string
	Profile   string // AWS profile from --profile or the environment
	// Target is the cluster or cloud named on the command line: the kube
	// context of kubectl (--context) and helm (--kube-context), the gcloud
	// project (--project), the az subscription (--subscription).
	Target string
	// TargetEnv holds what the command line says about the CLI's own
	// configuration (kubectl --kubeconfig, gcloud --configuration), as the
	// environment variable that would say the same, for resolving the
	// target when no --context or --project is given.
	TargetEnv map[string]string
	PlanFile  string // for apply of a saved plan
	Sub       string // engine subcommand, e.g. "destroy", "state rm"
	Via       []string
	// BackendConfig holds the -backend-config values of an init (files or
	// key=value pairs). Later commands in the same directory and command
	// line run against the backend they describe, not the one recorded by
	// the previous init.
	BackendConfig []string
	// SelectWorkspace is set by "workspace select|new NAME" (UnknownWorkspace
	// when NAME cannot be resolved); later commands
	// in the same directory run in that workspace.
	SelectWorkspace string
	// WorkspaceUnknown is set on a command after a workspace select whose
	// name cannot be resolved.
	WorkspaceUnknown bool `json:"-"`
	// TouchesState marks commands that read or write Terraform state, so
	// stale-state and backend checks apply.
	TouchesState bool
	// PlanWritten is set when an earlier step of the same command wrote the
	// saved plan this action applies: what is on disk when the hook runs is
	// not what will be applied.
	PlanWritten bool
	// PlanOrigin is, for a plan an earlier step wrote, the directory of the
	// terraform or tofu plan -out that wrote it; "" when another program
	// wrote it (cp, ln, a download) or it cannot be told.
	PlanOrigin string
	// DataDirWritten is set when an earlier step rewrote this directory's
	// .terraform (workspace, backend): the workspace and backend recorded
	// there now are not the ones the command will use.
	DataDirWritten bool
	// PlanStateDirs are the directories of the -state files the plan -out
	// that wrote PlanFile read.
	PlanStateDirs []string `json:"-"`
	// InstalledEarlier is set when an earlier step of the same command ran
	// init or get with an option that installs from somewhere the lock file
	// does not vouch for (-upgrade, -plugin-dir, -from-module, get -update,
	// providers lock or mirror); InitEarlier when it ran a plain init or get,
	// which installs what the lock file lists.
	InstalledEarlier, InitEarlier bool `json:"-"`
	// ConfigWritten is set when an earlier step of the same command writes
	// the configuration, .terraform, lock file, state or a tree under this
	// directory: what the hook read on disk is not what the call will use.
	ConfigWritten bool `json:"-"`
	// BackendConfigWritten is set when an earlier step of the same command
	// wrote one of the -backend-config files: what the init reads is then
	// not what is there now.
	BackendConfigWritten bool
	// Vars and VarFiles are the -var NAME=value pairs and the -var-file
	// files (absolute) the command gives; VarsUnknown says why one cannot
	// be resolved.
	Vars        map[string]string
	VarFiles    []string
	VarsUnknown string
	// StateFiles are the local state files -state, -state-out and -backup
	// name (absolute); StateUnknown is set when one cannot be resolved.
	StateFiles   []string
	StateUnknown bool
	// TargetUnknown says why the state, plan or directory a changing call
	// acts on cannot be told: arguments that cannot be resolved may name
	// another one (-state, -chdir, a planfile, TF_CLI_ARGS). The target is
	// then judged as protected.
	TargetUnknown string `json:"-"`
	// BackendConfigUnknown is set on an init whose -backend-config cannot
	// be resolved, and on the later calls in its directory, whose backend
	// is then unknown.
	BackendConfigUnknown bool `json:"-"`
	// Source is the terragrunt --source (or TG_SOURCE) as given;
	// SourceUnknown is set when it cannot be resolved.
	Source        string
	SourceUnknown bool
	// ConfigDir is the directory of the terragrunt.hcl that --config names,
	// when it is not Dir; the call is judged in both.
	ConfigDir string
	// AnyDir is set when the action may run in a directory the analysis
	// could not follow (cd to a computed path, a symlink made earlier in
	// the command, an analysis that stopped): it is judged at the most
	// protected tier under the repository root.
	AnyDir bool
	// AnyDirWhy says why, when the reason is not one of the analysis
	// losing the directory.
	AnyDirWhy string
	// Unnamed is set on a strict-shapes action whose command names no
	// infrastructure tool and no guard file; Named holds the names when it
	// does. In a repository with no config only a command that names one
	// is asked about (config.ShapesByWord).
	Unnamed bool     `json:"-"`
	Named   []string `json:"-"`
	// Subtree is set when the command runs in every unit under Dir
	// (terragrunt run --all, run-all, destroy-all): it is judged at the most
	// protected tier under Dir.
	Subtree bool
	// UnitsUnknown is set when those units cannot be listed before the
	// command runs (terragrunt stack run generates them).
	UnitsUnknown bool `json:"-"`
}

// Options configure classification.
type Options struct {
	// ProtectedPaths are glob patterns for guard files (hook config, applygate
	// config and log). Matching is on the cleaned absolute path.
	ProtectedPaths []string
	// Guard, when set, decides guard files instead of ProtectedPaths: it
	// resolves symlinks and case, and knows the concrete places guard files
	// live, so a directory that holds one counts too.
	Guard *guard.Set
	Home  string
	// UnknownCwd is set when the host does not report the directory a
	// command runs in, and Cwd is the session directory used instead. A
	// relative path from there with a guard file's name may then be one.
	UnknownCwd bool
	Cwd        string
}

// relGuard reports whether rel, written from dir, may be a guard file the
// hook cannot place: the command's directory is not known (the host did not
// report it, or the analysis lost it) and rel is relative to it.
func (o Options) relGuard(dir, rel string) bool {
	// The directory is unknown when the host does not report it, or when the
	// analysis lost it (cd to a glob, a substitution or a variable): the
	// command may then be writing in any directory under the root.
	if o.Guard == nil || rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(rel, "~") || !(dir == "" || o.UnknownCwd && dir == o.Cwd) {
		return false
	}
	return o.Guard.NamedLike(filepath.Base(rel))
}

func (o Options) protected(p string) bool {
	if o.Guard != nil {
		return o.Guard.Protected(p)
	}
	return IsProtectedPath(p, o.ProtectedPaths)
}

func (o Options) touches(p string) bool {
	if o.Guard != nil {
		return o.Guard.Touches(p)
	}
	return o.protected(p)
}

// removalOnly returns the absolute paths a call only removes or moves away:
// rm's operands, mv's sources (shell.Removes), and what git clean empties.
// Removing a directory that holds a guard file counts only when that file
// exists and its loss weakens the guard (guard.Set.RemovalTouches); writing,
// moving or extracting into it always counts.
func removalOnly(name string, args []shell.Word, dir, home string) map[string]bool {
	m := map[string]bool{}
	if name == "git" {
		if sub, _, _ := gitSubcommand(args, dir, home); sub == "clean" {
			for _, t := range gitTargets(args, dir, home) {
				m[t] = true
			}
		}
		return m
	}
	for _, w := range shell.Removes(name, args) {
		if w.Text != "" && w.Text != "-" {
			m[absPath(dir, w.Text, home)] = true
		}
	}
	return m
}

// gitTouchesHard is touchesFor without the soft targets (guard.Set.Soft).
func (o Options) gitTouchesHard(removes map[string]bool, p string) bool {
	if removes[p] {
		return o.Guard.RemovalTouchesHard(p)
	}
	return o.Guard.TouchesHard(p)
}

// touchesFor is touches, or for a path the call only removes (removalOnly)
// whether removing it can weaken the guard.
func (o Options) touchesFor(removes map[string]bool, p string) bool {
	if removes[p] && o.Guard != nil {
		return o.Guard.RemovalTouches(p)
	}
	return o.touches(p)
}

var engines = map[string]string{"terraform": "terraform", "tofu": "tofu", "opentofu": "tofu", "terragrunt": "terragrunt"}

// Invocations classifies the analyzer output. Invocations that do not touch
// infrastructure or guard files produce no action.
func Invocations(res *shell.Result, opt Options) []Action {
	var out []Action
	// written collects what each step writes, so a later step that applies
	// a planfile or reads .terraform is judged on what will be there, not on
	// what is there now.
	var written []string
	// named collects the paths earlier steps name in their arguments: a
	// program applygate does not model (aws s3 cp, scp, rclone, a script)
	// may write any of them.
	var named []string
	// retarget holds the cluster, project or subscription an earlier step
	// selected (kubectl config use-context, gcloud config set project, az
	// account set): later calls that name none target it.
	retarget := map[string]string{}
	// origin maps a path an earlier step wrote to the directory of the
	// plan -out that wrote it, or "" for any other writer.
	origin := map[string]string{}
	// originState maps a plan -out to the directories of the -state files
	// that plan read: the plan acts on their resources.
	originState := map[string][]string{}
	// seeded holds, per directory, the state files an earlier workspace new
	// -state=PATH copied into the workspace it selected: later commands
	// there run on that state.
	seeded := map[string][]string{}
	installed := map[string]bool{} // dir -> an earlier step ran init or get with an unvouched option
	initial := map[string]bool{}   // dir -> an earlier step ran a plain init or get
	for _, inv := range res.Invocations {
		acts := invocation(inv, opt)
		for i := range acts {
			a := &acts[i]
			if isEngine(a.Engine) && a.Dir != "" {
				a.InstalledEarlier, a.InitEarlier = installed[a.Dir], initial[a.Dir]
			}
			if (a.Engine == "terraform" || a.Engine == "tofu") && a.Dir != "" {
				if a.Sub == "workspace new" && len(a.StateFiles) > 0 {
					seeded[a.Dir] = append(seeded[a.Dir], a.StateFiles...)
				} else if s := seeded[a.Dir]; len(s) > 0 {
					a.StateFiles = append(a.StateFiles, s...)
				}
			}
			if t, ok := retarget[a.Engine]; ok && a.Target == "" {
				a.Target = t
			}
			if a.PlanFile != "" && a.Dir != "" {
				plan := absPath(a.Dir, a.PlanFile, opt.Home)
				a.PlanWritten = slices.Contains(written, writtenUnknown) || writtenAt(written, plan) || namedExactly(named, plan)
				if a.PlanWritten && !slices.Contains(written, writtenUnknown) && !namedExactly(named, plan) {
					a.PlanOrigin = origin[guard.Fold(filepath.Clean(plan))]
					a.PlanStateDirs = originState[guard.Fold(filepath.Clean(plan))]
				}
			}
			if a.Engine != "" && a.TargetUnknown == "" {
				// A credentials file the command points the CLI at (AWS_CONFIG_FILE,
				// KUBECONFIG, --kubeconfig) that an earlier step wrote may hold a
				// credential_process or exec entry: a program the hook cannot see.
				for _, k := range credFileEnv {
					paths := a.Env[k]
					if tv := a.TargetEnv[k]; tv != "" {
						paths = tv
					}
					for _, p := range filepath.SplitList(paths) {
						if p != "" && a.Dir != "" && (slices.Contains(written, writtenUnknown) || writtenAt(written, absPath(a.Dir, p, opt.Home))) {
							a.TargetUnknown = k + " names a file an earlier step of this command writes, which may name a program (credential_process, exec) the hook cannot see"
						}
					}
				}
			}
			if a.Engine == "terraform" || a.Engine == "tofu" || a.Engine == "terragrunt" {
				dataDir := ".terraform"

				if d := a.Env["TF_DATA_DIR"]; d != "" {
					dataDir = d
				}
				if a.Dir != "" {
					a.ConfigWritten = slices.Contains(written, writtenUnknown) || configWritten(written, origin, a.Dir)
					a.DataDirWritten = writtenAt(written, absPath(a.Dir, dataDir, opt.Home))
					for _, c := range a.BackendConfig {
						if backendConfigFile(c) && (slices.Contains(written, writtenUnknown) || writtenAt(written, absPath(a.Dir, c, opt.Home))) {
							a.BackendConfigWritten = true
						}
					}
				}
			}
		}
		out = append(out, acts...)
		if len(acts) > 0 && len(inv.Args) > 0 && inv.Args[0].Resolved {
			if _, ok := engines[shell.ProgName(inv.Args[0].Text)]; ok {
				out = append(out, engineOutputWrites(acts[0], inv)...)
			}
		}
		for _, a := range acts {
			if !isEngine(a.Engine) || a.Dir == "" {
				continue
			}
			switch a.Sub {
			case "init", "get":
				risky := a.Sub == "get" && hasOpt(inv.Args, "update") || a.Sub == "init" && (hasOpt(inv.Args, "upgrade") || hasOpt(inv.Args, "plugin-dir") || hasOpt(inv.Args, "from-module") || hasOpt(inv.Args, "lockfile") || hasOpt(inv.Args, "get-plugins"))
				if risky {
					installed[a.Dir] = true
				} else {
					initial[a.Dir] = true
				}
			case "providers lock", "providers mirror":
				installed[a.Dir] = true
			}
		}
		ws := stepWrites(inv, opt)
		planDir := ""
		var planState []string
		if len(inv.Args) > 0 && inv.Args[0].Resolved {
			if _, ok := engines[shell.ProgName(inv.Args[0].Text)]; ok {
				for _, a := range acts {
					if a.Engine == "terraform" || a.Engine == "tofu" {
						planDir = a.Dir
						for _, f := range a.StateFiles {
							planState = append(planState, filepath.Dir(f))
						}
						break
					}
				}
			}
		}
		for _, w := range ws {
			origin[guard.Fold(filepath.Clean(w))] = planDir
			if len(planState) > 0 {
				originState[guard.Fold(filepath.Clean(w))] = planState
			}
		}
		written = append(written, ws...)
		named = append(named, stepNames(inv, opt)...)
		if engines, t, ok := selects(inv); ok {
			for _, e := range engines {
				retarget[e] = t
			}
		}
	}
	for _, p := range res.Problems {
		a := Action{Class: Dynamic, Command: p.Text, Why: p.Reason, Dir: p.Dir, Via: p.Via, AnyDir: p.AnyDir}
		if p.Guard != "" {
			a.Class, a.Engine, a.Why = Tampering, "file", p.Reason
		}
		for _, m := range p.Mentions {
			if isGuardMention(m) {
				a.Class = Tampering
				a.Why = p.Reason + " (mentions " + m + ")"
			}
		}
		out = append(out, a)
	}
	return out
}

func isGuardMention(m string) bool {
	return strings.HasPrefix(m, "applygate") || strings.Contains(m, ".claude/settings") || strings.Contains(m, "managed-settings") ||
		strings.Contains(m, ".codex/") || strings.Contains(m, ".applygate.") || strings.Contains(m, ".seatbelt.") ||
		strings.Contains(m, ".cursor/hooks") || strings.Contains(m, ".gemini/settings") || strings.Contains(m, ".github/hooks") ||
		strings.Contains(m, ".copilot/") || strings.Contains(m, "hooks.json") || strings.Contains(m, ".devin/") ||
		strings.Contains(m, "devin/config") || strings.Contains(m, "opencode/plugins") || strings.Contains(m, "/hooks/PreToolUse") ||
		strings.Contains(m, "Cline/Hooks")
}

func words(inv shell.Invocation) []string {
	out := make([]string, len(inv.Args))
	for i, w := range inv.Args {
		if w.Resolved {
			out[i] = w.Text
		} else {
			out[i] = w.Prefix + "<?>"
		}
	}
	return out
}

func invocation(inv shell.Invocation, opt Options) []Action {
	cmdText := strings.Join(words(inv), " ")
	base := Action{Dir: inv.Dir, Env: inv.Env, Command: cmdText, Via: inv.Via, AnyDir: inv.Dir == "", ApproxDir: inv.Approx}
	var out []Action
	if why := plantsCommand(inv); why != "" {
		a := base
		a.Class, a.Engine, a.Why = Tampering, "file", why
		out = append(out, a)
	}

	// Writes to guard files through redirection, whatever the program.
	for _, r := range inv.Redirs {
		if !r.Write {
			continue
		}
		if !r.Target.Resolved {
			if opt.Guard != nil && r.Target.Prefix != "" && opt.Guard.GlobTouches(absPath(inv.Dir, r.Target.Prefix+"*", opt.Home)) {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", "redirect writes to "+r.Target.Prefix+"…, which may be a guard file"
				out = append(out, a)
				continue
			}
			if p := namesGuard("tee", []shell.Word{r.Target}, inv.Dir, opt); p != "" {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", "redirect writes to "+p+", which may be a guard file"
				out = append(out, a)
			}
			// true > terraform.tf*: the shell writes the file the glob matches.
			matched := false
			for _, m := range globMatches(r.Target, inv.Dir, opt.Home) {
				if isStateFile(m) {
					a := base
					a.Dir, a.AnyDir = filepath.Dir(m), false
					a.Class, a.Engine, a.Why, a.TouchesState = StateSurgery, "file", "redirect writes to state file "+m+" (through a glob)", true
					out = append(out, a)
					matched = true
					break
				}
			}
			if !matched && !strings.HasPrefix(r.Target.Text, "&") {
				// > "$f", > $OUT: the shell writes whatever the word holds,
				// which may be a state file in any directory under the root.
				a := base
				a.Class, a.Engine, a.AnyDir = ComplexShape, "file", true
				a.AnyDirWhy = "a redirect writes to a file named by a word the analysis cannot resolve, which may be a state file in any directory under the root"
				a.Why = a.AnyDirWhy
				out = append(out, a)
			}
			continue
		}
		if r.Target.Resolved {
			p := absPath(inv.Dir, r.Target.Text, opt.Home)
			if opt.protected(p) {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", "redirect writes to guard file "+p
				out = append(out, a)
			} else if opt.relGuard(inv.Dir, r.Target.Text) {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", "redirect writes to "+r.Target.Text+", which has a guard file's name, in a directory the host does not report"
				out = append(out, a)
			} else if isStateFile(p) {
				a := base
				a.Dir, a.AnyDir = filepath.Dir(p), false
				a.Class, a.Engine, a.Why, a.TouchesState = StateSurgery, "file", "redirect writes to state file "+p, true
				out = append(out, a)
			}
		}
	}

	if len(inv.Args) == 0 {
		return out
	}
	if !inv.Args[0].Resolved {
		a := base
		a.Class, a.Why = Dynamic, "program name cannot be resolved statically"
		a.AnyDir = true // what it is, and so where it goes, is not known
		return append(out, a)
	}
	name := shell.ProgName(inv.Args[0].Text)
	args := inv.Args[1:]
	switch lower := name; {
	case lower == "applygate" || lower == "seatbelt" || isSelf(absPath(inv.Dir, inv.Args[0].Text, opt.Home)):
		name = "applygate"
	case strings.Contains(inv.Args[0].Text, "/") || !knownProgram(lower):
		// A copy of applygate under another name: judge it by what its
		// arguments ask applygate to do.
		if why := selfTamper(args, false); why != "" {
			a := base
			a.Class, a.Engine, a.Why = Tampering, "applygate", why+" (through "+inv.Args[0].Text+", which may be a copy of applygate)"
			return append(out, a)
		}
	}
	// applygate run by another program from its arguments: a pty spawner
	// (python3 -c 'pty.spawn(sys.argv[1:])' applygate approve ID), a
	// launcher, or a name built from a variable (applygat${X}e).
	for i, w := range args {
		b := strings.ToLower(filepath.Base(w.Text))
		if !w.Resolved {
			b = strings.ToLower(filepath.Base(w.Prefix))
		}
		named := b == "applygate" || b == "seatbelt" || (!w.Resolved && (strings.HasPrefix(b, "applyg") || strings.HasPrefix(b, "seatb")))
		if named || (w.Resolved && isSelf(absPath(inv.Dir, w.Text, opt.Home))) {
			if why := selfTamper(args[i+1:], false); why != "" {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "applygate", why+" (run by "+name+")"
				return append(out, a)
			}
		}
	}

	if why := packageTamper(name, args); why != "" {
		a := base
		a.Class, a.Engine, a.Why = Tampering, "applygate", why
		return append(out, a)
	}
	// patch, git apply and git am write the files their patch text names,
	// which is not on the command line.
	if name == "patch" || name == "git" && len(args) > 0 && (args[0].Text == "apply" || args[0].Text == "am") || name == "applypatch" {
		if p := patchGuard(inv, args, opt); p != "" {
			a := base
			a.Class, a.Engine, a.Why = Tampering, "file", name+" applies a patch that changes guard file "+p
			return append(out, a)
		}
	}
	// Default-deny near guard files: a program that names one, or (when it
	// writes, removes or extracts) a directory that holds one, is
	// tampering unless it only reads. This does not depend on knowing how
	// the program writes.
	if p := namesGuard(name, args, inv.Dir, opt); p != "" {
		a := base
		a.Class, a.Engine, a.Why = Tampering, "file", name+" names guard file "+p+"; only reading it is allowed"
		return append(out, a)
	}

	if why := hostInstall(name, args); why != "" {
		a := base
		a.Class, a.Engine, a.Why = Tampering, "agent", why
		return append(out, a)
	}
	if _, isEngine := engines[name]; !isEngine && name != "aws" && name != "gsutil" && name != "gcloud" && name != "rclone" && name != "scp" {
		// az rest --output-file FILE, kubectl cp pod:/x FILE, docker cp: a
		// cloud or cluster CLI that names a state file may write it.
		if f := namedState(name, args, inv.Dir, opt); f != "" {
			a := base
			a.Dir, a.AnyDir = filepath.Dir(f), false
			a.Class, a.Engine, a.TouchesState = StateSurgery, "file", true
			a.Why = name + " names state file " + f + "; only reading it is allowed"
			return append(out, a)
		}
	}
	if name == "aws" || name == "gsutil" || name == "gcloud" || name == "rclone" || name == "scp" {
		// A download writes a local file the command names last: a state
		// file or a guard file in the way is overwritten.
		if tw := stateWrites(base, name, args, inv.Dir, opt); len(tw) > 0 {
			return append(out, tw...)
		}
		for _, t := range writeTargets(name, args, inv.Dir, opt.Home) {
			if opt.touches(t) {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", name+" writes "+t+", which holds a guard file"
				return append(out, a)
			}
		}
	}
	if e, ok := engines[name]; ok {
		a := base
		a.Engine = e
		terraformArgs(&a, args)
		if a.Class == UnknownWrapper && shell.IsBackstopVia(inv.Via) {
			// "brew install terraform tflint", "asdf install terraform
			// 1.9.0": terraform was an argument, not a command to run.
			return out
		}
		if a.ConfigDir != "" && a.ConfigDir != a.Dir {
			c := a
			c.Dir, c.AnyDir, c.ConfigDir = a.ConfigDir, false, ""
			return append(out, a, c)
		}
		return append(out, a)
	}
	switch name {
	case "aws":
		if a, ok := awsArgs(base, args); ok {
			out = append(out, a)
		}
		return out
	case "kubectl", "oc":
		if a, ok := kubectlArgs(base, args); ok {
			out = append(out, a)
		}
		return out
	case "helm":
		if a, ok := helmArgs(base, args); ok {
			out = append(out, a)
		}
		return out
	case "az", "gcloud", "gsutil":
		if a, ok := cloudCLIArgs(base, name, args); ok {
			out = append(out, a)
		}
		return out
	case "npx", "bunx", "pnpx":
		if agent, rest, ok := packageAgent(name, args); ok {
			if a, ok := agentFlags(base, agent, rest); ok {
				return append(out, a)
			}
		}
	case "claude", "codex", "cursor-agent", "copilot", "gemini", "opencode":
		if a, ok := agentFlags(base, name, args); ok {
			out = append(out, a)
		}
		return out
	case "applygate", "seatbelt":
		if why := selfTamper(args, true); why != "" {
			a := base
			a.Class, a.Engine, a.Why = Tampering, "applygate", why
			out = append(out, a)
		}
		return out
	case "go":
		// go run ./cmd/applygate approve ..., go run github.com/Flurit/applygate/cmd/applygate@v ...
		if len(args) >= 2 && args[0].Text == "run" {
			for i, w := range args[1:] {
				if strings.Contains(w.Text, "cmd/applygate") || strings.Contains(w.Text, "cmd/seatbelt") {
					if why := selfTamper(args[i+2:], true); why != "" {
						a := base
						a.Class, a.Engine, a.Why = Tampering, "applygate", why
						out = append(out, a)
					}
					return out
				}
			}
		}
	case "just", "task", "npm", "yarn", "pnpm", "bun", "mage", "invoke", "nx":
		if agent, rest, ok := packageAgent(name, args); ok {
			if a, ok := agentFlags(base, agent, rest); ok {
				return append(out, a)
			}
		}
		if t := destructiveTarget(args); t != "" {
			a := base
			a.Class, a.Why = UnknownWrapper, "wrapper target "+t+" looks destructive and its body is not analyzed"
			out = append(out, a)
		}
		return out
	case "make", "gmake":
		// Reached only when the Makefile or target could not be read.
		if t := destructiveTarget(args); t != "" {
			a := base
			a.Class, a.Why = UnknownWrapper, "make target "+t+" looks destructive and its recipe could not be read"
			out = append(out, a)
		}
		return out
	case "printenv":
		for _, w := range args {
			if isSecretEnv(w.Text) {
				a := base
				a.Class, a.Engine, a.Why = CredentialAccess, "env", "prints secret variable "+w.Text
				out = append(out, a)
			}
		}
		return out
	}

	if strings.Contains(inv.Args[0].Text, "/") {
		// A script we could not read (the analyzer follows readable ones).
		if t := destructiveTarget([]shell.Word{{Text: shell.ProgName(inv.Args[0].Text), Resolved: true}}); t != "" {
			a := base
			a.Class, a.Why = UnknownWrapper, "script "+inv.Args[0].Text+" looks destructive and could not be read"
			out = append(out, a)
		}
	}

	if a, ok := httpMutation(base, name, args); ok {
		out = append(out, a)
	}
	out = append(out, fileOps(base, name, args, inv.Dir, opt)...)
	return out
}

// credFileEnv are the variables that name a credentials or kube config
// file whose entries can run a program.
var credFileEnv = []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG", "KUBE_CONFIG_PATH"}

// CredFileEnv returns the variables that name a credentials or kube config
// file.
func CredFileEnv() []string { return credFileEnv }
