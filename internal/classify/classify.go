// Package classify maps analyzed invocations and tool calls to command classes.
package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/shell"
)

// Class is a command class from the v1 verdict table.
type Class string

const (
	ReadOnly         Class = "read-only"
	Mutating         Class = "mutating"    // import, refresh, test: changes state, not in the spec table
	CloudWrite       Class = "cloud-write" // cloud create/update calls: not in the spec table
	ApplySavedPlan   Class = "apply-saved-plan"
	UnreviewedApply  Class = "unreviewed-apply"
	Destroy          Class = "destroy"
	StateSurgery     Class = "state-surgery"
	CloudDestructive Class = "cloud-destructive"
	CredentialAccess Class = "credential-access" // not in the spec table
	UnknownWrapper   Class = "unknown-wrapper"
	// ComplexShape is a shell command in a protected tier that is not a
	// plain list or pipeline of known programs (strict shapes).
	ComplexShape Class = "complex-shape"
	Dynamic      Class = "dynamic"
	Tampering    Class = "guard-tampering"
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
	// may write any of them (4H13).
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

// httpMutation classifies network clients that send a request other than a
// read: a DELETE to a cloud or cluster API deletes what it names, and any
// other non-GET/HEAD request (an explicit method, a request body, a form or an
// upload) changes it, with whatever credentials the call or an earlier one
// obtained (an HCP Terraform run is a POST with a JSON body). Requests to this
// machine are ordinary work unless they are signed.
func httpMutation(base Action, name string, args []shell.Word) (Action, bool) {
	if name == "gh" || name == "glab" {
		// gh api -X DELETE, gh repo delete, gh secret delete and
		// gh workflow run (which starts a pipeline that can apply or
		// destroy) act on the remote repository and its automation.
		var pos []string
		method := ""
		body := false
		for i, w := range args {
			t := w.Text
			k, v, eq := strings.Cut(t, "=")
			switch {
			case (t == "-X" || t == "--method") && i+1 < len(args):
				method = strings.ToUpper(args[i+1].Text)
			case strings.HasPrefix(t, "-X") && len(t) > 2:
				method = strings.ToUpper(t[2:])
			case k == "--method" && eq:
				method = strings.ToUpper(v)
			case t == "-f" || t == "-F" || t == "--field" || t == "--raw-field" || t == "--input",
				k == "--field" && eq, k == "--raw-field" && eq, k == "--input" && eq,
				strings.HasPrefix(t, "-f") && len(t) > 2 && !strings.HasPrefix(t, "--"),
				strings.HasPrefix(t, "-F") && len(t) > 2 && !strings.HasPrefix(t, "--"):
				body = true
			case !strings.HasPrefix(t, "-"):
				pos = append(pos, t)
			}
		}
		a := base
		a.Engine = "http"
		if len(pos) > 0 && pos[0] == "api" && method == "" && body {
			method = "POST" // gh api sends a POST once it has fields or an input
		}
		switch {
		case len(pos) > 0 && pos[0] == "api" && method == "DELETE",
			len(pos) > 1 && pos[1] == "delete" && (pos[0] == "repo" || pos[0] == "secret" || pos[0] == "variable" || pos[0] == "release" || pos[0] == "workflow" || pos[0] == "run"):
			a.Class, a.Why = CloudDestructive, name+" "+strings.Join(pos, " ")+" deletes what it names on the remote"
			return a, true
		case len(pos) > 1 && pos[0] == "workflow" && pos[1] == "run", len(pos) > 0 && pos[0] == "api" && method != "" && method != "GET" && method != "HEAD":
			a.Class, a.Why = CloudWrite, name+" "+strings.Join(pos, " ")+" changes the remote or starts its automation"
			return a, true
		}
		return Action{}, false
	}
	if name != "curl" && name != "wget" && name != "http" && name != "https" && name != "xh" && name != "xhs" {
		return Action{}, false
	}
	method, body, signed := httpRequestShape(name, args)
	local := false
	for _, w := range args {
		if strings.Contains(w.Text, "://") || strings.HasPrefix(w.Text, "localhost") {
			t := strings.ToLower(w.Text)
			if strings.Contains(t, "://localhost") || strings.Contains(t, "://127.0.0.1") || strings.Contains(t, "://[::1]") || strings.HasPrefix(t, "localhost") {
				local = true
			} else {
				local = false
				break
			}
		}
	}
	if local && !signed {
		return Action{}, false // a service on this machine: ordinary work
	}
	if method == "" && body {
		method = "POST"
	}
	switch {
	case method == "DELETE":
		a := base
		a.Class, a.Engine = CloudDestructive, "http"
		a.Why = name + " sends a DELETE request, which deletes the resource it names"
		return a, true
	case method != "" && method != "GET" && method != "HEAD" && method != "OPTIONS":
		a := base
		a.Class, a.Engine = CloudWrite, "http"
		a.Why = name + " sends a " + method + " request, which changes the resource it names"
		if signed {
			a.Why = name + " sends a " + method + " request signed with credentials or through a socket, which changes the resource it names"
		}
		return a, true
	}
	return Action{}, false
}

// httpRequestShape reads the request a curl, wget or httpie call sends: its
// method ("" when it is the default for the options given), whether it sends
// a body, form or upload, and whether it is signed or goes through a socket.
// An unresolved method is reported as "UNKNOWN", which is not a read.
var knownHTTPMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "TRACE": true, "CONNECT": true}

func httpRequestShape(name string, args []shell.Word) (method string, body, signed bool) {
	set := func(w shell.Word, v string) {
		if !w.Resolved || v == "" {
			method = "UNKNOWN"
			return
		}
		method = strings.ToUpper(v)
	}
	get := false
	switch name {
	case "curl":
		for i := 0; i < len(args); i++ {
			t := args[i].Text
			if strings.HasPrefix(t, "--") {
				k, v, eq := strings.Cut(t, "=")
				switch k {
				case "--request":
					if eq {
						set(args[i], v)
					} else if i+1 < len(args) {
						i++
						set(args[i], args[i].Text)
					}
				case "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json", "--form", "--form-string", "--upload-file":
					body = true
					if !eq && i+1 < len(args) {
						i++
					}
				case "--get":
					get = true
				case "--head":
					method = "HEAD"
				case "--aws-sigv4", "--unix-socket", "--abstract-unix-socket", "--cert":
					signed = true
				}
				continue
			}
			if !strings.HasPrefix(t, "-") || t == "-" {
				continue
			}
			// A short cluster: flags run on until an option that takes a value,
			// whose value is the rest of the cluster or the next word.
			for j := 1; j < len(t); j++ {
				c := t[j]
				rest := t[j+1:]
				takes := strings.IndexByte("dFTXHuAbcCDeEKmoPQrtUwxyYzZ", c) >= 0
				switch c {
				case 'G':
					get = true
				case 'I':
					method = "HEAD"
				}
				if !takes {
					continue
				}
				val := rest
				if val == "" && i+1 < len(args) {
					i++
					val = args[i].Text
				}
				switch c {
				case 'd', 'F', 'T':
					body = true
				case 'X':
					set(args[i], val)
				case 'E':
					signed = true
				}
				break
			}
		}
		if get && method == "" {
			body = false // -G turns the data into a query string
		}
	case "wget":
		for i := 0; i < len(args); i++ {
			k, v, eq := strings.Cut(args[i].Text, "=")
			switch k {
			case "--method":
				if eq {
					set(args[i], v)
				} else if i+1 < len(args) {
					i++
					set(args[i], args[i].Text)
				}
			case "--post-data", "--post-file", "--body-data", "--body-file":
				body = true
			case "--certificate", "--private-key":
				signed = true
			}
		}
		if body && method == "" {
			method = "POST"
		}
	default: // httpie and xh: METHOD URL item...
		first := true
		for _, w := range args {
			t := w.Text
			if strings.HasPrefix(t, "-") {
				continue
			}
			if first {
				first = false
				if m := strings.ToUpper(t); knownHTTPMethods[m] || (t == m && len(t) > 2 && strings.Trim(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "") {
					set(w, m)
					continue
				}
			}
			if strings.Contains(t, "://") {
				continue
			}
			// key=value, key:=json and key=@file or key@file send a body;
			// key==value is a query parameter and Header:value a header.
			i := strings.IndexAny(t, "=@:")
			switch {
			case i < 0:
			case strings.HasPrefix(t[i:], "=="), strings.HasPrefix(t[i:], ":") && !strings.HasPrefix(t[i:], ":="):
			default:
				body = true
			}
		}
	}
	return
}

var destructiveWord = regexp.MustCompile(`(?i)(^|[^a-z])(destroy|teardown|tear-down|nuke|obliterate|decommission|wipe)([^a-z]|$)`)

func destructiveTarget(args []shell.Word) string {
	for _, w := range args {
		if strings.HasPrefix(w.Text, "-") {
			continue
		}
		if destructiveWord.MatchString(w.Text) {
			return w.Text
		}
	}
	return ""
}

var secretEnv = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSWORD|SESSION_TOKEN|ACCESS_KEY)`)

func isSecretEnv(s string) bool { return secretEnv.MatchString(s) }

func absPath(dir, p, home string) string {
	if strings.HasPrefix(p, "~/") && home != "" {
		p = filepath.Join(home, p[2:])
	}
	if filepath.IsAbs(p) || dir == "" {
		return shell.PhysicalJoin("", p)
	}
	return shell.PhysicalJoin(dir, p)
}

func isStateFile(p string) bool {
	if filepath.Base(filepath.Dir(p)) == ".terraform" {
		return false // the backend cache, not a state
	}
	b := filepath.Base(p)
	return strings.HasSuffix(b, ".tfstate") || strings.HasSuffix(b, ".tfstate.backup")
}

var credentialPath = regexp.MustCompile(`(^|/)\.aws/(credentials|sso/cache/|cli/cache/)|(^|/)\.terraform\.d/credentials\.tfrc\.json$|(^|/)\.terraformrc$`)

// IsCredentialPath reports whether p is a cloud or Terraform credential file.
func IsCredentialPath(p string) bool { return credentialPath.MatchString(filepath.ToSlash(p)) }

var writers = map[string]bool{
	"rm": true, "mv": true, "cp": true, "install": true, "ln": true, "tee": true, "truncate": true,
	"chmod": true, "chown": true, "chattr": true, "dd": true, "shred": true, "unlink": true, "rsync": true, "touch": true,
	"rmdir": true, "srm": true, "ditto": true, "sponge": true, "patch": true, "cpio": true,
	"vi": true, "vim": true, "nvim": true, "nano": true, "emacs": true, "ed": true, "ex": true, "pico": true,
}

// removers change or remove every path they are given, so a directory that
// holds a guard file counts: rm -rf ~/.claude, mv ~/.claude elsewhere.
var removers = map[string]bool{"rm": true, "rmdir": true, "srm": true, "unlink": true, "shred": true, "mv": true,
	"chmod": true, "chown": true, "chattr": true, "truncate": true, "ln": true}

// copiers write into their last argument, or the directory after -t.
var copiers = map[string]bool{"cp": true, "install": true, "rsync": true, "ditto": true}

// destroysFiles remove or overwrite the files they are given.
var destroysFiles = map[string]bool{"rm": true, "rmdir": true, "unlink": true, "shred": true, "srm": true, "mv": true, "cp": true,
	"install": true, "ln": true, "tee": true, "truncate": true, "dd": true, "rsync": true}

var readers = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true, "grep": true, "rg": true, "awk": true,
	"base64": true, "xxd": true, "od": true, "strings": true, "bat": true, "nl": true, "cp": true, "scp": true, "curl": true,
}

// fileOps classifies generic programs that write guard or state files or read
// credential files.
func fileOps(base Action, name string, args []shell.Word, dir string, opt Options) []Action {
	var out []Action
	tamper := func(why string) {
		a := base
		a.Class, a.Engine, a.Why = Tampering, "file", why
		out = append(out, a)
	}
	out = append(out, stateWrites(base, name, args, dir, opt)...)
	// Default-deny near state files, as near guard files: a program that is
	// not known to only read, and that names a state file, may overwrite it
	// whatever its option for doing so is called.
	if !slices.ContainsFunc(out, func(a Action) bool { return a.Class == StateSurgery }) {
		if f := namedState(name, args, dir, opt); f != "" {
			a := base
			a.Dir, a.AnyDir = filepath.Dir(f), false
			a.Class, a.Engine, a.TouchesState = StateSurgery, "file", true
			a.Why = name + " names state file " + f + "; only reading it is allowed"
			out = append(out, a)
		}
	}
	// A program that removes or overwrites files, given a name the analysis
	// cannot resolve (a loop variable, a command substitution, xargs input),
	// may name a state file in any directory under the root.
	if destroysFiles[name] && !slices.ContainsFunc(out, func(a Action) bool { return a.Class == StateSurgery }) {
		for _, w := range args {
			if !w.Resolved && !strings.HasPrefix(w.Prefix, "-") {
				a := base
				a.Class, a.Engine, a.AnyDir = ComplexShape, "file", true
				a.AnyDirWhy = name + " removes or overwrites a file it names with a word the analysis cannot resolve, which may be a state file in any directory under the root"
				a.Why = a.AnyDirWhy
				out = append(out, a)
				break
			}
		}
	}
	// Places the program writes, moves, removes or extracts into; a
	// directory that holds a guard file counts.
	for _, t := range writeTargets(name, args, dir, opt.Home) {
		if opt.touches(t) {
			tamper(name + " changes " + t + ", which holds a guard file")
			return out
		}
		if rel, ok := strings.CutPrefix(t, dir+"/"); ok && opt.relGuard(dir, rel) {
			tamper(name + " changes " + rel + ", which has a guard file's name, in a directory the host does not report")
			return out
		}
	}
	inPlace := false
	if name == "sed" || name == "gsed" || name == "perl" || name == "ruby" || name == "yq" {
		inPlace = inPlaceEdit(args)
	}
	isWriter := writers[name] || inPlace
	for _, w := range args {
		if !w.Resolved || w.Text == "" {
			continue
		}
		t := w.Text
		if strings.HasPrefix(t, "of=") && name == "dd" {
			t = t[3:]
		} else if strings.HasPrefix(t, "-") {
			continue
		}
		p := absPath(dir, t, opt.Home)
		switch {
		case isWriter && opt.protected(p):
			tamper(name + " modifies guard file " + p)
		case isWriter && opt.relGuard(dir, t):
			tamper(name + " modifies " + t + ", which has a guard file's name, in a directory the host does not report")
		case readers[name] && IsCredentialPath(p):
			a := base
			a.Class, a.Engine, a.Why = CredentialAccess, "file", name+" reads credential file "+p
			out = append(out, a)
		}
	}
	return out
}

// stepWrites returns the absolute paths one step of a command writes: its
// redirections, what writeTargets finds for its program, and the plan of
// terraform plan -out.
func stepWrites(inv shell.Invocation, opt Options) []string {
	var out []string
	for _, r := range inv.Redirs {
		if r.Write && r.Target.Resolved {
			out = append(out, absPath(inv.Dir, r.Target.Text, opt.Home))
		}
	}
	if len(inv.Args) == 0 || !inv.Args[0].Resolved {
		return out
	}
	name := shell.ProgName(inv.Args[0].Text)
	args := inv.Args[1:]
	if _, ok := engines[name]; ok {
		// -out is relative to -chdir, and TF_CLI_ARGS and
		// TF_CLI_ARGS_<subcommand> add options after the subcommand.
		dir, rest := inv.Dir, args
		for len(rest) > 0 && strings.HasPrefix(rest[0].Text, "-") {
			t := strings.TrimLeft(rest[0].Text, "-")
			switch v, ok := strings.CutPrefix(t, "chdir="); {
			case ok && rest[0].Resolved:
				dir = absPath(dir, v, opt.Home)
				if inv.Approx && !filepath.IsAbs(v) {
					dir = ""
				}
			case ok:
				dir = ""
			case t == "chdir" && len(rest) > 1:
				dir = absPath(dir, rest[1].Text, opt.Home)
				if !rest[1].Resolved || inv.Approx && !filepath.IsAbs(rest[1].Text) {
					dir = ""
				}
				rest = rest[1:]
			}
			rest = rest[1:]
		}
		sub := ""
		if len(rest) > 0 {
			sub, rest = rest[0].Text, rest[1:]
		}
		words := append(append([]shell.Word(nil), rest...), cliArgs(inv.Env, sub)...)
		if sub == "init" {
			for _, w := range words {
				if strings.HasPrefix(strings.TrimLeft(w.Text, "-"), "from-module") {
					// init -from-module copies a module's files into the
					// directory before anything else.
					if dir == "" {
						out = append(out, writtenUnknown)
					} else {
						out = append(out, dir)
					}
				}
			}
		}
		for i, w := range words {
			t, v := w.Text, ""
			switch {
			case strings.HasPrefix(t, "-out="):
				v = strings.TrimPrefix(t, "-out=")
			case t == "-out" && i+1 < len(words):
				w, v = words[i+1], words[i+1].Text
			case !w.Resolved && strings.Contains(t, "out"):
				out = append(out, writtenUnknown)
				continue
			default:
				continue
			}
			if !w.Resolved || dir == "" && !filepath.IsAbs(v) {
				out = append(out, writtenUnknown)
				continue
			}
			out = append(out, absPath(dir, v, opt.Home))
		}
		return out
	}
	out = append(out, writeTargets(name, args, inv.Dir, opt.Home)...)
	if name == "git" {
		out = append(out, gitTreeWrites(args, inv.Dir, opt.Home)...)
	}
	if name == "gh" || name == "glab" {
		// pr checkout, pr merge, repo sync, mr checkout and the like run git
		// in the repository and rewrite its tree.
		var pos []string
		for _, w := range args {
			if !strings.HasPrefix(w.Text, "-") {
				pos = append(pos, w.Text)
			}
		}
		if len(pos) >= 2 && inv.Dir != "" {
			switch pos[0] + " " + pos[1] {
			case "pr checkout", "pr merge", "repo sync", "mr checkout", "mr merge", "repo clone", "repo fork", "pr create", "mr create", "co":
				out = append(out, inv.Dir)
			}
		} else if len(pos) >= 1 && pos[0] == "co" && inv.Dir != "" {
			out = append(out, inv.Dir)
		}
		if len(pos) >= 2 && inv.Dir == "" {
			out = append(out, writtenUnknown)
		}
	}
	if (name == "sed" || name == "gsed" || name == "perl" || name == "ruby" || name == "yq") && inPlaceEdit(args) {
		// The first operand is the script (the expression for yq) unless -e,
		// -f or --expression gave one; the rest are the files edited.
		given := false
		for _, w := range args {
			if w.Text == "-e" || w.Text == "-f" || strings.HasPrefix(w.Text, "--expression") || strings.HasPrefix(w.Text, "--file") {
				given = true
			}
		}
		first := !given && name != "perl" && name != "ruby"
		for _, w := range args {
			if strings.HasPrefix(w.Text, "-") && w.Text != "-" {
				continue
			}
			if first {
				first = false
				continue
			}
			if w.Resolved && w.Text != "" {
				out = append(out, absPath(inv.Dir, w.Text, opt.Home))
			} else if !w.Resolved {
				out = append(out, writtenUnknown)
			}
		}
	}
	// cp, mv, ln and tee write their last argument even when it is a file.
	switch name {
	case "cp", "mv", "ln", "install", "tee", "touch", "truncate", "dd":
		for _, w := range args {
			if w.Resolved && !strings.HasPrefix(w.Text, "-") {
				t := w.Text
				if v, ok := strings.CutPrefix(t, "of="); ok {
					t = v
				}
				out = append(out, absPath(inv.Dir, t, opt.Home))
			}
		}
	}
	return out
}

// UnknownWorkspace is the SelectWorkspace of a workspace select whose name
// cannot be resolved.
const UnknownWorkspace = "\x00unknown"

// selects reports the target a step makes the CLI's default, and the
// engines that then use it. An unresolved one is "?", which matches no
// environment and so gets the rule for an unknown one.
func selects(inv shell.Invocation) ([]string, string, bool) {
	if len(inv.Args) == 0 || !inv.Args[0].Resolved {
		return nil, "", false
	}
	pos := positional(inv.Args[1:])
	val := func(i int) string {
		n := 0
		for _, w := range inv.Args[1:] {
			if strings.HasPrefix(w.Text, "-") {
				continue
			}
			if n == i {
				if !w.Resolved {
					return "?"
				}
				return w.Text
			}
			n++
		}
		return "?"
	}
	switch shell.ProgName(inv.Args[0].Text) {
	case "kubectl":
		if len(pos) >= 3 && pos[0] == "config" && pos[1] == "use-context" {
			return []string{"kubectl", "helm"}, val(2), true
		}
	case "gcloud":
		if len(pos) >= 4 && pos[0] == "config" && pos[1] == "set" && pos[2] == "project" {
			return []string{"gcloud"}, val(3), true
		}
	case "az":
		if len(pos) >= 2 && pos[0] == "account" && pos[1] == "set" {
			if v := flagValue(inv.Args[1:], "--subscription"); v != "" {
				return []string{"az"}, v, true
			}
			if v := flagValue(inv.Args[1:], "-s"); v != "" {
				return []string{"az"}, v, true
			}
			return []string{"az"}, "?", true
		}
	}
	return nil, "", false
}

// writtenUnknown stands for a planfile written where the analysis cannot
// tell: an unresolved -out, or one relative to a lost -chdir.
const writtenUnknown = "\x00unknown"

// pathReaders only read the files they name.
var pathReaders = map[string]bool{"cat": true, "less": true, "more": true, "head": true, "tail": true, "ls": true, "stat": true,
	"file": true, "wc": true, "grep": true, "egrep": true, "rg": true, "sha256sum": true, "shasum": true, "md5sum": true, "test": true,
	"[": true, "du": true, "echo": true, "printf": true, "realpath": true, "readlink": true, "basename": true, "dirname": true}

// stepNames returns the absolute paths a step names in its arguments (a
// word, or the value of --flag=value), for programs that are not readers or
// the engines or remote copies, whose writes stepWrites knows.
func stepNames(inv shell.Invocation, opt Options) []string {
	if len(inv.Args) == 0 || !inv.Args[0].Resolved || inv.Dir == "" {
		return nil
	}
	name := shell.ProgName(inv.Args[0].Text)
	if _, engine := engines[name]; engine || pathReaders[name] || remoteCopy(name, inv.Args[1:]) {
		return nil // stepWrites knows what these write
	}
	var out []string
	for _, w := range inv.Args[1:] {
		if !w.Resolved || w.Text == "" {
			continue
		}
		t := w.Text
		if strings.HasPrefix(t, "-") {
			_, v, ok := strings.Cut(t, "=")
			if !ok || v == "" {
				continue
			}
			t = v
		}
		if strings.Contains(t, "://") {
			continue
		}
		out = append(out, absPath(inv.Dir, t, opt.Home))
	}
	return out
}

// remoteCopy reports whether a command copies between a remote store and
// local files, with the destination last: scp, rclone copy, aws s3 cp,
// gsutil cp, gcloud storage cp.
func remoteCopy(name string, args []shell.Word) bool {
	var sub []string
	for _, w := range args {
		if !strings.HasPrefix(w.Text, "-") {
			sub = append(sub, w.Text)
		}
	}
	at := func(i int, ws ...string) bool { return len(sub) > i && slices.Contains(ws, sub[i]) }
	switch name {
	case "scp":
		return true
	case "rclone":
		return at(0, "copy", "copyto", "sync", "move", "moveto", "copyurl")
	case "aws":
		return at(0, "s3") && at(1, "cp", "mv", "sync")
	case "gsutil":
		return at(0, "cp", "mv", "rsync")
	case "gcloud":
		return at(0, "storage") && at(1, "cp", "mv", "rsync")
	}
	return false
}

// remotePath reports whether p names a remote location: a URL, or
// host:path with no slash before the colon.
func remotePath(p string) bool {
	if strings.Contains(p, "://") {
		return true
	}
	host, _, ok := strings.Cut(p, ":")
	return ok && host != "" && !strings.Contains(host, "/")
}

// namedExactly reports whether p itself is among named.
func namedExactly(named []string, p string) bool {
	p = guard.Fold(filepath.Clean(p))
	for _, n := range named {
		if guard.Fold(filepath.Clean(n)) == p {
			return true
		}
	}
	return false
}

// backendConfigFile reports whether a -backend-config value names a file
// rather than a key=value pair, by the rule preflight.BackendFromConfig
// reads it with.
func backendConfigFile(c string) bool {
	k, _, ok := strings.Cut(c, "=")
	return !ok || strings.ContainsAny(k, "/\\.")
}

// writtenAt reports whether p, or a directory holding it, is among written.
// Names are compared as the file system does (case folded on macOS and
// Windows).
func writtenAt(written []string, p string) bool {
	p = guard.Fold(filepath.Clean(p))
	for _, w := range written {
		if w == writtenUnknown {
			continue
		}
		w = guard.Fold(filepath.Clean(w))
		if w == p || strings.HasPrefix(p, w+string(filepath.Separator)) || strings.HasPrefix(w, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// writeTargets returns the absolute paths a program changes in a way that
// can replace or remove a guard file: what it removes or moves, the
// directory it copies or extracts into, the file it downloads to, and the
// paths git restores. Unknown programs return nothing.
func writeTargets(name string, args []shell.Word, dir, home string) []string {
	var out []string
	abs := func(p string) string { return absPath(dir, p, home) }
	paths := func(ws []shell.Word) []string {
		var ps []string
		for _, w := range ws {
			if w.Resolved && w.Text != "" && !strings.HasPrefix(w.Text, "-") {
				ps = append(ps, w.Text)
			}
		}
		return ps
	}
	// flagValue returns the value of a flag given as "-x v", "-xv", "--long v"
	// or "--long=v", including at the end of a short-flag cluster ("-so v").
	flagValue := func(short byte, long string) (string, bool) {
		for i, w := range args {
			t := w.Text
			if long != "" {
				if v, ok := strings.CutPrefix(t, long+"="); ok {
					return v, true
				}
				if t == long && i+1 < len(args) {
					return args[i+1].Text, true
				}
			}
			if short != 0 && len(t) >= 2 && t[0] == '-' && t[1] != '-' {
				if j := strings.IndexByte(t[1:], short); j >= 0 {
					if rest := t[j+2:]; rest != "" {
						return rest, true // -ofile
					}
					if i+1 < len(args) {
						return args[i+1].Text, true // -o file, -so file
					}
				}
			}
		}
		return "", false
	}
	has := func(ws ...string) bool {
		for _, w := range args {
			for _, x := range ws {
				if w.Text == x {
					return true
				}
			}
		}
		return false
	}
	switch {
	case removers[name]:
		for _, p := range paths(args) {
			out = append(out, abs(p))
		}
	case remoteCopy(name, args):
		// The last argument is the destination; a remote one (s3://b,
		// host:path) is not written here.
		if ps := paths(args); len(ps) >= 2 && !remotePath(ps[len(ps)-1]) {
			out = append(out, abs(ps[len(ps)-1]))
		}
	case copiers[name]:
		// Only cp and install take -t DIR; rsync's -t keeps times.
		if t, ok := flagValue('t', "--target-directory"); ok && (name == "cp" || name == "install") {
			out = append(out, abs(t))
		} else if ps := paths(args); len(ps) >= 2 {
			out = append(out, abs(ps[len(ps)-1]))
		}
	case name == "tar" || name == "bsdtar" || name == "gtar":
		extract, create := tarModes(args)
		if extract {
			if d, ok := flagValue('C', "--directory"); ok {
				out = append(out, abs(d))
			} else {
				out = append(out, abs("."))
			}
		}
		// Creating an archive writes the file -f names.
		if create {
			if f, ok := flagValue('f', "--file"); ok && f != "-" {
				out = append(out, abs(f))
			} else if len(args) > 1 && len(args[0].Text) > 1 && strings.Contains(args[0].Text, "f") && !strings.HasPrefix(args[0].Text, "--") {
				out = append(out, abs(args[1].Text)) // tar cf FILE: the old syntax
			}
		}
	case name == "7z" || name == "7za" || name == "7zz" || name == "7zr":
		if len(args) > 0 && (args[0].Text == "x" || args[0].Text == "e") {
			d := "."
			for _, w := range args {
				if v, ok := strings.CutPrefix(w.Text, "-o"); ok && v != "" {
					d = v
				}
			}
			out = append(out, abs(d))
		}
	case name == "unzip":
		if d, ok := flagValue('d', ""); ok {
			out = append(out, abs(d))
		} else {
			out = append(out, abs("."))
		}
	case name == "cpio":
		if has("-i", "--extract", "-p", "--pass-through") || (len(args) > 0 && strings.ContainsAny(strings.TrimPrefix(args[0].Text, "-"), "ip")) {
			if ps := paths(args); len(ps) > 0 && has("-p", "--pass-through") {
				out = append(out, abs(ps[len(ps)-1]))
			} else {
				out = append(out, abs("."))
			}
		}
	case name == "patch":
		if d, ok := flagValue('d', "--directory"); ok {
			out = append(out, abs(d))
		} else {
			out = append(out, abs("."))
		}
		for _, p := range paths(args) {
			out = append(out, abs(p))
		}
	case name == "curl":
		if o, ok := flagValue('o', "--output"); ok {
			out = append(out, abs(o))
		}
		if has("-O", "--remote-name", "--remote-name-all") || clusterHas(args, 'O') {
			for _, p := range paths(args) {
				if b := urlBase(p); b != "" {
					out = append(out, abs(b))
				}
			}
		}
	case name == "wget":
		if o, ok := flagValue('O', "--output-document"); ok {
			out = append(out, abs(o))
		} else {
			d := "."
			if p, ok := flagValue('P', "--directory-prefix"); ok {
				d = p
			}
			for _, p := range paths(args) {
				if b := urlBase(p); b != "" {
					out = append(out, abs(filepath.Join(d, b)))
				}
			}
		}
	case name == "sort":
		if o, ok := flagValue('o', "--output"); ok {
			out = append(out, abs(o))
		}
	case name == "base64" || name == "openssl" || name == "gpg" || name == "age":
		if o, ok := flagValue('o', "--output"); ok {
			out = append(out, abs(o))
		}
	case name == "xxd" || name == "uniq":
		// xxd -r IN OUT and uniq IN OUT write the second operand.
		if ps := paths(args); len(ps) >= 2 {
			out = append(out, abs(ps[1]))
		}
	case name == "yq" || name == "gsed":
		if has("-i", "--inplace", "--in-place") {
			for _, p := range paths(args) {
				out = append(out, abs(p))
			}
		}
	case name == "gzip" || name == "gunzip" || name == "bzip2" || name == "bunzip2" || name == "xz" || name == "unxz" || name == "zstd" || name == "unzstd" || name == "compress" || name == "uncompress":
		// In place unless -c writes to stdout: the file is replaced, and
		// decompressing writes the name without its suffix.
		if !has("-c", "--stdout", "--to-stdout") {
			dec := strings.HasPrefix(name, "un") || name == "gunzip" || name == "bunzip2" || has("-d", "--decompress", "--uncompress")
			for _, p := range paths(args) {
				out = append(out, abs(p))
				if dec {
					for _, suf := range []string{".gz", ".bz2", ".xz", ".zst", ".Z", ".z"} {
						if strings.HasSuffix(p, suf) {
							out = append(out, abs(strings.TrimSuffix(p, suf)))
						}
					}
				}
			}
		}
	case name == "zip":
		if ps := paths(args); len(ps) > 0 {
			out = append(out, abs(ps[0]))
			if has("-m", "--move") || clusterHas(args, 'm') {
				for _, p := range ps[1:] {
					out = append(out, abs(p))
				}
			}
		}
	case name == "find":
		if has("-delete") || execRemoves(args) {
			// The global options come first (-P -H -L -Ox -D opts -f PATH,
			// BSD -s -x -E -X), then the starting points.
			for i := 0; i < len(args); i++ {
				t := args[i].Text
				switch {
				case t == "-P" || t == "-H" || t == "-L" || t == "-s" || t == "-x" || t == "-E" || t == "-X" || t == "-d" || strings.HasPrefix(t, "-O") && len(t) > 2:
					continue
				case t == "-D" || t == "-f":
					if t == "-f" && i+1 < len(args) && args[i+1].Resolved {
						out = append(out, abs(args[i+1].Text))
					}
					i++
					continue
				}
				if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
					break
				}
				if args[i].Resolved {
					out = append(out, abs(t))
				}
			}
		}
	case name == "git":
		out = append(out, gitTargets(args, dir, home)...)
	}
	out = append(out, outputTargets(name, args, abs)...)
	if name == "aws" {
		// aws s3api get-object BUCKET KEY FILE writes FILE.
		var sub []string
		for _, w := range args {
			if !strings.HasPrefix(w.Text, "-") {
				sub = append(sub, w.Text)
			}
		}
		// Every get-* call that saves its answer takes the file as the last
		// word (apigateway get-export, iot-data get-thing-shadow, glacier
		// get-job-output, s3api get-object-torrent), and eks
		// update-kubeconfig rewrites the file --kubeconfig names.
		if len(sub) >= 3 && strings.HasPrefix(sub[1], "get-") {
			out = append(out, abs(sub[len(sub)-1]))
		}
		for i, w := range args {
			if k, v, eq := strings.Cut(w.Text, "="); k == "--kubeconfig" && eq && v != "" {
				out = append(out, abs(v))
			} else if w.Text == "--kubeconfig" && i+1 < len(args) && args[i+1].Resolved {
				out = append(out, abs(args[i+1].Text))
			}
		}
	}
	return out
}

// outputOpts are the options by which a program writes a file other than
// the ones it reads: its report, its dump, its output. The value is the
// next word or follows "=". A program not listed here may have such an
// option too; ask for those is the judge's and strict shapes' job.
// tfOut are the options by which terraform and tofu write a file: a plan
// over a state file replaces it.
var tfOut = []string{"-out", "--out", "-generate-config-out", "-state-out", "-backup"}

var outputOpts = map[string][]string{
	"curl":           {"-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii", "--stderr", "--libcurl"},
	"wget":           {"-O", "--output-document", "-o", "--output-file", "-a", "--append-output"},
	"tree":           {"-o", "--output"},
	"tfsec":          {"--out", "-O", "--output-file"},
	"terraform-docs": {"--output-file"},
	"trivy":          {"-o", "--output"},
	"checkov":        {"--output-file-path"},
	"tflint":         {"--out", "--output-file"},
	"infracost":      {"--out-file"},
	"go":             {"-o", "-outputdir", "-modfile", "-overlay", "-coverprofile", "-cpuprofile", "-memprofile", "-trace"},
	"gofmt":          {},
	"git":            {"--output"},
	"find":           {"-fprint", "-fprint0", "-fprintf", "-fls"},
	"terraform":      tfOut, "tofu": tfOut, "terragrunt": tfOut,
	"fd": {},
}

// outputTargets returns the files a program's output options name.
func outputTargets(name string, args []shell.Word, abs func(string) string) []string {
	opts := outputOpts[name]
	if len(opts) == 0 && name != "git" {
		return nil
	}
	var out []string
	for i, w := range args {
		t := w.Text
		if !w.Resolved {
			continue
		}
		k, v, eq := strings.Cut(t, "=")
		for _, o := range opts {
			match := k == o
			// GNU long options may be abbreviated to any unique prefix.
			if !match && name == "git" && strings.HasPrefix(o, "--") && len(k) >= 5 && strings.HasPrefix(o, k) {
				match = true
			}
			if !match && !eq && len(o) == 2 && o[0] == '-' && !strings.HasPrefix(t, "--") && len(t) > 2 && t[:2] == o {
				// -ofile
				out = append(out, abs(t[2:]))
				continue
			}
			if !match {
				continue
			}
			switch {
			case eq && v != "":
				out = append(out, abs(v))
			case !eq && i+1 < len(args) && args[i+1].Resolved:
				out = append(out, abs(args[i+1].Text))
			}
		}
	}
	return out
}

func clusterHas(args []shell.Word, c byte) bool {
	for _, w := range args {
		t := w.Text
		if len(t) > 1 && t[0] == '-' && t[1] != '-' && strings.IndexByte(t[1:], c) >= 0 {
			return true
		}
	}
	return false
}

// execRemoves reports whether find runs a remover through -exec or -execdir.
func execRemoves(args []shell.Word) bool {
	for i, w := range args {
		if (w.Text == "-exec" || w.Text == "-execdir" || w.Text == "-ok") && i+1 < len(args) && removers[shell.ProgName(args[i+1].Text)] {
			return true
		}
	}
	return false
}

// urlBase is the file name a download of u is saved under.
func urlBase(u string) string {
	if !strings.Contains(u, "://") {
		return ""
	}
	u, _, _ = strings.Cut(u, "?")
	u, _, _ = strings.Cut(u, "#")
	b := path.Base(u)
	if b == "" || b == "." || b == "/" || strings.Contains(b, ":") {
		return ""
	}
	return b
}

// gitTargets returns the paths a git command replaces or removes in the
// working tree: mv and rm arguments, paths checked out or restored from
// another ref, and the whole tree for apply, am and stash pop or apply.
func gitTargets(args []shell.Word, dir, home string) []string {
	base := dir
	i := 0
	for i < len(args) {
		t := args[i].Text
		switch {
		case t == "-C" && i+1 < len(args):
			base = absPath(base, args[i+1].Text, home)
			i += 2
			continue
		case t == "-c" && i+1 < len(args):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return nil
	}
	sub, rest := args[i].Text, args[i+1:]
	abs := func(p string) string { return absPath(base, p, home) }
	// The commands that rewrite the work tree rewrite all of it, not the
	// directory they run in: a state file anywhere in the repository.
	root := func() string { return repoRoot(abs(".")) }
	var out []string
	afterDashes := func() []string {
		var ps []string
		seen := false
		for _, w := range rest {
			if w.Text == "--" {
				seen = true
				continue
			}
			if seen && w.Resolved {
				ps = append(ps, abs(w.Text))
			}
		}
		return ps
	}
	switch sub {
	case "mv", "rm":
		for _, w := range rest {
			if w.Resolved && !strings.HasPrefix(w.Text, "-") {
				out = append(out, abs(w.Text))
			}
		}
	case "checkout", "reset":
		for _, w := range rest {
			// These replace the working tree with the committed one,
			// modified state files included.
			if sub == "reset" && (w.Text == "--hard" || w.Text == "--keep" || w.Text == "--merge") ||
				sub == "checkout" && (w.Text == "-f" || w.Text == "--force" || w.Text == "-B" || w.Text == "--discard-changes" || w.Text == "--merge") {
				out = append(out, root())
			}
		}
		if sub == "checkout" {
			// git checkout REV switches the work tree to REV; with -b NEW
			// only a start point does.
			pos, newBranch := 0, false
			for _, w := range rest {
				switch {
				case w.Text == "--":
				case w.Text == "-b" || w.Text == "-B":
					newBranch = true
				case !strings.HasPrefix(w.Text, "-"):
					pos++
				}
			}
			if pos > 0 && (!newBranch || pos > 1) {
				out = append(out, root())
			}
		}
		out = append(out, afterDashes()...)
		if sub == "checkout" {
			// "git checkout ref path": without --, an argument that is a
			// guard file or holds one is a path being restored.
			for _, w := range rest {
				if w.Resolved && !strings.HasPrefix(w.Text, "-") && w.Text != "--" {
					out = append(out, abs(w.Text))
				}
			}
		}
	case "restore":
		for _, w := range rest {
			if w.Resolved && !strings.HasPrefix(w.Text, "-") && w.Text != "--" {
				out = append(out, abs(w.Text))
			}
		}
	case "clean", "checkout-index", "read-tree", "merge", "pull", "rebase", "cherry-pick", "revert", "switch":
		out = append(out, root())
	case "apply", "am":
		out = append(out, root())
	case "stash":
		if len(rest) == 0 || rest[0].Text == "pop" || rest[0].Text == "apply" || rest[0].Text == "push" || rest[0].Text == "save" || strings.HasPrefix(rest[0].Text, "-") {
			out = append(out, root())
		}
	}
	return out
}

// IsProtectedPath reports whether p is a guard file by pattern alone, with
// symlinks and case resolved as the guard package does.
func IsProtectedPath(p string, patterns []string) bool {
	return guard.New(patterns, nil).Protected(p) || matchAny(filepath.ToSlash(filepath.Clean(p)), patterns)
}

func matchAny(p string, patterns []string) bool {
	for _, pat := range patterns {
		if MatchGlob(pat, p) {
			return true
		}
	}
	return false
}

// MatchGlob matches slash paths against patterns supporting *, ? and **.
// A pattern without a leading slash matches any suffix of the path.
func MatchGlob(pattern, p string) bool { return guard.MatchGlob(pattern, p) }

// selfTamper returns why an applygate command changes applygate itself, or
// "". Only a person approves a call, applies a plan through applygate,
// installs or removes the hook, or turns telemetry on or off. loose is false
// for a program that may not be applygate at all: only argument shapes no
// other tool uses count then.
func selfTamper(args []shell.Word, loose bool) string {
	pos := positional(args)
	if len(pos) == 0 {
		return ""
	}
	has := func(flag string) bool {
		for _, w := range args {
			if w.Text == flag || strings.HasPrefix(w.Text, flag+"=") {
				return true
			}
		}
		return false
	}
	switch pos[0] {
	case "approve":
		if loose || (len(pos) == 2 && hexID.MatchString(pos[1])) {
			return "approves a call applygate stopped, which only a person may do"
		}
	case "apply":
		if loose || has("--plan-json") || has("--engine") {
			return "applies a plan through applygate, whose confirmation only a person may give"
		}
	case "hook":
		if len(pos) >= 2 && (pos[1] == "install" || pos[1] == "remove" || pos[1] == "uninstall") && (loose || has("--agent") || has("--scope")) {
			return "changes applygate's hook installation, which only a person may do"
		}
	case "doctor":
		if has("--creds") {
			return "audits the credentials on this machine, which runs their credential helpers and calls the cloud: only a person may run it"
		}
	case "telemetry":
		if len(pos) >= 2 && (pos[1] == "on" || pos[1] == "off") {
			return "changes applygate's telemetry setting, which only a person may do"
		}
	case "trust":
		if loose || len(pos) == 1 || has("--cwd") {
			return "trusts a repository config, which only a person who reviewed it may do"
		}
	case "install", "uninstall":
		if loose || has("--managed") {
			return "changes applygate's own installation"
		}
	case "init", "disable":
		// --no-hooks and --scope are applygate's own flags.
		if loose || has("--no-hooks") || has("--scope") {
			return "changes applygate's own installation"
		}
	}
	return ""
}

var hexID = regexp.MustCompile(`^[0-9a-f]{8}$`)

// plantsCommand reports a program's own command that writes, into a config
// file outside the repository, a command the program runs later: a global
// git config key that runs a command, a gh or glab shell alias or pager,
// a kubeconfig exec credential plugin, an aws credential_process or pager.
// Plain calls of these programs in a protected tier would then run it.
func plantsCommand(inv shell.Invocation) string {
	if len(inv.Args) < 2 || !inv.Args[0].Resolved {
		return ""
	}
	var ws []string
	for _, w := range inv.Args[1:] {
		ws = append(ws, w.Text)
	}
	has := func(s ...string) bool {
		for _, w := range ws {
			for _, x := range s {
				if w == x || strings.HasPrefix(w, x+"=") {
					return true
				}
			}
		}
		return false
	}
	n := shell.ProgName(inv.Args[0].Text)
	// pos are the positional words, the values of the program's valued
	// options left out (aws --region X, kubectl --context X, gh -R X).
	valued := map[string]bool{}
	switch n {
	case "aws":
		valued = toSet("--profile", "--region", "--output", "--endpoint-url", "--query", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--color")
	case "kubectl":
		valued = toSet("-n", "--namespace", "--context", "--cluster", "--user", "-s", "--server", "--kubeconfig", "--as", "--as-group", "--token", "--request-timeout", "-v")
	case "gh", "glab":
		valued = toSet("-R", "--repo", "--hostname")
	}
	pos := func() []string {
		var out []string
		for i := 0; i < len(ws); i++ {
			w := ws[i]
			if strings.HasPrefix(w, "-") {
				if valued[w] {
					i++
				}
				continue
			}
			out = append(out, w)
		}
		return out
	}()
	switch {
	case n == "git":
		// git [-C dir] [-c k=v] ... config ...: the global options first.
		args := inv.Args[1:]
		for len(args) > 0 && strings.HasPrefix(args[0].Text, "-") {
			if t := args[0].Text; (t == "-C" || t == "-c" || t == "--git-dir" || t == "--work-tree" || t == "--namespace") && len(args) > 1 {
				args = args[1:]
			}
			args = args[1:]
		}
		if len(args) > 0 && args[0].Text == "replace" {
			for _, w := range args[1:] {
				if w.Text == "-l" || w.Text == "--list" || w.Text == "--format" {
					return ""
				}
			}
			// refs/replace makes git read other content for any object, a
			// lock file included, without changing a commit or a branch.
			return "git replace changes what git reads for an object"
		}
		if len(args) == 0 || args[0].Text != "config" {
			return ""
		}
		op, why := shell.GitConfigOp(args[1:])
		if op.Scope == "" {
			// The repository's own config: a key that runs a command, an
			// alias that is a shell command or a value off the safe list
			// makes the next plain git call run it, from wherever the
			// repository is. That is tampering in every tier, not only
			// where strict shapes asks.
			if op.Write && !shell.GitSafeKey(op.Key, op.Value, true) {
				return "git config " + op.Key + " in the repository sets something git runs later"
			}
			// Which branch is upstream is what the provider lock check trusts.
			if op.Write && strings.HasPrefix(op.Key, "branch.") && (strings.HasSuffix(op.Key, ".remote") || strings.HasSuffix(op.Key, ".merge") || strings.HasSuffix(op.Key, ".pushremote")) {
				return "git config " + op.Key + " re-points the upstream branch the provider lock check trusts"
			}
			return ""
		}
		if why != "" && why != "git config --edit runs an editor" {
			return "git config outside the repository: " + why
		}
		if why != "" || op.Write && !shell.GitSafeKey(op.Key, op.Value, true) {
			return "git config " + op.Key + " outside the repository may set a command git runs later"
		}
	case (n == "gh" || n == "glab") && len(pos) >= 2 && pos[0] == "alias" && pos[1] != "list":
		return n + " alias " + pos[1] + " defines a command " + n + " runs later"
	case (n == "gh" || n == "glab") && len(pos) >= 3 && pos[0] == "config" && pos[1] == "set" &&
		(pos[2] == "pager" || pos[2] == "editor" || pos[2] == "browser"):
		return n + " config set " + pos[2] + " names a program " + n + " runs later"
	case n == "kubectl" && len(pos) >= 2 && pos[0] == "config" && pos[1] == "set-credentials" && (has("--exec-command") || has("--auth-provider")):
		return "kubectl config set-credentials writes an exec credential plugin kubectl runs later"
	case n == "kubectl" && len(pos) >= 3 && pos[0] == "config" && pos[1] == "set" && strings.Contains(pos[2], ".exec"):
		return "kubectl config set writes an exec credential plugin kubectl runs later"
	case n == "aws" && len(pos) >= 3 && pos[0] == "configure" && pos[1] == "set" &&
		(strings.Contains(pos[2], "credential_process") || strings.Contains(pos[2], "cli_pager")):
		return "aws configure set " + pos[2] + " names a program aws runs later"
	}
	return ""
}

// isSelf reports whether p is the running applygate binary or one next to
// it, compared as files so a hard link or a copy's original counts.
func isSelf(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	for _, e := range guard.Executable() {
		if est, err := os.Stat(e); err == nil && os.SameFile(st, est) {
			return true
		}
	}
	// A copy under another name: the same size and the same content as the
	// running binary.
	self := selfDigest()
	return self.size > 0 && st.Size() == self.size && fileDigest(p) == self.sum
}

var selfOnce struct {
	once sync.Once
	size int64
	sum  string
}

func selfDigest() *struct {
	once sync.Once
	size int64
	sum  string
} {
	selfOnce.once.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		if fi, err := os.Stat(exe); err == nil {
			selfOnce.size, selfOnce.sum = fi.Size(), fileDigest(exe)
		}
	})
	return &selfOnce
}

func fileDigest(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// knownProgram reports whether name is a common program whose own
// subcommands share names with applygate's (git apply, npm init, terraform
// apply), so its arguments are never read as applygate's.
func knownProgram(name string) bool {
	switch name {
	case "git", "npm", "pnpm", "yarn", "bun", "npx", "go", "cargo", "terraform", "tofu", "terragrunt", "kubectl", "helm", "oc",
		"aws", "az", "gcloud", "gsutil", "pulumi", "cdk", "make", "gh", "glab", "docker", "podman", "brew", "pip", "pip3", "poetry", "uv",
		"claude", "codex", "pre-commit", "husky", "lefthook", "rails", "rake", "mix", "dotnet", "flux", "argocd", "kustomize":
		return true
	}
	return false
}

// positional returns the arguments that are not flags.
func positional(args []shell.Word) []string {
	var out []string
	for _, w := range args {
		if !strings.HasPrefix(w.Text, "-") {
			out = append(out, w.Text)
		}
	}
	return out
}

// readOnlyUse reports whether a program, as called, only reads the files it
// names, so naming a guard file is fine.
func readOnlyUse(name string, args []shell.Word) bool {
	has := func(flags ...string) bool {
		for _, w := range args {
			for _, f := range flags {
				if w.Text == f || strings.HasPrefix(w.Text, f+"=") {
					return true
				}
			}
		}
		return false
	}
	first := ""
	for _, w := range args {
		if !strings.HasPrefix(w.Text, "-") {
			first = w.Text
			break
		}
	}
	switch name {
	case "cat", "head", "tail", "less", "more", "ls", "stat", "file", "wc", "diff", "cmp", "test", "[", "sha256sum",
		"shasum", "md5sum", "sha1sum", "readlink", "realpath", "basename", "dirname", "du", "echo", "printf",
		"bat", "strings", "od", "hexdump", "jq", "grep", "egrep", "fgrep", "ack", "ag", "which", "type", "command":
		return true
	case "rg":
		return !has("--pre", "--pre-glob")
	case "yq":
		return !inPlaceEdit(args)
	case "tree":
		return !has("-o", "--output")
	case "find", "fd":
		return !has("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls", "-x", "-X", "--exec", "--exec-batch")
	case "git":
		switch first {
		case "status", "log", "diff", "show", "blame", "ls-files", "add", "commit", "cat-file", "ls-tree", "check-ignore", "check-attr", "rev-parse":
			// --output=FILE writes it, and git takes any unique prefix.
			for _, w := range args {
				if k, _, _ := strings.Cut(w.Text, "="); len(k) >= 5 && strings.HasPrefix("--output", k) || k == "-o" && first != "add" {
					return false
				}
			}
			return true
		}
	case "applygate", "seatbelt":
		switch first {
		case "check", "explain", "doctor", "report", "hosts", "version", "selftest", "plan-check":
			return true
		case "suggest":
			return !has("--out")
		}
	}
	return false
}

// namesGuard returns the guard path a command names, or "". A path counts
// when it is a guard file or lies in a guarded directory; a directory that
// holds a guard file counts only for a program that writes, removes or
// extracts. Words that cannot be resolved count when their literal text
// names a guard file, or when they are a glob that could match one.
func namesGuard(name string, args []shell.Word, dir string, opt Options) string {
	if opt.Guard == nil || readOnlyUse(name, args) {
		return ""
	}
	changes := writers[name] || removers[name] || copiers[name] || (name == "sed" || name == "gsed" || name == "perl" || name == "ruby" || name == "yq") && inPlaceEdit(args) || name == "tar" || name == "bsdtar" || name == "gtar" ||
		name == "unzip" || name == "7z" || name == "cpio" || name == "pax" || name == "find" || name == "fd" || name == "git" ||
		name == "busybox" || name == "toybox"
	var needles []string
	for _, w := range args {
		if name == "git" && strings.HasPrefix(w.Text, ":") && len(w.Text) > 1 && w.Text[1] != ':' {
			// A pathspec with magic: :(top).claude and :/.claude are from the
			// repository root, :(glob)**/settings.json is a pattern.
			rest, top := gitMagic(w.Text)
			if rest != "" || top {
				base := dir
				if top {
					base = repoRoot(dir)
				}
				p := absPath(base, rest, opt.Home)
				if strings.ContainsAny(rest, "*?[") {
					// A pattern may reach any directory of the repository.
					if opt.Guard.GlobTouches(p) || opt.Guard.GlobTouches(absPath(repoRoot(dir), rest, opt.Home)) {
						return w.Text
					}
				} else if opt.Guard.Protected(p) || changes && opt.Guard.Touches(p) {
					return p
				}
			}
			continue
		}
		if w.Resolved {
			// The word, and each part of a list (100644,sha,.applygate.yaml)
			// or an option value (--out=~/.claude/settings.json).
			for _, part := range append([]string{w.Text}, strings.FieldsFunc(w.Text, func(r rune) bool { return r == ',' || r == '=' || r == ':' })...) {
				if part == "" || part == "-" || strings.HasPrefix(part, "-") && part == w.Text {
					continue
				}
				p := absPath(dir, part, opt.Home)
				if opt.Guard.Protected(p) || changes && opt.Guard.Touches(p) {
					return p
				}
			}
			continue
		}
		t := w.Text
		if strings.ContainsAny(t, "*?[") {
			if opt.Guard.GlobTouches(absPath(dir, t, opt.Home)) {
				return t
			}
		}
		// A word with a part that is not known (${E:-settings.json}, $(…),
		// $X) after a literal prefix may be any name that starts with it.
		if pre := w.Prefix; changes && pre != "" {
			if i := strings.LastIndex(pre, "="); i >= 0 && (strings.HasPrefix(pre, "-") || strings.HasPrefix(pre, "of=")) {
				pre = pre[i+1:] // --output=~/.claude/${X}, of=~/.claude/${X}
			}
			if pre != "" && opt.Guard.GlobTouches(absPath(dir, pre+"*", opt.Home)) {
				return w.Prefix + "<?>"
			}
		}
		if needles == nil {
			needles = opt.Guard.Needles(opt.Home)
		}
		ft := guard.Fold(t)
		for _, n := range needles {
			if strings.Contains(ft, n) {
				return w.Prefix + "<?>" + strings.TrimPrefix(t, w.Prefix)
			}
		}
		// $XDG_CONFIG_HOME/applygate, ${DIR}/seatbelt: applygate's own
		// directories, named by the variable the hook itself reads.
		if changes && (strings.HasSuffix(ft, "/applygate") || strings.HasSuffix(ft, "/seatbelt")) {
			return t
		}
	}
	return ""
}

// gitMagic splits a git pathspec with magic (:(top,glob)path, :/path,
// :!path) into the path and whether it is from the repository root. Excluding
// magic (:!, :^, :(exclude)) names nothing.
func gitMagic(spec string) (path string, top bool) {
	rest := spec[1:]
	switch {
	case strings.HasPrefix(rest, "("):
		end := strings.Index(rest, ")")
		if end < 0 {
			return "", false
		}
		for _, m := range strings.Split(rest[1:end], ",") {
			switch m {
			case "top":
				top = true
			case "exclude":
				return "", false
			}
		}
		return rest[end+1:], top
	case strings.HasPrefix(rest, "/"):
		return rest[1:], true
	case strings.HasPrefix(rest, "!") || strings.HasPrefix(rest, "^"):
		return "", false
	}
	return rest, false
}

// packageTamper reports a package manager that removes, replaces or
// downgrades applygate itself: brew uninstall applygate, go install
// …/cmd/applygate@v0.1.0, pip uninstall applygate. A hook whose binary is
// gone fails open on several hosts.
func packageTamper(name string, args []shell.Word) string {
	mutating := map[string]bool{"uninstall": true, "remove": true, "rm": true, "erase": true, "purge": true, "upgrade": true,
		"reinstall": true, "install": true, "unlink": true, "link": true, "switch": true, "pin": true, "clean": true, "cleanup": true,
		"autoremove": true, "update": true, "add": true, "i": true, "un": true, "r": true}
	switch name {
	case "brew", "go", "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "cargo", "gem", "port", "apt", "apt-get", "dnf", "yum",
		"pacman", "apk", "nix-env", "nix", "uv", "mise", "asdf", "scoop", "choco", "winget", "snap", "launchctl":
	default:
		return ""
	}
	if name == "launchctl" {
		for _, w := range args {
			if w.Text == "setenv" || w.Text == "putenv" || w.Text == "unsetenv" {
				return "launchctl " + w.Text + " changes the environment every later session, and its hook, starts with"
			}
		}
		return ""
	}
	sub := ""
	named := false
	for _, w := range args {
		t := strings.ToLower(w.Text)
		if !w.Resolved {
			t = strings.ToLower(w.Prefix)
		}
		if sub == "" && !strings.HasPrefix(t, "-") {
			sub = t
			continue
		}
		if strings.Contains(t, "applygate") || strings.Contains(t, "seatbelt") {
			named = true
		}
	}
	if named && mutating[sub] {
		return name + " " + sub + " changes the applygate binary the hook runs, which only a person may do"
	}
	return ""
}

// configWritten reports whether an earlier write covers Terraform directory
// dir: the directory or one above it (a tree extracted, copied, checked
// out), or a file under it that Terraform reads (configuration, variables,
// .terraform, the lock file, state) or a path with no extension, which may
// be a directory of modules. A plan -out is left to the plan gate.
func configWritten(written []string, origin map[string]string, dir string) bool {
	d := guard.Fold(filepath.Clean(dir))
	for _, w := range written {
		if w == writtenUnknown {
			continue
		}
		w = guard.Fold(filepath.Clean(w))
		if origin[w] != "" {
			continue // a plan -out: the plan gate follows where it came from
		}
		if w == d || strings.HasPrefix(d, w+string(filepath.Separator)) {
			return true
		}
		rel, ok := strings.CutPrefix(w, d+string(filepath.Separator))
		if !ok {
			continue
		}
		b := filepath.Base(rel)
		if strings.HasPrefix(rel, ".terraform"+string(filepath.Separator)) || rel == ".terraform" || !strings.Contains(b, ".") || tfFile(b) {
			return true
		}
	}
	return false
}

// tfFile reports a file name Terraform or OpenTofu reads in a directory.
func tfFile(b string) bool {
	for _, s := range []string{".tf", ".tofu", ".tf.json", ".tofu.json", ".tfvars", ".tfvars.json", ".tfstate", ".tfstate.backup", ".hcl"} {
		if strings.HasSuffix(b, s) {
			return true
		}
	}
	return b == ".terraformrc" || b == "terraform.rc"
}

// gitTreeWrites returns the working tree a git command rewrites without
// naming paths: switching branches, merging, resetting, rebasing, pulling,
// cherry-picking and reverting.
func gitTreeWrites(args []shell.Word, dir, home string) []string {
	base := dir
	i := 0
	for i < len(args) {
		t := args[i].Text
		switch {
		case t == "-C" && i+1 < len(args):
			if !args[i+1].Resolved {
				return []string{writtenUnknown}
			}
			base = absPath(base, args[i+1].Text, home)
			i += 2
			continue
		case (t == "-c" || t == "--git-dir" || t == "--work-tree") && i+1 < len(args):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(args) || base == "" {
		return nil
	}
	switch args[i].Text {
	case "checkout", "switch", "merge", "reset", "rebase", "pull", "cherry-pick", "revert", "am", "apply", "stash", "restore", "worktree", "read-tree", "clean", "sparse-checkout", "update-index", "submodule":
		return []string{base}
	}
	return nil
}

// stateWrites classifies a program that overwrites, removes or copies a
// Terraform state file as state surgery, once in the directory it writes
// and once in the directory of each state file it copies from: a state
// copied out of a protected directory carries that tier.
func stateWrites(base Action, name string, args []shell.Word, dir string, opt Options) []Action {
	var targets, sources []string
	var pos []string
	for _, w := range args {
		if w.Resolved && w.Text != "" && !strings.HasPrefix(w.Text, "-") {
			pos = append(pos, absPath(dir, w.Text, opt.Home))
		}
	}
	switch {
	case copiers[name] || name == "mv" || name == "ln":
		// -t DIR, -tDIR, --target-directory DIR and --target-directory=DIR
		// name the destination; the words that are left are the sources.
		if td, rest, ok := targetDirectory(args); ok && name != "rsync" && name != "ditto" {
			args = rest
			pos = pos[:0]
			for _, w := range args {
				if w.Resolved && w.Text != "" && !strings.HasPrefix(w.Text, "-") {
					pos = append(pos, absPath(dir, w.Text, opt.Home))
				}
			}
			if td.Resolved {
				pos = append(pos, absPath(dir, td.Text, opt.Home))
			} else {
				args = append(append([]shell.Word(nil), args...), td)
			}
		}
		// A glob among the sources is expanded here, as the shell will do.
		for i, w := range args {
			if w.Resolved || strings.HasPrefix(w.Text, "-") || !strings.ContainsAny(w.Text, "*?[") || i == len(args)-1 {
				continue
			}
			ms, _ := filepath.Glob(absPath(dir, w.Text, opt.Home))
			if len(pos) == 0 {
				pos = append(pos, ms...)
				continue
			}
			pos = append([]string(nil), append(pos[:len(pos)-1], append(ms, pos[len(pos)-1])...)...)
		}
		if len(args) == 0 {
			return nil
		}
		if last := args[len(args)-1]; !last.Resolved {
			// cp x terraform.tf*: the destination is whatever the glob matches.
			for _, m := range globMatches(last, dir, opt.Home) {
				if isStateFile(m) {
					pos = append(pos, m)
					break
				}
			}
		}
		if len(pos) < 2 {
			return nil
		}
		dst := pos[len(pos)-1]
		for _, p := range pos[:len(pos)-1] {
			if isStateFile(p) {
				sources = append(sources, p)
			} else if sf := stateUnder(p); sf != "" {
				// cp -a ../prod/. . copies the state files in the directory.
				sources = append(sources, sf)
			} else if filepath.Base(p) == "terraform.tfstate.d" {
				sources = append(sources, filepath.Join(p, "terraform.tfstate"))
			}
		}
		if isStateFile(dst) {
			targets = append(targets, dst)
		} else if filepath.Base(dst) == "terraform.tfstate.d" && len(sources) > 0 {
			targets = append(targets, filepath.Join(dst, "terraform.tfstate"))
		} else if fi, err := os.Stat(dst); len(sources) > 0 && err == nil && fi.IsDir() {
			targets = append(targets, filepath.Join(dst, filepath.Base(sources[0])))
		} else if len(sources) > 0 && name == "mv" {
			targets = append(targets, sources...)
		}
		if name == "mv" {
			targets = append(targets, sources...)
			// Moving a directory takes the state files in it along.
			for _, p := range pos[:len(pos)-1] {
				if sf := stateUnder(p); sf != "" {
					targets = append(targets, sf)
				}
			}
		}
	case writers[name] || (name == "sed" || name == "gsed" || name == "perl" || name == "ruby" || name == "yq") && inPlaceEdit(args):
		for _, p := range pos {
			if isStateFile(p) {
				targets = append(targets, p)
			} else if removers[name] || name == "mv" || name == "rmdir" || name == "shred" {
				// Removing or moving a directory takes the state files in it.
				if sf := stateUnder(p); sf != "" {
					targets = append(targets, sf)
				} else if filepath.Base(p) == "terraform.tfstate.d" {
					targets = append(targets, filepath.Join(p, "terraform.tfstate"))
				}
			}
		}
		// A glob is expanded here, as the shell will: rm -f terraform.tfstate*
		for _, w := range args {
			if w.Resolved || strings.HasPrefix(w.Text, "-") || !strings.ContainsAny(w.Text, "*?[") {
				continue
			}
			ms, _ := filepath.Glob(absPath(dir, w.Text, opt.Home))
			for _, m := range ms {
				if isStateFile(m) {
					targets = append(targets, m)
				} else if sf := stateUnder(m); (removers[name] || name == "mv") && sf != "" {
					targets = append(targets, sf)
				}
			}
		}
	default:
		// Any other program that writes or removes what writeTargets
		// knows: a state file it names, or a directory it extracts into,
		// cleans or rewrites that holds one.
		for _, t := range writeTargets(name, args, dir, opt.Home) {
			if isStateFile(t) {
				targets = append(targets, t)
			} else if sf := stateUnder(t); sf != "" {
				targets = append(targets, sf)
			}
		}
		// sort -o terraform.tf* x: a glob that matches a state file stands
		// for it where the program writes.
		for i, w := range args {
			for _, m := range globMatches(w, dir, opt.Home) {
				if !isStateFile(m) {
					continue
				}
				a2 := append([]shell.Word(nil), args...)
				a2[i] = shell.Word{Text: m, Resolved: true, Prefix: m}
				for _, t := range writeTargets(name, a2, dir, opt.Home) {
					if isStateFile(t) {
						targets = append(targets, t)
					}
				}
			}
		}
		if len(targets) > 0 {
			var out []Action
			seen := map[string]bool{}
			for _, t := range targets {
				d := filepath.Dir(t)
				if seen[d] {
					continue
				}
				seen[d] = true
				a := base
				a.Dir, a.AnyDir = d, false
				a.Class, a.Engine, a.TouchesState = StateSurgery, "file", true
				a.Why = name + " changes or may replace state file " + t
				out = append(out, a)
			}
			return out
		}
	}
	if len(targets) == 0 {
		return nil
	}
	// A new copy (a backup) changes no state in use. Overwriting a state
	// file, or copying one from another directory into a Terraform
	// directory, does: the copy carries the source's tier.
	var all []string
	if len(sources) > 0 && name != "mv" {
		dst := targets[0]
		// The copy brings the configuration along when it copies a
		// directory or a .tf file too: the destination is then a copy of
		// that environment, state included.
		cfg := false
		for _, p := range pos[:len(pos)-1] {
			if fi, err := os.Stat(p); err == nil && (fi.IsDir() || tfFile(filepath.Base(p)) && !strings.Contains(p, ".tfstate")) {
				cfg = true
			}
		}
		into := filepath.Dir(dst) != filepath.Dir(sources[0]) && (tfDir(filepath.Dir(dst)) || cfg)
		switch {
		case into:
			all = append(all, dst)
			all = append(all, sources...)
		case overwrites(dst):
			all = append(all, dst)
		}
		if len(all) == 0 {
			return nil
		}
	} else {
		for _, t := range targets {
			if name == "mv" || removers[name] || overwrites(t) {
				all = append(all, t)
			}
		}
		if name == "mv" {
			all = append(all, sources...)
		}
	}
	if len(all) == 0 {
		return nil
	}
	var out []Action
	seen := map[string]bool{}
	for _, p := range all {
		d := filepath.Dir(p)
		if seen[d] {
			continue
		}
		seen[d] = true
		a := base
		a.Dir, a.AnyDir = d, false
		a.Class, a.Engine, a.TouchesState = StateSurgery, "file", true
		a.Why = name + " changes state file " + targets[0]
		if len(sources) > 0 && name != "mv" {
			a.Why = name + " writes " + targets[0] + " from state file " + sources[0]
		}
		out = append(out, a)
	}
	return out
}

// ModelledProgram reports whether the classifier reads the arguments of the
// program name: it writes, removes, copies, reads, runs code or is an engine.
// A repository config may not declare such a program a wrapper (which would
// skip the arguments the classifier reads), in its plain, g-prefixed
// (gtar, gmv) or versioned (python3.11) spelling.
func ModelledProgram(name string) bool {
	known := func(n string) bool {
		_, eng := engines[n]
		return eng || writers[n] || removers[n] || copiers[n] || readers[n] || destroysFiles[n] || stateReaders[n] || tableHandled[n] ||
			codeRunners[n] || knownProgram(n) || shell.KnownProgram(n) || n == "busybox" || n == "toybox" || n == "rename" || n == "claude" ||
			n == "codex" || n == "gemini" || n == "expect" || n == "runuser" || n == "taskset" || n == "ionice" || n == "chronic"
	}
	if known(name) || strings.HasPrefix(name, "g") && known(name[1:]) {
		return true
	}
	if base := versionSuffix.ReplaceAllString(name, ""); base != name && base != "" && known(base) {
		return true
	}
	return false
}

// versionSuffix is the version at the end of a program's file name
// (python3.11, terraform-1.5.7, node_v20).
var versionSuffix = regexp.MustCompile(`[-_]?v?[0-9][0-9.]*$`)

// stateReaders are programs that only read the files they are given (their
// options that write one are in outputOpts); naming a state file to them is
// fine. sed and awk are here for a file named as a word of its own, not for
// one named inside their script.
var stateReaders = map[string]bool{
	"cut": true, "sort": true, "tac": true, "rev": true, "nl": true, "column": true, "comm": true, "join": true, "paste": true,
	"fold": true, "wc": true, "expand": true, "unexpand": true, "fmt": true, "pr": true, "tr": true, "colrm": true, "awk": true,
	"gawk": true, "mawk": true, "nawk": true, "sed": true, "gsed": true, "uniq": true, "jless": true, "fx": true, "gron": true,
	"dasel": true, "hexdump": true, "zcat": true, "gzcat": true, "bzcat": true, "xzcat": true, "lsof": true, "fuser": true,
	"tfsec": true, "trivy": true, "checkov": true, "tflint": true, "infracost": true, "terraform-docs": true, "tree": true,
	"ls": true, "lsattr": true, "getfattr": true, "mdls": true, "xattr": true, "open": true, "code": true, "view": true,
	"hd": true, "xxd": true, "b2sum": true, "sha224sum": true, "sha384sum": true, "sha512sum": true, "cksum": true, "sum": true,
}

// tableHandled programs have their own rules for which words they write
// (writeTargets); the naming rule does not second-guess those.
var tableHandled = map[string]bool{
	"zip": true, "tar": true, "bsdtar": true, "gtar": true, "7z": true, "7za": true, "7zz": true, "7zr": true, "unzip": true, "cpio": true,
	"gzip": true, "gunzip": true, "bzip2": true, "bunzip2": true, "xz": true, "unxz": true, "zstd": true, "unzstd": true,
	"compress": true, "uncompress": true, "base64": true, "openssl": true, "gpg": true, "age": true, "patch": true, "find": true, "fd": true,
}

// codeRunners run code the analysis reads separately (or does not follow
// and asks about); the words they are given are not file operands.
var codeRunners = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "csh": true, "tcsh": true, "python": true,
	"python2": true, "python3": true, "node": true, "nodejs": true, "deno": true, "bun": true, "perl": true, "ruby": true, "php": true,
	"lua": true, "luajit": true, "tclsh": true, "swift": true, "java": true, "julia": true, "Rscript": true, "R": true, "osascript": true,
	"pwsh": true, "powershell": true, "make": true, "gmake": true, "go": true, "cargo": true, "npm": true, "pnpm": true, "yarn": true,
	"npx": true, "env": true, "xargs": true, "sudo": true, "time": true, "nohup": true, "timeout": true, "watch": true, "eval": true,
	"exec": true, "source": true, ".": true,
}

var stateToken = regexp.MustCompile("[^\\s\"'`<>|;&(){}=,:]*\\.tfstate(?:\\.backup)?")

// namedState returns a state file a program names, in any spelling: a word,
// an option's value (--out FILE, --out=FILE, -oFILE), a part of a list, or a
// file written inside a script word. "" when it names none, or when it is
// known to only read.
func namedState(name string, args []shell.Word, dir string, opt Options) string {
	if writers[name] || copiers[name] || removers[name] || name == "mv" || name == "ln" || tableHandled[name] || codeRunners[name] || readOnlyUse(name, args) {
		return ""
	}
	reader := stateReaders[name]
	check := func(c string) string {
		if c == "" || c == "-" || strings.Contains(c, "://") {
			return ""
		}
		if p := absPath(dir, c, opt.Home); isStateFile(p) {
			return p
		}
		return ""
	}
	for _, w := range args {
		if !w.Resolved || w.Text == "" {
			continue
		}
		t := w.Text
		script := strings.ContainsAny(t, " \t\n\"'`{}") // a word that holds more than a name
		if reader && !script {
			continue
		}
		if reader && name != "awk" && name != "gawk" && name != "mawk" && name != "nawk" && name != "sed" && name != "gsed" {
			continue
		}
		if strings.Contains(t, "://") {
			continue
		}
		if p := check(t); p != "" && !reader {
			return p
		}
		for _, part := range strings.FieldsFunc(t, func(r rune) bool { return r == '=' || r == ',' || r == ':' }) {
			if p := check(part); p != "" && !reader {
				return p
			}
		}
		if len(t) > 2 && t[0] == '-' && t[1] != '-' && !reader {
			if p := check(t[2:]); p != "" { // -oFILE
				return p
			}
		}
		if script {
			for _, m := range stateToken.FindAllString(t, -1) {
				if p := check(m); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

// targetDirectory finds the destination directory given by -t DIR, -tDIR,
// --target-directory DIR or --target-directory=DIR (any unique prefix of the
// long option, as GNU takes it) and returns the other words.
func targetDirectory(args []shell.Word) (shell.Word, []shell.Word, bool) {
	for i, w := range args {
		t := w.Text
		if !w.Resolved || !strings.HasPrefix(t, "-") || t == "--" {
			continue
		}
		switch {
		case t == "-t" || len(t) >= 4 && strings.HasPrefix("--target-directory", t):
			if i+1 >= len(args) {
				continue
			}
		case strings.HasPrefix(t, "--") && strings.Contains(t, "="):
			k, val, _ := strings.Cut(t, "=")
			if len(k) < 4 || !strings.HasPrefix("--target-directory", k) {
				continue
			}
			rest := append(append([]shell.Word(nil), args[:i]...), args[i+1:]...)
			return shell.Word{Text: val, Resolved: true, Prefix: val}, rest, true
		case strings.HasPrefix(t, "-t") && !strings.HasPrefix(t, "--") && len(t) > 2:
			rest := append(append([]shell.Word(nil), args[:i]...), args[i+1:]...)
			return shell.Word{Text: t[2:], Resolved: true, Prefix: t[2:]}, rest, true
		default:
			continue
		}
		rest := append(append([]shell.Word(nil), args[:i]...), args[i+2:]...)
		return args[i+1], rest, true
	}
	return shell.Word{}, nil, false
}

// inPlaceEdit reports sed's, perl's, ruby's or yq's in-place editing.
func inPlaceEdit(args []shell.Word) bool { return shell.InPlaceEdit(args) }

// tfDir reports whether d holds Terraform or OpenTofu configuration.
func tfDir(d string) bool {
	ents, err := os.ReadDir(d)
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, e := range ents {
		if n := e.Name(); tfFile(n) && !strings.Contains(n, ".tfstate") || n == ".terraform" || n == "terragrunt.hcl" {
			return true
		}
	}
	return false
}

// tarModes reports whether a tar command extracts or creates, reading its
// options as tar does: the old style (xf at the front), clusters (-xvf,
// -zxf), long options, and an option's value (-C DIR, -f FILE) skipped.
func tarModes(args []shell.Word) (extract, create bool) {
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		switch {
		case t == "--extract" || t == "--get":
			extract = true
		case t == "--create" || t == "--append" || t == "--update" || t == "--concatenate" || t == "--catenate" || t == "--delete":
			// Each writes the archive named by -f.
			create = true
		case strings.HasPrefix(t, "--"):
			if k, _, eq := strings.Cut(t, "="); !eq && (k == "--directory" || k == "--file" || k == "--files-from" || k == "--exclude-from" || k == "--transform" || k == "--use-compress-program" || k == "--to-command") {
				i++
			}
		case strings.HasPrefix(t, "-") || i == 0 && t != "":
			cluster := strings.TrimPrefix(t, "-")
			for j, ch := range cluster {
				switch ch {
				case 'x':
					extract = true
				case 'c', 'r', 'u', 'A':
					create = true
				case 'C', 'f', 'I', 'T', 'X', 'F', 'K', 'L':
					if j == len(cluster)-1 {
						i++
					}
				}
				if strings.ContainsRune("CfITXFKL", ch) {
					break
				}
			}
		}
	}
	return extract, create
}

// stateUnder returns a state file in directory d or any directory below it
// ("" when there is none): removing, moving, copying or rewriting the tree
// takes it along. The walk is bounded, and skips the caches that hold none.
func stateUnder(d string) string {
	if filepath.Base(d) == ".terraform" {
		return "" // the backend cache, not a state
	}
	n := 0
	found := ""
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if found != "" || depth > 8 || n > 20000 {
			return
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if n++; n > 20000 || found != "" {
				return
			}
			name := e.Name()
			switch {
			case !e.IsDir() && isStateFile(name):
				found = filepath.Join(dir, name)
			case e.IsDir() && name == "terraform.tfstate.d":
				found = filepath.Join(dir, name, "terraform.tfstate")
			case e.IsDir() && name != ".git" && name != ".terraform" && name != "node_modules" && name != ".cache" && name != ".venv":
				walk(filepath.Join(dir, name), depth+1)
			}
		}
	}
	walk(d, 0)
	return found
}

// repoRoot is the top of the git work tree containing dir, or dir itself.
func repoRoot(dir string) string {
	for d := dir; d != "" && d != "/" && d != "."; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return dir
}

// globMatches expands an unresolved word's glob against the file system.
func globMatches(w shell.Word, dir, home string) []string {
	if w.Resolved || !strings.ContainsAny(w.Text, "*?[") {
		return nil
	}
	ms, _ := filepath.Glob(absPath(dir, w.Text, home))
	return ms
}

// stateIn returns a state file held in directory d (or in its
// terraform.tfstate.d), "" when d holds none or is not a directory.
func stateIn(d string) string {
	if filepath.Base(d) == ".terraform" {
		return "" // the backend cache, not a state
	}
	ents, err := os.ReadDir(d)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !e.IsDir() && isStateFile(e.Name()) {
			return filepath.Join(d, e.Name())
		}
		if e.IsDir() && e.Name() == "terraform.tfstate.d" {
			return filepath.Join(d, e.Name(), "terraform.tfstate")
		}
	}
	return ""
}

// overwrites reports whether writing p replaces a state in use: an
// existing file, or the default local state file.
func overwrites(p string) bool {
	if filepath.Base(p) == "terraform.tfstate" {
		return true
	}
	_, err := os.Lstat(p)
	return err == nil || !os.IsNotExist(err)
}

// hostPackages are the agent CLIs' packages in npm and Homebrew.
var hostPackages = map[string]bool{"@anthropic-ai/claude-code": true, "@openai/codex": true, "@google/gemini-cli": true,
	"@github/copilot": true, "opencode-ai": true, "claude-code": true, "codex": true, "gemini-cli": true, "copilot-cli": true,
	"opencode": true}

// hostInstall reports a command that installs, updates or replaces an
// agent CLI: the program that reads the hook settings, managed ones
// included. A wrapper or an older release in its place can start sessions
// without the hook.
func hostInstall(name string, args []shell.Word) string {
	pos := positional(args)
	switch name {
	case "claude", "codex", "gemini", "copilot", "opencode", "cursor-agent":
		if len(pos) > 0 {
			switch pos[0] {
			case "install", "update", "upgrade", "migrate-installer":
				return name + " " + pos[0] + " replaces the agent CLI, which reads the hook settings"
			}
		}
		return ""
	case "npm", "pnpm", "yarn", "bun", "brew":
	default:
		return ""
	}
	if len(pos) == 0 {
		return ""
	}
	switch pos[0] {
	case "install", "i", "add", "update", "upgrade", "up", "reinstall", "link", "global":
	default:
		return ""
	}
	for _, p := range pos[1:] {
		pkg := p
		if j := strings.LastIndex(pkg, "@"); j > 0 {
			pkg = pkg[:j]
		}
		if hostPackages[strings.TrimPrefix(pkg, "--cask=")] {
			return name + " " + pos[0] + " " + p + " replaces an agent CLI, which reads the hook settings"
		}
	}
	return ""
}

// credFileEnv are the variables that name a credentials or kube config
// file whose entries can run a program.
var credFileEnv = []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "KUBECONFIG", "KUBE_CONFIG_PATH"}

// CredFileEnv returns the variables that name a credentials or kube config
// file.
func CredFileEnv() []string { return credFileEnv }

// patchGuard returns a guard file the patch text fed to patch or git apply
// names (the ---, +++, diff --git, rename and copy lines), at any strip
// level: patch -p0 takes the path as written, -p1 drops a component, and
// the default drops none to all depending on the version. "" when none or
// when the patch text is not known.
func patchGuard(inv shell.Invocation, args []shell.Word, opt Options) string {
	if opt.Guard == nil || inv.Stdin == "" {
		return ""
	}
	for _, line := range strings.Split(inv.Stdin, "\n") {
		var p string
		switch {
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			p = strings.TrimSpace(line[4:])
		case strings.HasPrefix(line, "rename to "), strings.HasPrefix(line, "rename from "), strings.HasPrefix(line, "copy to "):
			p = strings.TrimSpace(line[strings.LastIndex(line, " ")+1:])
		case strings.HasPrefix(line, "diff --git "):
			for _, f := range strings.Fields(line)[2:] {
				if g := patchPathGuard(f, inv.Dir, opt); g != "" {
					return g
				}
			}
			continue
		default:
			continue
		}
		// A timestamp may follow the name, after a tab.
		if i := strings.IndexByte(p, '\t'); i >= 0 {
			p = p[:i]
		}
		if g := patchPathGuard(p, inv.Dir, opt); g != "" {
			return g
		}
	}
	return ""
}

func patchPathGuard(p, dir string, opt Options) string {
	p = strings.Trim(p, "\"")
	if p == "" || p == "/dev/null" {
		return ""
	}
	for strip := 0; strip <= 6; strip++ {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		if strip >= len(parts) {
			break
		}
		rest := strings.Join(parts[strip:], "/")
		cand := rest
		if strip == 0 && strings.HasPrefix(p, "/") {
			cand = "/" + rest
		}
		abs := absPath(dir, cand, opt.Home)
		if opt.Guard.Protected(abs) {
			return abs
		}
	}
	return ""
}

func isEngine(e string) bool { return e == "terraform" || e == "tofu" || e == "terragrunt" }

// engineOutputWrites are the files a Terraform call writes that are not what
// it is for: plan -out=FILE and -generate-config-out=FILE write the file
// named whatever it holds, so naming a state file replaces it (a local state
// becomes a plan archive) from any directory.
func engineOutputWrites(base Action, inv shell.Invocation) []Action {
	var out []Action
	seen := map[string]bool{}
	args := inv.Args[1:]
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		for strings.HasPrefix(t, "--") && len(t) > 2 {
			t = t[1:]
		}
		name, v, eq := strings.Cut(t, "=")
		if name != "-out" && name != "-generate-config-out" || !args[i].Resolved {
			continue
		}
		if !eq && i+1 < len(args) {
			i++
			v = args[i].Text
		}
		if v == "" || v == "-" || inv.Dir == "" {
			continue
		}
		p := absPath(inv.Dir, v, "")
		if !isStateFile(p) || seen[p] {
			continue
		}
		seen[p] = true
		a := base
		a.Dir, a.AnyDir = filepath.Dir(p), false
		a.Class, a.Engine, a.TouchesState = StateSurgery, "file", true
		a.Why = inv.Args[0].Text + " " + name + " writes " + p + ", a state file, which it replaces with a plan"
		out = append(out, a)
	}
	return out
}
