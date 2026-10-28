// Package classify maps analyzed invocations and tool calls to command classes.
package classify

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Flurit/seatbelt/internal/shell"
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
	Dynamic          Class = "dynamic"
	Tampering        Class = "guard-tampering"
)

// Action is one classified, policy-relevant operation.
type Action struct {
	Class    Class
	Engine   string // terraform, tofu, terragrunt, aws, kubectl, agent, file, ""
	Command  string // the resolved command, for messages
	Why      string
	Dir      string
	Env      map[string]string
	Profile  string // AWS profile from --profile or the environment
	PlanFile string // for apply of a saved plan
	Sub      string // engine subcommand, e.g. "destroy", "state rm"
	Via      []string
	// BackendConfig holds the -backend-config values of an init (files or
	// key=value pairs). Later commands in the same directory and command
	// line run against the backend they describe, not the one recorded by
	// the previous init.
	BackendConfig []string
	// SelectWorkspace is set by "workspace select|new NAME"; later commands
	// in the same directory run in that workspace.
	SelectWorkspace string
	// TouchesState marks commands that read or write Terraform state, so
	// stale-state and backend checks apply.
	TouchesState bool
}

// Options configure classification.
type Options struct {
	// ProtectedPaths are glob patterns for guard files (hook config, seatbelt
	// config and log). Matching is on the cleaned absolute path.
	ProtectedPaths []string
	Home           string
}

var engines = map[string]string{"terraform": "terraform", "tofu": "tofu", "opentofu": "tofu", "terragrunt": "terragrunt"}

// Invocations classifies the analyzer output. Invocations that do not touch
// infrastructure or guard files produce no action.
func Invocations(res *shell.Result, opt Options) []Action {
	var out []Action
	for _, inv := range res.Invocations {
		out = append(out, invocation(inv, opt)...)
	}
	for _, p := range res.Problems {
		a := Action{Class: Dynamic, Command: p.Text, Why: p.Reason, Dir: p.Dir, Via: p.Via}
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
	return strings.Contains(m, ".claude/settings") || strings.Contains(m, "managed-settings") ||
		strings.Contains(m, ".codex/") || strings.Contains(m, ".seatbelt.")
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
	base := Action{Dir: inv.Dir, Env: inv.Env, Command: cmdText, Via: inv.Via}
	var out []Action

	// Writes to guard files through redirection, whatever the program.
	for _, r := range inv.Redirs {
		if !r.Write {
			continue
		}
		if r.Target.Resolved {
			p := absPath(inv.Dir, r.Target.Text, opt.Home)
			if IsProtectedPath(p, opt.ProtectedPaths) {
				a := base
				a.Class, a.Engine, a.Why = Tampering, "file", "redirect writes to guard file "+p
				out = append(out, a)
			} else if isStateFile(p) {
				a := base
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
		return append(out, a)
	}
	name := filepath.Base(inv.Args[0].Text)
	args := inv.Args[1:]

	if e, ok := engines[name]; ok {
		a := base
		a.Engine = e
		terraformArgs(&a, args)
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
	case "claude", "codex", "cursor-agent", "copilot", "gemini", "opencode":
		if a, ok := agentFlags(base, name, args); ok {
			out = append(out, a)
		}
		return out
	case "seatbelt":
		if len(args) >= 2 && args[0].Text == "hook" && (args[1].Text == "remove" || args[1].Text == "uninstall") ||
			len(args) >= 1 && (args[0].Text == "init" || args[0].Text == "disable") {
			a := base
			a.Class, a.Engine, a.Why = Tampering, "seatbelt", "changes seatbelt's own installation"
			out = append(out, a)
		}
		return out
	case "just", "task", "npm", "yarn", "pnpm", "bun", "mage", "invoke", "nx":
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
		if t := destructiveTarget([]shell.Word{{Text: filepath.Base(inv.Args[0].Text), Resolved: true}}); t != "" {
			a := base
			a.Class, a.Why = UnknownWrapper, "script "+inv.Args[0].Text+" looks destructive and could not be read"
			out = append(out, a)
		}
	}

	out = append(out, fileOps(base, name, args, inv.Dir, opt)...)
	return out
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
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if dir == "" {
		return filepath.Clean(p)
	}
	return filepath.Join(dir, p)
}

func isStateFile(p string) bool {
	b := filepath.Base(p)
	return strings.HasSuffix(b, ".tfstate") || strings.HasSuffix(b, ".tfstate.backup")
}

var credentialPath = regexp.MustCompile(`(^|/)\.aws/(credentials|sso/cache/|cli/cache/)|(^|/)\.terraform\.d/credentials\.tfrc\.json$|(^|/)\.terraformrc$`)

// IsCredentialPath reports whether p is a cloud or Terraform credential file.
func IsCredentialPath(p string) bool { return credentialPath.MatchString(filepath.ToSlash(p)) }

var writers = map[string]bool{
	"rm": true, "mv": true, "cp": true, "install": true, "ln": true, "tee": true, "truncate": true,
	"chmod": true, "chown": true, "chattr": true, "dd": true, "shred": true, "unlink": true, "rsync": true, "touch": true,
}

var readers = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true, "grep": true, "rg": true, "awk": true,
	"base64": true, "xxd": true, "od": true, "strings": true, "bat": true, "nl": true, "cp": true, "scp": true, "curl": true,
}

// fileOps classifies generic programs that write guard or state files or read
// credential files.
func fileOps(base Action, name string, args []shell.Word, dir string, opt Options) []Action {
	var out []Action
	inPlace := false
	if name == "sed" || name == "perl" || name == "ruby" {
		for _, w := range args {
			if strings.HasPrefix(w.Text, "-i") || w.Text == "--in-place" || strings.HasPrefix(w.Text, "-pi") {
				inPlace = true
			}
		}
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
		case isWriter && IsProtectedPath(p, opt.ProtectedPaths):
			a := base
			a.Class, a.Engine, a.Why = Tampering, "file", name+" modifies guard file "+p
			out = append(out, a)
		case isWriter && name != "cp" && isStateFile(p) && name != "rm":
			a := base
			a.Class, a.Engine, a.Why, a.TouchesState = StateSurgery, "file", name+" modifies state file "+p, true
			out = append(out, a)
		case readers[name] && IsCredentialPath(p):
			a := base
			a.Class, a.Engine, a.Why = CredentialAccess, "file", name+" reads credential file "+p
			out = append(out, a)
		}
	}
	return out
}

// IsProtectedPath reports whether p is a guard file.
func IsProtectedPath(p string, patterns []string) bool {
	s := filepath.ToSlash(filepath.Clean(p))
	for _, pat := range patterns {
		if MatchGlob(pat, s) {
			return true
		}
	}
	return false
}

// MatchGlob matches slash paths against patterns supporting *, ? and **.
// A pattern without a leading slash matches any suffix of the path.
func MatchGlob(pattern, p string) bool {
	pattern = filepath.ToSlash(pattern)
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ps := strings.Split(strings.Trim(p, "/"), "/")
	if strings.HasPrefix(pattern, "/") {
		return matchSegs(pp, ps)
	}
	for i := 0; i <= len(ps); i++ {
		if matchSegs(pp, ps[i:]) {
			return true
		}
	}
	return false
}

func matchSegs(pp, ps []string) bool {
	if len(pp) == 0 {
		return len(ps) == 0
	}
	if pp[0] == "**" {
		for i := 0; i <= len(ps); i++ {
			if matchSegs(pp[1:], ps[i:]) {
				return true
			}
		}
		return false
	}
	if len(ps) == 0 {
		return false
	}
	ok, err := filepath.Match(pp[0], ps[0])
	if err != nil || !ok {
		return false
	}
	return matchSegs(pp[1:], ps[1:])
}
