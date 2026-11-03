// Package classify maps analyzed invocations and tool calls to command classes.
package classify

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

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
	Dynamic          Class = "dynamic"
	Tampering        Class = "guard-tampering"
)

// Action is one classified, policy-relevant operation.
type Action struct {
	Class   Class
	Engine  string // terraform, tofu, terragrunt, aws, kubectl, agent, file, ""
	Command string // the resolved command, for messages
	Why     string
	Dir     string
	Env     map[string]string
	Profile string // AWS profile from --profile or the environment
	// Target is the cluster or cloud named on the command line: the kube
	// context of kubectl (--context) and helm (--kube-context), the gcloud
	// project (--project), the az subscription (--subscription).
	Target   string
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
	// PlanWritten is set when an earlier step of the same command wrote the
	// saved plan this action applies: what is on disk when the hook runs is
	// not what will be applied.
	PlanWritten bool
	// DataDirWritten is set when an earlier step rewrote this directory's
	// .terraform (workspace, backend): the workspace and backend recorded
	// there now are not the ones the command will use.
	DataDirWritten bool
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
	for _, inv := range res.Invocations {
		acts := invocation(inv, opt)
		for i := range acts {
			a := &acts[i]
			if a.PlanFile != "" && a.Dir != "" {
				a.PlanWritten = writtenAt(written, absPath(a.Dir, a.PlanFile, opt.Home))
			}
			if a.Engine == "terraform" || a.Engine == "tofu" || a.Engine == "terragrunt" {
				dataDir := ".terraform"
				if d := a.Env["TF_DATA_DIR"]; d != "" {
					dataDir = d
				}
				if a.Dir != "" {
					a.DataDirWritten = writtenAt(written, absPath(a.Dir, dataDir, opt.Home))
				}
			}
		}
		out = append(out, acts...)
		written = append(written, stepWrites(inv, opt)...)
	}
	for _, p := range res.Problems {
		a := Action{Class: Dynamic, Command: p.Text, Why: p.Reason, Dir: p.Dir, Via: p.Via}
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
	base := Action{Dir: inv.Dir, Env: inv.Env, Command: cmdText, Via: inv.Via}
	var out []Action

	// Writes to guard files through redirection, whatever the program.
	for _, r := range inv.Redirs {
		if !r.Write {
			continue
		}
		if r.Target.Resolved {
			p := absPath(inv.Dir, r.Target.Text, opt.Home)
			if opt.protected(p) {
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
	switch lower := strings.ToLower(name); {
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

	if e, ok := engines[name]; ok {
		a := base
		a.Engine = e
		terraformArgs(&a, args)
		if a.Class == UnknownWrapper && shell.IsBackstopVia(inv.Via) {
			// "brew install terraform tflint", "asdf install terraform
			// 1.9.0": terraform was an argument, not a command to run.
			return out
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
	case "az", "gcloud":
		if a, ok := cloudCLIArgs(base, name, args); ok {
			out = append(out, a)
		}
		return out
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
	"rmdir": true, "srm": true, "ditto": true, "sponge": true, "patch": true, "cpio": true,
	"vi": true, "vim": true, "nvim": true, "nano": true, "emacs": true, "ed": true, "ex": true, "pico": true,
}

// removers change or remove every path they are given, so a directory that
// holds a guard file counts: rm -rf ~/.claude, mv ~/.claude elsewhere.
var removers = map[string]bool{"rm": true, "rmdir": true, "srm": true, "unlink": true, "shred": true, "mv": true,
	"chmod": true, "chown": true, "chattr": true, "truncate": true, "ln": true}

// copiers write into their last argument, or the directory after -t.
var copiers = map[string]bool{"cp": true, "install": true, "rsync": true, "ditto": true}

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
	// Places the program writes, moves, removes or extracts into; a
	// directory that holds a guard file counts.
	for _, t := range writeTargets(name, args, dir, opt.Home) {
		if opt.touches(t) {
			tamper(name + " changes " + t + ", which holds a guard file")
			return out
		}
	}
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
		case isWriter && opt.protected(p):
			tamper(name + " modifies guard file " + p)
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
	name := filepath.Base(inv.Args[0].Text)
	args := inv.Args[1:]
	if _, ok := engines[name]; ok {
		for i, w := range args {
			t := w.Text
			if v, ok := strings.CutPrefix(t, "-out="); ok {
				out = append(out, absPath(inv.Dir, v, opt.Home))
			} else if t == "-out" && i+1 < len(args) {
				out = append(out, absPath(inv.Dir, args[i+1].Text, opt.Home))
			}
		}
		return out
	}
	out = append(out, writeTargets(name, args, inv.Dir, opt.Home)...)
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

// writtenAt reports whether p, or a directory holding it, is among written.
func writtenAt(written []string, p string) bool {
	p = filepath.Clean(p)
	for _, w := range written {
		w = filepath.Clean(w)
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
	case copiers[name]:
		// Only cp and install take -t DIR; rsync's -t keeps times.
		if t, ok := flagValue('t', "--target-directory"); ok && (name == "cp" || name == "install") {
			out = append(out, abs(t))
		} else if ps := paths(args); len(ps) >= 2 {
			out = append(out, abs(ps[len(ps)-1]))
		}
	case name == "tar" || name == "bsdtar" || name == "gtar":
		extract := has("-x", "--extract", "--get")
		if len(args) > 0 && !strings.HasPrefix(args[0].Text, "--") && strings.Contains(strings.TrimPrefix(args[0].Text, "-"), "x") {
			extract = true
		}
		if extract {
			if d, ok := flagValue('C', "--directory"); ok {
				out = append(out, abs(d))
			} else {
				out = append(out, abs("."))
			}
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
	case name == "find":
		if has("-delete") || execRemoves(args) {
			for _, w := range args {
				t := w.Text
				if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
					break
				}
				if w.Resolved {
					out = append(out, abs(t))
				}
			}
		}
	case name == "git":
		out = append(out, gitTargets(args, dir, home)...)
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
		if (w.Text == "-exec" || w.Text == "-execdir" || w.Text == "-ok") && i+1 < len(args) && removers[filepath.Base(args[i+1].Text)] {
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
	case "apply", "am":
		out = append(out, abs("."))
	case "stash":
		if len(rest) > 0 && (rest[0].Text == "pop" || rest[0].Text == "apply") {
			out = append(out, abs("."))
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
	case "telemetry":
		if len(pos) >= 2 && (pos[1] == "on" || pos[1] == "off") {
			return "changes applygate's telemetry setting, which only a person may do"
		}
	case "init", "disable":
		if loose {
			return "changes applygate's own installation"
		}
	}
	return ""
}

var hexID = regexp.MustCompile(`^[0-9a-f]{8}$`)

// isSelf reports whether p is the running applygate binary or one next to
// it, compared as files so a hard link or a copy's original counts.
func isSelf(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	for _, e := range guard.Executable() {
		if est, err := os.Stat(e); err == nil && os.SameFile(st, est) {
			return true
		}
	}
	return false
}

// knownProgram reports whether name is a common program whose own
// subcommands share names with applygate's (git apply, npm init, terraform
// apply), so its arguments are never read as applygate's.
func knownProgram(name string) bool {
	switch name {
	case "git", "npm", "pnpm", "yarn", "bun", "npx", "go", "cargo", "terraform", "tofu", "terragrunt", "kubectl", "helm", "oc",
		"aws", "az", "gcloud", "pulumi", "cdk", "make", "gh", "glab", "docker", "podman", "brew", "pip", "pip3", "poetry", "uv",
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
