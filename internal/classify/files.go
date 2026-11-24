package classify

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/shell"
)

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
	removes := removalOnly(name, args, dir, opt.Home)
	rewrite := false
	for _, t := range writeTargets(name, args, dir, opt.Home) {
		if name == "git" && opt.Guard != nil && !opt.gitTouchesHard(removes, t) {
			// Only a repository-level root (config, git or session) holds a
			// guard file here: git rewriting that work tree is asked about
			// (HookRewrite), not blocked.
			if !rewrite && opt.touchesFor(removes, t) {
				rewrite = true
				a := base
				a.Class, a.Engine = HookRewrite, "file"
				a.Why = "git rewrites " + t + ", which holds hook settings or the repository config; a commit could change them"
				out = append(out, a)
			}
			continue
		}
		if opt.touchesFor(removes, t) {
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
	if _, engine := engines[name]; engine || pathReaders[name] || shell.RemoteCopy(name, inv.Args[1:]) {
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

// writeTargets returns the paths a program writes, moves, removes or
// extracts into, as absolute paths: what its write rule in the shell package
// reads from the call (the matcher's own parse for a program with an
// allow-list entry), git's work-tree paths, and its output options.
func writeTargets(name string, args []shell.Word, dir, home string) []string {
	abs := func(p string) string { return absPath(dir, p, home) }
	var out []string
	if name == "git" {
		out = gitTargets(args, dir, home)
	} else {
		for _, w := range shell.Writes(name, args) {
			if w.Resolved && w.Text != "" && w.Text != "-" {
				out = append(out, abs(w.Text))
			}
		}
	}
	return append(out, outputTargets(name, args, abs)...)
}

// outputTargets returns the files a program's output options name.
func outputTargets(name string, args []shell.Word, abs func(string) string) []string {
	opts := shell.OutputOpts(name)
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
