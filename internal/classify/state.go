package classify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

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
// options that write one are in shell.OutputOpts); naming a state file to them is
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

// overwrites reports whether writing p replaces a state in use: an
// existing file, or the default local state file.
func overwrites(p string) bool {
	if filepath.Base(p) == "terraform.tfstate" {
		return true
	}
	_, err := os.Lstat(p)
	return err == nil || !os.IsNotExist(err)
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
