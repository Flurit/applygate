package shell

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// subscriptBuiltins take variable names, whose subscripts the shell
// evaluates as arithmetic.
var subscriptBuiltins = map[string]bool{"read": true, "mapfile": true, "readarray": true, "getopts": true, "declare": true,
	"typeset": true, "local": true, "export": true, "readonly": true, "unset": true, "printf": true, "test": true, "[": true, "let": true}

func (a *analyzer) env(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	es := cmdSt.clone()
	i := 0
	// optArg returns an option's argument: the rest of its own word when it
	// has one, else the next word.
	optArg := func(own string, w Word) (Word, bool) {
		if own != "" {
			return Word{Text: own, Resolved: w.Resolved, Prefix: own}, true
		}
		if i+1 < len(rest) {
			i++
			return rest[i], true
		}
		return Word{}, false
	}
	chdir := func(v Word) {
		if v.Resolved {
			es.dir = a.dirAbs(es, v.Text)
		} else {
			es.dir = ""
		}
	}
	// split runs env -S text: it has its own quoting, escapes and ${VAR},
	// so only plain words are split here.
	split := func(sw Word, next int) bool {
		if !sw.Resolved || strings.ContainsAny(sw.Text, "'\"\\$#") {
			a.problem(st, via, "env -S "+sw.Text, "env -S with text that cannot be resolved")
			return false
		}
		nr := append(lits(strings.Fields(sw.Text)...), rest[next:]...)
		a.env(nr, redirs, es, st, append(via, "env -S"), depth+1, in)
		return true
	}
	for i < len(rest) {
		w := rest[i]
		t := w.Text
		switch {
		case t == "--":
			i++
			a.call(rest[i:], redirs, es, st, append(via, "env"), depth+1, in)
			return
		case strings.HasPrefix(t, "--"):
			name, val, hasVal := strings.Cut(t, "=")
			var matches []string
			for _, o := range envLong {
				if strings.HasPrefix("--"+o, name) {
					matches = append(matches, o)
				}
			}
			own := ""
			if hasVal {
				own = val
			}
			if len(matches) > 1 {
				// An abbreviation getopt_long reports as ambiguous, or that
				// could be --chdir or --split-string: not followed.
				for _, m := range matches {
					if m == "chdir" || m == "split-string" {
						a.unbounded(st, via, joinWords(rest), "an env option that may be --chdir or --split-string")
						return
					}
				}
				i++
				continue
			}
			if len(matches) == 0 {
				i++
				continue
			}
			switch matches[0] {
			case "chdir":
				v, ok := optArg(own, w)
				if !ok {
					return
				}
				chdir(v)
				i++
			case "split-string":
				sw, ok := optArg(own, w)
				if !ok {
					return
				}
				split(sw, i+1)
				return
			case "unset", "argv0":
				v, ok := optArg(own, w)
				if matches[0] == "unset" && ok {
					delete(es.vars, v.Text)
				}
				i++
			default:
				i++
			}
		case strings.HasPrefix(t, "-") && len(t) > 1:
			// A cluster of short options: -i -0 -v take nothing; -u -C -S -P
			// -a take the rest of the word, or the next word.
			consumed := false
			for k := 1; k < len(t) && !consumed; k++ {
				switch t[k] {
				case 'u', 'C', 'S', 'P', 'a':
					v, ok := optArg(t[k+1:], w)
					if !ok {
						if t[k] == 'S' {
							return
						}
						consumed = true
						break
					}
					switch t[k] {
					case 'u':
						delete(es.vars, v.Text)
					case 'C':
						chdir(v)
					case 'S':
						split(v, i+1)
						return
					}
					consumed = true
				}
			}
			i++
		case strings.Contains(t, "=") && !strings.HasPrefix(t, "="):
			k, v, _ := strings.Cut(t, "=")
			es.vars[k] = value{text: v, ok: w.Resolved}
			es.exported[k] = true
			i++
		default:
			a.call(rest[i:], redirs, es, st, append(via, "env"), depth+1, in)
			return
		}
	}
}

// envLong are the long options of env (GNU coreutils), which getopt_long
// accepts by any unique prefix.
var envLong = []string{"ignore-environment", "null", "unset", "chdir", "split-string", "debug", "argv0", "block-signal",
	"default-signal", "ignore-signal", "list-signal-handling", "help", "version"}

// shell handles sh/bash/zsh invocations: -c strings, script files and stdin.
func (a *analyzer) shell(bn string, rest []Word, cmdSt, st *state, via []string, depth int, in stdin) {
	child := cmdSt.childState()
	var hasC, info bool
	var rcfiles []Word
	i := 0
	for i < len(rest) {
		t := rest[i].Text
		if t == "--version" || t == "--help" || t == "-h" {
			info = true
		}
		if (t == "--rcfile" || t == "--init-file") && i+1 < len(rest) {
			rcfiles = append(rcfiles, rest[i+1])
			i += 2
			continue
		}
		if t == "-o" || t == "+o" || t == "-O" || t == "+O" {
			if t == "-o" && i+1 < len(rest) && rest[i+1].Text == "allexport" {
				child.allexport = true
			}
			i += 2
			continue
		}
		if t == "--" {
			i++
			break
		}
		if strings.HasPrefix(t, "--") {
			i++
			continue
		}
		if (strings.HasPrefix(t, "-") || strings.HasPrefix(t, "+")) && len(t) > 1 {
			if strings.Contains(t[1:], "c") {
				hasC = true
			}
			if t[0] == '-' && strings.Contains(t[1:], "a") {
				child.allexport = true
			}
			i++
			continue
		}
		break
	}
	rest = rest[i:]
	a.startupFiles(bn, rcfiles, cmdSt, child, st, via, depth)
	label := bn
	switch {
	case hasC:
		if len(rest) == 0 {
			return
		}
		if !rest[0].Resolved {
			a.unbounded(st, via, bn+" -c "+rest[0].Text, bn+" -c with a command string that cannot be resolved statically, which may run anywhere")
			return
		}
		// sh -c 'cmd' arg0 arg1...: the first word after the string is $0.
		if len(rest) > 1 {
			child.arg0 = value{text: rest[1].Text, ok: rest[1].Resolved}
			child.params = valuesOf(rest[2:])
		}
		a.source(rest[0].Text, child, append(via, label+" -c"), depth+1)
	case len(rest) > 0:
		if !rest[0].Resolved {
			a.unbounded(st, via, bn+" "+joinWords(rest), bn+" running a script whose name cannot be resolved (a process substitution, a variable), which may run anywhere")
			return
		}
		b, err := a.read(st, rest[0].Text)
		if errorsIsWritten(err) {
			// Written in this command: what it does, and where (it may cd
			// anywhere), is unknown.
			a.unbounded(st, via, bn+" "+rest[0].Text, "script cannot be read: "+err.Error())
			return
		}
		if err != nil {
			a.problem(st, via, bn+" "+rest[0].Text, "script cannot be read: "+err.Error())
			return
		}
		child.params = valuesOf(rest[1:])
		child.arg0 = value{text: rest[0].Text, ok: true}
		a.source(string(b), child, append(via, bn+" "+rest[0].Text), depth+1)
	case in.present:
		if !in.known {
			a.unbounded(st, via, in.desc+" | "+bn, "text piped into "+bn+" cannot be resolved statically, which may run anywhere")
			return
		}
		a.source(in.text, child, append(via, in.desc+" | "+bn), depth+1)
	case !info:
		// A shell with no command string and no script reads commands from its
		// standard input: a descriptor opened earlier (exec <<< TEXT, exec 3<
		// FILE and <&3), a file opened for reading and writing (<>), or the
		// terminal. The analysis follows a here-document, a here-string, a
		// file and a pipe on this command only.
		a.unbounded(st, via, bn, bn+" reads its commands from its standard input, which comes from a source the analysis does not follow")
	}
}

// systemBinary reports whether p is under a directory the agent's user does
// not normally write.
func systemBinary(p string) bool {
	for _, d := range []string{"/bin/", "/sbin/", "/usr/", "/opt/homebrew/", "/System/", "/Library/", "/nix/store/", "/snap/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// isBinary reports whether a file is a compiled executable rather than
// text: an ELF, Mach-O or PE header, or a NUL byte near the start.
func isBinary(b []byte) bool {
	head := b[:min(len(b), 1024)]
	for _, magic := range [][]byte{{0x7f, 'E', 'L', 'F'}, {0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}, {'M', 'Z'}} {
		if bytes.HasPrefix(head, magic) {
			return true
		}
	}
	return bytes.IndexByte(head, 0) >= 0
}

// dotRelative reports whether a cd target starts with . or .., which cd
// takes as it is: CDPATH and cdable_vars do not apply.
func dotRelative(t string) bool {
	return t == "." || t == ".." || strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../")
}

// cdSearches reports whether cd may look a bare name up somewhere else:
// CDPATH is set (exported or not, with any value but empty) or cdable_vars
// is on.
func (a *analyzer) cdSearches(st *state) bool {
	if st.cdableVars {
		return true
	}
	if v, ok := st.vars["CDPATH"]; ok {
		return v.text != "" || !v.ok
	}
	_, inEnv := a.opt.Env["CDPATH"]
	return inEnv && a.opt.Env["CDPATH"] != ""
}

// cdPathDir is where cd NAME goes with the hook environment's CDPATH: the
// first CDPATH entry holding NAME (an empty entry or . is the current
// directory), else NAME under the current directory. It is "" (unknown)
// when the command set CDPATH or cdable_vars itself, or wrote files
// before the cd.
func (a *analyzer) cdPathDir(st *state, target string) string {
	v, set := st.vars["CDPATH"]
	if st.cdableVars || set && (!v.ok || v.text != a.opt.Env["CDPATH"]) || st.dir == "" || len(a.written) > 0 || a.writtenUnknown {
		return ""
	}
	for _, e := range strings.Split(a.opt.Env["CDPATH"], ":") {
		base := st.dir
		if e != "" && e != "." {
			if !filepath.IsAbs(e) {
				return ""
			}
			base = e
		}
		if fi, err := os.Stat(filepath.Join(base, target)); err == nil && fi.IsDir() {
			return filepath.Join(base, target)
		}
	}
	return a.abs(st, target)
}

// startupFiles runs what a shell reads before its command, in the shell's
// own state: BASH_ENV (bash without a terminal, bash -c included), ENV
// (sh, dash, ksh), ZDOTDIR's start-up files (zsh), and --rcfile or
// --init-file. A file that cannot be named or read exactly leaves what the
// shell runs unknown.
func (a *analyzer) startupFiles(bn string, rcfiles []Word, cmdSt, child, st *state, via []string, depth int) {
	var files []Word
	for _, k := range []string{"BASH_ENV", "ENV"} {
		if v, ok := cmdSt.vars[k]; ok && cmdSt.isExp(k) && (v.text != "" || !v.ok) {
			files = append(files, Word{Text: v.text, Resolved: v.ok, Prefix: v.text})
		}
	}
	if v, ok := cmdSt.vars["ZDOTDIR"]; ok && cmdSt.isExp("ZDOTDIR") && strings.HasPrefix(strings.TrimRight(bn, "0123456789.-"), "zsh") {
		if !v.ok {
			files = append(files, Word{})
		} else {
			for _, f := range []string{".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
				files = append(files, Word{Text: filepath.Join(v.text, f), Resolved: true, Prefix: filepath.Join(v.text, f)})
			}
		}
	}
	files = append(files, rcfiles...)
	for _, f := range files {
		if !f.Resolved {
			a.unbounded(st, via, bn+" start-up file "+f.Text, bn+" reads a start-up file that cannot be resolved statically")
			continue
		}
		b, err := a.read(child, f.Text)
		switch {
		case errorsIsWritten(err):
			a.unbounded(st, via, bn+" start-up file "+f.Text, bn+" reads the start-up file "+f.Text+", "+err.Error())
		case err != nil:
			// A start-up file that is not there is skipped by the shell.
		default:
			a.source(string(b), child, append(via, bn+" start-up file "+f.Text), depth+1)
		}
	}
}

var shebangShell = regexp.MustCompile(`^#!\s*(\S*/)?(env\s+)?(ba|z|da|k|mk|a)?sh\b`)

func (a *analyzer) script(name string, rest []Word, cmdSt, st *state, via []string, depth int) bool {
	b, err := a.read(st, name)
	if errorsIsWritten(err) {
		// Still recorded: the classifier judges the program by its
		// arguments too (a renamed copy of applygate). What it does, and
		// where, is unknown.
		a.unbounded(st, via, name, "script cannot be read: "+err.Error())
		return false
	}
	if err != nil {
		return false
	}
	if isBinary(b) {
		// A compiled program (/bin/rm), not a script: it is judged by its
		// name and arguments. One outside the system directories that
		// mentions an infrastructure tool (a program the agent built)
		// cannot be analyzed.
		if !systemBinary(a.abs(st, name)) {
			if m := Mentions(string(b)); len(m) > 0 {
				a.problem(st, via, name, "compiled program mentions "+strings.Join(m, ", ")+"; it cannot be analyzed")
			}
		}
		return false
	}
	src := string(b)
	first, _, _ := strings.Cut(src, "\n")
	if strings.HasPrefix(first, "#!") && !shebangShell.MatchString(first) {
		if g := a.guardIn(src); g != "" {
			a.guardProblem(st, via, name, "script in another language mentions the guard file "+g+"; cannot be analyzed", g)
		} else if m := Mentions(src); len(m) > 0 {
			a.problem(st, via, name, "script in another language mentions infrastructure tools or an AWS SDK; cannot be analyzed")
		}
		return false
	}
	child := cmdSt.childState()
	child.params = valuesOf(rest)
	child.arg0 = value{text: name, ok: true}
	a.source(src, child, append(via, "script "+name), depth+1)
	return true
}
