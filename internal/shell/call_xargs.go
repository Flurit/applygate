package shell

import (
	"regexp"
	"strings"
)

// xargs runs its command template with arguments read from stdin. With -I,
// -i or -J the placeholder is replaced by each input line; otherwise the
// input's words are appended. Known stdin (echo x | xargs ...) is used as
// is; unknown stdin makes the substituted words unresolved.
func (a *analyzer) xargs(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	valued := toSet("-I", "-J", "-n", "-P", "-d", "-a", "-E", "-L", "-s", "-R", "-S", "--max-args", "--max-procs",
		"--delimiter", "--arg-file", "--max-lines", "--max-chars", "--eof")
	repl, fromFile, splits := "", false, false
	i := 0
	for i < len(rest) {
		t := rest[i].Text
		if t == "--" {
			i++
			break
		}
		if !strings.HasPrefix(t, "-") || len(t) < 2 {
			break
		}
		name, val, eq := strings.Cut(t, "=")
		// Another delimiter (-0, -d), or lines taken as units (-L): the
		// items are not the words of the input, which only the default
		// splitting gives.
		if strings.HasPrefix(t, "--") {
			for _, l := range []string{"--null", "--delimiter", "--max-lines"} {
				if len(name) >= 3 && strings.HasPrefix(l, name) {
					splits = true
				}
			}
		} else if strings.ContainsAny(name[1:], "0dL") && !strings.HasPrefix(t, "-I") && !strings.HasPrefix(t, "-J") && !strings.HasPrefix(t, "-i") && !strings.HasPrefix(t, "-a") {
			splits = true
		}
		switch {
		case name == "-I" || name == "-J":
			if i+1 < len(rest) {
				repl = rest[i+1].Text
			}
		case strings.HasPrefix(t, "-I") || strings.HasPrefix(t, "-J"):
			repl = t[2:]
		case t == "-i" || name == "--replace":
			repl = "{}"
			if eq && val != "" {
				repl = val
			}
		case strings.HasPrefix(t, "-i"):
			repl = t[2:]
		case name == "-a" || name == "--arg-file" || strings.HasPrefix(t, "-a"):
			fromFile = true
		}
		if valued[name] && !eq {
			i++
		}
		i++
	}
	r := rest[min(i, len(rest)):]
	if len(r) == 0 {
		r = lits("echo")
	}
	label := append(via, "xargs")
	input, known := in.text, in.present && in.known && !fromFile && !splits
	if repl != "" {
		var lines []string
		for _, l := range strings.Split(strings.TrimRight(input, "\n"), "\n") {
			if l = strings.TrimLeft(l, " \t"); l != "" {
				lines = append(lines, l)
			}
		}
		if !known || len(lines) == 0 || len(lines) > 32 || strings.ContainsAny(input, `"'\\`) {
			a.call(placeholders(r, repl), redirs, cmdSt, st, label, depth+1, stdin{})
			return
		}
		for _, l := range lines {
			sub := make([]Word, len(r))
			for k, w := range r {
				sub[k] = w
				if w.Resolved && strings.Contains(w.Text, repl) {
					t := strings.ReplaceAll(w.Text, repl, l)
					sub[k] = Word{Text: t, Resolved: true, Prefix: t}
				}
			}
			a.call(sub, redirs, cmdSt, st, label, depth+1, stdin{})
		}
		return
	}
	f := strings.Fields(input)
	if !known || len(f) > 64 || strings.ContainsAny(input, `"'\\`) {
		// xargs parses quotes and backslashes in its input its own way.
		a.call(append(append([]Word(nil), r...), Word{Resolved: false}), redirs, cmdSt, st, label, depth+1, stdin{})
		return
	}
	a.call(append(append([]Word(nil), r...), lits(f...)...), redirs, cmdSt, st, label, depth+1, stdin{})
}

// placeholders marks the words that contain a placeholder unresolved, with
// the text before the placeholder as their prefix.
func placeholders(ws []Word, ph ...string) []Word {
	out := make([]Word, len(ws))
	for i, w := range ws {
		out[i] = w
		for _, p := range ph {
			if j := strings.Index(w.Text, p); j >= 0 && w.Resolved {
				out[i] = Word{Text: w.Text, Prefix: w.Text[:j]}
				break
			}
		}
	}
	return out
}

// parallelPH matches GNU parallel's replacement strings: {}, {.}, {/}, {//},
// {/.}, {#}, {%}, {n} and {n.} and similar.
var parallelPH = regexp.MustCompile(`\{[0-9]*[./#%]*[./]*\}`)

// parallel handles GNU parallel: parallel [opts] [command...] [::: args].
// The command is a shell command line, run once per argument with the
// argument in place of {} (or appended). Arguments after ::: are known;
// arguments from stdin are known when stdin is. With no command, each
// argument is itself a command line.
func (a *analyzer) parallel(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	valued := map[string]bool{
		"-j": true, "--jobs": true, "-N": true, "-n": true, "-L": true, "--max-lines": true,
		"-P": true, "--delay": true, "--timeout": true, "-S": true, "--sshlogin": true,
		"--colsep": true, "-d": true, "--delimiter": true, "-I": true, "--joblog": true, "--results": true,
		"-a": true, "--arg-file": true, "--tmpdir": true, "--workdir": true, "--wd": true,
	}
	r := skipFlags(rest, valued)
	sep := -1
	for i, w := range r {
		if t := w.Text; t == ":::" || t == "::::" || t == ":::+" || t == "::::+" {
			sep = i
			break
		}
	}
	tmpl := r
	var items []Word
	known := true
	if sep >= 0 {
		tmpl = r[:sep]
		for _, w := range r[sep+1:] {
			switch w.Text {
			case ":::", ":::+":
			case "::::", "::::+":
				known = false // arguments from files
			default:
				items = append(items, w)
				known = known && w.Resolved
			}
		}
	} else {
		known = in.present && in.known
		for _, l := range strings.Split(strings.TrimRight(in.text, "\n"), "\n") {
			if l != "" {
				items = append(items, Word{Text: l, Resolved: true, Prefix: l})
			}
		}
	}
	child := st.childState()
	cs := cmdSt
	if movesDir(rest[:len(rest)-len(r)]) {
		// --wd DIR: the jobs run there.
		child.dir = ""
		cs = cmdSt.clone()
		cs.dir = ""
	}
	label := append(via, "parallel")
	if !known || len(items) > 32 || !allResolved(tmpl) {
		if len(tmpl) == 0 {
			a.problem(st, via, "parallel "+joinWords(rest), "parallel runs command lines that cannot be resolved statically")
			return
		}
		a.call(append(placeholders(tmpl, "{"), Word{Resolved: false}), redirs, cs, st, label, depth+1, stdin{})
		return
	}
	line := joinWords(tmpl)
	for _, it := range items {
		cmd := it.Text
		if len(tmpl) > 0 {
			if parallelPH.MatchString(line) {
				cmd = parallelPH.ReplaceAllLiteralString(line, it.Text)
			} else {
				cmd = line + " " + it.Text
			}
		}
		a.source(cmd, child.clone(), label, depth+1)
	}
}

// stringLit matches a single-line string literal of the common languages.
var stringLit = regexp.MustCompile("'([^'\\\\\\n]*)'|\"([^\"\\\\\\n]*)\"|`([^`]*)`")

// litGap is what may sit between two literals that form one string: a
// concatenation operator (+ or .), nothing (Python's implicit
// concatenation), or the commas and parentheses of a path join.
var litGap = regexp.MustCompile(`^[\s+.,()]*$`)

// dejoinLiterals returns the strings that runs of adjacent literals build:
// '.'+'applygate.yaml', '~/' '.' 'claude' (implicit concatenation), and
// os.path.join(home, '.claude', 'settings.json'). Literals joined by an
// operator or nothing are concatenated; at a comma the run is written once
// with a space ('ter'+'raform', 'destroy') and once with a "/" (a path
// join). The result is s followed by those strings, one per line.
func dejoinLiterals(s string) string {
	locs := stringLit.FindAllStringSubmatchIndex(s, -1)
	var out []string
	var spaced, slashed strings.Builder
	n := 0
	flush := func() {
		if n > 1 {
			out = append(out, spaced.String(), slashed.String())
		}
		spaced.Reset()
		slashed.Reset()
		n = 0
	}
	end := -1
	for _, m := range locs {
		lit := ""
		for g := 2; g < len(m); g += 2 {
			if m[g] >= 0 {
				lit = s[m[g]:m[g+1]]
			}
		}
		if end >= 0 {
			gap := s[end:m[0]]
			switch {
			case !litGap.MatchString(gap):
				flush()
			case strings.ContainsAny(gap, ",()"):
				spaced.WriteByte(' ')
				slashed.WriteByte('/')
			}
		}
		spaced.WriteString(lit)
		slashed.WriteString(lit)
		n++
		end = m[1]
	}
	flush()
	if len(out) == 0 {
		return s
	}
	return s + "\n" + strings.Join(out, "\n")
}

func (a *analyzer) reparse(r []Word, st *state, via []string, label string, depth int) {
	a.reparseIn(r, st.childState(), via, label, depth)
}

func (a *analyzer) reparseIn(r []Word, child *state, via []string, label string, depth int) {
	if len(r) == 0 {
		return
	}
	if !allResolved(r) {
		a.problem(child, via, label+" "+joinWords(r), label+" with a command that cannot be resolved statically")
		return
	}
	a.source(joinWords(r), child, append(via, label), depth+1)
}

func (a *analyzer) findExec(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) {
	for i := 0; i < len(rest); i++ {
		t := rest[i].Text
		if t != "-exec" && t != "-execdir" && t != "-ok" && t != "-okdir" && t != "-x" && t != "--exec" && t != "-X" && t != "--exec-batch" {
			continue
		}
		j := i + 1
		for j < len(rest) && rest[j].Text != ";" && rest[j].Text != "+" && rest[j].Text != `\;` {
			j++
		}
		sub := append([]Word(nil), rest[i+1:j]...)
		for k := range sub {
			// find replaces {} anywhere in an argument (-chdir={}).
			if pre, _, found := strings.Cut(sub[k].Text, "{}"); found {
				sub[k] = Word{Resolved: false, Prefix: pre, Text: pre}
			}
		}
		es := cmdSt
		if t == "-execdir" || t == "-okdir" {
			// The command runs in the directory of each file found.
			es = cmdSt.clone()
			es.dir = ""
		}
		a.call(sub, nil, es, st, append(via, "find "+t), depth+1, stdin{})
		i = j
	}
}
