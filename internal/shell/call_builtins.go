package shell

import (
	"path/filepath"
	"strings"
)

// directoryBuiltin handles popd, dirs, cd and pushd, which move the directory
// and the directory stack the analysis tracks.
// Every return inside the switch means the call is handled; falling out of it
// leaves the call to the code after the dispatch in call0.
func (a *analyzer) directoryBuiltin(c *callCtx) (handled bool) {
	rest, bn, st := c.rest, c.bn, c.st
	handled = true
	switch bn {
	case "popd":
		// popd returns to the directory pushd left (an empty stack is an
		// error and changes nothing); +N and -N make the directory unknown.
		n := len(st.dirStack)
		switch {
		case len(rest) == 0 && n > 0:
			st.dir, st.dirStack = st.dirStack[n-1], st.dirStack[:n-1]
		case len(rest) == 0:
		case len(rest) == 1 && rest[0].Text == "-n" && n > 0:
			st.dirStack = st.dirStack[:n-1]
		default:
			st.dir, st.dirStack = "", nil
		}
		return
	case "dirs":
		for _, w := range rest {
			if w.Text == "-c" {
				st.dirStack = nil
			}
		}
		return
	case "cd", "chdir", "pushd":
		if bn == "pushd" {
			n := len(st.dirStack)
			switch {
			case len(rest) == 0 && n > 0:
				// Swaps the top two directories.
				st.dir, st.dirStack[n-1] = st.dirStack[n-1], st.dir
				return
			case len(rest) == 0:
				return
			case strings.HasPrefix(rest[0].Text, "+") || strings.HasPrefix(rest[0].Text, "-") && rest[0].Text != "--" || !rest[0].Resolved:
				// Rotating the stack, or -n: the directory is not tracked.
				st.dir, st.dirStack = "", nil
				return
			}
			st.dirStack = append(st.dirStack, st.dir)
		}
		target := ""
		ok, physical := true, false
		operands := 0
		for _, w := range rest {
			if strings.HasPrefix(w.Text, "-") && w.Resolved && w.Text != "-" {
				physical = physical || w.Text != "--" && strings.Contains(w.Text, "P")
				continue
			}
			if operands == 0 {
				target, ok = w.Text, w.Resolved
			}
			operands++
		}
		if operands > 1 {
			// zsh: cd OLD NEW replaces OLD with NEW in the working directory
			// (bash refuses). Where it lands is not the first word.
			st.dir = ""
			return
		}
		switch {
		case !ok:
			st.dir = ""
		case st.approx && target != "" && target != "~" && !strings.HasPrefix(target, "~/") && !filepath.IsAbs(target):
			// From a directory the host did not report, a relative cd leads
			// to a place that is not known.
			st.dir = ""
		case target == "" || target == "~":
			st.dir = a.opt.Env["HOME"]
		case target == "-":
			st.dir = ""
		case strings.HasPrefix(target, "~") && !strings.HasPrefix(target, "~/"):
			// ~- is OLDPWD, ~+ is PWD, ~user another home, ~N the stack.
			st.dir = ""
		case !filepath.IsAbs(target) && !dotRelative(target) && a.cdSearches(st):
			// With CDPATH set, or cdable_vars on, a bare name may go to a
			// directory elsewhere, or to a variable's value. A CDPATH from
			// the person's own environment is followed as bash does;
			// otherwise the directory is unknown.
			st.dir = a.cdPathDir(st, target)
		case st.dir == "" && !filepath.IsAbs(target):
		default:
			logical := target
			if !filepath.IsAbs(target) {
				logical = filepath.Join(st.dir, target)
			}
			st.dir = a.dirAbs(st, target)
			if filepath.IsAbs(target) {
				st.approx = false
			}
			if !physical && !samePlace(filepath.Clean(logical), st.dir) {
				// cd follows .. in the text of the path, cd -P (and set -P)
				// where a symlink really leads: which one runs is not
				// known here.
				st.dir = ""
			}
			if st.dir != "" && a.writtenAt(st.dir, true) != "" {
				// An earlier step linked, moved or extracted something
				// here: it may be a symlink to anywhere.
				st.dir = ""
			}
			if st.dir != "" && a.opt.IsDir != nil && !a.opt.IsDir(st.dir) && !a.created(st.dir) {
				// The directory does not exist: cd fails, and the shell
				// stays where it was, which the hook cannot assume the
				// command expects.
				st.dir = ""
			}
		}
		return
	}
	return false
}

// stateBuiltin handles the other shell builtins: those that change state the
// analysis follows (variables, traps, the command hash, options, aliases) and
// those that run what they are given (eval, source).
// Every return inside the switch means the call is handled; falling out of it
// leaves the call to the code after the dispatch in call0.
func (a *analyzer) stateBuiltin(c *callCtx) (handled bool) {
	args, rest, bn, st, via, depth := c.args, c.rest, c.bn, c.st, c.via, c.depth
	handled = true
	switch bn {
	case "read", "mapfile", "readarray", "getopts":
		// The variables these builtins assign hold text read at run time.
		for _, n := range assignedBy(bn, rest) {
			st.vars[n] = value{}
		}
		return
	case "declare", "typeset", "local", "export", "readonly", "nameref":
		// Reached through builtin, command or a name built at run time.
		for _, w := range rest {
			name, val, eq := strings.Cut(w.Text, "=")
			switch {
			case !w.Resolved || bn == "nameref" || strings.HasPrefix(w.Text, "-") && strings.Contains(w.Text, "n"):
				st.nameref = true
			case strings.HasPrefix(w.Text, "-") || strings.HasPrefix(w.Text, "+"):
			case eq:
				st.vars[name] = value{text: val, ok: true}
			}
		}
		return
	case "printf":
		for _, n := range assignedBy(bn, rest) {
			st.vars[n] = value{}
		}
	case "trap":
		// trap ARG SIGNAL...: ARG runs as if by eval when the signal or
		// EXIT comes. One argument, or - or "", only resets handlers.
		r := rest
		if len(r) > 0 && r[0].Text == "--" {
			r = r[1:]
		}
		if len(r) < 2 || r[0].Resolved && (r[0].Text == "-" || r[0].Text == "" || strings.HasPrefix(r[0].Text, "-")) {
			return
		}
		if !r[0].Resolved {
			a.problem(st, via, joinWords(args), "trap with a command that cannot be resolved statically")
			return
		}
		// The handler fires later, after any cd, so its directory is
		// unknown: it is judged at the most protected tier under the root.
		// It runs on a copy, since a handler's own assignments happen then.
		t := st.clone()
		t.dir = ""
		a.source(r[0].Text, t, append(via, "trap"), depth+1)
		return
	case "shift":
		n := 1
		if len(rest) > 0 {
			if !rest[0].Resolved || len(rest[0].Text) != 1 || rest[0].Text[0] < '0' || rest[0].Text[0] > '9' {
				st.params, st.paramsOK = []value{}, false
				return
			}
			n = int(rest[0].Text[0] - '0')
		}
		if st.params != nil {
			st.params = st.params[min(n, len(st.params)):]
		}
		return
	case "hash":
		// hash -p PATH NAME... makes each NAME run PATH; hash -r forgets.
		for i := 0; i < len(rest); i++ {
			switch t := rest[i].Text; {
			case t == "-r":
				st.hashed = nil
			case t == "-p" && i+1 < len(rest):
				p := rest[i+1]
				i++
				for _, n := range rest[i+1:] {
					if st.hashed == nil {
						st.hashed = map[string]Word{}
					}
					if !n.Resolved {
						// Any name may now run p.
						a.problem(st, via, "hash -p "+joinWords(rest), "hash -p binds a name that cannot be resolved statically")
						continue
					}
					st.hashed[n.Text] = p
				}
				return
			case !rest[i].Resolved:
				a.problem(st, via, "hash "+joinWords(rest), "hash with an argument that cannot be resolved statically")
				return
			case strings.Contains(t, "=") && !strings.HasPrefix(t, "-"):
				// zsh: hash NAME=PATH makes NAME run PATH.
				n, p, _ := strings.Cut(t, "=")
				if st.hashed == nil {
					st.hashed = map[string]Word{}
				}
				st.hashed[n] = Word{Text: p, Resolved: true, Prefix: p}
			}
		}
		return
	case "shopt":
		// shopt -s cdable_vars: cd NAME may go to $NAME.
		set := false
		for _, w := range rest {
			switch {
			case w.Text == "-s":
				set = true
			case w.Text == "-u":
				set = false
			case !w.Resolved || set && w.Text == "cdable_vars":
				st.cdableVars = true
			}
		}
		return
	case "set":
		// set -- a b, or set a b, replaces the positional parameters.
		for i := 0; i < len(rest); i++ {
			t := rest[i].Text
			if t == "-o" || t == "+o" {
				if i+1 < len(rest) && rest[i+1].Text == "allexport" {
					st.allexport = t == "-o"
				}
				if i+1 < len(rest) && rest[i+1].Text == "keyword" && t == "-o" {
					a.unbounded(st, via, "set -o keyword", "set -k turns words after a command into environment, which the analyzer does not follow")
				}
				i++
				continue
			}
			if rest[i].Resolved && len(t) > 1 && (t[0] == '-' || t[0] == '+') && t[1] != '-' {
				if strings.Contains(t[1:], "a") {
					st.allexport = t[0] == '-'
				}
				if t[0] == '-' && strings.Contains(t[1:], "k") {
					a.unbounded(st, via, "set "+t, "set -k turns words after a command into environment, which the analyzer does not follow")
				}
			}
			if t == "--" || !strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "+") || !rest[i].Resolved {
				if t == "--" && rest[i].Resolved {
					i++
				}
				st.params = valuesOf(rest[i:])
				st.paramsOK = true
				return
			}
		}
		return
	case "alias":
		for _, w := range rest {
			if k, v, ok := strings.Cut(w.Text, "="); ok && w.Resolved {
				st.aliases[k] = v
			}
		}
		return
	case "eval":
		if !allResolved(rest) {
			a.problem(st, via, joinWords(args), "eval of text that cannot be resolved statically")
			st.dir = "" // the text may cd
			return
		}
		a.source(joinWords(rest), st, append(via, "eval"), depth+1)
		return
	case "source", ".":
		if len(rest) == 0 {
			return
		}
		if !rest[0].Resolved {
			a.unbounded(st, via, joinWords(args), "source of a file whose name cannot be resolved (a process substitution, a variable), which may run anywhere")
			st.dir = ""
			return
		}
		b, err := a.read(st, rest[0].Text)
		if err != nil {
			a.unbounded(st, via, joinWords(args), "source of a file that cannot be read: "+err.Error())
			st.dir = ""
			return
		}
		a.source(string(b), st, append(via, "source "+rest[0].Text), depth+1)
		return
	}
	return false
}
