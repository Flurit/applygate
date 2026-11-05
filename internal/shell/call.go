package shell

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "mksh": true, "busybox": false,
	// Not POSIX shells, but their -c string and scripts start programs the
	// same way; text the bash parser cannot read is a problem.
	"fish": true, "csh": true, "tcsh": true, "yash": true, "posh": true, "elvish": true, "nu": true, "xonsh": true, "oksh": true, "loksh": true}

// base is the program name a command word runs, as lookups compare it.
func base(name string) string { return ProgName(name) }

// bypassesFunctions are the wrappers that look a program up on PATH: a shell
// function or alias of the same name is not what they run.
var bypassesFunctions = toSet("command", "exec", "builtin", "nohup", "chronic", "unbuffer", "setsid", "caffeinate", "env", "env -s",
	"timeout", "nice", "ionice", "stdbuf", "taskset", "sudo", "doas", "xargs", "find", "parallel", "chroot", "terragrunt")

// shellBuiltins act only inside the shell; their names are case-sensitive.
var shellBuiltins = toSet("cd", "chdir", "pushd", "popd", "dirs", "alias", "unalias", "eval", "source", ".", "trap", "read", "mapfile",
	"readarray", "getopts", "shift", "set", "declare", "typeset", "local", "export", "readonly", "nameref", "builtin")

// ProgName returns the program name a command word runs, as every engine,
// wrapper and interpreter lookup compares it: the base name in lower case,
// without a Windows .exe suffix. macOS and Windows file systems ignore case,
// so TERRAFORM runs terraform there; the name is folded on every platform.
func ProgName(name string) string {
	return strings.TrimSuffix(strings.ToLower(filepath.Base(name)), ".exe")
}

func lits(ss ...string) []Word {
	out := make([]Word, len(ss))
	for i, s := range ss {
		out[i] = Word{Text: s, Resolved: true, Prefix: s}
	}
	return out
}

// call handles one simple command. cmdSt carries prefix assignments; st is
// the enclosing shell state (mutated by cd, alias, and similar builtins). It
// marks the invocation of the command as followed when the command started
// others of its own that the analysis took apart.
func (a *analyzer) call(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	n0 := len(a.res.Invocations)
	a.call0(args, redirs, cmdSt, st, via, depth, in)
	if len(args) == 0 || n0 >= len(a.res.Invocations) {
		return
	}
	own, followed := -1, false
	for j := n0; j < len(a.res.Invocations); j++ {
		inv := &a.res.Invocations[j]
		if len(inv.Via) > len(via) {
			if l := inv.Via[len(via)]; (!strings.Contains(l, "(unrecognized wrapper)") || strings.Contains(l, "(runner)")) && !strings.HasPrefix(l, "alias ") && !strings.HasPrefix(l, "function ") {
				followed = true
			}
		} else if own < 0 && len(inv.Args) == len(args) && len(inv.Args) > 0 && inv.Args[0].Text == args[0].Text && len(inv.Via) == len(via) {
			own = j
		}
	}
	if own >= 0 && followed {
		a.res.Invocations[own].Followed = true
	}
}

func (a *analyzer) call0(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	if len(redirs) > 0 {
		// Redirections are applied by the shell before the command runs, so a
		// command that reduces to no program the analyzer records (env with
		// no command, cd, set, eval, trap, a wrapper with nothing to run)
		// still opens its targets: they are recorded as a write of their own
		// unless the call recorded them itself.
		n0, dir, env := len(a.res.Invocations), cmdSt.dir, cmdSt.env()
		defer func() {
			for _, inv := range a.res.Invocations[n0:] {
				if len(inv.Redirs) > 0 {
					return
				}
			}
			a.res.Invocations = append(a.res.Invocations, Invocation{Dir: dir, Approx: st.approx, Env: env, Redirs: redirs, Via: append([]string(nil), via...)})
		}()
	}
	if len(args) == 0 {
		// exec 5<>file: the redirections apply to the shell itself.
		if len(redirs) > 0 && len(via) > 0 && via[len(via)-1] == "exec" {
			a.res.Invocations = append(a.res.Invocations, Invocation{Dir: cmdSt.dir, Approx: cmdSt.approx, Env: cmdSt.env(), Redirs: redirs, Via: append([]string(nil), via...)})
		}
		return
	}
	if depth > a.opt.MaxDepth {
		a.unbounded(st, via, joinWords(args), "nesting deeper than the analyzer follows")
		return
	}
	record := func() {
		inv := Invocation{
			Args: args, Dir: cmdSt.dir, Approx: cmdSt.approx, Env: cmdSt.env(), Redirs: redirs, Via: append([]string(nil), via...),
		}
		if in.present && in.known {
			inv.Stdin = in.text
		}
		a.res.Invocations = append(a.res.Invocations, inv)
	}
	if !args[0].Resolved {
		record()
		// The program may be cd, pushd, source or eval: after it the
		// shell's directory is not known.
		st.dir = ""
		return
	}
	if p, ok := st.hashed[args[0].Text]; ok && !strings.Contains(args[0].Text, "/") {
		// hash -p PATH NAME: NAME runs PATH.
		args = append([]Word{p}, args[1:]...)
		if !p.Resolved {
			record()
			return
		}
	}
	name := args[0].Text
	bn := base(name)
	rest := args[1:]

	// Aliases expand only on unquoted names; we do not track quoting of the
	// name, so expand whenever the name matches.
	if rep, ok := st.aliases[name]; ok && !strings.Contains(name, "/") {
		a.alias(name, rep, rest, redirs, cmdSt, st, via, depth, in)
		// A bash alias takes effect for the next line of input, not for the
		// rest of the line that defines it, and the analysis does not know
		// which this is: the program of that name is followed as well.
		if hasShape(bn) || tfEngines[bn] {
			delete(st.aliases, name)
			a.call(args, redirs, cmdSt, st, via, depth, in)
			if _, redefined := st.aliases[name]; !redefined {
				st.aliases[name] = rep
			}
		}
		return
	}
	if body, ok := st.funcs[name]; ok {
		if len(via) > 0 && bypassesFunctions[viaProgram(via[len(via)-1])] {
			// command, env, exec, xargs and the wrappers that start a program
			// find the program of that name, never the function.
			a.unbounded(st, via, joinWords(args), viaProgram(via[len(via)-1])+" runs the program "+name+", not the function of that name, and the analysis does not follow both")
			return
		}
		a.function(name, body, rest, st, via, depth, in)
		return
	}

	spec, ok := a.opt.Wrappers[filepath.Base(name)]
	if !ok {
		spec, ok = a.opt.Wrappers[bn]
	}
	if ok {
		if cmd, profile, ok := configWrapper(spec, rest); ok {
			ws := cmdSt.clone()
			switch {
			case profile.Resolved && profile.Text != "":
				ws.vars["AWS_PROFILE"] = value{text: profile.Text, ok: true}
				ws.exported["AWS_PROFILE"] = true
			case profile.Text != "":
				// A profile that cannot be resolved is unknown, not absent.
				ws.vars["AWS_PROFILE"] = value{}
				ws.exported["AWS_PROFILE"] = true
			}
			a.call(cmd, redirs, ws, st, append(via, bn+" (configured wrapper)"), depth+1, in)
			return
		}
	}

	if bn == "unset" && name == bn {
		a.unset(rest, st, via)
	}
	a.noteWrites(bn, rest, cmdSt)
	a.callbackBuiltin(bn, rest, st, via, depth)
	if subscriptBuiltins[bn] {
		for _, w := range rest {
			if subscriptRuns(w) {
				a.unbounded(st, via, bn+" "+w.Text, bn+" names a variable whose subscript holds a command substitution; the shell evaluates the subscript, which runs it")
				break
			}
		}
	}

	if name != bn && shellBuiltins[bn] && !strings.Contains(name, "/") {
		// Builtins are matched exactly: CD or Source is a program lookup,
		// which on a case-insensitive disk finds at most a no-op script.
		record()
		a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
		return
	}

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
	case "tmux", "screen":
		// A command a new session, window or pane runs: tmux new-session -d
		// 'cmd', split-window, respawn-pane, run-shell; screen -dmS NAME cmd.
		// It runs in the pane's directory (-c), else one not known.
		if cmd, dir, ok := multiplexerCommand(bn, rest); ok {
			child := st.childState()
			child.dir = ""
			if dir != nil {
				if dir.Resolved {
					child.dir = a.dirAbs(st, dir.Text)
				}
			}
			a.reparseIn(cmd, child, via, bn, depth)
			return
		}
		// Keys typed into another terminal run there: tmux send-keys -t PANE
		// 'cmd' Enter, screen -X stuff 'cmd\n'. The pane's directory is not
		// known.
		if text, ok, resolved := typedText(bn, rest); ok {
			if !resolved {
				a.problem(st, via, joinWords(args), bn+" types text into another terminal that cannot be resolved statically")
				return
			}
			child := st.childState()
			child.dir = ""
			a.source(text, child, append(via, bn+" send-keys"), depth+1)
			return
		}
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
	case "exec", "command", "builtin", "nohup", "time", "chronic", "unbuffer", "setsid", "caffeinate", "noglob", "nocorrect", "-":
		if bn == "command" || bn == "type" {
			// command's own options come before the command: -v and -V look a
			// name up, and a -v after the command is that command's option.
			for _, w := range rest {
				if w.Text == "-v" || w.Text == "-V" {
					return // lookup only
				}
				if !strings.HasPrefix(w.Text, "-") || w.Text == "--" {
					break
				}
			}
		}
		a.call(skipFlags(rest, map[string]bool{"-a": true}), redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "direnv", "mise", "rtx", "asdf", "devbox", "nix", "nix-shell", "sops":
		if cmd, script, ok := envRunner(bn, rest); ok {
			if script != nil {
				if !script.Resolved {
					a.problem(st, via, joinWords(args), bn+" runs a command line that cannot be resolved statically")
					return
				}
				a.source(script.Text, cmdSt.childState(), append(via, bn), depth+1)
				return
			}
			// The environment these runners load (.envrc, mise.toml [env],
			// devbox.json, a flake's shell hook) is not read here, so any of
			// the tier signals in it is unknown, not absent.
			es := cmdSt.clone()
			for _, k := range TierEnv {
				if _, set := es.vars[k]; !set {
					es.vars[k] = value{}
					es.exported[k] = true
				}
			}
			if n := len(rest) - len(cmd); n >= 0 && movesDir(rest[:n]) {
				es.dir = "" // mise -C DIR, mise exec --cd DIR
			}
			a.call(cmd, redirs, es, st, append(via, bn), depth+1, in)
			return
		}
	case "aws-vault", "aws-okta", "gds", "saml2aws", "aws-sso", "doppler", "op", "chamber", "infisical", "dotenvx", "envchain", "aws-runas":
		if cmd, script, profile, ok := credentialWrapper(bn, rest); ok {
			// The wrapped command runs with the wrapper's credentials; the
			// profile or role it names is a tier signal like AWS_PROFILE.
			ws := cmdSt.clone()
			switch {
			case profile.Resolved && profile.Text != "":
				ws.vars["AWS_PROFILE"] = value{text: profile.Text, ok: true}
				ws.exported["AWS_PROFILE"] = true
			case profile.Text != "":
				// A profile that cannot be resolved is unknown, not absent.
				ws.vars["AWS_PROFILE"] = value{}
				ws.exported["AWS_PROFILE"] = true
			}
			if secretsRunners[bn] {
				// A secrets runner sets variables from a store the hook
				// cannot read, any of the tier signals among them.
				for _, k := range TierEnv {
					if _, set := ws.vars[k]; !set {
						ws.vars[k] = value{}
						ws.exported[k] = true
					}
				}
			}
			if script != nil {
				if !script.Resolved {
					a.problem(st, via, joinWords(args), bn+" runs a command line that cannot be resolved statically")
					return
				}
				a.source(script.Text, ws.childState(), append(via, bn), depth+1)
				return
			}
			a.call(cmd, redirs, ws, st, append(via, bn), depth+1, in)
			return
		}
		// Not a shape it knows: the backstop still looks for a standalone
		// terraform, tofu or terragrunt argument.
		record()
		a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
		return
	case "sudo", "doas":
		// sudo -D DIR and --chdir=DIR run the command in DIR (when sudoers
		// allows it): the directory is DIR, or unknown when DIR is not.
		ss := cmdSt
		for i, w := range rest {
			t := w.Text
			if !strings.HasPrefix(t, "-") {
				break
			}
			var dir Word
			switch {
			case t == "-D" && i+1 < len(rest):
				dir = rest[i+1]
			case strings.HasPrefix(t, "--chdir="):
				dir = Word{Text: strings.TrimPrefix(t, "--chdir="), Resolved: w.Resolved, Prefix: strings.TrimPrefix(t, "--chdir=")}
			case strings.HasPrefix(t, "-D") && len(t) > 2 && !strings.HasPrefix(t, "--"):
				dir = Word{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}
			default:
				continue
			}
			ss = cmdSt.clone()
			if dir.Resolved {
				ss.dir = a.dirAbs(ss, dir.Text)
			} else {
				ss.dir = ""
			}
		}
		a.call(skipFlags(rest, map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true}), redirs, ss, st, append(via, bn), depth+1, in)
		return
	case "nice", "ionice", "stdbuf", "taskset":
		valued := map[string]bool{"-n": true, "-c": true, "-p": true, "-i": true, "-o": true, "-e": true, "-w": true}
		r := skipFlags(rest, valued)
		if bn == "taskset" {
			if len(r) > 0 {
				r = r[1:] // CPU mask
			}
		}
		a.call(r, redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "flock":
		// flock [opts] FILE -c 'command line' | flock -c 'command line' FILE |
		// flock [opts] FILE command...
		for i, w := range rest {
			t := w.Text
			if cmd, ok := strings.CutPrefix(t, "--command="); ok {
				a.reparseIn([]Word{{Text: cmd, Resolved: w.Resolved, Prefix: cmd}}, cmdSt.childState(), via, "flock -c", depth)
				return
			}
			if (t == "-c" || t == "--command" || strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.HasSuffix(t, "c")) && i+1 < len(rest) {
				a.reparseIn(rest[i+1:i+2], cmdSt.childState(), via, "flock -c", depth)
				return
			}
		}
		r := skipFlags(rest, toSet("-w", "--timeout", "-E", "--conflict-exit-code"))
		if len(r) > 0 {
			r = r[1:]
		}
		if len(r) > 0 && (r[0].Text == "-c" || r[0].Text == "--command") {
			a.reparseIn(r[1:min(2, len(r))], cmdSt.childState(), via, "flock -c", depth)
			return
		}
		a.call(r, redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "su", "runuser":
		// su [opts] [-] [user [args]] -c 'command line': a login shell (-, -l)
		// starts in the user's home.
		child := cmdSt.childState()
		for i, w := range rest {
			t := w.Text
			if t == "-" || t == "-l" || t == "--login" {
				child.dir = ""
			}
			if t == "-c" || t == "--command" || t == "--session-command" {
				a.reparseIn(rest[i+1:min(i+2, len(rest))], child, via, bn+" -c", depth)
				return
			}
			if v, ok := strings.CutPrefix(t, "--command="); ok {
				a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child, via, bn+" -c", depth)
				return
			}
		}
		record()
		return
	case "conda", "mamba", "micromamba", "pixi", "uv", "poetry", "pipenv", "hatch", "pdm", "rye":
		// <tool> run [opts] command... runs the command in the environment.
		if cmd, dir, ok := envRun(rest); ok {
			es := cmdSt.clone()
			if dir != nil {
				if dir.Resolved {
					es.dir = a.dirAbs(es, dir.Text)
				} else {
					es.dir = ""
				}
			}
			a.call(cmd, redirs, es, st, append(via, bn+" run"), depth+1, in)
			return
		}
		// Options before "run" (poetry -C DIR run ...): the backstop still
		// finds a standalone engine, in a directory it no longer knows.
		record()
		a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
		return
	case "git":
		a.git(rest, cmdSt, st, via, depth)
		record()
		return
	case "scp", "sftp", "rsync":
		a.sshOptions(bn, rest, cmdSt, via, depth)
		record()
		return
	case "repeat":
		// zsh: repeat N command... runs the command N times, a cd included.
		if len(rest) >= 2 {
			a.call(rest[1:], redirs, cmdSt, st, append(via, "repeat"), depth+1, in)
			return
		}
	case "terragrunt", "tg":
		// terragrunt exec [--] CMD ARGS...: CMD runs in the unit's directory.
		if len(rest) > 0 && rest[0].Text == "exec" {
			r := rest[1:]
			for len(r) > 0 && r[0].Resolved && strings.HasPrefix(r[0].Text, "-") && r[0].Text != "--" {
				r = r[1:]
			}
			if len(r) > 0 && r[0].Text == "--" {
				r = r[1:]
			}
			if len(r) > 0 {
				record()
				a.call(r, redirs, cmdSt, st, append(via, "terragrunt exec"), depth+1, in)
				return
			}
		}
	case "timeout":
		r := skipFlags(rest, map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true})
		if len(r) > 0 {
			r = r[1:] // duration
		}
		a.call(r, redirs, cmdSt, st, append(via, "timeout"), depth+1, in)
		return
	case "env":
		a.env(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "xargs":
		a.xargs(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "watch":
		r := skipFlags(rest, map[string]bool{"-n": true, "--interval": true, "-d": false})
		a.reparse(r, st, via, "watch", depth)
		return
	case "script":
		// script [-q] [-c command] file; -c takes the command. The short flag
		// is often bundled into a cluster, e.g. "script -qc '<cmd>' out".
		for i, w := range rest {
			t := w.Text
			cFlag := t == "-c" || t == "--command" ||
				(len(t) >= 2 && t[0] == '-' && t[1] != '-' && strings.HasSuffix(t, "c"))
			if cFlag && i+1 < len(rest) {
				a.reparse(rest[i+1:i+2], st, via, "script -c", depth)
				return
			}
		}
		// BSD and macOS: script [-adkpqr] [-F pipe] [-t time] file command...
		// runs the trailing argv in a new pseudo-terminal.
		if r := skipFlags(rest, map[string]bool{"-F": true, "-t": true, "-T": true}); len(r) > 1 {
			a.call(r[1:], redirs, cmdSt, st, append(via, "script"), depth+1, in)
			return
		}
		record()
		return
	case "chroot":
		// chroot [options] newroot [command ...]; the trailing argv is a
		// command that runs inside the new root. Skip options and newroot.
		r := skipFlags(rest, map[string]bool{"--userspec": true, "--groups": true})
		if len(r) > 1 {
			a.call(r[1:], redirs, cmdSt, st, append(via, "chroot"), depth+1, in)
			return
		}
		record()
		return
	case "parallel":
		a.parallel(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "ssh":
		a.sshOptions(bn, rest, cmdSt, via, depth)
		// ssh [opts] host [command...]: the remote command runs elsewhere,
		// but we still look at it so a remote terraform destroy is not hidden.
		r := skipFlags(rest, map[string]bool{"-p": true, "-i": true, "-l": true, "-o": true, "-F": true, "-J": true, "-L": true, "-R": true, "-D": true, "-E": true, "-S": true, "-W": true, "-b": true, "-c": true, "-m": true, "-O": true, "-Q": true, "-w": true, "-B": true, "-e": true, "-I": true})
		if len(r) > 1 {
			rs := st.childState()
			rs.dir = ""
			a.reparseIn(r[1:], rs, via, "ssh "+r[0].Text, depth)
		}
		record()
		return
	case "find", "fd":
		a.findExec(rest, redirs, cmdSt, st, via, depth)
		record()
		return
	case "make", "gmake":
		if a.make(args, cmdSt, st, via, depth) {
			return
		}
		record()
		return
	case "docker", "podman", "nerdctl":
		a.container(args, redirs, cmdSt, st, via, depth)
		record()
		return
	}

	if shells[bn] || bn == "busybox" && len(rest) > 0 && shells[rest[0].Text] {
		if bn == "busybox" {
			rest = rest[1:]
		}
		a.shell(bn, rest, cmdSt, st, via, depth, in)
		return
	}
	if lang := langOf(bn); lang != "" {
		a.foreign(bn, lang, args, cmdSt, st, via, in)
		record()
		return
	}
	// A path to a script: read it and analyze it as shell when it is one.
	if strings.Contains(name, "/") {
		if a.script(name, rest, cmdSt, st, via, depth) {
			return
		}
	}
	// Backstop for wrappers applygate does not know: a standalone terraform,
	// tofu or terragrunt argument starts the command the wrapper would run.
	record()
	a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
}

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

func (a *analyzer) foreign(bn, lang string, args []Word, cmdSt, st *state, via []string, in stdin) {
	// literal is true when the whole body is known: resolved code
	// arguments, a resolved here-document or here-string, or a file on
	// disk. Text piped in from a decoder or built from variables is never
	// a plain file edit.
	codes, script, rest, stdinCode := interpArgs(lang, args[1:])
	var code string
	literal := true
	for _, c := range codes {
		if !c.Resolved {
			a.problem(st, via, bn+" "+joinWords(args[1:]), bn+" runs code that cannot be resolved statically")
			return
		}
	}
	switch {
	case len(codes) > 0:
		parts := make([]string, len(codes))
		for i, c := range codes {
			parts[i] = c.Text
		}
		code = strings.Join(parts, "\n")
	case script != nil:
		if !script.Resolved {
			a.problem(st, via, bn+" "+joinWords(args[1:]), bn+" runs a script whose name cannot be resolved statically")
			return
		}
		b, err := a.read(st, script.Text)
		if err != nil {
			if errorsIsWritten(err) {
				a.problem(st, via, bn+" "+script.Text, bn+" runs "+script.Text+", "+err.Error())
				return
			}
			// No file to read: the arguments are all there is to look at.
			code, literal = joinWords(args[1:]), false
			break
		}
		code = string(b)
	case stdinCode && in.present:
		code, literal = in.text, in.known && !strings.HasPrefix(in.desc, "output of")
	default:
		// No code argument found: a mention anywhere in the arguments
		// still counts.
		code, literal = joinWords(args[1:]), false
	}
	// Interpreter code is opaque, so the only signal is a textual mention. A
	// tool name split across string-literal concatenation (e.g. 'ter'+'raform',
	// "terra"."form") hides from a plain scan, so also test a form with those
	// joins collapsed.
	// Code that names a guard file is tampering, whether or not it also
	// mentions an infrastructure tool.
	if g := a.guardIn(code); g != "" {
		a.guardProblem(st, via, bn+" "+code, bn+" code mentions the guard file "+g+"; it cannot be analyzed", g)
		return
	}
	mentions := Mentions(code)
	for _, m := range Mentions(dejoinLiterals(code)) {
		if !slices.Contains(mentions, m) {
			mentions = append(mentions, m)
		}
	}
	if len(mentions) == 0 {
		return
	}
	if lang == "awk" && !awkRuns.MatchString(code) {
		// An awk program starts commands only through system(), getline
		// from a command, or print into a pipe.
		return
	}
	// A body that mentions a tool but cannot run anything is a file edit
	// (interp.go): note it instead of asking.
	if literal {
		if why, ok := a.fileOnly(bn, code, rest, st.dir); ok {
			a.note(bn + " code mentions " + strings.Join(mentions, ", ") + " but " + why + "; treated as a file edit")
			return
		} else if why != "" {
			a.problem(st, via, bn+" "+code, bn+" code mentions infrastructure tools, an AWS SDK or guard files; it cannot be analyzed ("+why+")")
			return
		}
	}
	a.problem(st, via, bn+" "+code, bn+" code mentions infrastructure tools, an AWS SDK or guard files; it cannot be analyzed")
}

var awkRuns = regexp.MustCompile(`\bsystem\s*\(|\|\s*getline|\|&|print[f]?\b[^;}]*\|`)

// langOf names the interpreter family of a program, or "".
func langOf(bn string) string {
	switch t := strings.TrimRight(bn, "0123456789.-"); t {
	case "python", "pypy", "py":
		return "python"
	case "perl":
		return "perl"
	case "ruby", "jruby", "truffleruby":
		return "ruby"
	case "node", "nodejs":
		return "node"
	case "deno", "bun", "php", "osascript", "expect", "julia":
		return t
	case "pwsh", "powershell":
		return "pwsh"
	case "awk", "gawk", "mawk", "nawk", "goawk":
		return "awk"
	case "lua", "luajit":
		return "lua"
	case "tclsh", "wish", "jimsh":
		return "tcl"
	case "rscript":
		return "r"
	}
	return ""
}

// interpArgs finds the code an interpreter runs from its arguments: the
// code options (python -c, perl and ruby -e also inside a cluster such as
// -we or -Ic, node --eval and -p, ...), else the script path, the first
// argument that is not an option. stdinCode is true when neither is given
// and the interpreter reads its program from stdin. rest is what the body
// receives as arguments.
func interpArgs(lang string, args []Word) (codes []Word, script *Word, rest []Word, stdinCode bool) {
	// codeFlags are the short options whose value is code; inCluster says
	// whether they may end a cluster of short flags (-Ic, -we). valued are
	// the options that take a separate value; attach are the short options
	// whose value may follow them in the same word (-Idir).
	var codeFlags, valued, longCode map[string]bool
	attach := ""
	switch lang {
	case "python":
		codeFlags, valued, attach = toSet("c"), toSet("-W", "-X", "--check-hash-based-pycs"), "WX"
	case "perl":
		codeFlags, attach = toSet("e", "E"), "IMmxiF0lCdD"
	case "ruby":
		codeFlags, valued, attach = toSet("e"), toSet("-I", "-r", "-C", "-E"), "IrCEFi0lxTWK"
	case "node", "bun":
		codeFlags, valued = toSet("e", "p"), toSet("-r", "--require", "--import", "--loader", "--input-type", "-C", "--conditions", "--env-file")
		longCode = toSet("--eval", "--print")
	case "php":
		codeFlags, valued = toSet("r", "B", "R", "E"), toSet("-d", "-c", "-z", "-t", "-f")
	case "osascript":
		codeFlags, valued = toSet("e"), toSet("-l", "-s")
	case "expect":
		codeFlags, valued = toSet("c"), toSet("-f")
	case "lua":
		codeFlags, valued = toSet("e"), toSet("-l")
	case "r":
		codeFlags = toSet("e")
	case "julia":
		codeFlags, valued = toSet("e", "E"), toSet("-L", "-J", "-p", "-t", "--load", "--sysimage", "--procs", "--threads")
		longCode = toSet("--eval", "--print")
	case "awk":
		valued = toSet("-F", "-v", "-f", "-i", "-l", "-E", "--field-separator", "--assign", "--file", "--include", "--load", "--exec")
		longCode = toSet("-e", "--source")
	case "tcl":
		valued = toSet("-encoding")
	}
	switch lang {
	case "deno":
		// deno eval CODE; deno run [options] SCRIPT
		for i, w := range args {
			if w.Text == "eval" && i+1 < len(args) {
				for j := i + 1; j < len(args); j++ {
					if !strings.HasPrefix(args[j].Text, "-") {
						return []Word{args[j]}, nil, args[j+1:], false
					}
				}
			}
		}
		return nil, nil, args, false
	case "pwsh":
		return pwshArgs(args)
	}
	progFiles := false
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := w.Text
		if !w.Resolved && !strings.HasPrefix(w.Prefix, "-") {
			if script == nil && len(codes) == 0 && !progFiles {
				return codes, &args[i], args[i+1:], false
			}
			break
		}
		name, val, eq := strings.Cut(t, "=")
		switch {
		case t == "--":
			if len(codes) == 0 && !progFiles && i+1 < len(args) && lang != "awk" {
				return codes, &args[i+1], args[i+2:], false
			}
			if lang == "awk" && len(codes) == 0 && !progFiles && i+1 < len(args) {
				return []Word{args[i+1]}, nil, args[i+2:], false
			}
			return codes, nil, args[i+1:], false
		case t == "-":
			return codes, nil, args[i+1:], len(codes) == 0
		case longCode[name]:
			if eq {
				codes = append(codes, Word{Text: val, Resolved: w.Resolved, Prefix: val})
			} else if i+1 < len(args) {
				codes = append(codes, args[i+1])
				i++
			}
		case lang == "awk" && (name == "-f" || name == "--file" || name == "-E" || name == "--exec"):
			progFiles = true
			i++
		case lang == "python" && t == "-m":
			// A module runs: its arguments are all there is to look at.
			return codes, nil, args[i+1:], false
		case valued[name] && !eq:
			i++
		case strings.HasPrefix(t, "--") || !strings.HasPrefix(t, "-") || len(t) < 2:
			if strings.HasPrefix(t, "--") {
				continue
			}
			if len(codes) > 0 || progFiles {
				return codes, nil, args[i:], false
			}
			if lang == "awk" {
				return []Word{w}, nil, args[i+1:], false
			}
			return codes, &args[i], args[i+1:], false
		default:
			// A cluster of short options: a code flag takes the rest of
			// the word or the next argument; an attach option takes the
			// rest of the word.
			for k := 1; k < len(t); k++ {
				c := t[k : k+1]
				if codeFlags[c] {
					if v := t[k+1:]; v != "" {
						codes = append(codes, Word{Text: v, Resolved: w.Resolved, Prefix: v})
					} else if i+1 < len(args) {
						codes = append(codes, args[i+1])
						i++
					}
					break
				}
				if strings.Contains(attach, c) {
					if k == len(t)-1 && valued["-"+c] {
						i++
					}
					break
				}
			}
		}
	}
	if len(codes) > 0 {
		return codes, nil, nil, false
	}
	return nil, nil, nil, !progFiles
}

// pwshArgs finds the code of pwsh and powershell: -Command (any prefix of
// it, any case) takes the rest of the line; -EncodedCommand is base64 of
// UTF-16 text; -File names a script.
func pwshArgs(args []Word) (codes []Word, script *Word, rest []Word, stdinCode bool) {
	for i, w := range args {
		t := strings.ToLower(w.Text)
		if !strings.HasPrefix(t, "-") || len(t) < 2 {
			// powershell.exe treats bare arguments as a command.
			return args[i:], nil, nil, false
		}
		switch n := t[1:]; {
		case strings.HasPrefix("command", n):
			return args[i+1:], nil, nil, false
		case n == "e" || n == "ec" || strings.HasPrefix("encodedcommand", n) && len(n) > 1:
			if i+1 < len(args) {
				if c, ok := decodeUTF16Base64(args[i+1]); ok {
					return []Word{c}, nil, nil, false
				}
				return []Word{{Prefix: ""}}, nil, nil, false
			}
		case strings.HasPrefix("file", n):
			if i+1 < len(args) {
				return nil, &args[i+1], args[i+2:], false
			}
		}
	}
	return nil, nil, nil, true
}

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

// container unwraps "docker run ... <image> args" when the image is a
// Terraform or OpenTofu image, so the arguments are classified as such.
func (a *analyzer) container(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) {
	// The subcommand: the first word that is not an option, and "container"
	// or "compose" are followed by theirs. Only run, create and exec start a
	// command in a container; the image of run and create is the first word
	// after the options that is not an option's value, and exec has a
	// container name instead. A later word that mentions terraform (the text
	// of sh -c, a path in the container) is not an image.
	sub, start := "", 0
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i].Text, "-") {
			continue
		}
		if sub == "" && (args[i].Text == "container" || args[i].Text == "compose") {
			sub = args[i].Text
			continue
		}
		sub, start = args[i].Text, i+1
		break
	}
	switch sub {
	case "run", "create", "exec":
	default:
		return
	}
	skip := false
	for i, w := range args {
		if i < start {
			continue
		}
		if skip {
			skip = false
			continue
		}
		// An option's value (-e TF_DATA_DIR=..., -v ...:/terraform) is not
		// the image; an image name has no "=".
		if t := w.Text; strings.HasPrefix(t, "-") {
			skip = !strings.Contains(t, "=") && containerValued[t]
			continue
		}
		if strings.Contains(w.Text, "=") {
			continue
		}
		if sub == "exec" {
			// The first word is the container; what follows runs inside it,
			// where the host's directory and mounts do not map back.
			if r := args[i+1:]; len(r) > 0 && tfEngines[base(r[0].Text)] {
				cs := cmdSt.clone()
				cs.dir = ""
				a.call(r, redirs, cs, st, append(via, args[0].Text+" exec"), depth+1, stdin{})
			}
			return
		}
		img := strings.ToLower(w.Text)
		engine := ""
		switch {
		case strings.Contains(img, "terragrunt"):
			engine = "terragrunt"
		case strings.Contains(img, "opentofu") || strings.Contains(img, "/tofu"):
			engine = "tofu"
		case strings.Contains(img, "terraform"):
			engine = "terraform"
		}
		if engine == "" || strings.HasPrefix(img, "-") {
			return
		}
		r := args[i+1:]
		if len(r) > 0 && (base(r[0].Text) == "terraform" || base(r[0].Text) == "tofu" || base(r[0].Text) == "terragrunt") {
			r = r[1:]
		}
		cs := cmdSt.clone()
		var toHost func(string) (string, bool)
		opts := splitShortOpts(args[1:i])
		cs.dir, toHost = a.containerDir(opts, cmdSt)
		// The container's environment: -e NAME=VALUE sets a variable,
		// -e NAME passes the host's (unknown here), and --env-file sets
		// what a file says, any tier signal among them.
		for k := 0; k < len(opts); k++ {
			t := opts[k].Text
			f, v, eq := strings.Cut(t, "=")
			switch f {
			case "-e", "--env":
				var e Word
				if eq {
					e = Word{Text: v, Resolved: opts[k].Resolved}
				} else if k+1 < len(opts) {
					k++
					e = opts[k]
				}
				name, val, has := strings.Cut(e.Text, "=")
				switch {
				case name == "":
				case !e.Resolved || !has:
					cs.vars[name] = value{}
				default:
					if hp, ok := toHost(val); ok {
						val = hp
					} else if strings.HasPrefix(val, "/") {
						cs.vars[name] = value{}
						cs.exported[name] = true
						continue
					}
					cs.vars[name] = value{text: val, ok: true}
				}
				cs.exported[name] = true
			case "--env-file":
				if !eq {
					k++
				}
				for _, n := range TierEnv {
					cs.vars[n] = value{}
					cs.exported[n] = true
				}
			}
		}
		// Absolute paths in the arguments are the container's: those under
		// a mount are the host paths it maps, others are not on the host.
		r = append([]Word(nil), r...)
		for k, x := range r {
			name, val, eq := strings.Cut(x.Text, "=")
			p := x.Text
			if eq && strings.HasPrefix(name, "-") {
				p = val
			}
			if !x.Resolved || !strings.HasPrefix(p, "/") {
				continue
			}
			if hp, ok := toHost(p); ok {
				if eq && strings.HasPrefix(name, "-") {
					r[k] = Word{Text: name + "=" + hp, Resolved: true, Prefix: name + "=" + hp}
				} else {
					r[k] = Word{Text: hp, Resolved: true, Prefix: hp}
				}
			} else {
				r[k] = Word{Text: strings.TrimSuffix(x.Text, p), Prefix: strings.TrimSuffix(x.Text, p)}
			}
		}
		a.call(append(lits(engine), r...), redirs, cs, st, append(via, args[0].Text+" image "+w.Text), depth+1, stdin{})
		return
	}
}

// splitShortOpts rewrites a short option glued to its value, alone or at the
// end of a cluster of flags (-eNAME=val, -ieNAME=val, -w/dir, -vSRC:DST), into
// the option and its value as two words, the way the program reads them.
func splitShortOpts(opts []Word) []Word {
	const flags, valued = "itdqPD", "evwupl"
	var out []Word
	for _, w := range opts {
		t := w.Text
		if len(t) < 3 || t[0] != '-' || t[1] == '-' {
			out = append(out, w)
			continue
		}
		k := 1
		for k < len(t) && strings.IndexByte(flags, t[k]) >= 0 {
			k++
		}
		if k >= len(t) || strings.IndexByte(valued, t[k]) < 0 {
			out = append(out, w)
			continue
		}
		for _, f := range t[1:k] {
			out = append(out, Word{Text: "-" + string(f), Resolved: true, Prefix: "-" + string(f)})
		}
		out = append(out, Word{Text: "-" + string(t[k]), Resolved: true, Prefix: "-" + string(t[k])})
		if rest := t[k+1:]; rest != "" {
			out = append(out, Word{Text: rest, Resolved: w.Resolved, Prefix: rest})
		}
	}
	return out
}

// containerDir is the host directory a container's command runs in: the
// mount source under its working directory (-v SRC:DST -w DST/sub), or ""
// (unknown) when that cannot be followed. Without both a mount and a
// working directory the command runs in the image's own directory, which is
// not the host's either.
func (a *analyzer) containerDir(opts []Word, cmdSt *state) (string, func(string) (string, bool)) {
	type mount struct{ src, dst string }
	var mounts []mount
	wd, ok := "", true
	val := func(i int, name string) (string, int) {
		t := opts[i].Text
		if v, found := strings.CutPrefix(t, name+"="); found {
			ok = ok && opts[i].Resolved
			return v, i
		}
		if i+1 < len(opts) {
			ok = ok && opts[i+1].Resolved
			return opts[i+1].Text, i + 1
		}
		return "", i
	}
	for i := 0; i < len(opts); i++ {
		t := opts[i].Text
		f, _, _ := strings.Cut(t, "=")
		switch f {
		case "-v", "--volume":
			v, j := val(i, f)
			i = j
			src, dst, found := strings.Cut(v, ":")
			if found {
				dst, _, _ = strings.Cut(dst, ":")
				mounts = append(mounts, mount{src, dst})
			}
		case "--mount":
			v, j := val(i, f)
			i = j
			var m mount
			for _, kv := range strings.Split(v, ",") {
				k, x, _ := strings.Cut(kv, "=")
				switch k {
				case "src", "source":
					m.src = x
				case "dst", "destination", "target":
					m.dst = x
				}
			}
			mounts = append(mounts, m)
		case "-w", "--workdir":
			wd, i = val(i, f)
		}
	}
	toHost := func(p string) (string, bool) {
		if !ok {
			return "", false
		}
		best := -1
		for k, m := range mounts {
			if m.src == "" || m.dst == "" {
				continue
			}
			if p == m.dst || strings.HasPrefix(p, strings.TrimSuffix(m.dst, "/")+"/") {
				if best < 0 || len(m.dst) > len(mounts[best].dst) {
					best = k
				}
			}
		}
		if best < 0 {
			return "", false
		}
		m := mounts[best]
		rel := strings.TrimPrefix(strings.TrimPrefix(p, m.dst), "/")
		return a.abs(cmdSt, filepath.Join(m.src, rel)), true
	}
	if !ok || wd == "" || !path.IsAbs(wd) {
		return "", toHost
	}
	d, _ := toHost(wd)
	return d, toHost
}

// skipFlags drops leading options; valued names consume the next word.
func skipFlags(ws []Word, valued map[string]bool) []Word {
	i := 0
	for i < len(ws) {
		t := ws[i].Text
		if t == "--" {
			return ws[i+1:]
		}
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		if valued[t] {
			i += 2
			continue
		}
		i++
	}
	if i > len(ws) {
		return nil
	}
	return ws[i:]
}

func valuesOf(ws []Word) []value {
	out := make([]value, len(ws))
	for i, w := range ws {
		out[i] = value{text: w.Text, ok: w.Resolved}
	}
	return out
}

func allResolved(ws []Word) bool {
	for _, w := range ws {
		if !w.Resolved {
			return false
		}
	}
	return true
}

func joinWords(ws []Word) string {
	parts := make([]string, len(ws))
	for i, w := range ws {
		if w.Resolved {
			parts[i] = w.Text
		} else {
			parts[i] = w.Prefix + "<?>"
		}
	}
	return strings.Join(parts, " ")
}

var mentionRe = regexp.MustCompile(`(?i)\bapplygate\W+(approve|trust|telemetry\W+o(n|ff)|init|disable|hook\W+(remove|uninstall)|(un)?install|doctor\W+--creds)\b|\b(terraform|tofu|terragrunt|kubectl)\b|\baws\s+[a-z0-9-]+\s+[a-z0-9-]+|\.claude/settings|managed-settings|\.codex/(hooks\.json|config\.toml)|\.applygate\.ya?ml|\.seatbelt\.ya?ml|\.aws/credentials|\.tfstate\b|\b(boto3|botocore|aws-sdk)\b|@aws-sdk/|github\.com/aws/aws-sdk-go`)

// Mentions returns the infrastructure or guard-file words found in text.
func Mentions(text string) []string {
	m := mentionRe.FindAllString(text, 8)
	if len(m) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range m {
		s = strings.ToLower(strings.Join(strings.Fields(s), " "))
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// credentialWrapper finds the command that a credential or secrets runner
// executes, and the AWS profile or role it runs it under:
//
//	aws-vault exec PROFILE [--] cmd     aws-okta exec PROFILE [--] cmd
//	gds aws ROLE [--] cmd               aws-runas PROFILE cmd
//	saml2aws exec [--exec-profile P] [--] cmd
//	aws-sso exec [-p P] [--] cmd        envchain NAMESPACE cmd
//	doppler run [flags] [--] cmd        op run [flags] [--] cmd
//	chamber exec SERVICE... -- cmd      infisical run [flags] [--] cmd
//	dotenvx run [flags] [--] cmd
//	doppler|infisical run [flags] --command 'command line'
//
// A command line given as one string is returned in script instead. ok is
// false when the arguments do not have that shape (for example "aws-vault
// list" or "op read"), in which case nothing is executed.
func credentialWrapper(bn string, rest []Word) (cmd []Word, script *Word, profile Word, ok bool) {
	sub := map[string]string{"aws-vault": "exec", "aws-okta": "exec", "gds": "aws", "saml2aws": "exec",
		"aws-sso": "exec", "doppler": "run", "op": "run", "chamber": "exec", "infisical": "run", "dotenvx": "run"}
	if want, has := sub[bn]; has {
		if len(rest) == 0 || rest[0].Text != want {
			return nil, nil, Word{}, false
		}
		rest = rest[1:]
	}
	// Tools whose first positional argument names the profile or role.
	positionalProfile := bn == "aws-vault" || bn == "aws-okta" || bn == "gds" || bn == "aws-runas" || bn == "envchain"
	// Secrets runners whose flags name no AWS profile. Their command normally
	// follows "--"; without it, it starts at the first argument that is not a
	// flag or a flag's value (chamber's leading arguments are service names,
	// so there only "--" or the end of the arguments decides).
	secretsRunner := bn == "doppler" || bn == "op" || bn == "chamber" || bn == "infisical" || bn == "dotenvx"
	profileFlags := map[string]bool{"--exec-profile": true, "-p": true, "--profile": true}
	valued := map[string]bool{"--duration": true, "-d": true, "--region": true, "--mfa-token": true, "-t": true,
		"--prompt": true, "--exec-profile": true, "-p": true, "--profile": true, "-a": true, "--idp-account": true,
		"--project": true, "--config": true, "-c": true, "--env-file": true, "--env": true, "--account": true,
		"--role": true, "--session-ttl": true, "--assume-role-ttl": true,
		// doppler, infisical, dotenvx
		"--token": true, "--mount": true, "--mount-format": true, "--mount-template": true, "--fallback": true,
		"--name-transformer": true, "--projectId": true, "--path": true, "--tags": true, "--domain": true,
		"-f": true, "-fk": true, "--env-keys-file": true, "-e": true, "--convention": true}
	firstPos := -1
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		if !w.Resolved {
			t = w.Prefix
		}
		name, val, eq := strings.Cut(t, "=")
		switch {
		case t == "--" && w.Resolved:
			return rest[i+1:], nil, profile, i+1 < len(rest)
		case secretsRunner && name == "--command" && (bn == "doppler" || bn == "infisical"):
			if eq {
				return nil, &Word{Text: val, Resolved: w.Resolved, Prefix: val}, profile, true
			}
			if i+1 < len(rest) {
				return nil, &rest[i+1], profile, true
			}
			return nil, nil, profile, false
		case secretsRunner && strings.HasPrefix(t, "-"):
			if !eq && valued[name] {
				i++
			}
		case secretsRunner && bn != "chamber":
			return rest[i:], nil, profile, true
		case secretsRunner:
			if firstPos < 0 {
				firstPos = i
			}
		case strings.HasPrefix(t, "-"):
			if profileFlags[name] {
				if eq {
					profile = presentWord(Word{Text: val, Resolved: w.Resolved, Prefix: val})
				} else if i+1 < len(rest) {
					profile = presentWord(rest[i+1])
				}
			}
			if !eq && valued[name] {
				i++
			}
		case positionalProfile:
			profile = presentWord(w)
			positionalProfile = false
		default:
			return rest[i:], nil, profile, true
		}
	}
	if firstPos >= 0 {
		return rest[firstPos:], nil, profile, true
	}
	return nil, nil, profile, false
}

// guardIn returns the guard needle that text names, comparing without case
// and with string-literal joins collapsed ('appro' + 'vals.json').
func (a *analyzer) guardIn(text string) string {
	if len(a.opt.GuardNeedles) == 0 || text == "" {
		return ""
	}
	low, joined := strings.ToLower(text), strings.ToLower(dejoinLiterals(text))
	for _, n := range a.opt.GuardNeedles {
		n = strings.ToLower(n)
		if strings.Contains(low, n) || strings.Contains(joined, n) {
			return n
		}
	}
	return ""
}

func (a *analyzer) guardProblem(st *state, via []string, text, reason, guard string) {
	a.problem(st, via, text, reason)
	a.res.Problems[len(a.res.Problems)-1].Guard = guard
}

// typedText returns the text tmux send-keys or screen -X stuff types into
// another terminal, with Enter and C-m as newlines. ok is false for other
// subcommands; resolved is false when a key cannot be resolved.
func typedText(bn string, rest []Word) (text string, ok, resolved bool) {
	resolved = true
	var keys []Word
	switch bn {
	case "tmux":
		i := 0
		for i < len(rest) && rest[i].Text != "send-keys" && rest[i].Text != "send" {
			i++
		}
		if i == len(rest) {
			return "", false, true
		}
		for j := i + 1; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "-t" || t == "-N" || t == "-c":
				j++
			case strings.HasPrefix(t, "-") && len(t) > 1:
			default:
				keys = append(keys, rest[j])
			}
		}
	case "screen":
		for j := 0; j+1 < len(rest); j++ {
			if rest[j].Text == "-X" && (rest[j+1].Text == "stuff" || rest[j+1].Text == "exec") {
				keys = rest[j+2:]
				break
			}
		}
		if keys == nil {
			return "", false, true
		}
	}
	var b strings.Builder
	for _, k := range keys {
		if !k.Resolved {
			resolved = false
		}
		switch k.Text {
		case "Enter", "C-m", "KPEnter", "C-j":
			b.WriteString("\n")
			continue
		}
		t := strings.ReplaceAll(strings.ReplaceAll(k.Text, `\n`, "\n"), `\r`, "\n")
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString(" ")
		}
		b.WriteString(t)
	}
	return b.String(), true, resolved
}

// function runs a function body in the caller's shell, as bash does: its cd
// and assignments stay after it returns, except the variables it declares
// local, which get back their earlier values. The function is not visible
// inside its own body, which stops recursion.
func (a *analyzer) function(name string, body *syntax.Stmt, rest []Word, st *state, via []string, depth int, in stdin) {
	params, paramsOK, locals := st.params, st.paramsOK, st.locals
	st.params, st.paramsOK, st.locals = valuesOf(rest), true, map[string]*value{}
	delete(st.funcs, name)
	a.stmt(body, st, append(via, "function "+name), depth+1, in)
	if _, redefined := st.funcs[name]; !redefined {
		st.funcs[name] = body
	}
	for k, v := range st.locals {
		if v == nil {
			delete(st.vars, k)
		} else {
			st.vars[k] = *v
		}
	}
	st.params, st.paramsOK, st.locals = params, paramsOK, locals
}

// assignedBy returns the variables read, mapfile, readarray, getopts or
// printf -v assign.
func assignedBy(bn string, rest []Word) []string {
	var valued map[string]bool
	def := ""
	switch bn {
	case "read":
		valued, def = toSet("-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u"), "REPLY"
	case "mapfile", "readarray":
		valued, def = toSet("-d", "-n", "-O", "-s", "-u", "-C", "-c"), "MAPFILE"
	case "getopts":
		if len(rest) >= 2 {
			return []string{rest[1].Text, "OPTARG", "OPTIND"}
		}
		return []string{"OPTARG", "OPTIND"}
	case "printf":
		for i, w := range rest {
			if w.Text == "-v" && i+1 < len(rest) {
				return []string{rest[i+1].Text}
			}
			if v, ok := strings.CutPrefix(w.Text, "-v"); ok && v != "" {
				return []string{v}
			}
			if !strings.HasPrefix(w.Text, "-") {
				break
			}
		}
		return nil
	}
	var names []string
	for i := 0; i < len(rest); i++ {
		t := rest[i].Text
		if t == "--" {
			for _, w := range rest[i+1:] {
				names = append(names, w.Text)
			}
			break
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			if t == "-a" && i+1 < len(rest) {
				names = append(names, rest[i+1].Text)
			}
			if valued[t] {
				i++
			}
			continue
		}
		names = append(names, t)
	}
	if len(names) == 0 {
		names = []string{def}
	}
	return names
}

// envRun finds the command that conda, mamba, uv, poetry and similar run:
// <tool> run [opts] [--] command... . dir is the --cwd given, if any.
func envRun(rest []Word) (cmd []Word, dir *Word, ok bool) {
	if len(rest) == 0 || rest[0].Text != "run" {
		return nil, nil, false
	}
	valued := toSet("-n", "--name", "-p", "--prefix", "--cwd", "--env", "-e", "--environment", "--manifest-path",
		"--with", "--python", "--project", "--directory", "--group", "--extra", "--package", "--env-file")
	r := rest[1:]
	for i := 0; i < len(r); i++ {
		t := r[i].Text
		name, val, eq := strings.Cut(t, "=")
		switch {
		case t == "--":
			return r[i+1:], dir, i+1 < len(r)
		case name == "--cwd" || name == "--directory":
			if eq {
				dir = &Word{Text: val, Resolved: r[i].Resolved, Prefix: val}
			} else if i+1 < len(r) {
				dir = &r[i+1]
				i++
			}
		case strings.HasPrefix(t, "-"):
			if valued[name] && !eq {
				i++
			}
		default:
			return r[i:], dir, true
		}
	}
	return nil, nil, false
}

// gitExecKeys are git configuration keys whose value is a command git runs
// through the shell.
var gitExecKeys = toSet("core.pager", "core.sshcommand", "core.fsmonitor", "core.editor", "core.askpass", "core.hookspath",
	"sequence.editor", "diff.external", "credential.helper", "gpg.program", "gpg.ssh.program", "uploadpack.packobjectshook")

// gitExecEnv are environment variables whose value is a command git runs.
var gitExecEnv = []string{"GIT_SSH_COMMAND", "GIT_SSH", "GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_EXTERNAL_DIFF",
	"GIT_ASKPASS", "GIT_PROXY_COMMAND", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS", "SUDO_EDITOR", "KUBE_EDITOR", "GH_EDITOR",
	"HELM_EDITOR", "GLAB_EDITOR", "PSQL_EDITOR", "FCEDIT"}

// git analyzes the commands git runs through its own options: -c alias.X=!cmd
// when X is the subcommand, -c keys whose value is a command, bisect run,
// rebase -x/--exec, submodule foreach, and the GIT_* command variables.
func (a *analyzer) git(rest []Word, cmdSt, st *state, via []string, depth int) {
	child := cmdSt.childState()
	run := func(w Word, label string) {
		a.reparseIn([]Word{w}, child.clone(), via, label, depth)
	}
	// Options that name a program git runs: the transport's upload-pack and
	// receive-pack, archive's --exec, and filter-branch's filters.
	for i := 0; i < len(rest); i++ {
		k, v, eq := strings.Cut(rest[i].Text, "=")
		if full := gitLongName(k, gitRunOpts); full != "" {
			if eq {
				run(Word{Text: v, Resolved: rest[i].Resolved, Prefix: v}, "git "+full)
			} else if i+1 < len(rest) {
				run(rest[i+1], "git "+full)
				i++
			}
		}
	}
	for _, k := range gitExecEnv {
		if v, ok := cmdSt.vars[k]; ok && cmdSt.isExp(k) && (v.text != "" || !v.ok) {
			run(Word{Text: v.text, Resolved: v.ok, Prefix: v.text}, "git "+k)
		}
	}
	// GIT_CONFIG_COUNT with GIT_CONFIG_KEY_n and GIT_CONFIG_VALUE_n are
	// -c pairs; GIT_CONFIG_PARAMETERS and other config files may hold any.
	envVal := func(k string) (value, bool) {
		v, ok := cmdSt.vars[k]
		return v, ok && cmdSt.isExp(k)
	}
	for k := range cmdSt.vars {
		n, ok := strings.CutPrefix(k, "GIT_CONFIG_KEY_")
		if !ok || !cmdSt.isExp(k) {
			continue
		}
		key, val := cmdSt.vars[k], value{}
		if v, ok := envVal("GIT_CONFIG_VALUE_" + n); ok {
			val = v
		}
		if !key.ok || gitExecKey(strings.ToLower(key.text)) || strings.HasPrefix(strings.ToLower(key.text), "alias.") {
			run(Word{Text: val.text, Resolved: val.ok && key.ok, Prefix: val.text}, "git "+k)
		}
	}
	for _, k := range []string{"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG"} {
		if v, ok := envVal(k); ok && !(v.ok && (v.text == "" || v.text == "/dev/null")) {
			a.problem(st, via, "git "+joinWords(rest), k+" gives git configuration applygate cannot read, which may run programs")
		}
	}
	aliases := map[string]Word{}
	i := 0
	for i < len(rest) {
		t := rest[i].Text
		switch {
		case t == "-c" && i+1 < len(rest):
			kv := rest[i+1]
			k, v, _ := strings.Cut(kv.Text, "=")
			if !kv.Resolved {
				k, v, _ = strings.Cut(kv.Prefix, "=")
			}
			k = strings.ToLower(k)
			val := Word{Text: v, Resolved: kv.Resolved, Prefix: v}
			switch {
			case strings.HasPrefix(k, "alias."):
				aliases[strings.TrimPrefix(k, "alias.")] = val
			case gitExecKey(k):
				run(val, "git -c "+k)
			}
			i += 2
			continue
		case t == "-C" && i+1 < len(rest):
			if rest[i+1].Resolved {
				child.dir = a.dirAbs(child, rest[i+1].Text)
			} else {
				child.dir = ""
			}
			i += 2
			continue
		case (t == "--git-dir" || t == "--work-tree" || t == "--namespace" || t == "--exec-path" || t == "--config-env") && i+1 < len(rest):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(rest) {
		return
	}
	sub, args := rest[i].Text, rest[i+1:]
	if v, ok := aliases[strings.ToLower(sub)]; ok && strings.HasPrefix(v.Prefix, "!") {
		v.Text, v.Prefix = strings.TrimPrefix(v.Text, "!"), strings.TrimPrefix(v.Prefix, "!")
		line := append([]Word{v}, args...)
		if !allResolved(line) {
			a.problem(st, via, "git "+joinWords(rest), "git alias runs a command that cannot be resolved statically")
			return
		}
		a.source(joinWords(line), child, append(via, "git alias "+sub), depth+1)
		return
	}
	switch sub {
	case "bisect":
		if len(args) > 1 && args[0].Text == "run" {
			a.call(args[1:], nil, child, child, append(via, "git bisect run"), depth+1, stdin{})
		}
	case "rebase":
		gitCmdOpt(args, "-x", "--exec", run, "git rebase --exec")
	case "difftool", "mergetool":
		gitCmdOpt(args, "-x", "--extcmd", run, "git "+sub+" --extcmd")
	case "grep":
		// -O and --open-files-in-pager take their pager only glued on.
		for _, w := range args {
			if k, v, eq := strings.Cut(w.Text, "="); eq && gitLongName(k, []string{"--open-files-in-pager"}) != "" {
				run(Word{Text: v, Resolved: w.Resolved, Prefix: v}, "git grep -O")
			} else if v, ok := strings.CutPrefix(w.Text, "-O"); ok && v != "" && !strings.HasPrefix(w.Text, "--") {
				run(Word{Text: v, Resolved: w.Resolved, Prefix: strings.TrimPrefix(w.Prefix, "-O")}, "git grep -O")
			}
		}
	case "submodule":
		for j, w := range args {
			if w.Text == "foreach" {
				if r := skipFlags(args[j+1:], nil); len(r) > 0 {
					a.reparseIn(r, child.clone(), via, "git submodule foreach", depth)
				}
				break
			}
		}
	}
}

// gitExecKey reports whether a git config key's value is a command.
func gitExecKey(k string) bool {
	return gitExecKeys[k] || strings.HasPrefix(k, "pager.") || strings.HasSuffix(k, ".textconv") ||
		strings.HasPrefix(k, "filter.") || strings.HasSuffix(k, ".command") || strings.HasSuffix(k, ".cmd")
}

// gitRunOpts are the long options whose value is a program git runs.
var gitRunOpts = []string{"--upload-pack", "--receive-pack", "--exec", "--upload-archive", "--tree-filter", "--index-filter", "--msg-filter",
	"--env-filter", "--commit-filter", "--tag-name-filter", "--parent-filter", "--subdirectory-filter"}

// gitLongName returns the long option k (a --name without its value) stands
// for among the candidates: git takes any unique prefix of a long option, so
// --exe is --exec and --tree-f is --tree-filter. A prefix that fits more
// than one (git refuses it) is taken as the first, the safe reading here.
func gitLongName(k string, candidates []string) string {
	if !strings.HasPrefix(k, "--") || len(k) < 4 {
		return ""
	}
	for _, c := range candidates {
		if strings.HasPrefix(c, k) {
			return c
		}
	}
	return ""
}

// gitCmdOpt runs the value of an option that takes a command: separate
// (-x cmd, --exec cmd), with = (--exec=cmd), glued to the short form (-xcmd),
// after other short options in a cluster (-qx cmd), or through an
// abbreviated long name (--exe cmd).
func gitCmdOpt(args []Word, short, long string, run func(Word, string), label string) {
	for j, w := range args {
		k, v, eq := strings.Cut(w.Text, "=")
		switch {
		case w.Text == short || gitLongName(k, []string{long}) != "" && !eq:
			if j+1 < len(args) {
				run(args[j+1], label)
			}
		case eq && gitLongName(k, []string{long}) != "":
			run(Word{Text: v, Resolved: w.Resolved, Prefix: strings.TrimPrefix(w.Prefix, k+"=")}, label)
		case strings.HasPrefix(w.Text, "-") && !strings.HasPrefix(w.Text, "--") && strings.Contains(w.Text[1:], short[1:]):
			// The short option's letter inside a cluster: what follows it is
			// the command, or the next word when it ends the cluster.
			cl := w.Text[1:]
			at := strings.Index(cl, short[1:])
			if rest := cl[at+1:]; rest != "" {
				run(Word{Text: rest, Resolved: w.Resolved, Prefix: rest}, label)
			} else if j+1 < len(args) {
				run(args[j+1], label)
			}
		}
	}
}

// sshOptions analyzes the commands ssh, scp, sftp and rsync run on this
// machine: -o ProxyCommand=..., LocalCommand, KnownHostsCommand, and
// rsync's -e/--rsh program.
func (a *analyzer) sshOptions(bn string, rest []Word, cmdSt *state, via []string, depth int) {
	child := cmdSt.childState()
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		var opt Word
		switch {
		case bn == "rsync" && (t == "-e" || t == "--rsh") && i+1 < len(rest):
			a.reparseIn([]Word{rest[i+1]}, child.clone(), via, "rsync "+t, depth)
			i++
			continue
		case bn == "rsync" && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 2 && strings.Contains(t[1:], "e"):
			// -e'cmd', -ze 'cmd': e takes the rest of the cluster, else the next word.
			k := strings.IndexByte(t, 'e')
			if v := t[k+1:]; v != "" {
				a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child.clone(), via, "rsync -e", depth)
			} else if i+1 < len(rest) {
				a.reparseIn([]Word{rest[i+1]}, child.clone(), via, "rsync -e", depth)
				i++
			}
			continue
		case (bn == "scp" || bn == "sftp") && t == "-S" && i+1 < len(rest):
			// -S names the program that makes the connection.
			a.reparseIn([]Word{rest[i+1]}, child.clone(), via, bn+" -S", depth)
			i++
			continue
		case (bn == "scp" || bn == "sftp") && strings.HasPrefix(t, "-S") && len(t) > 2:
			a.reparseIn([]Word{{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}}, child.clone(), via, bn+" -S", depth)
			continue
		case bn == "rsync" && strings.HasPrefix(t, "--rsh="):
			v := strings.TrimPrefix(t, "--rsh=")
			a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child.clone(), via, "rsync --rsh", depth)
			continue
		case t == "-o" && i+1 < len(rest):
			opt = rest[i+1]
			i++
		case strings.HasPrefix(t, "-o") && len(t) > 2:
			opt = Word{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}
		default:
			continue
		}
		text := opt.Text
		if !opt.Resolved {
			text = opt.Prefix
		}
		// ssh splits keyword and value at the first space, tab or =:
		// "ProxyCommand terraform -chdir=../prod destroy" is a space form.
		var k, v string
		if i := strings.IndexAny(text, " \t="); i >= 0 {
			k, v = text[:i], strings.TrimLeft(text[i+1:], " \t=")
		} else {
			k = text
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "proxycommand", "localcommand", "knownhostscommand":
			if v = strings.TrimSpace(v); strings.EqualFold(v, "none") {
				continue
			}
			a.reparseIn([]Word{{Text: v, Resolved: opt.Resolved, Prefix: v}}, child.clone(), via, bn+" -o "+k, depth)
		}
	}
}

// alias runs an alias: its text is shell source, so it may hold operators
// (x='cd . && terraform destroy'). The alias is not expanded again inside
// its own text, so alias terraform='terraform destroy' runs terraform.
func (a *analyzer) alias(name, rep string, rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	label := append(via, "alias "+name)
	delete(st.aliases, name)
	defer func() {
		if _, redefined := st.aliases[name]; !redefined {
			st.aliases[name] = rep
		}
	}()
	if nestingDepth(rep) > maxNesting || chainLength(rep) > maxChain {
		a.unbounded(st, via, rep, "alias "+name+" nests deeper than the analyzer parses")
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(rep), "")
	if err != nil {
		a.unbounded(st, via, rep, "alias "+name+" could not be parsed as shell: "+err.Error())
		return
	}
	if len(f.Stmts) == 1 {
		if c, ok := f.Stmts[0].Cmd.(*syntax.CallExpr); ok && len(c.Assigns) == 0 && len(f.Stmts[0].Redirs) == 0 && !f.Stmts[0].Background && len(c.Args) > 0 {
			// A plain command: its words take the place of the name.
			var words []Word
			for _, w := range c.Args {
				words = append(words, a.words(w, st, via, depth)...)
			}
			a.call(append(words, rest...), redirs, cmdSt, st, label, depth+1, in)
			return
		}
	}
	if !allResolved(rest) {
		a.problem(st, via, name+" "+joinWords(rest), "alias "+name+" is a command line and its arguments cannot be resolved statically")
		return
	}
	text := rep
	for _, w := range rest {
		text += " " + shellQuote(w.Text)
	}
	a.source(text, st, label, depth+1)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// multiplexerCommand returns the shell command a tmux or screen invocation
// starts, and the directory given with -c, if any.
func multiplexerCommand(bn string, rest []Word) (cmd []Word, dir *Word, ok bool) {
	switch bn {
	case "tmux":
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i].Text, "-") { // global options
			if t := rest[i].Text; t == "-L" || t == "-S" || t == "-f" || t == "-T" {
				i++
			}
			i++
		}
		if i >= len(rest) {
			return nil, nil, false
		}
		switch rest[i].Text {
		case "new-session", "new", "new-window", "neww", "split-window", "splitw", "respawn-pane", "respawnp",
			"respawn-window", "respawnw", "run-shell", "run", "display-popup", "popup":
		default:
			return nil, nil, false
		}
		valued := toSet("-c", "-e", "-F", "-l", "-n", "-s", "-t", "-x", "-y", "-b", "-d", "-h", "-w", "-T")
		boolean := toSet("-d", "-P", "-k", "-a", "-b", "-h", "-v", "-f", "-Z", "-E", "-B", "-C", "-A", "-D", "-X")
		for j := i + 1; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "--":
				return rest[j+1:], dir, j+1 < len(rest)
			case t == "-c" && j+1 < len(rest):
				dir = &rest[j+1]
				j++
			case boolean[t]:
			case valued[t]:
				j++
			case strings.HasPrefix(t, "-") && len(t) > 1:
			default:
				return rest[j:], dir, true
			}
		}
		return nil, nil, false
	case "screen":
		valued := toSet("-S", "-t", "-c", "-e", "-h", "-p", "-s", "-T", "-X", "-Logfile")
		for j := 0; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "-X":
				return nil, nil, false // a command to a running session (stuff)
			case valued[t]:
				j++
			case strings.HasPrefix(t, "-"):
			default:
				return rest[j:], nil, true
			}
		}
	}
	return nil, nil, false
}

// TierEnv are the environment variables that select what a cloud or
// Terraform call acts on. One that is exported with a value that cannot
// be resolved (empty in the action's environment) makes the target
// unknown, not absent.
var TierEnv = []string{"TF_WORKSPACE", "TF_CLI_ARGS", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE",
	"AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "KUBECONFIG", "HELM_KUBECONTEXT", "CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT",
	"CLOUDSDK_ACTIVE_CONFIG_NAME", "AZURE_CONFIG_DIR", "AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID", "GOOGLE_PROJECT",
	"GOOGLE_CLOUD_PROJECT", "TG_WORKING_DIR", "TERRAGRUNT_WORKING_DIR"}

// secretsRunners set variables from a secrets store.
var secretsRunners = toSet("doppler", "op", "chamber", "infisical", "dotenvx")

// presentWord marks a word that is there but resolves to nothing, so that
// it is not taken for an absent one.
func presentWord(w Word) Word {
	if !w.Resolved && w.Text == "" {
		w.Text = "\x00"
	}
	return w
}

// containerValued are docker's and podman's run options that take the next
// word as their value.
var containerValued = toSet("-e", "--env", "--env-file", "-v", "--volume", "--mount", "-w", "--workdir", "--name", "-p",
	"--publish", "--network", "--net", "--entrypoint", "-u", "--user", "--platform", "-l", "--label", "--label-file",
	"-h", "--hostname", "--add-host", "--dns", "--cap-add", "--cap-drop", "--device", "-m", "--memory", "--cpus",
	"--pull", "--restart", "--log-driver", "--log-opt", "--tmpfs", "--ulimit", "--security-opt", "--volumes-from",
	"--secret", "--ssh", "--userns", "--pid", "--ipc", "--uts", "--cgroupns", "--runtime", "-a", "--attach", "--cidfile")

// unset forgets what unset removes: with -f a function, and without it a
// variable or, when there is none, a function. A name that is a function and
// may be a variable too is not followed.
func (a *analyzer) unset(rest []Word, st *state, via []string) {
	fn := false
	for _, w := range rest {
		t := w.Text
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			if strings.Contains(t, "f") {
				fn = true
			}
			if strings.Contains(t, "v") {
				fn = false
			}
			continue
		}
		if !w.Resolved {
			if len(st.funcs) > 0 || len(st.aliases) > 0 {
				a.unbounded(st, via, "unset "+t, "unset of a name that cannot be resolved while functions or aliases are defined")
			}
			continue
		}
		if _, isFn := st.funcs[t]; isFn {
			if fn {
				delete(st.funcs, t)
			} else {
				a.unbounded(st, via, "unset "+t, "unset of "+t+" removes a variable or, when there is none, the function of that name")
			}
		}
		delete(st.aliases, t)
	}
}
