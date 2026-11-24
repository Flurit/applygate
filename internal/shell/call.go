package shell

import (
	"path/filepath"
	"regexp"
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

// TierEnv are the environment variables that select what a cloud or
// Terraform call acts on. One that is exported with a value that cannot
// be resolved (empty in the action's environment) makes the target
// unknown, not absent.
var TierEnv = []string{"TF_WORKSPACE", "TF_CLI_ARGS", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE",
	"AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN", "KUBECONFIG", "HELM_KUBECONTEXT", "CLOUDSDK_CONFIG", "CLOUDSDK_CORE_PROJECT",
	"CLOUDSDK_ACTIVE_CONFIG_NAME", "AZURE_CONFIG_DIR", "AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID", "GOOGLE_PROJECT",
	"GOOGLE_CLOUD_PROJECT", "TG_WORKING_DIR", "TERRAGRUNT_WORKING_DIR"}

// presentWord marks a word that is there but resolves to nothing, so that
// it is not taken for an absent one.
func presentWord(w Word) Word {
	if !w.Resolved && w.Text == "" {
		w.Text = "\x00"
	}
	return w
}

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
