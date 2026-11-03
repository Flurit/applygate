package shell

import (
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

// shellBuiltins act only inside the shell; their names are case-sensitive.
var shellBuiltins = toSet("cd", "pushd", "popd", "dirs", "alias", "unalias", "eval", "source", ".", "trap", "read", "mapfile",
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
// the enclosing shell state (mutated by cd, alias, and similar builtins).
func (a *analyzer) call(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	if len(args) == 0 {
		return
	}
	if depth > a.opt.MaxDepth {
		a.unbounded(st, via, joinWords(args), "nesting deeper than the analyzer follows")
		return
	}
	record := func() {
		a.res.Invocations = append(a.res.Invocations, Invocation{
			Args: args, Dir: cmdSt.dir, Env: cmdSt.env(), Redirs: redirs, Via: append([]string(nil), via...),
		})
	}
	if !args[0].Resolved {
		record()
		return
	}
	name := args[0].Text
	bn := base(name)
	rest := args[1:]

	// Aliases expand only on unquoted names; we do not track quoting of the
	// name, so expand whenever the name matches.
	if rep, ok := st.aliases[name]; ok && !strings.Contains(name, "/") {
		a.alias(name, rep, rest, redirs, cmdSt, st, via, depth, in)
		return
	}
	if body, ok := st.funcs[name]; ok {
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
			if profile.Resolved && profile.Text != "" {
				ws.vars["AWS_PROFILE"] = value{text: profile.Text, ok: true}
				ws.exported["AWS_PROFILE"] = true
			}
			a.call(cmd, redirs, ws, st, append(via, bn+" (configured wrapper)"), depth+1, in)
			return
		}
	}

	a.noteWrites(bn, rest, cmdSt)

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
	case "cd", "pushd":
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
		ok := true
		for _, w := range rest {
			if strings.HasPrefix(w.Text, "-") && w.Resolved && w.Text != "-" {
				continue
			}
			target, ok = w.Text, w.Resolved
			break
		}
		switch {
		case !ok:
			st.dir = ""
		case target == "" || target == "~":
			st.dir = a.opt.Env["HOME"]
		case target == "-":
			st.dir = ""
		case st.dir == "" && !filepath.IsAbs(target):
		default:
			st.dir = a.abs(st, target)
			if a.writtenAt(st.dir, true) != "" {
				// An earlier step linked, moved or extracted something
				// here: it may be a symlink to anywhere.
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
		a.source(r[0].Text, st, append(via, "trap"), depth+1)
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
	case "set":
		// set -- a b, or set a b, replaces the positional parameters.
		for i := 0; i < len(rest); i++ {
			t := rest[i].Text
			if t == "-o" || t == "+o" {
				i++
				continue
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
			return
		}
		a.source(joinWords(rest), st, append(via, "eval"), depth+1)
		return
	case "source", ".":
		if len(rest) == 0 {
			return
		}
		if !rest[0].Resolved {
			a.problem(st, via, joinWords(args), "source of a file whose name cannot be resolved")
			return
		}
		b, err := a.read(st, rest[0].Text)
		if err != nil {
			a.problem(st, via, joinWords(args), "source of a file that cannot be read: "+err.Error())
			return
		}
		a.source(string(b), st, append(via, "source "+rest[0].Text), depth+1)
		return
	case "exec", "command", "builtin", "nohup", "time", "chronic", "unbuffer", "setsid", "caffeinate", "noglob":
		if bn == "command" || bn == "type" {
			for _, w := range rest {
				if w.Text == "-v" || w.Text == "-V" {
					return // lookup only
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
			a.call(cmd, redirs, cmdSt, st, append(via, bn), depth+1, in)
			return
		}
	case "aws-vault", "aws-okta", "gds", "saml2aws", "aws-sso", "doppler", "op", "chamber", "infisical", "dotenvx", "envchain", "aws-runas":
		if cmd, script, profile, ok := credentialWrapper(bn, rest); ok {
			// The wrapped command runs with the wrapper's credentials; the
			// profile or role it names is a tier signal like AWS_PROFILE.
			ws := cmdSt.clone()
			if profile.Resolved && profile.Text != "" {
				ws.vars["AWS_PROFILE"] = value{text: profile.Text, ok: true}
				ws.exported["AWS_PROFILE"] = true
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
		a.call(skipFlags(rest, map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true}), redirs, cmdSt, st, append(via, bn), depth+1, in)
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
		// flock [opts] FILE -c 'command line' | flock [opts] FILE command...
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
					es.dir = a.abs(es, dir.Text)
				} else {
					es.dir = ""
				}
			}
			a.call(cmd, redirs, es, st, append(via, bn+" run"), depth+1, in)
			return
		}
		record()
		return
	case "git":
		a.git(rest, cmdSt, st, via, depth)
		record()
		return
	case "scp", "sftp", "rsync":
		a.sshOptions(bn, rest, cmdSt, via, depth)
		record()
		return
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

func (a *analyzer) env(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int, in stdin) {
	es := cmdSt.clone()
	i := 0
	for i < len(rest) {
		w := rest[i]
		t := w.Text
		switch {
		case t == "-i" || t == "--ignore-environment" || t == "-0" || t == "--null" || t == "-v":
			i++
		case t == "-u" || t == "--unset":
			if i+1 < len(rest) {
				delete(es.vars, rest[i+1].Text)
			}
			i += 2
		case t == "-C" || t == "--chdir":
			if i+1 < len(rest) {
				if rest[i+1].Resolved {
					es.dir = a.abs(es, rest[i+1].Text)
				} else {
					es.dir = ""
				}
			}
			i += 2
		case strings.HasPrefix(t, "--chdir="):
			es.dir = a.abs(es, strings.TrimPrefix(t, "--chdir="))
			i++
		case t == "-S" || t == "--split-string" || strings.HasPrefix(t, "-S") || strings.HasPrefix(t, "--split-string="):
			sw, next := Word{}, i+1
			switch {
			case t == "-S" || t == "--split-string":
				if i+1 >= len(rest) {
					return
				}
				sw, next = rest[i+1], i+2
			case strings.HasPrefix(t, "-S"):
				sw = Word{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}
			default:
				v := strings.TrimPrefix(t, "--split-string=")
				sw = Word{Text: v, Resolved: w.Resolved, Prefix: v}
			}
			// env -S has its own quoting, escapes and ${VAR}: only plain
			// words are split here.
			if !sw.Resolved || strings.ContainsAny(sw.Text, "'\"\\$#") {
				a.problem(st, via, "env -S "+sw.Text, "env -S with text that cannot be resolved")
				return
			}
			nr := append(lits(strings.Fields(sw.Text)...), rest[next:]...)
			a.env(nr, redirs, es, st, append(via, "env -S"), depth+1, in)
			return
		case strings.HasPrefix(t, "-"):
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

// shell handles sh/bash/zsh invocations: -c strings, script files and stdin.
func (a *analyzer) shell(bn string, rest []Word, cmdSt, st *state, via []string, depth int, in stdin) {
	child := cmdSt.childState()
	var hasC bool
	i := 0
	for i < len(rest) {
		t := rest[i].Text
		if t == "-o" || t == "+o" || t == "-O" || t == "+O" || t == "--rcfile" || t == "--init-file" {
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
			i++
			continue
		}
		break
	}
	rest = rest[i:]
	label := bn
	switch {
	case hasC:
		if len(rest) == 0 {
			return
		}
		if !rest[0].Resolved {
			a.problem(st, via, bn+" -c "+rest[0].Text, bn+" -c with a command string that cannot be resolved statically")
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
			a.problem(st, via, bn+" "+joinWords(rest), bn+" running a script whose name cannot be resolved")
			return
		}
		b, err := a.read(st, rest[0].Text)
		if err != nil {
			a.problem(st, via, bn+" "+rest[0].Text, "script cannot be read: "+err.Error())
			return
		}
		child.params = valuesOf(rest[1:])
		child.arg0 = value{text: rest[0].Text, ok: true}
		a.source(string(b), child, append(via, bn+" "+rest[0].Text), depth+1)
	case in.present:
		if !in.known {
			a.problem(st, via, in.desc+" | "+bn, "text piped into "+bn+" cannot be resolved statically")
			return
		}
		a.source(in.text, child, append(via, in.desc+" | "+bn), depth+1)
	}
}

var shebangShell = regexp.MustCompile(`^#!\s*(\S*/)?(env\s+)?(ba|z|da|k|mk|a)?sh\b`)

func (a *analyzer) script(name string, rest []Word, cmdSt, st *state, via []string, depth int) bool {
	b, err := a.read(st, name)
	if errorsIsWritten(err) {
		// Still recorded: the classifier judges the program by its
		// arguments too (a renamed copy of applygate).
		a.problem(st, via, name, "script cannot be read: "+err.Error())
		return false
	}
	if err != nil {
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
	repl, fromFile := "", false
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
	input, known := in.text, in.present && in.known && !fromFile
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
	label := append(via, "parallel")
	if !known || len(items) > 32 || !allResolved(tmpl) {
		if len(tmpl) == 0 {
			a.problem(st, via, "parallel "+joinWords(rest), "parallel runs command lines that cannot be resolved statically")
			return
		}
		a.call(append(placeholders(tmpl, "{"), Word{Resolved: false}), redirs, cmdSt, st, label, depth+1, stdin{})
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

// concatRe matches a string-literal concatenation operator sitting between two
// quotes, e.g. `'+'`, `" . "`, "`+`". Collapsing it rejoins split literals.
var concatRe = regexp.MustCompile("['\"`]\\s*[+.]\\s*['\"`]")

func dejoinLiterals(s string) string { return concatRe.ReplaceAllString(s, "") }

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
			if sub[k].Text == "{}" {
				sub[k] = Word{Resolved: false}
			}
		}
		a.call(sub, nil, cmdSt, st, append(via, "find "+t), depth+1, stdin{})
		i = j
	}
}

// container unwraps "docker run ... <image> args" when the image is a
// Terraform or OpenTofu image, so the arguments are classified as such.
func (a *analyzer) container(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) {
	for i, w := range args {
		if i < 2 {
			continue
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
			continue
		}
		r := args[i+1:]
		if len(r) > 0 && (base(r[0].Text) == "terraform" || base(r[0].Text) == "tofu" || base(r[0].Text) == "terragrunt") {
			r = r[1:]
		}
		a.call(append(lits(engine), r...), redirs, cmdSt, st, append(via, args[0].Text+" image "+w.Text), depth+1, stdin{})
		return
	}
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

var mentionRe = regexp.MustCompile(`(?i)\bapplygate\W+(approve|telemetry\W+o(n|ff)|init|disable|hook\W+(remove|uninstall))\b|\b(terraform|tofu|terragrunt|kubectl)\b|\baws\s+[a-z0-9-]+\s+[a-z0-9-]+|\.claude/settings|managed-settings|\.codex/(hooks\.json|config\.toml)|\.applygate\.ya?ml|\.seatbelt\.ya?ml|\.aws/credentials|\.tfstate\b|\b(boto3|botocore|aws-sdk)\b|@aws-sdk/|github\.com/aws/aws-sdk-go`)

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
					profile = Word{Text: val, Resolved: w.Resolved, Prefix: val}
				} else if i+1 < len(rest) {
					profile = rest[i+1]
				}
			}
			if !eq && valued[name] {
				i++
			}
		case positionalProfile:
			profile = w
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
	"GIT_ASKPASS", "GIT_PROXY_COMMAND"}

// git analyzes the commands git runs through its own options: -c alias.X=!cmd
// when X is the subcommand, -c keys whose value is a command, bisect run,
// rebase -x/--exec, submodule foreach, and the GIT_* command variables.
func (a *analyzer) git(rest []Word, cmdSt, st *state, via []string, depth int) {
	child := cmdSt.childState()
	run := func(w Word, label string) {
		a.reparseIn([]Word{w}, child.clone(), via, label, depth)
	}
	for _, k := range gitExecEnv {
		if v, ok := cmdSt.vars[k]; ok && cmdSt.exported[k] && (v.text != "" || !v.ok) {
			run(Word{Text: v.text, Resolved: v.ok, Prefix: v.text}, "git "+k)
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
			case gitExecKeys[k] || strings.HasPrefix(k, "pager.") || strings.HasSuffix(k, ".textconv") ||
				strings.HasPrefix(k, "filter.") || strings.HasSuffix(k, ".command") || strings.HasSuffix(k, ".cmd"):
				run(val, "git -c "+k)
			}
			i += 2
			continue
		case t == "-C" && i+1 < len(rest):
			if rest[i+1].Resolved {
				child.dir = a.abs(child, rest[i+1].Text)
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
		for j, w := range args {
			if (w.Text == "-x" || w.Text == "--exec") && j+1 < len(args) {
				run(args[j+1], "git rebase --exec")
			} else if v, ok := strings.CutPrefix(w.Text, "--exec="); ok {
				run(Word{Text: v, Resolved: w.Resolved, Prefix: v}, "git rebase --exec")
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
		k, v, ok := strings.Cut(text, "=")
		if !ok {
			k, v, _ = strings.Cut(text, " ")
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
