package shell

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "mksh": true, "busybox": false}

var foreignInterpreters = map[string]string{
	"python": "-c", "python3": "-c", "python2": "-c", "perl": "-e", "ruby": "-e",
	"node": "-e", "deno": "eval", "php": "-r", "pwsh": "-c", "powershell": "-c", "osascript": "-e",
	"expect": "-c",
}

func base(name string) string { return filepath.Base(name) }

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
		a.problem(st, via, joinWords(args), "nesting deeper than the analyzer follows")
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
		f := strings.Fields(rep)
		if len(f) > 0 && f[0] != name {
			a.call(append(lits(f...), rest...), redirs, cmdSt, st, append(via, "alias "+name), depth+1, in)
			return
		}
	}
	if body, ok := st.funcs[name]; ok {
		fst := st.clone()
		fst.params = make([]value, len(rest))
		for i, w := range rest {
			fst.params[i] = value{text: w.Text, ok: w.Resolved}
		}
		delete(fst.funcs, name) // stop direct recursion
		a.stmt(body, fst, append(via, "function "+name), depth+1, in)
		return
	}

	if spec, ok := a.opt.Wrappers[bn]; ok {
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

	switch bn {
	case "cd", "pushd":
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
		b, err := a.opt.ReadFile(a.abs(st, rest[0].Text))
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
	case "nice", "ionice", "stdbuf", "flock", "taskset":
		valued := map[string]bool{"-n": true, "-c": true, "-p": true, "-i": true, "-o": true, "-e": true, "-w": true}
		r := skipFlags(rest, valued)
		if bn == "flock" || bn == "taskset" {
			if len(r) > 0 {
				r = r[1:] // lock file or CPU mask
			}
		}
		a.call(r, redirs, cmdSt, st, append(via, bn), depth+1, in)
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
		r := skipFlags(rest, map[string]bool{"-I": true, "-n": true, "-P": true, "-d": true, "-a": true, "-E": true, "-L": true, "-s": true, "-i": false})
		if len(r) == 0 {
			r = lits("echo")
		}
		r = append(append([]Word(nil), r...), Word{Resolved: false})
		a.call(r, redirs, cmdSt, st, append(via, "xargs"), depth+1, stdin{})
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
		a.parallel(rest, redirs, cmdSt, st, via, depth)
		return
	case "ssh":
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
	if flag, ok := foreignInterpreters[strings.TrimRight(bn, "0123456789.")]; ok || foreignInterpreters[bn] != "" {
		if flag == "" {
			flag = foreignInterpreters[bn]
		}
		a.foreign(bn, flag, args, cmdSt, st, via, in)
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
		case t == "-S" || t == "--split-string":
			if i+1 < len(rest) {
				split := strings.Fields(rest[i+1].Text)
				if !rest[i+1].Resolved {
					a.problem(st, via, "env -S "+rest[i+1].Text, "env -S with text that cannot be resolved")
					return
				}
				nr := append(lits(split...), rest[i+2:]...)
				a.env(nr, redirs, es, st, append(via, "env -S"), depth+1, in)
			}
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
		b, err := a.opt.ReadFile(a.abs(st, rest[0].Text))
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
	b, err := a.opt.ReadFile(a.abs(st, name))
	if err != nil {
		return false
	}
	src := string(b)
	first, _, _ := strings.Cut(src, "\n")
	if strings.HasPrefix(first, "#!") && !shebangShell.MatchString(first) {
		if m := Mentions(src); len(m) > 0 {
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

func (a *analyzer) foreign(bn, flag string, args []Word, cmdSt, st *state, via []string, in stdin) {
	var code string
	// literal is true when the whole body is known: a resolved -c argument, a
	// resolved here-document or here-string, or a file on disk. Text piped
	// in from a decoder or built from variables is never a plain file edit.
	literal := false
	// rest holds the arguments the body receives as input (flags, the
	// script's own arguments), without the code itself.
	rest := args[1:]
	for i, w := range args[1:] {
		if w.Text == flag && i+2 < len(args) {
			code, literal = args[i+2].Text, args[i+2].Resolved
			rest = append(append([]Word(nil), args[1:i+1]...), args[i+3:]...)
			break
		}
	}
	if code == "" && in.present {
		code, literal = in.text, in.known && !strings.HasPrefix(in.desc, "output of")
	}
	if code == "" && len(args) > 1 && !strings.HasPrefix(args[1].Text, "-") && args[1].Resolved {
		if b, err := a.opt.ReadFile(a.abs(st, args[1].Text)); err == nil {
			code, literal = string(b), true
			rest = args[2:]
		}
	}
	// Interpreter code is opaque, so the only signal is a textual mention. A
	// tool name split across string-literal concatenation (e.g. 'ter'+'raform',
	// "terra"."form") hides from a plain scan, so also test a form with those
	// joins collapsed.
	mentions := Mentions(code)
	for _, m := range Mentions(dejoinLiterals(code)) {
		if !slices.Contains(mentions, m) {
			mentions = append(mentions, m)
		}
	}
	if len(mentions) == 0 {
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

// parallel handles GNU parallel: parallel [opts] [command...] [:::|:::: args].
// The command template before the first ::: is reparsed with the substituted
// arguments represented as one unresolved word; if the template is empty the
// ::: entries are themselves the commands.
func (a *analyzer) parallel(rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) {
	valued := map[string]bool{
		"-j": true, "--jobs": true, "-N": true, "-n": true, "-L": true, "--max-lines": true,
		"-P": true, "--delay": true, "--timeout": true, "-S": true, "--sshlogin": true,
		"--colsep": true, "-d": true, "--delimiter": true, "-I": true, "--joblog": true, "--results": true,
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
	if sep >= 0 {
		tmpl = r[:sep]
	}
	if len(tmpl) > 0 {
		call := append(append([]Word(nil), tmpl...), Word{Resolved: false})
		a.call(call, redirs, cmdSt, st, append(via, "parallel"), depth+1, stdin{})
		return
	}
	if sep >= 0 {
		for _, w := range r[sep+1:] {
			if t := w.Text; t == ":::" || t == "::::" || t == ":::+" || t == "::::+" {
				continue
			}
			a.reparse([]Word{w}, st, via, "parallel", depth)
		}
		return
	}
	a.res.Invocations = append(a.res.Invocations, Invocation{Args: rest, Dir: cmdSt.dir, Env: cmdSt.env(), Redirs: redirs, Via: append([]string(nil), via...)})
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
