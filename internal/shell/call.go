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

	c := &callCtx{args: args, rest: rest, name: name, bn: bn, redirs: redirs, cmdSt: cmdSt, st: st, via: via, depth: depth, in: in, record: record}
	if a.directoryBuiltin(c) || a.stateBuiltin(c) || a.environmentWrapper(c) || a.processWrapper(c) || a.toolRunner(c) {
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

// infraNameRe are the infrastructure programs Mentions does not list:
// those with rules of their own (docs/capabilities.md) and those the docs
// name as not covered. A bare aws counts here; Mentions wants a service and
// an operation after it.
var infraNameRe = regexp.MustCompile(`(?i)\b(opentofu|aws|helm|oc|gcloud|gsutil|az|eksctl|pulumi|cdk|flux|argocd|ansible|vault|kustomize)\b`)

// NamesInfra returns the infrastructure tools and guard files text names:
// what Mentions finds, and the other infrastructure programs as whole
// words. It is a word match on text as written, for the question "does
// this command have anything to do with infrastructure"; it proves nothing
// about a text that names none.
func NamesInfra(text string) []string {
	out := Mentions(text)
	for _, s := range infraNameRe.FindAllString(text, 8) {
		if s = strings.ToLower(s); !slices.Contains(out, s) {
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
