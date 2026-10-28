// Package shell turns a command string into the program invocations a shell
// would run, resolving what it can statically and reporting what it cannot.
//
// It never executes anything. Constructs whose effect depends on runtime data
// (unknown variables, fetched text, encoded payloads it cannot decode) are
// reported as Problems so the policy can refuse them instead of guessing.
package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Word is one resolved argument.
type Word struct {
	Text     string // best-effort text; unresolved parts are left out
	Resolved bool   // false when any part depends on runtime data
	Prefix   string // literal text before the first unresolved part
	// unquoted is set when an unquoted expansion contributed text, so the
	// shell would split the result into fields.
	unquoted bool
}

// Invocation is one program the shell would start.
type Invocation struct {
	Args   []Word
	Dir    string // effective working directory; "" when unknown
	Env    map[string]string
	Redirs []Redir
	Via    []string // how we got here: "bash -c", "make destroy", ...
}

// Name returns the resolved program name ("" when unresolved).
func (inv Invocation) Name() string {
	if len(inv.Args) == 0 || !inv.Args[0].Resolved {
		return ""
	}
	return inv.Args[0].Text
}

// Redir is an output or input redirection attached to an invocation.
type Redir struct {
	Op     string
	Target Word
	Write  bool
}

// Problem is something the analyzer refused to resolve.
type Problem struct {
	Text   string   // the construct, shortened
	Reason string   // why it could not be resolved
	Via    []string // nesting context
	Dir    string
	// Mentions lists infrastructure words seen in opaque text (for example
	// "terraform" inside python -c code). Empty when nothing was recognized.
	Mentions []string
}

// Result is the outcome of Analyze.
type Result struct {
	Invocations []Invocation
	Problems    []Problem
}

// Options control resolution.
type Options struct {
	Dir      string            // starting working directory (absolute)
	Env      map[string]string // known environment (HOME, USER, ...)
	Aliases  map[string]string // name -> replacement words
	ReadFile func(path string) ([]byte, error)
	MaxDepth int
}

const maxFileSize = 512 << 10

// DefaultReadFile reads a regular file up to maxFileSize bytes.
func DefaultReadFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	return os.ReadFile(path)
}

// Analyze parses cmd and returns the invocations it would run.
func Analyze(cmd string, opt Options) *Result {
	if opt.MaxDepth == 0 {
		opt.MaxDepth = 8
	}
	if opt.ReadFile == nil {
		opt.ReadFile = DefaultReadFile
	}
	a := &analyzer{opt: opt, res: &Result{}, budget: 2000}
	st := newState(opt)
	a.source(cmd, st, nil, 0)
	return a.res
}

type value struct {
	text string
	ok   bool
}

type state struct {
	vars     map[string]value
	exported map[string]bool
	params   []value // $1..$n inside a function body or script
	paramsOK bool
	arg0     value // $0 inside a script
	dir      string
	funcs    map[string]*syntax.Stmt
	aliases  map[string]string
}

func newState(opt Options) *state {
	st := &state{
		vars:     map[string]value{},
		exported: map[string]bool{},
		dir:      opt.Dir,
		funcs:    map[string]*syntax.Stmt{},
		aliases:  map[string]string{},
		paramsOK: true,
	}
	for k, v := range opt.Aliases {
		st.aliases[k] = v
	}
	return st
}

func (s *state) clone() *state {
	c := *s
	c.vars = make(map[string]value, len(s.vars))
	for k, v := range s.vars {
		c.vars[k] = v
	}
	c.exported = make(map[string]bool, len(s.exported))
	for k, v := range s.exported {
		c.exported[k] = v
	}
	c.funcs = make(map[string]*syntax.Stmt, len(s.funcs))
	for k, v := range s.funcs {
		c.funcs[k] = v
	}
	c.aliases = make(map[string]string, len(s.aliases))
	for k, v := range s.aliases {
		c.aliases[k] = v
	}
	return &c
}

// childState is the state a new shell process starts with: exported
// variables only, same directory.
func (s *state) childState() *state {
	c := s.clone()
	for k := range c.vars {
		if !c.exported[k] {
			delete(c.vars, k)
		}
	}
	c.funcs = map[string]*syntax.Stmt{}
	c.params = nil
	c.paramsOK = true
	return c
}

func (s *state) env() map[string]string {
	env := map[string]string{}
	for k := range s.exported {
		if v, ok := s.vars[k]; ok && v.ok {
			env[k] = v.text
		} else {
			env[k] = "" // exported but unresolved
		}
	}
	return env
}

type analyzer struct {
	opt    Options
	res    *Result
	budget int // statements left to walk
	work   int // word parts and output evaluations done
	quiet  int // >0 while resolving a word only for its value
}

const maxWork = 50000

type stdin struct {
	text    string
	known   bool
	present bool
	desc    string
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

func (a *analyzer) problem(st *state, via []string, text, reason string) {
	a.res.Problems = append(a.res.Problems, Problem{
		Text: short(text), Reason: reason, Via: append([]string(nil), via...), Dir: st.dir,
		Mentions: Mentions(text),
	})
}

// source parses and walks a shell program.
func (a *analyzer) source(src string, st *state, via []string, depth int) {
	if depth > a.opt.MaxDepth {
		a.problem(st, via, src, "nesting deeper than the analyzer follows")
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		a.problem(st, via, src, "could not parse as shell: "+err.Error())
		return
	}
	for _, s := range f.Stmts {
		a.stmt(s, st, via, depth, stdin{})
	}
}

func (a *analyzer) stmts(ss []*syntax.Stmt, st *state, via []string, depth int) {
	for _, s := range ss {
		a.stmt(s, st, via, depth, stdin{})
	}
}

func (a *analyzer) stmt(s *syntax.Stmt, st *state, via []string, depth int, in stdin) {
	if s == nil {
		return
	}
	a.budget--
	if a.budget < 0 {
		if a.budget == -1 {
			a.problem(st, via, "", "command too large to analyze")
		}
		return
	}
	var redirs []Redir
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			w := a.word(r.Hdoc, st, via, depth)
			in = stdin{text: w.Text, known: w.Resolved, present: true, desc: "here-document"}
		case syntax.WordHdoc:
			w := a.word(r.Word, st, via, depth)
			in = stdin{text: w.Text, known: w.Resolved, present: true, desc: "here-string"}
		case syntax.RdrIn:
			w := a.word(r.Word, st, via, depth)
			in = stdin{present: true, desc: "file " + w.Text}
			if w.Resolved {
				if b, err := a.opt.ReadFile(a.abs(st, w.Text)); err == nil {
					in.text, in.known = string(b), true
				}
			}
			redirs = append(redirs, Redir{Op: r.Op.String(), Target: w})
		default:
			w := a.word(r.Word, st, via, depth)
			write := r.Op != syntax.DplIn && r.Op != syntax.DplOut
			redirs = append(redirs, Redir{Op: r.Op.String(), Target: w, Write: write})
		}
	}
	switch c := s.Cmd.(type) {
	case *syntax.CallExpr:
		a.callExpr(c, redirs, st, via, depth, in)
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.Pipe, syntax.PipeAll:
			left := st.clone()
			a.stmt(c.X, left, via, depth, in)
			out, ok := a.stdout(c.X, st.clone(), in, 0)
			a.stmt(c.Y, st.clone(), via, depth, stdin{text: out, known: ok, present: true, desc: "output of " + short(nodeText(c.X))})
		default:
			a.stmt(c.X, st, via, depth, in)
			a.stmt(c.Y, st, via, depth, stdin{})
		}
	case *syntax.Subshell:
		a.stmts(c.Stmts, st.clone(), via, depth)
	case *syntax.Block:
		a.stmts(c.Stmts, st, via, depth)
	case *syntax.IfClause:
		for ic := c; ic != nil; ic = ic.Else {
			a.stmts(ic.Cond, st, via, depth)
			a.stmts(ic.Then, st, via, depth)
		}
	case *syntax.WhileClause:
		a.stmts(c.Cond, st, via, depth)
		a.stmts(c.Do, st, via, depth)
	case *syntax.ForClause:
		if wi, ok := c.Loop.(*syntax.WordIter); ok {
			var items []Word
			allOK := true
			for _, w := range wi.Items {
				for _, x := range a.words(w, st, via, depth) {
					items = append(items, x)
					allOK = allOK && x.Resolved
				}
			}
			if allOK && len(items) > 0 && len(items) <= 32 {
				for _, it := range items {
					st.vars[wi.Name.Value] = value{text: it.Text, ok: true}
					a.stmts(c.Do, st, via, depth)
				}
				return
			}
			st.vars[wi.Name.Value] = value{}
		}
		a.stmts(c.Do, st, via, depth)
	case *syntax.CaseClause:
		for _, it := range c.Items {
			a.stmts(it.Stmts, st, via, depth)
		}
	case *syntax.FuncDecl:
		if c.Name == nil {
			// Anonymous function: runs immediately.
			a.stmt(c.Body, st, via, depth, in)
			return
		}
		st.funcs[c.Name.Value] = c.Body
	case *syntax.DeclClause:
		export := c.Variant.Value == "export"
		for _, as := range c.Args {
			if as.Name == nil {
				continue
			}
			if as.Naked {
				if export {
					st.exported[as.Name.Value] = true
				}
				continue
			}
			a.assign(as, st, via, depth)
			if export {
				st.exported[as.Name.Value] = true
			}
		}
	case *syntax.TimeClause:
		a.stmt(c.Stmt, st, via, depth, in)
	case *syntax.CoprocClause:
		a.stmt(c.Stmt, st.clone(), via, depth, in)
	case *syntax.TestClause, *syntax.ArithmCmd, *syntax.LetClause:
		// Conditions and arithmetic start no programs, except through
		// command substitutions, which the word walk below would catch;
		// we walk the source text for those to stay conservative.
		a.substitutionsIn(s, st, via, depth)
	case nil:
	default:
		a.problem(st, via, nodeText(s), fmt.Sprintf("unsupported shell construct %T", c))
	}
}

// substitutionsIn walks command and process substitutions nested in n.
func (a *analyzer) substitutionsIn(n syntax.Node, st *state, via []string, depth int) {
	syntax.Walk(n, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CmdSubst:
			a.stmts(x.Stmts, st.clone(), via, depth)
			return false
		case *syntax.ProcSubst:
			a.stmts(x.Stmts, st.clone(), via, depth)
			return false
		}
		return true
	})
}

func (a *analyzer) assign(as *syntax.Assign, st *state, via []string, depth int) {
	if as.Array != nil || as.Index != nil {
		st.vars[as.Name.Value] = value{}
		a.substitutionsIn(as, st, via, depth)
		return
	}
	var w Word
	if as.Value != nil {
		w = a.word(as.Value, st, via, depth)
	} else {
		w = Word{Resolved: true}
	}
	if as.Append {
		prev := st.vars[as.Name.Value]
		st.vars[as.Name.Value] = value{text: prev.text + w.Text, ok: prev.ok && w.Resolved}
		return
	}
	st.vars[as.Name.Value] = value{text: w.Text, ok: w.Resolved}
}

func (a *analyzer) callExpr(c *syntax.CallExpr, redirs []Redir, st *state, via []string, depth int, in stdin) {
	if len(c.Args) == 0 {
		for _, as := range c.Assigns {
			a.assign(as, st, via, depth)
		}
		return
	}
	// Prefix assignments apply to this command only.
	cmdSt := st.clone()
	for _, as := range c.Assigns {
		a.assign(as, cmdSt, via, depth)
		cmdSt.exported[as.Name.Value] = true
	}
	var args []Word
	for _, w := range c.Args {
		args = append(args, a.words(w, st, via, depth)...)
	}
	a.call(args, redirs, cmdSt, st, via, depth, in)
}

// words resolves one syntax word, applying brace expansion.
func (a *analyzer) words(w *syntax.Word, st *state, via []string, depth int) []Word {
	cp := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
	if syntax.SplitBraces(cp) {
		n := 1
		for _, p := range cp.Parts {
			if be, ok := p.(*syntax.BraceExp); ok {
				n *= max(len(be.Elems), 1)
			}
			if n > 64 {
				// Too many expansions to follow: the BraceExp part makes
				// the word unresolved.
				return []Word{a.word(cp, st, via, depth)}
			}
		}
		exp := expand.Braces(cp)
		if len(exp) > 1 && len(exp) <= 64 {
			out := make([]Word, 0, len(exp))
			for _, e := range exp {
				out = append(out, a.split(a.word(e, st, via, depth), st)...)
			}
			return out
		}
	}
	return a.split(a.word(w, st, via, depth), st)
}

// split applies field splitting to a word built from unquoted expansions:
// x="terraform destroy"; $x runs two words, not one.
func (a *analyzer) split(w Word, st *state) []Word {
	if !w.unquoted {
		return []Word{w}
	}
	if _, custom := st.vars["IFS"]; custom {
		w.Resolved = false
		return []Word{w}
	}
	if !w.Resolved {
		return []Word{w}
	}
	f := strings.Fields(w.Text)
	if len(f) <= 1 {
		if len(f) == 1 {
			w.Text, w.Prefix = f[0], f[0]
		}
		return []Word{w}
	}
	out := make([]Word, len(f))
	for i, x := range f {
		out[i] = Word{Text: x, Resolved: true, Prefix: x}
	}
	return out
}

func (a *analyzer) word(w *syntax.Word, st *state, via []string, depth int) Word {
	if w == nil {
		return Word{Resolved: true}
	}
	var b strings.Builder
	res := Word{Resolved: true}
	mark := func() {
		if res.Resolved {
			res.Prefix = b.String()
		}
		res.Resolved = false
	}
	for i, p := range w.Parts {
		if !res.unquoted {
			switch p.(type) {
			case *syntax.ParamExp, *syntax.CmdSubst:
				res.unquoted = true
			}
		}
		a.part(p, st, via, depth, &b, mark, i == 0, false)
	}
	res.Text = b.String()
	if res.Resolved {
		res.Prefix = res.Text
	}
	return res
}

func (a *analyzer) part(p syntax.WordPart, st *state, via []string, depth int, b *strings.Builder, mark func(), first, inDbl bool) {
	a.work++
	if a.work > maxWork {
		if a.work == maxWork+1 {
			a.res.Problems = append(a.res.Problems, Problem{Text: "", Reason: "command too complex to analyze", Dir: st.dir})
		}
		mark()
		return
	}
	switch x := p.(type) {
	case *syntax.Lit:
		v := x.Value
		if inDbl {
			b.WriteString(unescapeDbl(v))
			return
		}
		v = unescapeLit(v)
		if first && (v == "~" || strings.HasPrefix(v, "~/")) {
			if home, ok := a.opt.Env["HOME"]; ok {
				v = home + v[1:]
			}
		}
		b.WriteString(v)
	case *syntax.SglQuoted:
		if x.Dollar {
			b.WriteString(ansiC(x.Value))
		} else {
			b.WriteString(x.Value)
		}
	case *syntax.DblQuoted:
		for _, q := range x.Parts {
			a.part(q, st, via, depth, b, mark, false, true)
		}
	case *syntax.ParamExp:
		v, ok := a.param(x, st)
		if ok {
			b.WriteString(v)
		} else {
			mark()
		}
	case *syntax.CmdSubst:
		if a.quiet == 0 {
			a.stmts(x.Stmts, st.clone(), via, depth)
		}
		if len(x.Stmts) == 1 {
			if out, ok := a.stdout(x.Stmts[0], st.clone(), stdin{}, 0); ok {
				b.WriteString(strings.TrimRight(out, "\n"))
				return
			}
		}
		mark()
	case *syntax.ProcSubst:
		if a.quiet == 0 {
			a.stmts(x.Stmts, st.clone(), via, depth)
		}
		mark()
	case *syntax.ExtGlob:
		b.WriteString(x.Op.String() + x.Pattern.Value + ")")
	default:
		// Arithmetic and anything else: not resolved statically.
		mark()
	}
}

var safeEnv = map[string]bool{"HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "TMPDIR": true}

func (a *analyzer) param(x *syntax.ParamExp, st *state) (string, bool) {
	if x.Param == nil || x.Excl || x.Length || x.Width || x.Index != nil ||
		x.Slice != nil || x.Repl != nil || x.Exp != nil || x.Flags != nil || x.NestedParam != nil {
		return "", false
	}
	name := x.Param.Value
	if v, ok := st.vars[name]; ok {
		return v.text, v.ok
	}
	if name == "PWD" && st.dir != "" {
		return st.dir, true
	}
	if name == "0" {
		return st.arg0.text, st.arg0.ok
	}
	if n := len(name); n == 1 && name[0] >= '1' && name[0] <= '9' {
		i := int(name[0] - '1')
		if st.params != nil && i < len(st.params) {
			return st.params[i].text, st.params[i].ok
		}
		return "", false
	}
	if safeEnv[name] {
		if v, ok := a.opt.Env[name]; ok {
			return v, true
		}
	}
	return "", false
}

func (a *analyzer) abs(st *state, p string) string {
	if filepath.IsAbs(p) || st.dir == "" {
		return filepath.Clean(p)
	}
	return filepath.Join(st.dir, p)
}

func nodeText(n syntax.Node) string {
	var b strings.Builder
	if err := syntax.NewPrinter(syntax.Minify(true)).Print(&b, n); err != nil {
		return ""
	}
	return b.String()
}

func unescapeLit(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unescapeDbl(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ansiC decodes the body of a $'...' string.
func ansiC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case 'x':
			n, v := 0, 0
			for n < 2 && i+1 < len(s) && isHex(s[i+1]) {
				i++
				v = v*16 + hexVal(s[i])
				n++
			}
			b.WriteByte(byte(v))
		case '0', '1', '2', '3', '4', '5', '6', '7':
			v, n := int(s[i]-'0'), 1
			for n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
				i++
				v = v*8 + int(s[i]-'0')
				n++
			}
			b.WriteByte(byte(v))
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}
