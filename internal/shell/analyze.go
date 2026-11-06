// Package shell turns a command string into the program invocations a shell
// would run, resolving what it can statically and reporting what it cannot.
//
// It never executes anything. Constructs whose effect depends on runtime data
// (unknown variables, fetched text, encoded payloads it cannot decode) are
// reported as Problems so the policy can refuse them instead of guessing.
package shell

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
	Args []Word
	Dir  string // effective working directory; "" when unknown
	// Approx is set when Dir is only the session directory, used because
	// the host does not report the command's own: a relative -chdir or -C
	// from it is not known.
	Approx bool
	Env    map[string]string
	Redirs []Redir
	Via    []string // how we got here: "bash -c", "make destroy", ...
	// Stdin is the text fed to the program (a here-document, a here-string,
	// a file it is redirected from, or what a known pipeline gives it) when
	// the analysis knows it.
	Stdin string
	// Followed is set on an invocation the analysis took apart: it started
	// other invocations of its own (make with its recipes, docker run with
	// the image's command, xargs, bash -c with literal text), which are
	// judged where they run. A program whose command line was only searched
	// for a standalone terraform (the backstop for unrecognized programs) is
	// not followed.
	Followed bool
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
	// Guard is the guard file opaque text names, if any: code that names
	// one is guard tampering whatever else it does.
	Guard string
	// AnyDir is set when the analysis stopped (a parse error, the statement
	// budget or the work limit): what it did not see may run in any
	// directory, so the problem is judged at the most protected tier the
	// command could reach, not at the directory it started in.
	AnyDir bool
}

// Result is the outcome of Analyze.
type Result struct {
	Invocations []Invocation
	Problems    []Problem
	// Notes explain constructs that were examined and found harmless, such
	// as an interpreter body that mentions a tool but can only edit files.
	Notes []string
}

// Options control resolution.
type Options struct {
	Dir     string            // starting working directory (absolute)
	Env     map[string]string // known environment (HOME, USER, ...)
	Aliases map[string]string // name -> replacement words
	// Wrappers are extra programs, from the user's config, that run the
	// command given in their arguments.
	Wrappers map[string]WrapperSpec
	ReadFile func(path string) ([]byte, error)
	// IsDir reports whether a directory exists. When it is set, a cd to
	// a directory that does not exist, and that no earlier step creates,
	// leaves the directory unknown: the cd fails and the shell stays
	// where it was.
	IsDir func(path string) bool
	// UnknownBase is set when the host does not report the directory the
	// command runs in and Dir is the session directory used instead.
	UnknownBase bool
	MaxDepth    int
	// ProtectedPaths are the guard-file patterns from the config. An
	// interpreter body that names one of them is never a plain file edit.
	ProtectedPaths []string
	// GuardNeedles are strings that name a guard file (paths and distinctive
	// names, lower case); opaque code containing one is guard tampering.
	GuardNeedles []string
	// ProtectedPath reports whether an absolute path is a guard file (the
	// classify package's matcher); the files an interpreter body writes are
	// resolved against its directory and checked with it.
	ProtectedPath func(string) bool
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
// maxAnalyzeBytes is the largest command text the analyzer parses.
const maxAnalyzeBytes = 1 << 20

func Analyze(cmd string, opt Options) *Result {
	if opt.MaxDepth == 0 {
		opt.MaxDepth = 8
	}
	if opt.ReadFile == nil {
		opt.ReadFile = DefaultReadFile
	}
	a := &analyzer{opt: opt, res: &Result{}, budget: 2000}
	st := newState(opt)
	if len(cmd) > maxAnalyzeBytes {
		// The syntax tree of a command takes about 200 times its size in
		// memory; one this large is not parsed, and what it may run is not
		// known.
		a.unbounded(st, nil, cmd[:256], "command too large to analyze")
		return a.res
	}
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
	// approx is set while dir is only the session directory the host
	// reports for a command whose own directory it does not: a relative cd,
	// -C or -chdir from there leads to a place that is not known.
	approx   bool
	funcs    map[string]*syntax.Stmt
	aliases  map[string]string
	dirStack []string // pushd's stack, most recent last
	// locals names the variables declared local in the running function
	// body, with the value each had before; nil outside a function.
	locals map[string]*value
	// nameref is set once declare -n or local -n has run, or a declaration
	// assigned a variable whose name is built at run time: any variable may
	// then have changed, so no variable value is known.
	nameref bool
	// cdableVars is set by shopt -s cdable_vars: cd NAME may go to $NAME.
	cdableVars bool
	// hashed are the programs hash -p bound to names.
	hashed map[string]Word
	// allexport is set by set -a (or -o allexport): every later assignment
	// is exported. proc is the hook's own environment: a name in it is
	// exported already, so assigning it keeps it exported (AWS_PROFILE=x
	// changes what a child sees).
	allexport bool
	proc      map[string]string
}

// isExp reports whether a child process sees the variable k.
func (s *state) isExp(k string) bool {
	if s.exported[k] || s.allexport {
		return true
	}
	_, ok := s.proc[k]
	return ok
}

func newState(opt Options) *state {
	st := &state{
		vars:     map[string]value{},
		exported: map[string]bool{},
		dir:      opt.Dir,
		approx:   opt.UnknownBase,
		funcs:    map[string]*syntax.Stmt{},
		aliases:  map[string]string{},
		paramsOK: true,
		proc:     opt.Env,
	}
	for k, v := range opt.Aliases {
		st.aliases[k] = v
	}
	return st
}

// zshQualifierRuns matches zsh glob qualifiers that run code: e with any
// delimiter (e:...:, e'...') and + with a function name.
var zshQualifierRuns = regexp.MustCompile(`(^|[^A-Za-z0-9])(e[^A-Za-z0-9\s]|\+[A-Za-z_])`)

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
	c.dirStack = slices.Clone(s.dirStack)
	if s.hashed != nil {
		c.hashed = make(map[string]Word, len(s.hashed))
		for k, v := range s.hashed {
			c.hashed[k] = v
		}
	}
	if s.locals != nil {
		c.locals = make(map[string]*value, len(s.locals))
		for k, v := range s.locals {
			c.locals[k] = v
		}
	}
	return &c
}

// childState is the state a new shell process starts with: exported
// variables only, same directory.
func (s *state) childState() *state {
	c := s.clone()
	for k := range c.vars {
		if !c.isExp(k) {
			delete(c.vars, k)
		}
	}
	c.funcs = map[string]*syntax.Stmt{}
	c.params = nil
	c.paramsOK = true
	c.dirStack, c.locals = nil, nil
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
	for k, v := range s.vars {
		if _, done := env[k]; done || !s.isExp(k) {
			continue
		}
		if v.ok {
			env[k] = v.text
		} else {
			env[k] = ""
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
	// noGlob is >0 while resolving a word the shell does not glob: a
	// here-document body or an assignment value.
	noGlob int
	// written holds the paths earlier steps of the command write
	// (written.go); writtenUnknown is set when a step writes to a path
	// that cannot be resolved.
	written        map[string]writeKind
	writtenUnknown bool
}

const maxWork = 50000

// maxText bounds a resolved word and a variable's value. Longer text is
// left unresolved: doubling a variable (x=$x$x) or a long brace sequence
// would otherwise grow without bound, in branches that never run too.
const maxText = 64 << 10

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
	for _, p := range a.res.Problems {
		if p.Text == short(text) && p.Reason == reason && p.Dir == st.dir && slices.Equal(p.Via, via) {
			return
		}
	}
	a.res.Problems = append(a.res.Problems, Problem{
		Text: short(text), Reason: reason, Via: append([]string(nil), via...), Dir: st.dir,
		Mentions: Mentions(text),
	})
}

// unbounded records a problem after which the analysis stopped.
func (a *analyzer) unbounded(st *state, via []string, text, reason string) {
	a.problem(st, via, text, reason)
	a.res.Problems[len(a.res.Problems)-1].AnyDir = true
}

func (a *analyzer) note(text string) {
	if !slices.Contains(a.res.Notes, text) {
		a.res.Notes = append(a.res.Notes, text)
	}
}

// source parses and walks a shell program.
func (a *analyzer) source(src string, st *state, via []string, depth int) {
	if depth > a.opt.MaxDepth {
		a.unbounded(st, via, src, "nesting deeper than the analyzer follows")
		return
	}
	if nestingDepth(src) > maxNesting {
		// The parser and the walk recurse per level; deeper text would
		// overflow the stack and kill the process with no verdict.
		a.unbounded(st, via, src, "nesting deeper than the analyzer follows")
		return
	}
	if chainLength(src) > maxChain {
		// A long && or | chain, or a long arithmetic sum, parses to a tree
		// as deep as it is long, and the walk recurses along it: past a few
		// hundred thousand links the stack overflows and the process dies
		// with no verdict, and memory runs to hundreds of times the text.
		a.unbounded(st, via, "", "a chain of more than "+strconv.Itoa(maxChain)+" commands or operands, which the analyzer does not follow")
		return
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		// A shell runs the lines before a syntax error: walk them too.
		var pe syntax.ParseError
		if errors.As(err, &pe) && pe.Pos.Line() > 1 {
			lines := strings.SplitAfter(src, "\n")
			before := strings.Join(lines[:min(int(pe.Pos.Line())-1, len(lines))], "")
			if g, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(before), ""); err == nil {
				for _, s := range g.Stmts {
					a.stmt(s, st, via, depth, stdin{})
				}
			}
		}
		a.unbounded(st, via, src, "could not parse as shell: "+err.Error())
		return
	}
	for _, s := range f.Stmts {
		a.stmt(s, st, via, depth, stdin{})
	}
}

func (a *analyzer) stmts(ss []*syntax.Stmt, st *state, via []string, depth int) {
	a.stmtsIn(ss, st, via, depth, stdin{})
}

// stmtsIn walks statements that share one standard input: the input given
// to a compound command ({ …; } <<EOF, while …; done < f) is there for any
// command inside it to read.
func (a *analyzer) stmtsIn(ss []*syntax.Stmt, st *state, via []string, depth int, in stdin) {
	for _, s := range ss {
		a.stmt(s, st, via, depth, in)
	}
}

// clobberTargets reads zsh's >! >>! >&! &>! (and >| style) operators. The
// bash grammar this parser follows reads them as the plain operator and a
// target of "!", so the file is the next word of the command, which it sees
// as an argument. The file is moved from the arguments to the redirection.
func clobberTargets(s *syntax.Stmt) {
	c, ok := s.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.DplOut:
		default:
			continue
		}
		if r.Word == nil || r.Word.Lit() != "!" {
			continue
		}
		end := r.Word.End().Offset()
		for i, arg := range c.Args {
			if arg.Pos().Offset() >= end {
				r.Word = arg
				c.Args = append(append([]*syntax.Word(nil), c.Args[:i]...), c.Args[i+1:]...)
				break
			}
		}
	}
}

func (a *analyzer) stmt(s *syntax.Stmt, st *state, via []string, depth int, in stdin) {
	if s == nil {
		return
	}
	a.budget--
	if a.budget < 0 {
		if a.budget == -1 {
			a.unbounded(st, via, "", "command too large to analyze")
		}
		return
	}
	if s.Background {
		// cmd & runs in a subshell: its cd and assignments stay there.
		st = st.clone()
	}
	var redirs []Redir
	clobberTargets(s)
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			w := a.hdocWord(r, st, via, depth)
			in = stdin{text: w.Text, known: w.Resolved, present: true, desc: "here-document"}
		case syntax.WordHdoc:
			w := a.word(r.Word, st, via, depth)
			in = stdin{text: w.Text, known: w.Resolved, present: true, desc: "here-string"}
		case syntax.RdrIn:
			w := a.word(r.Word, st, via, depth)
			in = stdin{present: true, desc: "file " + w.Text}
			if w.Resolved {
				if b, err := a.read(st, w.Text); err == nil {
					in.text, in.known = string(b), true
				}
			}
			redirs = append(redirs, Redir{Op: r.Op.String(), Target: w})
		default:
			// A brace expansion in the target ({a,b}.json) is several files:
			// zsh writes every one (multios), bash refuses. Each is a write.
			for _, w := range a.words(r.Word, st, via, depth) {
				write := r.Op != syntax.DplIn && r.Op != syntax.DplOut
				if r.Op == syntax.DplOut || r.Op == syntax.DplIn {
					// >&FD and >&- duplicate or close a descriptor; >& FILE (bash
					// and zsh) sends stdout and stderr to the file. A word that
					// is not a number or - is a file, and one that cannot be
					// resolved may be.
					t := w.Text
					fd := t == "-" || t != "" && strings.Trim(t, "0123456789") == "" ||
						len(t) > 1 && t[len(t)-1] == '-' && strings.Trim(t[:len(t)-1], "0123456789") == ""
					if !fd && !(w.Resolved && t == "") {
						write = r.Op == syntax.DplOut
					}
				}
				redirs = append(redirs, Redir{Op: r.Op.String(), Target: w, Write: write})
			}
		}
	}
	defer func() {
		for _, r := range redirs {
			if r.Write && r.Target.Text != "/dev/null" && !strings.HasPrefix(r.Target.Text, "&") {
				a.wrote(st, r.Target, wroteFile)
			}
		}
	}()
	// Redirections of a statement that is not a simple command with words
	// ({ …; } > f, ( … ) > f, if …; fi > f, a bare > f) apply all the same:
	// they are recorded as an invocation with no program.
	if c, isCall := s.Cmd.(*syntax.CallExpr); (!isCall || len(c.Args) == 0) && len(redirs) > 0 {
		a.res.Invocations = append(a.res.Invocations, Invocation{Dir: st.dir, Approx: st.approx, Env: st.env(), Redirs: redirs, Via: append([]string(nil), via...)})
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
			ys := st.clone()
			a.stmt(c.Y, ys, via, depth, stdin{text: out, known: ok, present: true, desc: "output of " + short(pipeSource(c.X))})
			// zsh (and bash with lastpipe) runs the last element in the
			// current shell, bash in a subshell: a cd there may or may not
			// move the shell.
			if ys.dir != st.dir {
				st.dir = ""
			}
		default:
			a.stmt(c.X, st, via, depth, in)
			a.stmt(c.Y, st, via, depth, stdin{})
		}
	case *syntax.Subshell:
		a.stmtsIn(c.Stmts, st.clone(), via, depth, in)
	case *syntax.Block:
		a.stmtsIn(c.Stmts, st, via, depth, in)
	case *syntax.IfClause:
		for ic := c; ic != nil; ic = ic.Else {
			a.stmtsIn(ic.Cond, st, via, depth, in)
			a.stmtsIn(ic.Then, st, via, depth, in)
		}
	case *syntax.WhileClause:
		a.stmtsIn(c.Cond, st, via, depth, in)
		a.stmtsIn(c.Do, st, via, depth, in)
	case *syntax.ForClause:
		if cl, ok := c.Loop.(*syntax.CStyleLoop); ok {
			a.arith(cl, st, via, depth)
		}
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
					a.stmtsIn(c.Do, st, via, depth, in)
				}
				return
			}
			st.vars[wi.Name.Value] = value{}
		} else {
			a.substitutionsIn(c.Loop, st, via, depth)
		}
		a.stmtsIn(c.Do, st, via, depth, in)
	case *syntax.CaseClause:
		a.word(c.Word, st, via, depth)
		for _, it := range c.Items {
			for _, p := range it.Patterns {
				a.substitutionsIn(p, st, via, depth)
			}
			a.stmtsIn(it.Stmts, st, via, depth, in)
		}
	case *syntax.FuncDecl:
		if c.Name == nil {
			// Anonymous function: runs immediately.
			a.stmt(c.Body, st, via, depth, in)
			return
		}
		st.funcs[c.Name.Value] = c.Body
		if n := c.Name.Value; n == "command_not_found_handle" || n == "command_not_found_handler" || zshHook(n) {
			// bash and zsh run it for any command they cannot find, and
			// zsh its hook functions (chpwd after a cd, TRAPEXIT at exit),
			// so it may run at any later point, after any cd.
			t := st.clone()
			t.dir = ""
			a.stmt(c.Body, t, append(via, n), depth+1, stdin{})
			// It runs in this shell (TRAPDEBUG before every command), so
			// a cd in it moves what follows.
			st.dir, st.dirStack = "", nil
		}
	case *syntax.DeclClause:
		a.declClause(c, st, via, depth)
	case *syntax.TimeClause:
		a.stmt(c.Stmt, st, via, depth, in)
	case *syntax.CoprocClause:
		a.stmt(c.Stmt, st.clone(), via, depth, in)
	case *syntax.TestClause, *syntax.ArithmCmd, *syntax.LetClause:
		// Conditions and arithmetic start no programs, except through
		// command substitutions, which the word walk below would catch;
		// we walk the source text for those to stay conservative. Arithmetic
		// in them evaluates subscripts, which can run commands.
		a.arith(s, st, via, depth)
		a.substitutionsIn(s, st, via, depth)
	case nil:
	default:
		a.substitutionsIn(c, st, via, depth)
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

// declClause handles declare, typeset, local, export, readonly and
// nameref. Options apply to the names after them; -n makes a name refer to
// another variable, and a name built at run time could be any variable.
func (a *analyzer) declClause(c *syntax.DeclClause, st *state, via []string, depth int) {
	variant := c.Variant.Value
	export := variant == "export"
	ref := variant == "nameref"
	// Inside a function, local, declare and typeset make a local variable.
	local := st.locals != nil && (variant == "local" || variant == "declare" || variant == "typeset")
	for _, as := range c.Args {
		if as.Name == nil {
			if as.Value == nil {
				continue
			}
			w := a.word(as.Value, st, via, depth)
			switch {
			case !w.Resolved:
				st.nameref = true
			case strings.HasPrefix(w.Text, "-") || strings.HasPrefix(w.Text, "+"):
				on := w.Text[0] == '-'
				for _, f := range w.Text[1:] {
					switch f {
					case 'n':
						ref = ref || on
					case 'x':
						export = export || on
					case 'g':
						local = local && !on
					}
				}
			default:
				if subscriptRuns(w) {
					a.unbounded(st, via, w.Text, "a declaration names a variable whose subscript holds a command substitution; the shell evaluates the subscript, which runs it")
				}
				name, val, eq := strings.Cut(w.Text, "=")
				a.promptVar(name, val, st, via, depth)
				a.declare(name, st, local)
				if eq {
					st.vars[name] = capped(val, true)
				}
				if export {
					st.exported[name] = true
				}
				st.nameref = st.nameref || ref
			}
			continue
		}
		name := as.Name.Value
		a.declare(name, st, local)
		if ref {
			st.nameref = true
		}
		if as.Naked {
			if local {
				st.vars[name] = value{ok: true}
			}
		} else {
			a.assign(as, st, via, depth)
		}
		if export {
			st.exported[name] = true
		}
	}
}

// declare records a function's local variable with the value it had before.
func (a *analyzer) declare(name string, st *state, local bool) {
	if !local || st.locals == nil {
		return
	}
	if _, seen := st.locals[name]; seen {
		return
	}
	if v, ok := st.vars[name]; ok {
		st.locals[name] = &v
	} else {
		st.locals[name] = nil
	}
}

func (a *analyzer) assign(as *syntax.Assign, st *state, via []string, depth int) {
	if as.Array != nil || as.Index != nil {
		st.vars[as.Name.Value] = value{}
		a.substitutionsIn(as, st, via, depth)
		a.arith(as, st, via, depth)
		return
	}
	var w Word
	if as.Value != nil {
		a.noGlob++
		w = a.word(as.Value, st, via, depth)
		a.noGlob--
	} else {
		w = Word{Resolved: true}
	}
	a.promptVar(as.Name.Value, w.Text, st, via, depth)
	if as.Append {
		prev := st.vars[as.Name.Value]
		st.vars[as.Name.Value] = capped(prev.text+w.Text, prev.ok && w.Resolved)
		return
	}
	st.vars[as.Name.Value] = capped(w.Text, w.Resolved)
}

// litOnly reports whether parts hold no expansion.
func litOnly(parts []syntax.WordPart) bool {
	for _, p := range parts {
		switch x := p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			if !litOnly(x.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// capped is a variable's value, unresolved when it is longer than maxText.
func capped(text string, ok bool) value {
	if len(text) > maxText {
		return value{}
	}
	return value{text: text, ok: ok}
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

const braceGuardMax = 1024

// litLen sums the literal length of a word's parts, stopping once it exceeds
// cap. It is a cheap size estimate used to skip brace expansion on huge words.
func litLen(parts []syntax.WordPart, cap int) int {
	n := 0
	for _, p := range parts {
		switch x := p.(type) {
		case *syntax.Lit:
			n += len(x.Value)
		case *syntax.SglQuoted:
			n += len(x.Value)
		case *syntax.DblQuoted:
			n += litLen(x.Parts, cap)
		default:
			n++
		}
		if n > cap {
			return n
		}
	}
	return n
}

// words resolves one syntax word, applying brace expansion.
func (a *analyzer) words(w *syntax.Word, st *state, via []string, depth int) []Word {
	cp := &syntax.Word{Parts: append([]syntax.WordPart(nil), w.Parts...)}
	// syntax.SplitBraces allocates heavily on deeply nested braces (e.g.
	// "{{{...}}}") even when there is nothing to expand. A real brace
	// expansion is short, so skip it for pathologically long words (worst case under the cap stays small).
	if litLen(w.Parts, braceGuardMax) <= braceGuardMax && syntax.SplitBraces(cp) {
		n := 1
		for _, p := range cp.Parts {
			if be, ok := p.(*syntax.BraceExp); ok {
				n *= braceCount(be)
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
	if ws, ok := a.allParams(w, st); ok {
		return ws
	}
	return a.split(a.word(w, st, via, depth), st)
}

// braceCount is how many words a brace expansion makes: its elements, or
// for a sequence ({1..N}, {a..z}) the length of the range. A range that
// cannot be counted counts as too many.
func braceCount(be *syntax.BraceExp) int {
	if !be.Sequence {
		return max(len(be.Elems), 1)
	}
	if len(be.Elems) < 2 {
		return 1 << 30
	}
	end := func(e *syntax.Word) (int, bool) {
		t := e.Lit()
		if n, err := strconv.Atoi(t); err == nil {
			return n, true
		}
		if len(t) == 1 {
			return int(t[0]), true
		}
		return 0, false
	}
	lo, ok1 := end(be.Elems[0])
	hi, ok2 := end(be.Elems[1])
	if !ok1 || !ok2 {
		return 1 << 30
	}
	step := 1
	if len(be.Elems) > 2 {
		n, err := strconv.Atoi(be.Elems[2].Lit())
		if err != nil || n == 0 {
			return 1 << 30
		}
		step = max(n, -n)
	}
	d := hi - lo
	if d < 0 {
		d = -d
	}
	if d/step > 1<<20 {
		return 1 << 30
	}
	return d/step + 1
}

// allParams expands a word that is exactly "$@" or $@ into one word per
// positional parameter, so a wrapper function like retry() { "$@"; } is
// analyzed as the command it runs. ok is false outside a function or script,
// or for any other word.
func (a *analyzer) allParams(w *syntax.Word, st *state) ([]Word, bool) {
	if st.params == nil || len(w.Parts) != 1 {
		return nil, false
	}
	p := w.Parts[0]
	if dq, isDq := p.(*syntax.DblQuoted); isDq {
		if len(dq.Parts) != 1 {
			return nil, false
		}
		p = dq.Parts[0]
	}
	pe, isPe := p.(*syntax.ParamExp)
	if !isPe || pe.Param == nil || pe.Param.Value != "@" || pe.Index != nil || pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Length || pe.Excl {
		return nil, false
	}
	out := make([]Word, len(st.params))
	for i, v := range st.params {
		out[i] = Word{Text: v.text, Resolved: v.ok}
		if v.ok {
			out[i].Prefix = v.text
		}
	}
	return out, true
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
	// A literal word is as long as the command that holds it; only
	// expansions can grow past it.
	literal := litOnly(w.Parts)
	for i, p := range w.Parts {
		if !res.unquoted {
			switch p.(type) {
			case *syntax.ParamExp, *syntax.CmdSubst:
				res.unquoted = true
			}
		}
		a.part(p, st, via, depth, &b, mark, i == 0, false)
		if b.Len() > maxText && !literal {
			mark()
			res.Prefix = res.Prefix[:min(len(res.Prefix), maxText)]
			return Word{Prefix: res.Prefix, unquoted: res.unquoted}
		}
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
			a.res.Problems = append(a.res.Problems, Problem{Text: "", Reason: "command too complex to analyze", Dir: st.dir, AnyDir: true})
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
		if i := globAt(v); a.noGlob == 0 && (i >= 0 || first && len(v) > 1 && v[0] == '=') {
			// The shell expands a glob against the file system, and zsh
			// expands =name to the path of name: neither is known here.
			if i < 0 {
				i = 0
			}
			b.WriteString(unescapeLit(v[:i]))
			mark()
			b.WriteString(unescapeLit(v[i:]))
			return
		}
		v = unescapeLit(v)
		if first && (v == "~" || strings.HasPrefix(v, "~/")) {
			if home, ok := a.opt.Env["HOME"]; ok {
				v = home + v[1:]
			}
		} else if first && strings.HasPrefix(v, "~") && len(v) > 1 && v[1] != '/' {
			// ~+ is the working directory, ~- the previous one, ~user
			// another person's home, ~N a stack entry. Only ~+ is known.
			if st != nil && st.dir != "" && (v == "~+" || strings.HasPrefix(v, "~+/")) {
				v = st.dir + v[2:]
			} else {
				mark()
			}
		}
		b.WriteString(v)
	case *syntax.SglQuoted:
		if x.Dollar {
			v, ok := ansiC(x.Value)
			if !ok {
				mark()
			}
			b.WriteString(v)
		} else {
			b.WriteString(x.Value)
		}
	case *syntax.DblQuoted:
		for _, q := range x.Parts {
			a.part(q, st, via, depth, b, mark, false, true)
		}
	case *syntax.ParamExp:
		if a.quiet == 0 && (x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil) {
			// ${x:-$(cmd)} and ${a[$(cmd)]} run cmd.
			a.substitutionsIn(x, st, via, depth)
			if x.Slice != nil || x.Index != nil {
				a.arith(x, st, via, depth)
			}
		}
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
		if out, ok := a.stdoutSeq(x.Stmts, st.clone()); ok {
			b.WriteString(strings.TrimRight(out, "\n"))
			return
		}
		mark()
	case *syntax.ProcSubst:
		if a.quiet == 0 {
			a.stmts(x.Stmts, st.clone(), via, depth)
		}
		mark()
	case *syntax.ExtGlob:
		mark()
		b.WriteString(x.Op.String() + x.Pattern.Value + ")")
		// In zsh, *(e:code:) and *(+func) are glob qualifiers that run code
		// for each match.
		if x.Op == syntax.GlobZeroOrMore && zshQualifierRuns.MatchString(x.Pattern.Value) {
			a.problem(st, via, x.Op.String()+x.Pattern.Value+")", "a zsh glob qualifier runs code; it cannot be analyzed")
		}
	default:
		// Arithmetic and anything else: not resolved statically, but any
		// command substitution inside still runs.
		if a.quiet == 0 {
			if _, ok := p.(*syntax.ArithmExp); ok {
				a.arith(p, st, via, depth)
			}
			if be, ok := p.(*syntax.BraceExp); ok {
				// syntax.Walk does not know brace expansions; walk each
				// element's words.
				for _, e := range be.Elems {
					a.substitutionsIn(e, st, via, depth)
				}
			} else {
				a.substitutionsIn(p, st, via, depth)
			}
		}
		mark()
	}
}

var safeEnv = map[string]bool{"HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "TMPDIR": true}

func (a *analyzer) param(x *syntax.ParamExp, st *state) (string, bool) {
	// ${BASH_SOURCE[0]} and $BASH_SOURCE are the running script's path.
	if x.Param != nil && x.Param.Value == "BASH_SOURCE" && x.Exp == nil && x.Slice == nil && x.Repl == nil &&
		!x.Length && !x.Excl && (x.Index == nil || nodeText(x.Index) == "0") {
		return st.arg0.text, st.arg0.ok
	}
	if x.Param == nil || x.Excl || x.Length || x.Width || x.Index != nil ||
		x.Slice != nil || x.Repl != nil || x.Exp != nil || x.Flags != nil || x.NestedParam != nil {
		return "", false
	}
	name := x.Param.Value
	if st.nameref {
		return "", false
	}
	if v, ok := st.vars[name]; ok {
		return v.text, v.ok
	}
	if name == "PWD" && st.dir != "" {
		return st.dir, true
	}
	if name == "0" {
		return st.arg0.text, st.arg0.ok
	}
	if (name == "@" || name == "*" || name == "#") && st.params != nil {
		if name == "#" {
			return fmt.Sprint(len(st.params)), true
		}
		parts := make([]string, len(st.params))
		for i, v := range st.params {
			if !v.ok {
				return "", false
			}
			parts[i] = v.text
		}
		return strings.Join(parts, " "), true
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

// abs is where p names from the current directory, as the kernel resolves
// it (see PhysicalJoin).
// dirAbs resolves p, a directory a command is run in or moves to. From a
// directory that is only approximate, a relative one is not known ("").
func (a *analyzer) dirAbs(st *state, p string) string {
	if st.approx && !filepath.IsAbs(p) {
		return ""
	}
	return a.abs(st, p)
}

func (a *analyzer) abs(st *state, p string) string {
	if filepath.IsAbs(p) || st.dir == "" {
		return PhysicalJoin("", p)
	}
	return PhysicalJoin(st.dir, p)
}

// limitWriter aborts after max bytes so printing a huge node (e.g. the whole
// upstream of a 60k-stage pipeline) stays O(1) instead of rendering it all only
// for short() to throw it away. The printer stops at the first write error.
type limitWriter struct {
	b   strings.Builder
	max int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.b.Len() >= w.max {
		return 0, errWriteLimit
	}
	if n := w.max - w.b.Len(); len(p) > n {
		w.b.Write(p[:n])
		return n, errWriteLimit
	}
	return w.b.Write(p)
}

var errWriteLimit = errors.New("node text limit reached")

func nodeText(n syntax.Node) string {
	w := &limitWriter{max: 4096}
	// A write-limit error is expected and means the output was truncated.
	_ = syntax.NewPrinter(syntax.Minify(true)).Print(w, n)
	return w.b.String()
}

// pipeSource names the left side of a pipe for a human-readable "output of …"
// message. Rendering a composite upstream is O(n) (the printer traverses the
// whole node even past a write limit), which in a 60k-stage pipeline becomes
// O(n) per stage. So small upstreams are rendered exactly as before; only a
// pathologically large one is labelled generically.
func pipeSource(n syntax.Node) string {
	if smallNode(n, 32) {
		return nodeText(n)
	}
	return "a pipeline"
}

// smallNode reports whether n contains at most budget statements, visiting at
// most budget+1 of them. Cheap even when called per pipe stage.
func smallNode(n syntax.Node, budget int) bool {
	count := 0
	ok := true
	syntax.Walk(n, func(nd syntax.Node) bool {
		if !ok {
			return false
		}
		if _, isStmt := nd.(*syntax.Stmt); isStmt {
			if count++; count > budget {
				ok = false
				return false
			}
		}
		return true
	})
	return ok
}

// hdocWord is the text a here-document gives its command. A quoted delimiter
// ('EOF', "EOF", \EOF) makes the body literal: a backslash stays. With a bare
// delimiter the shell expands $, backquote and backslash inside it as in
// double quotes, and a backslash removes itself only before $, backquote,
// another backslash and a newline. Reading the body as a word, which drops
// every backslash, turned the quote-escape idiom of a nested sh -c into
// different text, so a command nested in a here-document was analyzed as
// something the shell did not run.
func (a *analyzer) hdocWord(r *syntax.Redirect, st *state, via []string, depth int) Word {
	if r.Hdoc == nil {
		return Word{Resolved: true}
	}
	quoted := false
	if r.Word != nil {
		for _, p := range r.Word.Parts {
			switch x := p.(type) {
			case *syntax.SglQuoted, *syntax.DblQuoted:
				quoted = true
			case *syntax.Lit:
				if strings.Contains(x.Value, `\`) {
					quoted = true
				}
			}
		}
	}
	var b strings.Builder
	res := Word{Resolved: true}
	mark := func() {
		if res.Resolved {
			res.Prefix = b.String()
		}
		res.Resolved = false
	}
	for _, p := range r.Hdoc.Parts {
		if lit, ok := p.(*syntax.Lit); ok {
			if quoted {
				b.WriteString(lit.Value)
			} else {
				b.WriteString(unescapeHdoc(lit.Value))
			}
			continue
		}
		a.part(p, st, via, depth, &b, mark, false, true)
		if b.Len() > maxText {
			mark()
			res.Prefix = res.Prefix[:min(len(res.Prefix), maxText)]
			return Word{Prefix: res.Prefix}
		}
	}
	res.Text = b.String()
	if res.Resolved {
		res.Prefix = res.Text
	}
	return res
}

// unescapeHdoc removes the backslash of \$, \`+"`"+`, \\ and a backslash-newline, the
// only escapes an unquoted here-document body has.
func unescapeHdoc(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\\\n", s[i+1]) >= 0 {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
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

// globAt returns the index of the first unescaped glob character in an
// unquoted literal (*, ?, or a [ closed later in the word), or -1.
func globAt(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '*', '?':
			return i
		case '[':
			if strings.Contains(s[i+1:], "]") {
				return i
			}
		}
	}
	return -1
}

// ansiC decodes the body of a $'...' string. ok is false for escapes whose
// result depends on the locale or that it does not model (\u, \U, \c).
func ansiC(s string) (string, bool) {
	ok := true
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
		case 'u', 'U', 'c':
			ok = false
			b.WriteByte('\\')
			b.WriteByte(s[i])
		case '\\', '\'', '"', '?':
			b.WriteByte(s[i])
		default:
			// Bash keeps the backslash of an escape it does not know.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String(), ok
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

// maxNesting bounds the brackets the parser is given, far above what a
// person writes and far below what overflows the stack.
const maxNesting = 2000

// nestingDepth is the deepest nesting of what the parser recurses on in
// src: parentheses (subshells, $( ), arithmetic) and braces that open a
// block ("{" followed by white space). Quoting is ignored: an overestimate
// is safe. Braces inside a word ({a,b}) are not counted.
func nestingDepth(src string) int {
	d, m := 0, 0
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case c == '(' || c == '{' && i+1 < len(src) && (src[i+1] == ' ' || src[i+1] == '\t' || src[i+1] == '\n'):
			d++
			if d > m {
				m = d
			}
		case c == ')' || c == '}':
			if d > 0 {
				d--
			}
		}
	}
	return m
}

// maxChain is the most binary operators (&&, ||, |, +) one program may chain.
const maxChain = 20000

// chainLength counts the operators that nest left to right in the parse
// tree: &&, || and | between commands, and + - * in arithmetic. Quoting is
// ignored: an overestimate is safe.
func chainLength(src string) int {
	n := 0
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '&', '|':
			n++
			if i+1 < len(src) && src[i+1] == src[i] {
				i++
			}
		case '+':
			n++
		}
	}
	return n
}

// zshHook reports whether zsh calls a function of this name on its own:
// the hook functions and the TRAP<signal> handlers.
func zshHook(n string) bool {
	switch n {
	case "chpwd", "precmd", "preexec", "periodic", "zshexit", "zshaddhistory":
		return true
	}
	return strings.HasPrefix(n, "TRAP")
}

// zshSpecial are zsh parameters whose assignment changes what a command
// name runs or which files zsh reads: the function, command, alias and
// builtin tables, the search paths, and the hook arrays.
func zshSpecial(n string) bool {
	switch n {
	case "path", "fpath", "cdpath", "manpath", "module_path", "mailpath", "functions", "commands", "aliases", "galiases",
		"saliases", "builtins", "dis_functions", "dis_aliases", "dis_builtins", "dis_galiases", "dis_saliases", "parameters",
		"options", "nameddirs", "userdirs", "reswords", "dis_reswords", "psvar", "zle_highlight":
		return true
	}
	return strings.HasSuffix(n, "_functions")
}
