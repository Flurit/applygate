package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PlainShape reports whether cmd is plain: it parses, its structure is a
// list or pipeline (&&, ||, |, ;) of simple commands with plain words, the
// analysis found no problem, every variable it sets is on plainEnv, and
// every program it runs, wrappers, shells and make recipes included, is a
// resolved name whose call fits its shape (shapes.go). why says what is not
// plain. Arguments need not resolve unless a shape reads them: that was
// measured (review/v0.6.0/2026-11-03-strict-shapes.md, variant B) to ask
// about far fewer real agent calls for no extra catch.
func PlainShape(cmd string, res *Result) (ok bool, why string) {
	ok, why, _ = PlainShapeUnseen(cmd, res)
	return ok, why
}

// PlainShapeUnseen is PlainShape that also reports whether what is not plain
// can run code the analysis does not see: a program with no shape, a program
// named by a path or not resolved, a part the analysis could not resolve, a
// variable a program reads, git state, a command that does not parse. A
// command that is not plain only in its syntax (a loop, a function, a
// substitution, a test) is followed by the analysis, so each program in it is
// judged where it runs. unseen is the first reason code may run unseen, empty
// when none does.
func PlainShapeUnseen(cmd string, res *Result) (ok bool, why string, unseen string) {
	if nestingDepth(cmd) > maxNesting {
		return false, "nesting deeper than the analyzer parses", "nesting deeper than the analyzer parses"
	}
	if chainLength(cmd) > maxChain {
		r := "a chain of more than " + strconv.Itoa(maxChain) + " commands or operands"
		return false, r, r
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return false, "it does not parse", "it does not parse"
	}
	// set records the first reason a command is not plain, and whether any
	// reason leaves code unseen. The walk goes on past a syntax-only reason,
	// since the programs inside a loop or a function can run unseen code too.
	set := func(r string, hidden bool) {
		if r == "" {
			return
		}
		if why == "" {
			why = r
		}
		if hidden && unseen == "" {
			unseen = r
		}
	}
	bare := map[*syntax.Assign]bool{} // assignments with no command
	syntax.Walk(f, func(n syntax.Node) bool {
		if n == nil {
			return true
		}
		switch x := n.(type) {
		case *syntax.File, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted, *syntax.Redirect, *syntax.Comment:
			if q, ok := x.(*syntax.SglQuoted); ok && q.Dollar {
				set("a $'...' string", false)
			}
		case *syntax.Assign:
			// A variable set for a command, or in the shell, which an
			// exported one passes on: its value must be literal, and
			// pagers may only be turned off. A shell variable with a lower
			// case letter is local: programs read upper-case names.
			v, lit := litWord(x.Value)
			if bare[x] && x.Name != nil && strings.ToUpper(x.Name.Value) != x.Name.Value &&
				!x.Append && x.Array == nil && x.Index == nil && !zshSpecial(x.Name.Value) {
				break
			}
			if x.Name == nil || x.Append || x.Array != nil || x.Index != nil {
				set("an array or appended variable", true)
			} else if !lit {
				set("the variable "+x.Name.Value+" set to a value that cannot be resolved", true)
			} else {
				set(plainEnvVar(x.Name.Value, v, true), true)
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				for _, as := range x.Assigns {
					bare[as] = true
				}
			}
			// hash NAME=PATH (zsh) and hash -p PATH NAME make NAME run PATH.
			if len(x.Args) > 1 {
				if n, ok := litWord(x.Args[0]); ok && n == "hash" {
					for _, w := range x.Args[1:] {
						if t, ok := litWord(w); !ok || t == "-p" || t == "-d" || strings.Contains(t, "=") {
							set("hash binding a name to a program", true)
						}
					}
				}
			}
			// read, mapfile, readarray and getopts assign the names they
			// are given text read at run time: an upper-case name (one a
			// program may read, PATH and HOME included) or a zsh special
			// array is not plain, as NAME=$(...) is not.
			set(runtimeAssign(x.Args), true)
			// env NAME=value: the same rule as an assignment.
			if len(x.Args) > 0 {
				if n, ok := litWord(x.Args[0]); ok && ProgName(n) == "env" {
					for _, w := range x.Args[1:] {
						t, ok := litWord(w)
						k, v, isAssign := strings.Cut(t, "=")
						if !isAssign || strings.HasPrefix(t, "-") || k == "" {
							continue
						}
						if !ok {
							set("the variable "+k+" set to a value that cannot be resolved", true)
						} else {
							set(plainEnvVar(k, v, true), true)
						}
					}
				}
			}
		case *syntax.Stmt:
			if x.Background || x.Coprocess || x.Negated {
				set("a background or negated statement", false)
			}
		case *syntax.BinaryCmd:
			if x.Op != syntax.AndStmt && x.Op != syntax.OrStmt && x.Op != syntax.Pipe {
				set("the operator "+x.Op.String(), false)
			}
		case *syntax.ParamExp:
			if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
				set("a parameter expansion", false)
			}
		default:
			r, known := describe(n)
			set(r, !known)
		}
		return true
	})
	if len(res.Problems) > 0 {
		set("a part the analyzer cannot resolve ("+res.Problems[0].Reason+")", true)
	}
	// writesGit is set once a step can have written git state without
	// naming it (a new repository, an extracted archive, a recursive
	// copy): git's state is read before the command runs, so a later git
	// command would run what that step put there.
	writesGit := false
	followed := map[string]bool{}
	for _, inv := range res.Invocations {
		for _, v := range inv.Via {
			followed[viaProgram(v)] = true
		}
	}
	for _, inv := range res.Invocations {
		if len(inv.Args) == 0 {
			continue // a bare redirection
		}
		// A wrapper or shell the command ran through counts as a program
		// of its own (env, bash -c, xargs), and so does the program it
		// ran, a make recipe's included.
		for _, v := range inv.Via {
			if n := viaProgram(v); !hasShape(n) {
				// A wrapper the analysis followed (xargs, make, docker, an
				// alias, bash -c with literal text) runs what it expands to,
				// which is judged on its own; what it could not follow is a
				// problem, not a wrapper.
				set("the program "+n, false)
			}
		}
		if !inv.Args[0].Resolved {
			set("a program name that cannot be resolved", true)
			continue
		}
		// A program the analysis took apart (make with its recipes, docker run
		// with the image's command, pnpm exec, xargs) is followed: what it
		// runs is judged as invocations of their own. One it could not (a
		// nested agent, python3, a name no shape knows) can run anything.
		set(shapeOf(inv), !followed[ProgName(inv.Args[0].Text)])
		if n := ProgName(inv.Args[0].Text); n == "git" && writesGit {
			set("git after an earlier step that can write git state", true)
		} else if writesGitState(n, inv.Args[1:], inv.Dir) {
			writesGit = true
		}
		// The repository's hooks and config are read by later git
		// commands, this one's included (gitState).
		words := inv.Args[1:]
		for _, r := range inv.Redirs {
			words = append(words, r.Target)
		}
		for _, w := range words {
			if gitStatePath(optText(w)) {
				set("a path in a git directory's hooks or config", true)
			}
		}
	}
	return why == "", why, unseen
}

// viaProgram is the program in an Invocation.Via label: "bash -c",
// "make destroy", "printf | bash" (a pipe into a shell).
func viaProgram(v string) string {
	if i := strings.LastIndex(v, " | "); i >= 0 {
		v = v[i+3:]
	}
	if f := strings.Fields(v); len(f) > 0 {
		return ProgName(f[0])
	}
	return ""
}

// describe names a syntax node plain commands do not have, and says whether
// it is one the analysis follows (known) rather than a node type it has no
// name for.
func describe(n syntax.Node) (string, bool) {
	switch n.(type) {
	case *syntax.FuncDecl:
		return "a function", true
	case *syntax.CmdSubst:
		return "a command substitution", true
	case *syntax.ProcSubst:
		return "a process substitution", true
	case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause:
		return "arithmetic", true
	case *syntax.Subshell, *syntax.Block:
		return "a subshell or block", true
	case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		return "a loop or conditional", true
	case *syntax.DeclClause:
		return "a declaration", true
	case *syntax.TestClause:
		return "a [[ ]] test", true
	case *syntax.ExtGlob, *syntax.BraceExp:
		return "an extended glob or brace expansion", true
	case *syntax.WordIter, *syntax.CStyleLoop, *syntax.CaseItem, *syntax.ArrayExpr, *syntax.ArrayElem, *syntax.TimeClause, *syntax.CoprocClause,
		*syntax.BinaryArithm, *syntax.UnaryArithm, *syntax.ParenArithm, *syntax.BinaryTest, *syntax.UnaryTest, *syntax.ParenTest:
		return strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax."), true
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax."), false
}

// writesGitState reports whether a step can create or change a git
// directory without naming its files.
func writesGitState(n string, args []Word, dir string) bool {
	has := func(short byte, long ...string) bool {
		for _, w := range args {
			t := optText(w)
			if t == "--" {
				break
			}
			for _, l := range long {
				if t == l {
					return true
				}
			}
			if short != 0 && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.IndexByte(t[1:], short) >= 0 {
				return true
			}
		}
		return false
	}
	switch n {
	case "git":
		for _, w := range args {
			if t := optText(w); !strings.HasPrefix(t, "-") {
				return t == "init" || t == "clone" || t == "submodule" || t == "worktree"
			}
		}
	case "unzip", "bsdtar", "7z", "cpio", "rsync", "ditto", "patch":
		return true
	case "tar":
		return has('x', "--extract", "--get") || len(args) > 0 && !strings.HasPrefix(optText(args[0]), "-") && strings.Contains(optText(args[0]), "x")
	case "cp":
		return has('r', "--recursive", "--archive") || has('R') || has('a')
	case "mv", "ln":
		// A directory moved or linked into place.
		for _, w := range args {
			t := optText(w)
			if !w.Resolved {
				return true
			}
			if strings.HasPrefix(t, "-") {
				continue
			}
			if fi, err := os.Stat(PhysicalJoin(dir, t)); err == nil && fi.IsDir() || dir == "" {
				return true
			}
		}
	}
	return false
}

// gitStatePath reports whether p names a git directory's hooks, config or
// the git directories of submodules.
func gitStatePath(p string) bool {
	segs := strings.Split(filepath.ToSlash(p), "/")
	for i, s := range segs {
		if (s == ".git" || strings.HasSuffix(s, ".git")) && i+1 < len(segs) {
			// A repository's .git, or a bare repository named x.git.
			switch segs[i+1] {
			case "hooks", "config", "config.worktree", "modules", "commondir", "info", "worktrees":
				return true
			}
		}
		if s == ".git" && i+1 == len(segs) {
			// The .git entry itself: replaced by a file pointing elsewhere.
			return true
		}
	}
	return false
}

func hasShape(n string) bool {
	_, ok := shapes[n]
	return ok
}

// litWord is a word's text when it is made of literal parts only.
func litWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			if x.Dollar {
				return "", false
			}
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				l, ok := q.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(l.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// stateBuiltins change the shell itself: what a name runs, its options,
// its environment or its handlers.
var stateBuiltins = toSet("alias", "unalias", "hash", "enable", "disable", "shopt", "setopt", "unsetopt", "set", "bind", "trap",
	"autoload", "zmodload", "compdef", "functions", "export", "typeset", "declare", "local", "readonly", "source", ".", "eval",
	"rehash", "emulate", "builtin", "command_not_found_handle", "unset", "unfunction", "zle", "fc", "history", "umask", "ulimit")

// DefinesState reports what in cmd changes a shell that keeps running after
// it ("" when nothing does): a function, an alias or other state builtin, or
// a variable assignment on its own.
func DefinesState(cmd string) string {
	if chainLength(cmd) > maxChain || nestingDepth(cmd) > maxNesting {
		return "input too long or too deep to read"
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return "input that does not parse"
	}
	why := ""
	syntax.Walk(f, func(n syntax.Node) bool {
		if why != "" {
			return false
		}
		switch x := n.(type) {
		case *syntax.FuncDecl:
			why = "a function definition"
		case *syntax.DeclClause:
			why = "a declaration"
		case *syntax.CallExpr:
			if len(x.Args) == 0 && len(x.Assigns) > 0 {
				why = "a variable assignment"
				break
			}
			if len(x.Args) > 0 {
				name, ok := litWord(x.Args[0])
				if !ok {
					why = "a command name that cannot be resolved"
				} else if stateBuiltins[name] {
					why = "the builtin " + name
				}
			}
		}
		return why == ""
	})
	return why
}

// runtimeAssign reports a read, mapfile, readarray or getopts call (also
// through builtin or command) that assigns a variable a program could read.
func runtimeAssign(args []*syntax.Word) string {
	var ws []Word
	for _, a := range args {
		t, ok := litWord(a)
		ws = append(ws, Word{Text: t, Resolved: ok, Prefix: t})
	}
	for len(ws) > 0 && ws[0].Resolved && (ws[0].Text == "builtin" || ws[0].Text == "command") {
		ws = ws[1:]
	}
	if len(ws) == 0 || !ws[0].Resolved {
		return ""
	}
	bn := ws[0].Text
	switch bn {
	case "read", "mapfile", "readarray", "getopts":
	default:
		return ""
	}
	for _, w := range ws[1:] {
		if !w.Resolved {
			return "a " + bn + " whose words cannot be resolved"
		}
	}
	for _, n := range assignedBy(bn, ws[1:]) {
		switch n {
		case "REPLY", "MAPFILE", "OPTARG", "OPTIND":
			continue
		}
		if n == strings.ToUpper(n) || zshSpecial(n) {
			return "the variable " + n + " set by " + bn + " to text read at run time"
		}
	}
	return ""
}
