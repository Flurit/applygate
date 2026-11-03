package shell

import (
	"fmt"
	"path/filepath"
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
	if nestingDepth(cmd) > maxNesting {
		return false, "nesting deeper than the analyzer parses"
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return false, "it does not parse"
	}
	bare := map[*syntax.Assign]bool{} // assignments with no command
	syntax.Walk(f, func(n syntax.Node) bool {
		if why != "" || n == nil {
			return why == ""
		}
		switch x := n.(type) {
		case *syntax.File, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted, *syntax.Redirect, *syntax.Comment:
			if q, ok := x.(*syntax.SglQuoted); ok && q.Dollar {
				why = "a $'...' string"
			}
		case *syntax.Assign:
			// A variable set for a command, or in the shell, which an
			// exported one passes on: its value must be literal, and
			// pagers may only be turned off. A shell variable with a lower
			// case letter is local: programs read upper-case names.
			v, lit := litWord(x.Value)
			if bare[x] && x.Name != nil && strings.ToUpper(x.Name.Value) != x.Name.Value {
				break
			}
			if x.Name == nil || x.Append || x.Array != nil || x.Index != nil {
				why = "an array or appended variable"
			} else if !lit {
				why = "the variable " + x.Name.Value + " set to a value that cannot be resolved"
			} else {
				why = plainEnvVar(x.Name.Value, v, true)
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				for _, as := range x.Assigns {
					bare[as] = true
				}
			}
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
							why = "the variable " + k + " set to a value that cannot be resolved"
						} else if why = plainEnvVar(k, v, true); why != "" {
							break
						}
					}
				}
			}
		case *syntax.Stmt:
			if x.Background || x.Coprocess || x.Negated {
				why = "a background or negated statement"
			}
		case *syntax.BinaryCmd:
			if x.Op != syntax.AndStmt && x.Op != syntax.OrStmt && x.Op != syntax.Pipe {
				why = "the operator " + x.Op.String()
			}
		case *syntax.ParamExp:
			if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
				why = "a parameter expansion"
			}
		default:
			why = describe(n)
		}
		return why == ""
	})
	if why != "" {
		return false, why
	}
	if len(res.Problems) > 0 {
		return false, "a part the analyzer cannot resolve (" + res.Problems[0].Reason + ")"
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
				return false, "the program " + n
			}
		}
		if !inv.Args[0].Resolved {
			return false, "a program name that cannot be resolved"
		}
		if why := shapeOf(inv); why != "" {
			return false, why
		}
		// The repository's hooks and config are read by later git
		// commands, this one's included (gitRepoState).
		words := inv.Args[1:]
		for _, r := range inv.Redirs {
			words = append(words, r.Target)
		}
		for _, w := range words {
			if gitStatePath(optText(w)) {
				return false, "a path in a git directory's hooks or config"
			}
		}
	}
	return true, ""
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

func describe(n syntax.Node) string {
	switch n.(type) {
	case *syntax.FuncDecl:
		return "a function"
	case *syntax.CmdSubst:
		return "a command substitution"
	case *syntax.ProcSubst:
		return "a process substitution"
	case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause:
		return "arithmetic"
	case *syntax.Subshell, *syntax.Block:
		return "a subshell or block"
	case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		return "a loop or conditional"
	case *syntax.DeclClause:
		return "a declaration"
	case *syntax.TestClause:
		return "a [[ ]] test"
	case *syntax.ExtGlob, *syntax.BraceExp:
		return "an extended glob or brace expansion"
	}
	return strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax.")
}

// gitStatePath reports whether p names a git directory's hooks, config or
// the git directories of submodules.
func gitStatePath(p string) bool {
	segs := strings.Split(filepath.ToSlash(p), "/")
	for i, s := range segs {
		if s == ".git" && i+1 < len(segs) {
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
