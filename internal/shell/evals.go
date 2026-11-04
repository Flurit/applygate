package shell

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Places where the shell evaluates text as code without a word that looks
// like a command: arithmetic (an array subscript in it may hold a command
// substitution that runs), builtin callbacks (mapfile -C, compgen -C) and
// prompt variables. Round 9 found each of them; the rule is that text the
// shell evaluates must be shown to be a number, a name or a literal command
// the analyzer can follow, or the command is unbounded.

var (
	numberRe     = regexp.MustCompile(`^(0[xX][0-9a-fA-F]+|[0-9]+(#[0-9a-zA-Z@_]+)?)$`)
	arithIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	arithText    = regexp.MustCompile(`^[0-9+\-*/%()<>=!&|^~?:, \t]*$`)
	subscripts   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\[[0-9A-Za-z_+\-*/ ]*\]$`)
)

// cmdSubstIn reports whether s holds a command substitution or backticks.
func cmdSubstIn(s string) bool { return strings.Contains(s, "$(") || strings.Contains(s, "`") }

// subscriptRuns reports whether a word names a variable with a subscript
// that holds a command substitution: the shell evaluates the subscript as
// arithmetic, which runs it (read 'a[$(cmd)]', declare, printf -v, unset).
func subscriptRuns(w Word) bool {
	return strings.Contains(w.Text, "[") && cmdSubstIn(w.Text) || !w.Resolved && strings.Contains(w.Prefix, "[") && cmdSubstIn(w.Prefix)
}

// numericValue reports whether the variable name holds only a number or an
// arithmetic expression of numbers, to the depth the analyzer follows.
func (st *state) numericValue(name string, depth int) bool {
	v, set := st.vars[name]
	if !set {
		return true // unset is 0
	}
	if !v.ok || depth > 4 {
		return false
	}
	t := strings.TrimSpace(v.text)
	switch {
	case t == "" || numberRe.MatchString(t) || arithText.MatchString(t):
		return true
	case arithIdentRe.MatchString(t):
		return st.numericValue(t, depth+1)
	}
	return false
}

// arithWordSafe reports whether an operand of arithmetic is shown to be a
// number, a variable that holds one, or an expression of those.
func (a *analyzer) arithWordSafe(w *syntax.Word, st *state) bool {
	for _, p := range w.Parts {
		if !a.arithPartSafe(p, st) {
			return false
		}
	}
	return true
}

func (a *analyzer) arithPartSafe(p syntax.WordPart, st *state) bool {
	switch x := p.(type) {
	case *syntax.Lit:
		t := strings.TrimSpace(x.Value)
		return t == "" || numberRe.MatchString(t) || arithText.MatchString(t) || subscripts.MatchString(t) ||
			arithIdentRe.MatchString(t) && st.numericValue(t, 0)
	case *syntax.SglQuoted:
		t := strings.TrimSpace(x.Value)
		return numberRe.MatchString(t) || arithText.MatchString(t)
	case *syntax.DblQuoted:
		for _, q := range x.Parts {
			if !a.arithPartSafe(q, st) {
				return false
			}
		}
		return true
	case *syntax.ArithmExp:
		return true // scanned on its own
	case *syntax.ParamExp:
		if x.Length || x.Width {
			return true
		}
		if x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Excl || x.Names != 0 {
			return false
		}
		switch n := x.Param.Value; n {
		case "?", "#", "$", "!", "-", "@", "*", "RANDOM", "SECONDS", "LINENO", "BASHPID", "PPID", "UID", "EUID":
			return true
		default:
			return arithIdentRe.MatchString(n) && st.numericValue(n, 0)
		}
	}
	return false
}

// arithExprSafe walks an arithmetic expression and reports whether every
// operand is safe.
func (a *analyzer) arithExprSafe(e syntax.ArithmExpr, st *state) bool {
	ok := true
	syntax.Walk(e, func(n syntax.Node) bool {
		if !ok {
			return false
		}
		if w, isWord := n.(*syntax.Word); isWord {
			if !a.arithWordSafe(w, st) {
				ok = false
			}
			return false
		}
		return true
	})
	return ok
}

// arith finds the arithmetic evaluations in n ($((…)), ((…)), let, a C-style
// for loop, an array index or a ${x:off:len} offset, [[ … -eq … ]], an
// indexed assignment) and makes the command unbounded when an operand is not
// shown to be a number.
func (a *analyzer) arith(n syntax.Node, st *state, via []string, depth int) {
	if a.quiet != 0 || n == nil {
		return
	}
	bad := func(text string) {
		a.unbounded(st, via, text, "arithmetic evaluates a value the analyzer cannot show is a number; a subscript in it may hold a command substitution, which runs")
	}
	syntax.Walk(n, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.ArithmExp:
			if !a.arithExprSafe(x.X, st) {
				bad(nodeText(x))
			}
			return true
		case *syntax.ArithmCmd:
			if !a.arithExprSafe(x.X, st) {
				bad(nodeText(x))
			}
			return true
		case *syntax.LetClause:
			for _, e := range x.Exprs {
				if !a.arithExprSafe(e, st) {
					bad(nodeText(x))
					break
				}
			}
			return true
		case *syntax.CStyleLoop:
			for _, e := range []syntax.ArithmExpr{x.Init, x.Cond, x.Post} {
				if e != nil && !a.arithExprSafe(e, st) {
					bad(nodeText(x))
					break
				}
			}
			return true
		case *syntax.ParamExp:
			if x.Index != nil && !a.arithExprSafe(x.Index, st) {
				bad(nodeText(x))
			}
			if x.Slice != nil {
				for _, e := range []syntax.ArithmExpr{x.Slice.Offset, x.Slice.Length} {
					if e != nil && !a.arithExprSafe(e, st) {
						bad(nodeText(x))
						break
					}
				}
			}
			return true
		case *syntax.Assign:
			if x.Index != nil && !a.arithExprSafe(x.Index, st) {
				bad(nodeText(x))
			}
			return true
		case *syntax.BinaryTest:
			switch x.Op {
			case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
				for _, o := range []syntax.TestExpr{x.X, x.Y} {
					if w, ok := o.(*syntax.Word); ok && !a.arithWordSafe(w, st) {
						bad(nodeText(x))
						break
					}
				}
			}
			return true
		case *syntax.UnaryTest:
			if x.Op == syntax.TsVarSet || x.Op == syntax.TsRefVar {
				if w, ok := x.X.(*syntax.Word); ok && !a.arithWordSafe(w, st) {
					bad(nodeText(x))
				}
			}
			return true
		}
		return true
	})
}

// callbackBuiltin handles the builtins whose option runs a command: mapfile
// and readarray -C, compgen and complete -C. The command runs as if by
// eval, here and now or later.
func (a *analyzer) callbackBuiltin(bn string, rest []Word, st *state, via []string, depth int) {
	switch bn {
	case "mapfile", "readarray", "compgen", "complete":
	default:
		return
	}
	for i := 0; i < len(rest); i++ {
		t := rest[i].Text
		if !strings.HasPrefix(t, "-") || strings.HasPrefix(t, "--") || !strings.Contains(t[1:], "C") {
			continue
		}
		cmd, glued := "", ""
		if k := strings.Index(t, "C"); k+1 < len(t) {
			glued = t[k+1:]
		}
		switch {
		case glued != "":
			a.source(glued, st.clone(), append(via, bn+" -C"), depth+1)
		case i+1 < len(rest) && rest[i+1].Resolved:
			cmd = rest[i+1].Text
			a.source(cmd, st.clone(), append(via, bn+" -C"), depth+1)
		default:
			a.unbounded(st, via, bn+" -C", bn+" -C with a command that cannot be resolved statically, which runs it")
		}
	}
}

// promptVars are variables the shell evaluates as text: a command
// substitution in one runs when the prompt or the trace line is shown.
var promptVars = map[string]bool{"PS0": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true, "PROMPT_COMMAND": true}

func (a *analyzer) promptVar(name, val string, st *state, via []string, depth int) {
	if promptVars[name] && (cmdSubstIn(val) || name == "PROMPT_COMMAND" && strings.TrimSpace(val) != "") {
		a.unbounded(st, via, name+"="+val, name+" holds code the shell runs when it is expanded, which the analyzer does not follow")
	}
}
