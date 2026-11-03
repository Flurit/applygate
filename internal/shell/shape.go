package shell

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// plainPrograms are the programs a plain command may run: builtins with no
// effect on later commands, text and file tools, version control, build
// tools and the infrastructure CLIs applygate classifies. Interpreters and
// shells are not here, since their code is opaque, and neither are builtins
// that change how later commands resolve (alias, hash, shopt, set, trap).
var plainPrograms = toSet(
	"cd", "pwd", "echo", "printf", "true", "false", "test", "[", "exit", "export", "unset", "sleep", "date", "which", "type",
	"ls", "cat", "head", "tail", "wc", "grep", "egrep", "rg", "sort", "uniq", "cut", "tr", "tee", "diff", "cmp", "less", "more",
	"tree", "stat", "file", "du", "df", "basename", "dirname", "realpath", "readlink", "mkdir", "touch", "cp", "mv", "rm",
	"ln", "chmod", "find", "jq", "yq", "sed", "column", "xxd", "od", "base64", "sha256sum", "shasum", "md5sum", "env",
	"tar", "unzip", "zip", "gzip", "gunzip", "curl", "wget", "nl", "fold", "comm", "join", "paste", "seq", "id", "whoami",
	"uname", "hostname", "printenv", "git", "gh", "glab", "go", "gofmt", "cargo", "rustc", "npm", "npx", "pnpm", "yarn",
	"make", "docker", "podman", "pre-commit", "terraform", "tofu", "terragrunt", "tflint", "tfsec", "checkov", "trivy",
	"terraform-docs", "infracost", "kubectl", "helm", "kustomize", "aws", "az", "gcloud", "gsutil", "packer", "vault",
	"conftest", "opa", "shellcheck", "actionlint", "brew", "pip", "pip3", "uv", "poetry", "man", "applygate",
)

// PlainShape reports whether cmd is plain: it parses, its structure is a
// list or pipeline (&&, ||, |, ;) of simple commands with plain words, the
// analysis found no problem, and every program it runs, wrappers and shells
// included, is a resolved name on the plain list. why says what is not
// plain. Arguments need not resolve: that was measured
// (review/v0.6.0/2026-11-03-strict-shapes.md, variant B) to ask about far
// fewer real agent calls for no extra catch.
func PlainShape(cmd string, res *Result) (ok bool, why string) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return false, "it does not parse"
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if why != "" || n == nil {
			return why == ""
		}
		switch x := n.(type) {
		case *syntax.File, *syntax.CallExpr, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted,
			*syntax.Redirect, *syntax.Assign, *syntax.Comment:
			if q, ok := x.(*syntax.SglQuoted); ok && q.Dollar {
				why = "a $'...' string"
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
		// ran, except in a make recipe, which is a file in the repository.
		recipe := false
		for _, v := range inv.Via {
			n := viaProgram(v)
			if !plainPrograms[n] {
				return false, "the program " + n
			}
			recipe = recipe || n == "make"
		}
		if recipe {
			continue
		}
		if !inv.Args[0].Resolved {
			return false, "a program name that cannot be resolved"
		}
		if n := ProgName(inv.Args[0].Text); !plainPrograms[n] {
			return false, "the program " + n
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
