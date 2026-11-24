package shell

import (
	"regexp"
	"slices"
	"strings"
)

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
