package shell

import (
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// maxDecodeBytes caps decoder/decompressor output so a decompression bomb
// cannot blow up memory. A real embedded command is tiny.
const maxDecodeBytes = 256 << 10

// stdout computes what a statement would print, for the small set of
// commands whose output is fully determined by their arguments and input:
// echo, printf %s, cat, base64 -d, xxd -r -p, rev, which/command -v, and
// pipelines of these. Anything else returns ok=false.
func (a *analyzer) stdout(s *syntax.Stmt, st *state, in stdin, depth int) (string, bool) {
	a.work++
	if s == nil || depth > 8 || a.work > maxWork {
		return "", false
	}
	for _, r := range s.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			a.noGlob++
			w := a.wordQuiet(r.Hdoc, st)
			a.noGlob--
			in = stdin{text: w.Text, known: w.Resolved, present: true}
		case syntax.WordHdoc:
			w := a.wordQuiet(r.Word, st)
			in = stdin{text: w.Text + "\n", known: w.Resolved, present: true}
		case syntax.RdrIn:
			w := a.wordQuiet(r.Word, st)
			if !w.Resolved {
				return "", false
			}
			b, err := a.read(st, w.Text)
			if err != nil {
				return "", false
			}
			in = stdin{text: string(b), known: true, present: true}
		default:
			return "", false // output goes elsewhere
		}
	}
	switch c := s.Cmd.(type) {
	case *syntax.BinaryCmd:
		if c.Op == syntax.AndStmt {
			// cd X && pwd: both sides run in order, in the same shell.
			left, ok := a.stdout(c.X, st, in, depth+1)
			if !ok {
				return "", false
			}
			right, ok := a.stdout(c.Y, st, stdin{}, depth+1)
			return left + right, ok
		}
		if c.Op != syntax.Pipe {
			return "", false
		}
		left, ok := a.stdout(c.X, st, in, depth+1)
		if !ok {
			return "", false
		}
		return a.stdout(c.Y, st, stdin{text: left, known: true, present: true}, depth+1)
	case *syntax.Subshell:
		if len(c.Stmts) == 1 {
			return a.stdout(c.Stmts[0], st, in, depth+1)
		}
	case *syntax.Block:
		if len(c.Stmts) == 1 {
			return a.stdout(c.Stmts[0], st, in, depth+1)
		}
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return "", false
		}
		var args []Word
		for _, w := range c.Args {
			args = append(args, a.wordQuiet(w, st))
		}
		if !allResolved(args) {
			return "", false
		}
		return a.builtinOut(args, st, in)
	}
	return "", false
}

// wordQuiet resolves a word without walking nested substitutions as
// executed commands (the main walk already does that).
func (a *analyzer) wordQuiet(w *syntax.Word, st *state) Word {
	saved := a.res
	a.res = &Result{}
	a.quiet++
	defer func() { a.res = saved; a.quiet-- }()
	return a.word(w, st, nil, a.opt.MaxDepth-1)
}

func (a *analyzer) builtinOut(args []Word, st *state, in stdin) (string, bool) {
	if _, ok := st.funcs[args[0].Text]; ok {
		return "", false // a function of that name runs, not the builtin
	}
	if _, ok := st.aliases[args[0].Text]; ok {
		return "", false
	}
	name := base(args[0].Text)
	rest := texts(args[1:])
	switch name {
	case "echo":
		// Bash's echo interprets escapes only with -e; zsh's echo and a
		// POSIX sh with xpg_echo always do. Text with a backslash is known
		// only when -e or -E says which.
		nl, esc, raw := true, false, false
		for len(rest) > 0 && len(rest[0]) > 1 && rest[0][0] == '-' && strings.Trim(rest[0][1:], "neE") == "" {
			for _, c := range rest[0][1:] {
				switch c {
				case 'n':
					nl = false
				case 'e':
					esc, raw = true, false
				case 'E':
					esc, raw = false, true
				}
			}
			rest = rest[1:]
		}
		out := strings.Join(rest, " ")
		if esc {
			var ok, stop bool
			if out, ok, stop = echoEscapes(out); !ok {
				return "", false
			}
			if stop {
				return out, true
			}
		} else if !raw && strings.Contains(out, `\`) {
			return "", false
		}
		if nl {
			out += "\n"
		}
		return out, true
	case "printf":
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			// No format, or an option such as -v that prints nothing.
			return "", false
		}
		format := rest[0]
		vals := rest[1:]
		if strings.Count(format, "%") != strings.Count(format, "%s")+2*strings.Count(format, "%%") {
			return "", false
		}
		esc := func(s string) (string, bool) { return ansiC(s) }
		var b strings.Builder
		for first := true; first || len(vals) > 0; first = false {
			f := format
			for {
				i := strings.Index(f, "%")
				if i < 0 {
					t, ok := esc(f)
					if !ok {
						return "", false
					}
					b.WriteString(t)
					break
				}
				t, ok := esc(f[:i])
				if !ok {
					return "", false
				}
				b.WriteString(t)
				if strings.HasPrefix(f[i:], "%%") {
					b.WriteByte('%')
				} else {
					if len(vals) > 0 {
						b.WriteString(vals[0])
						vals = vals[1:]
					}
				}
				f = f[i+2:]
			}
			if !strings.Contains(format, "%s") {
				break
			}
		}
		return b.String(), true
	case "cat":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "-") {
			return in.text, in.present && in.known
		}
		var b strings.Builder
		for _, f := range rest {
			if strings.HasPrefix(f, "-") {
				return "", false
			}
			data, err := a.read(st, f)
			if err != nil {
				return "", false
			}
			b.Write(data)
		}
		return b.String(), true
	case "base64", "gbase64", "openssl":
		if name == "openssl" {
			if len(rest) == 0 || rest[0] != "base64" && rest[0] != "enc" {
				return "", false
			}
		}
		decode := false
		for _, f := range rest {
			if f == "-d" || f == "--decode" || f == "-D" {
				decode = true
			}
		}
		if !decode || !in.present || !in.known {
			return "", false
		}
		clean := strings.Join(strings.Fields(in.text), "")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(clean); err == nil {
				return string(b), true
			}
		}
		return "", false
	case "base32", "gbase32":
		decode := false
		for _, f := range rest {
			if f == "-d" || f == "--decode" {
				decode = true
			}
		}
		if !decode || !in.present || !in.known {
			return "", false
		}
		clean := strings.ToUpper(strings.Join(strings.Fields(in.text), ""))
		for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.HexEncoding} {
			if b, err := enc.DecodeString(clean); err == nil {
				return string(b), true
			}
			if b, err := enc.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "=")); err == nil {
				return string(b), true
			}
		}
		return "", false
	case "gzip", "gunzip", "zcat", "pigz", "unpigz":
		if !in.present || !in.known {
			return "", false
		}
		decode := name == "gunzip" || name == "zcat" || name == "unpigz"
		for _, f := range rest {
			if f == "-d" || f == "--decode" || f == "--decompress" || f == "--uncompress" ||
				(strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.ContainsRune(f, 'd')) {
				decode = true
			}
		}
		if !decode {
			return "", false
		}
		zr, err := gzip.NewReader(strings.NewReader(in.text))
		if err != nil {
			return "", false
		}
		// One byte past the cap: output that does not fit is not known,
		// since what follows the cut could be the command.
		b, err := io.ReadAll(io.LimitReader(zr, maxDecodeBytes+1))
		if err != nil || len(b) > maxDecodeBytes {
			return "", false
		}
		return string(b), true
	case "tee":
		// tee copies stdin to stdout (file writes are a side effect we don't
		// model here), so for stdout it is a passthrough. This resolves
		// `... | tee file | sh` to the piped text.
		if !in.present {
			return "", false
		}
		return in.text, in.known
	case "xxd":
		if !in.present || !in.known || !containsAll(rest, "-r", "-p") && !containsAll(rest, "-r", "-ps") {
			return "", false
		}
		b, err := hex.DecodeString(strings.Join(strings.Fields(in.text), ""))
		if err != nil {
			return "", false
		}
		return string(b), true
	case "rev":
		if !in.present || !in.known {
			return "", false
		}
		lines := strings.Split(in.text, "\n")
		for i, l := range lines {
			r := []rune(l)
			for x, y := 0, len(r)-1; x < y; x, y = x+1, y-1 {
				r[x], r[y] = r[y], r[x]
			}
			lines[i] = string(r)
		}
		return strings.Join(lines, "\n"), true
	case "which", "type":
		if len(rest) > 0 && !strings.HasPrefix(rest[len(rest)-1], "-") {
			return rest[len(rest)-1] + "\n", true
		}
	case "command":
		if len(rest) == 2 && (rest[0] == "-v" || rest[0] == "-V") {
			return rest[1] + "\n", true
		}
	case "dirname":
		if len(rest) == 1 {
			return filepath.Dir(rest[0]) + "\n", true
		}
	case "basename":
		if len(rest) == 1 {
			return filepath.Base(rest[0]) + "\n", true
		}
	case "cd":
		// Only inside a command substitution's own shell: changes the
		// directory that a later pwd in the same substitution reports.
		if len(rest) != 1 || strings.HasPrefix(rest[0], "-") || st.dir == "" && !filepath.IsAbs(rest[0]) {
			return "", false
		}
		st.dir = a.abs(st, rest[0])
		return "", true
	case "pwd":
		if st.dir != "" {
			return st.dir + "\n", true
		}
	case "true", ":":
		return "", true
	}
	return "", false
}

func texts(ws []Word) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Text
	}
	return out
}

func containsAll(ss []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, s := range ss {
			if s == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// stdoutSeq is stdout for a list of statements run in order in one shell,
// such as the body of $(cd "$dir"; pwd).
func (a *analyzer) stdoutSeq(stmts []*syntax.Stmt, st *state) (string, bool) {
	if len(stmts) == 0 || len(stmts) > 4 {
		return "", false
	}
	var b strings.Builder
	for _, s := range stmts {
		out, ok := a.stdout(s, st, stdin{}, 0)
		if !ok {
			return "", false
		}
		b.WriteString(out)
	}
	return b.String(), true
}

// echoEscapes decodes the escapes bash's echo -e understands: \0NNN is
// octal with up to three digits after the 0, and \c ends all output (stop).
// ok is false for \u and \U, whose result depends on the locale.
func echoEscapes(s string) (out string, ok, stop bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'c':
			return b.String(), true, true
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte(11)
		case '\\':
			b.WriteByte('\\')
		case '0':
			v := 0
			for n := 0; n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7'; n++ {
				i++
				v = v*8 + int(s[i]-'0')
			}
			b.WriteByte(byte(v))
		case 'x':
			if i+1 >= len(s) || !isHex(s[i+1]) {
				b.WriteString(`\x`)
				continue
			}
			v := 0
			for n := 0; n < 2 && i+1 < len(s) && isHex(s[i+1]); n++ {
				i++
				v = v*16 + hexVal(s[i])
			}
			b.WriteByte(byte(v))
		case 'u', 'U':
			return "", false, false
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String(), true, false
}
