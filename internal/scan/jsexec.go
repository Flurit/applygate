package scan

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// jsCommand is one tools.exec_command({...}) call in the JavaScript a Codex
// "exec" tool call carries.
type jsCommand struct{ cmd, workdir string }

// jsExecCommands returns the commands a Codex "exec" tool call runs. Codex
// can have the model write its tool calls as JavaScript:
//
//	const r = await tools.exec_command({cmd:"terraform plan", workdir:"/repo/envs/dev"});
//
// Only a cmd (and workdir) written as a plain string literal is read: a
// variable, a concatenation or a template with ${...} has no value here, and
// such a call is left out rather than guessed at.
func jsExecCommands(src string) []jsCommand {
	const call = "tools.exec_command("
	var out []jsCommand
	for {
		i := strings.Index(src, call)
		if i < 0 {
			return out
		}
		src = src[i+len(call):]
		p := &jsParser{s: src}
		if c, ok := p.object(); ok && c.cmd != "" {
			out = append(out, c)
		}
	}
}

type jsParser struct {
	s string
	i int
}

func (p *jsParser) space() {
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
		p.i++
	}
}

// object reads an object literal and returns its cmd and workdir when both
// are plain strings (workdir may be absent).
func (p *jsParser) object() (jsCommand, bool) {
	var c jsCommand
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != '{' {
		return c, false
	}
	p.i++
	for {
		p.space()
		if p.i >= len(p.s) {
			return c, false
		}
		switch p.s[p.i] {
		case '}':
			return c, true
		case ',':
			p.i++
			continue
		}
		key, ok := p.key()
		if !ok {
			return c, false
		}
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return c, false // shorthand ({cmd}) or a spread: no value to read
		}
		p.i++
		p.space()
		if key == "cmd" || key == "workdir" {
			v, ok := p.str()
			if !ok {
				return c, false
			}
			// The literal must be the whole value: "a" + b is not known.
			p.space()
			if p.i >= len(p.s) || (p.s[p.i] != ',' && p.s[p.i] != '}') {
				return c, false
			}
			if key == "cmd" {
				c.cmd = v
			} else {
				c.workdir = v
			}
			continue
		}
		if !p.skipValue() {
			return c, false
		}
	}
}

func (p *jsParser) key() (string, bool) {
	if p.i < len(p.s) && (p.s[p.i] == '"' || p.s[p.i] == '\'') {
		return p.str()
	}
	start := p.i
	for p.i < len(p.s) {
		ch := p.s[p.i]
		if ch == '_' || ch == '$' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i], p.i > start
}

// str reads a string literal: "...", '...' or a template without ${...}.
func (p *jsParser) str() (string, bool) {
	if p.i >= len(p.s) {
		return "", false
	}
	q := p.s[p.i]
	if q != '"' && q != '\'' && q != '`' {
		return "", false
	}
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		ch := p.s[p.i]
		switch {
		case ch == q:
			p.i++
			return b.String(), true
		case q == '`' && ch == '$' && p.i+1 < len(p.s) && p.s[p.i+1] == '{':
			return "", false
		case q != '`' && ch == '\n':
			return "", false
		case ch != '\\':
			b.WriteByte(ch)
			p.i++
		default:
			if !p.escape(&b) {
				return "", false
			}
		}
	}
	return "", false
}

// escape reads one backslash escape at p.i.
func (p *jsParser) escape(b *strings.Builder) bool {
	if p.i+1 >= len(p.s) {
		return false
	}
	e := p.s[p.i+1]
	p.i += 2
	hex := func(n int) bool {
		if p.i+n > len(p.s) {
			return false
		}
		v, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
		if err != nil {
			return false
		}
		p.i += n
		b.WriteRune(rune(v))
		return true
	}
	switch e {
	case 'n':
		b.WriteByte('\n')
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'v':
		b.WriteByte('\v')
	case '0':
		b.WriteByte(0)
	case '\n': // a line continuation
	case 'x':
		return hex(2)
	case 'u':
		if p.i < len(p.s) && p.s[p.i] == '{' {
			end := strings.IndexByte(p.s[p.i:], '}')
			if end < 0 {
				return false
			}
			v, err := strconv.ParseUint(p.s[p.i+1:p.i+end], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return false
			}
			p.i += end + 1
			b.WriteRune(rune(v))
			return true
		}
		return hex(4)
	default:
		b.WriteByte(e)
	}
	return true
}

// skipValue moves past a value that is not read, to the , or } that ends it.
func (p *jsParser) skipValue() bool {
	depth := 0
	for p.i < len(p.s) {
		switch ch := p.s[p.i]; ch {
		case '"', '\'', '`':
			if _, ok := p.str(); !ok {
				return false
			}
			continue
		case '(', '[', '{':
			depth++
		case ')', ']':
			depth--
		case '}':
			if depth == 0 {
				return true
			}
			depth--
		case ',':
			if depth == 0 {
				return true
			}
		}
		if depth < 0 {
			return false
		}
		p.i++
	}
	return false
}
