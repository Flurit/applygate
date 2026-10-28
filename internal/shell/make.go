package shell

import (
	"path/filepath"
	"regexp"
	"strings"
)

// make resolves "make [opts] [VAR=val] [targets]" by reading the Makefile and
// analyzing the recipes of the requested targets and their prerequisites.
// It returns false when the Makefile cannot be read, so the caller records
// the invocation and the classifier falls back to the target name.
func (a *analyzer) make(args []Word, cmdSt, st *state, via []string, depth int) bool {
	dir := cmdSt.dir
	file := ""
	vars := map[string]string{}
	var targets []string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		if !w.Resolved {
			a.problem(st, via, joinWords(args), "make argument cannot be resolved statically")
			return true
		}
		switch {
		case t == "-n" || t == "--dry-run" || t == "--just-print" || t == "--recon" || t == "-p" || t == "-q" || t == "--question":
			return true // prints or queries only
		case t == "-C" || t == "--directory":
			if i+1 < len(rest) {
				dir = filepath.Join(dir, rest[i+1].Text)
				if filepath.IsAbs(rest[i+1].Text) {
					dir = rest[i+1].Text
				}
				i++
			}
		case strings.HasPrefix(t, "-C") && len(t) > 2:
			dir = filepath.Join(dir, t[2:])
		case t == "-f" || t == "--file" || t == "--makefile":
			if i+1 < len(rest) {
				file = rest[i+1].Text
				i++
			}
		case t == "-j" || t == "-l" || t == "-o" || t == "-W" || t == "-I":
			i++
		case strings.HasPrefix(t, "-"):
		case strings.Contains(t, "="):
			k, v, _ := strings.Cut(t, "=")
			vars[strings.TrimSpace(k)] = v
		default:
			targets = append(targets, t)
		}
	}
	if dir == "" {
		return false
	}
	var src []byte
	var err error
	if file != "" {
		src, err = a.opt.ReadFile(filepath.Join(dir, file))
	} else {
		for _, n := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if src, err = a.opt.ReadFile(filepath.Join(dir, n)); err == nil {
				break
			}
		}
	}
	if err != nil {
		return false
	}
	mf := parseMakefile(string(src))
	for k, v := range vars {
		mf.vars[k] = v
	}
	if len(targets) == 0 && mf.first != "" {
		targets = []string{mf.first}
	}
	found := false
	seen := map[string]bool{}
	var visit func(t string, d int)
	visit = func(t string, d int) {
		if seen[t] || d > 16 {
			return
		}
		seen[t] = true
		r, ok := mf.rules[t]
		if !ok {
			return
		}
		found = true
		for _, p := range r.prereqs {
			visit(mf.expand(p), d+1)
		}
		for _, line := range r.recipe {
			line = strings.TrimLeft(line, "@-+ \t")
			line = mf.expand(line)
			child := cmdSt.childState()
			child.dir = dir
			a.source(line, child, append(via, "make "+t), depth+1)
		}
	}
	for _, t := range targets {
		visit(t, 0)
	}
	return found
}

type makeRule struct {
	prereqs []string
	recipe  []string
}

type makefile struct {
	vars  map[string]string
	rules map[string]*makeRule
	first string
}

var (
	makeAssign = regexp.MustCompile(`^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|=)\s*(.*)$`)
	makeRuleRe = regexp.MustCompile(`^([^:=#\t][^:=#]*?)\s*::?\s*([^=].*)?$`)
	makeVarRef = regexp.MustCompile(`\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]`)
)

func parseMakefile(src string) *makefile {
	mf := &makefile{vars: map[string]string{}, rules: map[string]*makeRule{}}
	var cur []*makeRule
	lines := strings.Split(strings.ReplaceAll(src, "\\\n", " "), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "\t") {
			for _, r := range cur {
				r.recipe = append(r.recipe, strings.TrimPrefix(line, "\t"))
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if m := makeAssign.FindStringSubmatch(trim); m != nil {
			if m[2] == "+=" {
				mf.vars[m[1]] = strings.TrimSpace(mf.vars[m[1]] + " " + m[3])
			} else if m[2] != "?=" || mf.vars[m[1]] == "" {
				mf.vars[m[1]] = m[3]
			}
			cur = nil
			continue
		}
		if m := makeRuleRe.FindStringSubmatch(trim); m != nil {
			cur = nil
			deps, inline, _ := strings.Cut(m[2], ";")
			for _, t := range strings.Fields(m[1]) {
				if strings.HasPrefix(t, ".") {
					continue
				}
				r := mf.rules[t]
				if r == nil {
					r = &makeRule{}
					mf.rules[t] = r
				}
				r.prereqs = append(r.prereqs, strings.Fields(deps)...)
				if strings.TrimSpace(inline) != "" {
					r.recipe = append(r.recipe, inline)
				}
				if mf.first == "" {
					mf.first = t
				}
				cur = append(cur, r)
			}
			continue
		}
		cur = nil
	}
	return mf
}

// expand substitutes $(VAR) and ${VAR} references that the Makefile defines
// and turns $$ into $. Unknown references are left in place; the shell
// analysis then sees "$(NAME)" as a command substitution it cannot resolve.
func (mf *makefile) expand(s string) string {
	for i := 0; i < 8; i++ {
		n := makeVarRef.ReplaceAllStringFunc(s, func(ref string) string {
			name := makeVarRef.FindStringSubmatch(ref)[1]
			if v, ok := mf.vars[name]; ok {
				return v
			}
			return ref
		})
		if n == s {
			break
		}
		s = n
	}
	return strings.ReplaceAll(s, "$$", "$")
}
