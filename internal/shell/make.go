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
	var files []string
	vars := map[string]string{}
	var targets []string
	// Under -n, -q and -t make runs only the recipe lines marked + or that
	// use $(MAKE). -p prints its database and still runs everything.
	dry := false
	for _, k := range []string{"MAKEFILES", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS"} {
		if v, ok := cmdSt.vars[k]; ok && cmdSt.exported[k] && (v.text != "" || !v.ok) {
			a.problem(st, via, k+"="+v.text+" "+joinWords(args), k+" in the environment changes what make reads or does; it cannot be analyzed")
			return true
		}
	}
	setDir := func(d string) {
		if filepath.IsAbs(d) {
			dir = d
		} else if dir != "" {
			dir = filepath.Join(dir, d)
		}
		if dir != "" && a.writtenAt(dir, true) != "" {
			// An earlier step linked, moved or extracted something here:
			// it may be a symlink to anywhere.
			dir = ""
		}
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		if !w.Resolved {
			a.problem(st, via, joinWords(args), "make argument cannot be resolved statically")
			return true
		}
		next := func() (string, bool) {
			if i+1 < len(rest) {
				i++
				return rest[i].Text, rest[i].Resolved
			}
			return "", false
		}
		name, val, eq := strings.Cut(t, "=")
		switch {
		case t == "-n" || t == "--dry-run" || t == "--just-print" || t == "--recon" || t == "-q" || t == "--question" || t == "-t" || t == "--touch":
			dry = true
		case t == "-C" || t == "--directory":
			if d, ok := next(); ok {
				setDir(d)
			}
		case strings.HasPrefix(t, "--") && eq && name == "--directory":
			setDir(val)
		case strings.HasPrefix(t, "-C") && len(t) > 2:
			setDir(t[2:])
		case t == "-f" || t == "--file" || t == "--makefile":
			if f, ok := next(); ok {
				files = append(files, f)
			}
		case strings.HasPrefix(t, "--") && eq && (name == "--file" || name == "--makefile"):
			files = append(files, val)
		case strings.HasPrefix(t, "-f") && len(t) > 2 && !strings.HasPrefix(t, "--"):
			files = append(files, t[2:])
		case t == "-j" || t == "-l" || t == "-o" || t == "-W" || t == "-I" || t == "--eval" || t == "-E":
			if t == "--eval" || t == "-E" {
				a.problem(st, via, joinWords(args), "make --eval adds makefile text; it cannot be analyzed")
				return true
			}
			i++
		case strings.HasPrefix(t, "--eval="):
			a.problem(st, via, joinWords(args), "make --eval adds makefile text; it cannot be analyzed")
			return true
		case strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsAny(t[1:], "nqt") && strings.Trim(t[1:], "nqtksiBeSrRwp") == "":
			dry = true
		case strings.HasPrefix(t, "-"):
		case strings.Contains(t, "="):
			k, v, _ := strings.Cut(t, "=")
			vars[strings.TrimSpace(k)] = v
		default:
			targets = append(targets, t)
		}
	}
	if dir == "" {
		if cmdSt.dir != "" {
			// -C into a directory that cannot be followed: the recipes run
			// somewhere unknown, in a makefile that cannot be read.
			a.unbounded(st, via, joinWords(args), "make -C into a directory that cannot be followed")
			return true
		}
		return false
	}
	var src []byte
	var err error
	read := func(f string) ([]byte, error) {
		if !filepath.IsAbs(f) {
			f = filepath.Join(dir, f)
		}
		return a.read(cmdSt, f)
	}
	if len(files) > 0 {
		for _, f := range files {
			b, e := read(f)
			if e != nil {
				err = e
				break
			}
			src = append(append(src, b...), '\n')
		}
	} else {
		for _, n := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if src, err = read(n); err == nil {
				break
			}
		}
	}
	if errorsIsWritten(err) {
		a.problem(st, via, joinWords(args), "make reads a makefile that "+err.Error())
		return true
	}
	if err != nil {
		return false
	}
	// include, -include and sinclude pull other makefiles in.
	for n, seen := 0, map[string]bool{}; n < 8; n++ {
		m := makeInclude.FindAllStringSubmatch(string(src), -1)
		added := false
		for _, inc := range m {
			for _, f := range strings.Fields(inc[2]) {
				if seen[f] || strings.Contains(f, "$") {
					continue
				}
				seen[f] = true
				if b, e := read(f); e == nil {
					src = append(append(src, '\n'), b...)
					added = true
				} else if inc[1] == "" {
					a.problem(st, via, joinWords(args), "make includes "+f+", which cannot be read: "+e.Error())
					return true
				}
			}
		}
		if !added {
			break
		}
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
		if mf.oneshell {
			// One shell runs the whole recipe, so a cd carries across lines.
			var lines []string
			marked := false
			for _, line := range r.recipe {
				prefix := line[:len(line)-len(strings.TrimLeft(line, "@-+ \t"))]
				marked = marked || strings.Contains(prefix, "+") || strings.Contains(line, "$(MAKE)") || strings.Contains(line, "${MAKE}")
				lines = append(lines, mf.expand(strings.TrimLeft(line, "@-+ \t")))
			}
			if dry && !marked {
				return
			}
			child := cmdSt.childState()
			child.dir = dir
			a.source(strings.Join(lines, "\n"), child, append(via, "make "+t), depth+1)
			return
		}
		for _, line := range r.recipe {
			prefix := line[:len(line)-len(strings.TrimLeft(line, "@-+ \t"))]
			if dry && !strings.Contains(prefix, "+") && !strings.Contains(line, "$(MAKE)") && !strings.Contains(line, "${MAKE}") {
				continue
			}
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
	vars     map[string]string
	rules    map[string]*makeRule
	first    string
	oneshell bool // .ONESHELL: each recipe runs in one shell
}

var (
	makeInclude = regexp.MustCompile(`(?m)^(-|s)?include\s+(.+)$`)
	makeAssign  = regexp.MustCompile(`^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|=)\s*(.*)$`)
	makeRuleRe  = regexp.MustCompile(`^([^:=#\t][^:=#]*?)\s*::?\s*([^=].*)?$`)
	makeVarRef  = regexp.MustCompile(`\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]`)
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
				if t == ".ONESHELL" {
					mf.oneshell = true
				}
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
