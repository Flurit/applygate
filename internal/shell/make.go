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
		if v, ok := cmdSt.vars[k]; ok && cmdSt.isExp(k) && (v.text != "" || !v.ok) {
			a.unbounded(st, via, k+"="+v.text+" "+joinWords(args), k+" in the environment changes what make reads or does (MAKEFLAGS=-C DIR changes the directory); it cannot be analyzed")
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
	rest := splitMakeShort(args[1:])
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := makeLongOption(w.Text)
		if !w.Resolved {
			a.unbounded(st, via, joinWords(args), "make argument cannot be resolved statically (it may be -C DIR)")
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
				a.unbounded(st, via, joinWords(args), "make --eval adds makefile text; it cannot be analyzed")
				return true
			}
			i++
		case strings.HasPrefix(t, "--eval="):
			a.unbounded(st, via, joinWords(args), "make --eval adds makefile text; it cannot be analyzed")
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
	if mf.unsafe != "" {
		// A feature that changes which recipe runs, or what it says, in a
		// way this reader does not follow.
		a.unbounded(st, via, joinWords(args), "the makefile uses "+mf.unsafe+", which is not analyzed, so what its recipes run and where is unknown")
		return true
	}
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
			mf.recipeEnv(child, vars)
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
			mf.recipeEnv(child, vars)
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
	// exports are the variables the makefile exports to its recipes
	// (export NAME, export NAME=val); exportAll is .EXPORT_ALL_VARIABLES.
	exports   map[string]bool
	exportAll bool
	// unsafe names a makefile feature the reader does not follow: define
	// blocks, conditionals, pattern and default rules, a default goal,
	// recipe prefix and shell flags, second expansion, eval and call.
	unsafe string
}

var makeUnsafe = regexp.MustCompile(`(?m)^\s*(define\s|endef\b|ifeq\b|ifneq\b|ifdef\b|ifndef\b|else\b|endif\b|vpath\b|\.DEFAULT_GOAL\b|\.DEFAULT\s*:|\.RECIPEPREFIX\b|\.SHELLFLAGS\b|\.SECONDEXPANSION\b|export\s*$|unexport\b)`)
var makeUnsafeFn = regexp.MustCompile(`\$[({]\s*(eval|call|foreach|shell|file|value)\b`)

var makeTargetVar = regexp.MustCompile(`^[^\s:=#][^:=#]*:\s*(export\s+|override\s+|private\s+)*[A-Za-z_][A-Za-z0-9_.-]*\s*(:=|::=|\+=|\?=|=)`)

// recipeEnv sets the environment a recipe starts with: the variables the
// makefile exports (all of them under .EXPORT_ALL_VARIABLES), and every
// variable given on the command line, which make passes on to recipes.
func (mf *makefile) recipeEnv(child *state, cmdline map[string]string) {
	set := func(name string) {
		v := mf.expand(mf.vars[name])
		if strings.Contains(v, "$") {
			child.vars[name] = value{}
		} else {
			child.vars[name] = value{text: v, ok: true}
		}
		child.exported[name] = true
	}
	for n := range mf.exports {
		set(n)
	}
	if mf.exportAll {
		for n := range mf.vars {
			set(n)
		}
	}
	for n := range cmdline {
		set(n)
	}
}

var (
	makeInclude = regexp.MustCompile(`(?m)^(-|s)?include\s+(.+)$`)
	makeAssign  = regexp.MustCompile(`^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:=|::=|\+=|=)\s*(.*)$`)
	makeRuleRe  = regexp.MustCompile(`^([^:=#\t][^:=#]*?)\s*::?\s*([^=].*)?$`)
	makeVarRef  = regexp.MustCompile(`\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]`)
)

func parseMakefile(src string) *makefile {
	mf := &makefile{vars: map[string]string{}, rules: map[string]*makeRule{}, exports: map[string]bool{}}
	if m := makeUnsafe.FindStringSubmatch(src); m != nil {
		mf.unsafe = strings.TrimSpace(m[1])
	} else if m := makeUnsafeFn.FindStringSubmatch(src); m != nil {
		mf.unsafe = "$(" + m[1] + ")"
	}
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
		if rest, ok := strings.CutPrefix(trim, "export "); ok {
			for _, n := range strings.Fields(strings.SplitN(rest, "=", 2)[0]) {
				mf.exports[strings.TrimRight(n, ":+?")] = true
			}
		}
		if makeTargetVar.MatchString(trim) && mf.unsafe == "" {
			mf.unsafe = "a target-specific variable"
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
				if strings.Contains(t, "%") && mf.unsafe == "" {
					mf.unsafe = "a pattern rule"
				}
				if t == ".ONESHELL" {
					mf.oneshell = true
				}
				if t == ".EXPORT_ALL_VARIABLES" {
					mf.exportAll = true
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

// splitMakeShort splits a cluster of short options that ends in one taking a
// value (-sC../prod, -kC dir) into separate words, the way getopt reads it.
func splitMakeShort(rest []Word) []Word {
	var out []Word
	for _, w := range rest {
		t := w.Text
		if len(t) < 3 || t[0] != '-' || t[1] == '-' {
			out = append(out, w)
			continue
		}
		k := strings.IndexAny(t[1:], "CfIoWEjl")
		if k < 0 {
			out = append(out, w)
			continue
		}
		k++
		for _, f := range t[1:k] {
			out = append(out, Word{Text: "-" + string(f), Resolved: true, Prefix: "-" + string(f)})
		}
		opt := "-" + string(t[k])
		out = append(out, Word{Text: opt, Resolved: true, Prefix: opt})
		if v := t[k+1:]; v != "" {
			out = append(out, Word{Text: v, Resolved: w.Resolved, Prefix: v})
		}
	}
	return out
}

// makeLong are the long options of GNU make that matter to the analysis;
// getopt_long accepts any unique prefix of an option name.
var makeLong = []string{"--directory", "--file", "--makefile", "--eval", "--dry-run", "--just-print", "--recon", "--question", "--touch",
	"--include-dir", "--what-if", "--new-file", "--assume-new", "--old-file", "--assume-old", "--always-make", "--jobs", "--load-average",
	"--max-load", "--keep-going", "--silent", "--quiet", "--ignore-errors", "--no-builtin-rules", "--no-builtin-variables", "--warn-undefined-variables"}

// makeLongOption expands an abbreviated long option (--dir=x is --directory=x)
// to its full name when the prefix is unique; otherwise it is returned as it is.
func makeLongOption(t string) string {
	if !strings.HasPrefix(t, "--") || len(t) < 4 {
		return t
	}
	name, val, eq := strings.Cut(t, "=")
	var match string
	for _, o := range makeLong {
		if o == name {
			return t
		}
		if strings.HasPrefix(o, name) {
			if match != "" && match != o {
				return t // ambiguous
			}
			match = o
		}
	}
	if match == "" {
		return t
	}
	if eq {
		return match + "=" + val
	}
	return match
}
