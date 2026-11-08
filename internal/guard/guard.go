// Package guard decides whether a path is one of applygate's guard files:
// the hook settings of every host, applygate's own config, log, approvals,
// judge cache and binary, and the repository config. Paths are compared
// after resolving symlinks and, on file systems that ignore case, after
// folding case, so ".APPLYGATE.YAML" or a symlinked parent is the same file.
package guard

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/text/unicode/norm"
)

// FoldCase is true where the default file system ignores case.
var FoldCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// Set is the guard files and directories for one decision.
type Set struct {
	patterns []string // slash globs; a pattern without a leading slash matches any suffix
	targets  []string // concrete canonical paths; their ancestors are guarded too
	// progDirs and progNames guard any of these names in any of these
	// directories (PATH plants), without a target for each pair.
	progDirs  map[string]bool
	progNames map[string]bool
	// progPrefixes guard every name that starts with one of them
	// (git-remote-*, docker-credential-*).
	progPrefixes []string
	// plantPats and plantTargets are the guard files that matter only for
	// what is placed in them (a provider binary, a git hook, an MCP server
	// list): removing one cannot weaken the guard (RemovalTouches).
	plantPats    map[string]bool
	plantTargets map[string]bool
	// softTargets are guard files guarded only because the session or the
	// git repository is rooted where they are, not by a config (Soft).
	softTargets map[string]bool
	// canon maps the targets given to New to their canonical form, so
	// PlantOnly and Soft need not resolve them again.
	canon map[string]string
}

// New returns the guard set for patterns (globs, as in the config) and
// targets (concrete files and directories that exist or will exist at a
// known place, such as ~/.claude/settings.json or the running binary).
func New(patterns, targets []string) *Set {
	s := &Set{}
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			p = canonicalGlob(p)
		}
		s.patterns = append(s.patterns, fold(filepath.ToSlash(p)))
	}
	seen := map[string]bool{}
	s.canon = make(map[string]string, len(targets))
	for _, t := range targets {
		if t == "" || !filepath.IsAbs(t) {
			continue
		}
		c, ok := s.canon[t]
		if !ok {
			c = Canonical(t)
			s.canon[t] = c
		}
		if !seen[c] {
			seen[c] = true
			s.targets = append(s.targets, c)
		}
	}
	return s
}

// Programs guards every name in names placed in any of dirs: program paths
// such as ~/.local/bin/git. They are not looked for in code (Needles):
// ordinary scripts name program paths.
func (s *Set) Programs(dirs, names []string) *Set {
	if s.progDirs == nil {
		s.progDirs, s.progNames = map[string]bool{}, map[string]bool{}
	}
	for _, d := range dirs {
		if filepath.IsAbs(d) {
			s.progDirs[Canonical(d)] = true
		}
	}
	for _, n := range names {
		if pre, ok := strings.CutSuffix(n, "*"); ok && pre != "" {
			s.progPrefixes = append(s.progPrefixes, fold(pre))
			continue
		}
		s.progNames[fold(n)] = true
	}
	return s
}

// PlantOnly marks patterns and targets, given as to New, as guard files
// whose removal cannot weaken the guard: they hold code or settings that a
// later program runs, so placing one is tampering and removing one is not.
// A target also given to New by a pattern that is not plant-only must not
// be passed here.
func (s *Set) PlantOnly(patterns, targets []string) *Set {
	if s.plantPats == nil {
		s.plantPats, s.plantTargets = map[string]bool{}, map[string]bool{}
	}
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			p = canonicalGlob(p)
		}
		s.plantPats[fold(filepath.ToSlash(p))] = true
	}
	for _, t := range targets {
		if t != "" && filepath.IsAbs(t) {
			s.plantTargets[s.canonical(t)] = true
		}
	}
	return s
}

// Soft marks targets, given as to New, as guarded only because the session
// directory or the nearest git root is where they are: a command that
// rewrites a work tree without naming them (git checkout, pull) is asked
// about there rather than blocked (TouchesHard). A target a config root or
// home also stands for must not be passed here.
func (s *Set) Soft(targets []string) *Set {
	if s.softTargets == nil {
		s.softTargets = map[string]bool{}
	}
	for _, t := range targets {
		if t != "" && filepath.IsAbs(t) {
			s.softTargets[s.canonical(t)] = true
		}
	}
	return s
}

// canonical is Canonical(t) for a target given to New, without resolving it
// again.
func (s *Set) canonical(t string) string {
	if c, ok := s.canon[t]; ok {
		return c
	}
	return Canonical(t)
}

// program reports whether canonical path c is a guarded program path.
func (s *Set) program(c string) bool {
	if !s.progDirs[path.Dir(c)] {
		return false
	}
	b := path.Base(c)
	if s.progNames[b] {
		return true
	}
	for _, pre := range s.progPrefixes {
		if strings.HasPrefix(b, pre) {
			return true
		}
	}
	return false
}

// holdsProgram reports whether canonical directory c is, or holds, a
// directory of guarded programs.
func (s *Set) holdsProgram(c string) bool {
	if len(s.progNames) == 0 && len(s.progPrefixes) == 0 {
		return false
	}
	for d := range s.progDirs {
		if d == c || c == "/" || strings.HasPrefix(d, strings.TrimSuffix(c, "/")+"/") {
			return true
		}
	}
	return false
}

// NamedLike reports whether a file name is the name of a guard file or
// directory (settings.json, hooks.json, config.toml, ...): with no
// directory to resolve against, a relative path with that name may be one.
func (s *Set) NamedLike(name string) bool {
	name = fold(name)
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, t := range s.targets {
		if path.Base(t) == name {
			return true
		}
	}
	for _, p := range s.patterns {
		lit := strings.TrimSuffix(strings.TrimPrefix(p, "**/"), "/**")
		if !strings.ContainsAny(lit, "*?[") && path.Base(lit) == name {
			return true
		}
	}
	switch name {
	case "approvals.json", "judge-cache.json", "telemetry.json", "decisions.jsonl", "config.yaml", "trusted.json":
		return true
	}
	return false
}

// Canonical returns p cleaned, with symlinks resolved on its longest
// existing prefix, and case folded where the file system ignores case. p
// must be absolute.
func Canonical(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if r, ok := evalSymlinks(cur); ok {
			p = filepath.Join(r, rest)
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
	return fold(filepath.ToSlash(p))
}

// resolved caches EvalSymlinks for the life of the process: one decision
// resolves dozens of guard paths that share their parents (~/.claude/...).
var resolved sync.Map // path -> string ("" when it does not resolve)

func evalSymlinks(p string) (string, bool) {
	if v, ok := resolved.Load(p); ok {
		return v.(string), v.(string) != ""
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		r = ""
	}
	resolved.Store(p, r)
	return r, r != ""
}

// CanonicalGlob canonicalizes the literal prefix of an absolute glob, as
// Canonical does a path.
func CanonicalGlob(p string) string { return canonicalGlob(p) }

// canonicalGlob canonicalizes the literal prefix of an absolute glob.
func canonicalGlob(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	i := strings.IndexAny(p, "*?[")
	if i < 0 {
		return Canonical(p)
	}
	j := strings.LastIndex(p[:i], "/")
	if j <= 0 {
		return p
	}
	return Canonical(p[:j]) + p[j:]
}

// fold returns s as a case-insensitive file system compares it: Unicode
// NFC (APFS ignores normalization), lower case, and the code points such
// file systems fold onto ASCII letters that strings.ToLower leaves alone
// (U+017F long s and U+212A Kelvin sign).
func fold(s string) string {
	if !FoldCase {
		return s
	}
	s = norm.NFC.String(s)
	s = strings.NewReplacer("\u017f", "s", "\u212a", "k").Replace(s)
	return strings.ToLower(s)
}

// Fold is fold for other packages: text compared with Needles.
func Fold(s string) string { return fold(s) }

// GlobTouches reports whether an absolute glob could match a guard file or a
// directory that holds one: rm ~/.claude/setting*.json, rm -rf ~/.clau?e.
func (s *Set) GlobTouches(pattern string) bool {
	if s == nil || !filepath.IsAbs(pattern) {
		return false
	}
	pat := canonicalGlob(pattern)
	for _, t := range s.targets {
		for a := t; ; a = path.Dir(a) {
			if shellGlob(pat, a) {
				return true
			}
			if a == "/" || a == "." || a == path.Dir(a) {
				break
			}
		}
	}
	if dir := path.Dir(pat); s.progDirs[dir] {
		for n := range s.progNames {
			if segMatch(path.Base(pat), n) {
				return true
			}
		}
		for _, pre := range s.progPrefixes {
			if segMatch(path.Base(pat), pre+"a") {
				return true
			}
		}
	} else if !strings.ContainsAny(dir, "*?[") && s.holdsProgram(dir) && strings.ContainsAny(path.Base(pat), "*?[") {
		return true
	}
	// The repository config and other dot-names that may live in any
	// directory (.applygate.yaml); other names, settings.json or the
	// applygate binary, count only through the concrete targets above.
	base := path.Base(pat)
	for _, p := range s.patterns {
		if b := path.Base(p); !strings.ContainsAny(b, "*?[") && strings.HasPrefix(b, ".") {
			if segMatch(base, b) {
				return true
			}
		}
	}
	return false
}

// Protected reports whether p (absolute) is a guard file or lies inside a
// guarded directory.
func (s *Set) Protected(p string) bool {
	if s == nil || !filepath.IsAbs(p) {
		return false
	}
	// The path is checked as resolved and as written (its directory
	// resolved, its last part as it is): a symlink on PATH, which is how
	// Homebrew installs every program, resolves into the Cellar, and a
	// guard file may itself be a link to the file that holds its content.
	c := Canonical(p)
	w := Canonical(filepath.Dir(filepath.Clean(p))) + "/" + fold(filepath.Base(filepath.Clean(p)))
	w = strings.Replace(w, "//", "/", 1)
	for _, x := range []string{c, w} {
		for _, pat := range s.patterns {
			if MatchGlob(pat, x) {
				return true
			}
		}
		for _, t := range s.targets {
			if x == t {
				return true
			}
		}
		if s.program(x) {
			return true
		}
	}
	return false
}

// removalProtected is Protected for a removal: a plant-only guard file
// (PlantOnly) does not count.
func (s *Set) removalProtected(p string, hard bool) bool {
	c := Canonical(p)
	w := Canonical(filepath.Dir(filepath.Clean(p))) + "/" + fold(filepath.Base(filepath.Clean(p)))
	w = strings.Replace(w, "//", "/", 1)
	for _, x := range []string{c, w} {
		for _, pat := range s.patterns {
			if !s.plantPats[pat] && MatchGlob(pat, x) {
				return true
			}
		}
		for _, t := range s.targets {
			if x == t && !s.plantTargets[t] && !(hard && s.softTargets[t]) {
				return true
			}
		}
		if s.program(x) {
			return true
		}
	}
	return false
}

// RemovalTouches reports whether removing p (absolute) can weaken the
// guard: p is a guard file whose loss weakens it (hook settings, applygate's
// config, state and binary), or a directory that holds one that exists now.
// A guard file that matters only for what is placed in it (PlantOnly) does
// not count, nor does one that does not exist: removing a directory cannot
// remove it. Writing, moving or extracting into a directory is Touches.
func (s *Set) RemovalTouches(p string) bool { return s.removalTouches(p, false) }

// RemovalTouchesHard is RemovalTouches without the soft targets (Soft).
func (s *Set) RemovalTouchesHard(p string) bool { return s.removalTouches(p, true) }

func (s *Set) removalTouches(p string, hard bool) bool {
	if s == nil || !filepath.IsAbs(p) {
		return false
	}
	if s.removalProtected(p, hard) {
		return true
	}
	c := Canonical(p)
	for _, t := range s.targets {
		if s.plantTargets[t] || hard && s.softTargets[t] {
			continue
		}
		if c == "/" || strings.HasPrefix(t, strings.TrimSuffix(c, "/")+"/") {
			// Only a file that is not there cannot be removed: an error
			// other than not-exist (a directory that cannot be searched)
			// counts as there.
			if _, err := os.Lstat(t); !errors.Is(err, fs.ErrNotExist) {
				return true
			}
		}
	}
	return s.holdsProgram(c)
}

// Touches reports whether writing, moving, removing or extracting into p
// (absolute) can change a guard file: p is one, or is a directory that holds
// one, such as ~/.claude for ~/.claude/settings.json or the repository root
// for its .applygate.yaml.
func (s *Set) Touches(p string) bool { return s.touches(p, false) }

// TouchesHard is Touches without the soft targets (Soft): only what a config
// root, home or applygate's own files hold.
func (s *Set) TouchesHard(p string) bool { return s.touches(p, true) }

func (s *Set) touches(p string, hard bool) bool {
	if s == nil || !filepath.IsAbs(p) {
		return false
	}
	if hard && len(s.softTargets) > 0 {
		if s.protectedHard(p) {
			return true
		}
	} else if s.Protected(p) {
		return true
	}
	c := Canonical(p)
	for _, t := range s.targets {
		if hard && s.softTargets[t] {
			continue
		}
		if c == "/" || strings.HasPrefix(t, strings.TrimSuffix(c, "/")+"/") {
			return true
		}
	}
	return s.holdsProgram(c)
}

// protectedHard is Protected with a soft target matching only as a pattern
// does: patterns name guard files wherever they are.
func (s *Set) protectedHard(p string) bool {
	c := Canonical(p)
	w := Canonical(filepath.Dir(filepath.Clean(p))) + "/" + fold(filepath.Base(filepath.Clean(p)))
	w = strings.Replace(w, "//", "/", 1)
	for _, x := range []string{c, w} {
		for _, pat := range s.patterns {
			if MatchGlob(pat, x) {
				return true
			}
		}
		for _, t := range s.targets {
			if x == t && !s.softTargets[t] {
				return true
			}
		}
		if s.program(x) {
			return true
		}
	}
	return false
}

// Needles are strings whose presence in opaque text (interpreter code, a
// script in another language) means the text names a guard file: the
// concrete paths, their ~ forms, and the distinctive names in the patterns.
// They are folded; compare against folded text.
func (s *Set) Needles(home string) []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = fold(strings.TrimSpace(n))
		if len(n) >= 6 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	h := ""
	if home != "" {
		h = Canonical(home)
	}
	for _, t := range s.targets {
		add(t)
		if h != "" && strings.HasPrefix(t, h+"/") {
			rel := strings.TrimPrefix(t, h+"/")
			add("~/" + rel)
			add("$HOME/" + rel)
			add("${HOME}/" + rel)
		}
	}
	for _, p := range s.patterns {
		lit := strings.TrimSuffix(strings.TrimPrefix(p, "**/"), "/**")
		if strings.ContainsAny(lit, "*?[") || strings.HasPrefix(lit, "/") {
			continue
		}
		add(lit)
	}
	for _, n := range []string{"approvals.json", "judge-cache.json", "telemetry.json", "decisions.jsonl", "applygate/config.yaml", "seatbelt/config.yaml"} {
		add(n)
	}
	return out
}

// MatchGlob matches slash paths against patterns supporting *, ? and **.
// A pattern without a leading slash matches any suffix of the path.
func MatchGlob(pattern, p string) bool {
	pattern = filepath.ToSlash(pattern)
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ps := strings.Split(strings.Trim(p, "/"), "/")
	if strings.HasPrefix(pattern, "/") {
		return matchSegs(pp, ps)
	}
	for i := 0; i <= len(ps); i++ {
		if matchSegs(pp, ps[i:]) {
			return true
		}
	}
	return false
}

func matchSegs(pp, ps []string) bool {
	if len(pp) == 0 {
		return len(ps) == 0
	}
	if pp[0] == "**" {
		for i := 0; i <= len(ps); i++ {
			if matchSegs(pp[1:], ps[i:]) {
				return true
			}
		}
		return false
	}
	if len(ps) == 0 {
		return false
	}
	ok, err := filepath.Match(pp[0], ps[0])
	if err != nil || !ok {
		return false
	}
	return matchSegs(pp[1:], ps[1:])
}

// Executable returns the running binary's canonical path and the
// applygate and seatbelt binaries next to it, which a hook entry may name.
// The path is resolved once per process: every invocation asks.
func Executable() []string {
	exe := executable()
	if exe == "" {
		return nil
	}
	dir := filepath.Dir(exe)
	return []string{exe, filepath.Join(dir, "applygate"), filepath.Join(dir, "seatbelt")}
}

var executable = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe
})

// shellGlob matches an absolute path the way the shell expands a glob: one
// segment per segment, and a segment starting with "." only when the
// pattern's segment does too (no dotglob).
func shellGlob(pattern, p string) bool {
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	ps := strings.Split(strings.Trim(p, "/"), "/")
	if len(pp) != len(ps) {
		return false
	}
	for i := range pp {
		if !segMatch(pp[i], ps[i]) {
			return false
		}
	}
	return true
}

func segMatch(pat, seg string) bool {
	if strings.HasPrefix(seg, ".") && !strings.HasPrefix(pat, ".") {
		return false
	}
	ok, err := path.Match(pat, seg)
	return err == nil && ok
}
