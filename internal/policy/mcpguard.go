package policy

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
)

// GuardOptions returns the classifier options for cfg in env: the guard
// patterns, and the guard set that also knows where guard files live under
// the user's home and the repository root.
// MCPGuardPath returns a guard path that a call to an MCP tool outside the
// known-tool table names in its arguments, or "". Any string argument that
// resolves to a guard file, or to a directory that holds one, counts, unless
// the tool's name says it only reads (read_file, list_directory).
// readOnlyToolName reports whether an MCP tool's name says it only reads:
// every word of it (split at _, -, . and case changes) is a read verb or a
// noun, and at least one is a read verb. Any other word (replace, sync,
// apply, and words applygate does not know) may write, which is the
// default for a call that names a guard file.
func readOnlyToolName(tool string) bool {
	if i := strings.LastIndex(tool, "__"); i >= 0 {
		tool = tool[i+2:]
	}
	verb := false
	for _, w := range toolWords(tool) {
		switch {
		case readVerbs[w]:
			verb = true
		case !readNouns[w]:
			return false
		}
	}
	return verb
}

var (
	readVerbs = toSet("read", "get", "list", "search", "view", "stat", "info", "find", "show", "describe", "tree", "cat", "head", "tail", "grep", "glob", "inspect", "query", "fetch", "lookup", "ls", "exists", "count", "diff", "check", "validate", "preview")
	readNouns = toSet("file", "files", "dir", "dirs", "directory", "directories", "text", "content", "contents", "multiple", "many", "path", "paths", "metadata", "details", "status", "by", "name", "in", "of", "all", "recent", "project", "workspace", "symbols", "symbol", "definition", "references", "lines", "range", "tree", "entries", "info")
)

func toSet(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// toolWords splits a tool name into lower-case words at _, -, . and case
// changes: searchAndReplace and search_and_replace are the same words.
func toolWords(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || i+1 < len(rs) && unicode.IsLower(rs[i+1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

func MCPGuardPath(cfg *config.Config, env map[string]string, tool, cwd string, args json.RawMessage) string {
	name := strings.ToLower(tool)
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if readOnlyToolName(tool) {
		return ""
	}
	var v any
	if json.Unmarshal(args, &v) != nil {
		return ""
	}
	copt := GuardOptions(cfg, env)
	var found string
	n, overflow := 0, false
	var walk func(any, int)
	walk = func(x any, depth int) {
		if found != "" {
			return
		}
		if depth > 8 || n > 500 {
			overflow = true
			return
		}
		n++
		switch t := x.(type) {
		case string:
			if t == "" || !strings.ContainsAny(t, "/.~") {
				return
			}
			p := t
			if strings.HasPrefix(p, "~/") {
				p = filepath.Join(copt.Home, p[2:])
			} else if !filepath.IsAbs(p) {
				p = filepath.Join(cwd, p)
			}
			// Cleaned first: ./ and // pad a path past any length.
			if p = filepath.Clean(p); len(p) > 4096 {
				overflow = true
				return
			}
			if copt.Guard.Touches(p) {
				found = p
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
	if found == "" && overflow {
		// Arguments too large or deep to walk: the call names a guard file
		// when its text does, once padding is taken out.
		found = guardInText(copt, cwd, string(args))
	}
	return found
}

// guardInText returns the guard path a text names, by the guard set's
// needles, with ./ and // collapsed; "" when it names none.
func guardInText(copt classify.Options, cwd, text string) string {
	t := strings.ToLower(text)
	for {
		u := strings.ReplaceAll(strings.ReplaceAll(t, "/./", "/"), "//", "/")
		if u == t {
			break
		}
		t = u
	}
	for _, nd := range copt.Guard.Needles(copt.Home) {
		if !strings.Contains(t, nd) {
			continue
		}
		var cands []string
		switch {
		case strings.HasPrefix(nd, "/"):
			cands = []string{nd}
		case strings.HasPrefix(nd, "~/"), strings.HasPrefix(nd, "$home/"), strings.HasPrefix(nd, "${home}/"):
			_, rel, _ := strings.Cut(nd, "/")
			cands = []string{filepath.Join(copt.Home, rel)}
		default:
			cands = []string{filepath.Join(copt.Home, nd), filepath.Join(cwd, nd)}
		}
		for _, c := range cands {
			if copt.Guard.Touches(c) {
				return c
			}
		}
		return cands[0]
	}
	return ""
}
