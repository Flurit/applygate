// Package mcpmap translates calls to known infrastructure MCP tools into the
// shell command each is equivalent to, so the shell analyzer, tiers, preflight
// and plan gate judge them like the command itself.
//
// The table is data (rules.json): one entry per server, written from that
// server's source code, which every entry names. A tool that is not in the
// table is not judged; the hook logs it and allows it as before.
package mcpmap

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

// Table is the parsed rule set.
type Table struct {
	Servers []Server `json:"servers"`
}

// Server describes the judged tools of one MCP server.
type Server struct {
	Name   string `json:"name"`
	Source string `json:"source"` // repository, commit and files read
	Tools  []Tool `json:"tools"`
}

// Tool maps one tool to a command.
type Tool struct {
	Names []string `json:"names"`
	// Requires are argument names that must be present, so a tool of
	// another server with the same name is not mistaken for this one.
	Requires []string `json:"requires,omitempty"`
	// Shell is the argument that holds a shell command, analyzed as is.
	Shell string `json:"shell,omitempty"`
	// Cases build the command from the arguments; the first case whose
	// conditions hold is used.
	Cases []Case `json:"cases,omitempty"`
	// Dir is the argument that holds the working directory.
	Dir string `json:"dir,omitempty"`
	// Note is shown with the verdict (what the server does, in short).
	Note string `json:"note,omitempty"`
}

// Case is one command template. In Command, {arg} is replaced by the
// argument's value as one shell word and {arg...} by each element of an array
// argument as its own word; an absent or empty argument drops its word.
// {arg|kebab} turns a CamelCase value into the CLI's kebab-case
// (DeleteCluster -> delete-cluster), and {arg|raw} inserts a command held in
// an argument as is, unquoted. In {arg...} a bare "|" stays a pipe, for
// servers that build pipelines from argv arrays. An argument name may be a dotted path
// into nested objects (params.is-destroy). A command that starts with "?" is
// not a command but the reason the call cannot be judged from its arguments
// (for example applying a remote run whose plan the hook cannot read); the
// call is then asked about, like any command applygate cannot resolve.
type Case struct {
	When    map[string][]string `json:"when,omitempty"` // argument -> accepted values (case-insensitive)
	Command string              `json:"command"`
}

// Result is a translated call.
type Result struct {
	Server  string
	Command string
	Dir     string // "" when the call names no absolute directory
	Note    string
}

var table Table

func init() {
	if err := json.Unmarshal(rulesJSON, &table); err != nil {
		panic("mcpmap: rules.json: " + err.Error())
	}
	if err := table.validate(); err != nil {
		panic("mcpmap: rules.json: " + err.Error())
	}
}

// Rules returns the built-in table.
func Rules() *Table { return &table }

var placeholder = regexp.MustCompile(`\{([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(\|kebab|\|raw)?(\.\.\.)?\}`)

func (t *Table) validate() error {
	for _, s := range t.Servers {
		if s.Name == "" || s.Source == "" {
			return fmt.Errorf("server without name or source")
		}
		for _, tl := range s.Tools {
			if len(tl.Names) == 0 {
				return fmt.Errorf("%s: tool without names", s.Name)
			}
			if (tl.Shell == "") == (len(tl.Cases) == 0) {
				return fmt.Errorf("%s %v: exactly one of shell and cases", s.Name, tl.Names)
			}
			for _, c := range tl.Cases {
				if strings.TrimSpace(c.Command) == "" {
					return fmt.Errorf("%s %v: empty command", s.Name, tl.Names)
				}
			}
		}
	}
	return nil
}

// ToolName is the tool part of mcp__<server>__<tool>. Server names may
// themselves contain "__", so the tool is what follows the last "__".
func ToolName(full string) string {
	s := strings.TrimPrefix(full, "mcp__")
	if i := strings.LastIndex(s, "__"); i >= 0 {
		return s[i+2:]
	}
	return s
}

// Translate returns the command a known MCP call is judged as. ok is false
// for a tool the table does not describe. A known tool whose arguments
// cannot be read, or match no case, still translates: to a command the
// analyzer cannot resolve, so it is asked about rather than allowed.
func (t *Table) Translate(fullName string, raw json.RawMessage, cwd string) (Result, bool) {
	tool := ToolName(fullName)
	var args map[string]any
	parseErr := json.Unmarshal(raw, &args)
	for _, s := range t.Servers {
		for _, tl := range s.Tools {
			if !contains(tl.Names, tool) || !hasAll(args, tl.Requires) {
				continue
			}
			r := Result{Server: s.Name, Note: tl.Note}
			if parseErr != nil {
				r.Command = unresolved(tool, "its arguments are not a JSON object")
				return r, true
			}
			// A relative directory is resolved by the server against its
			// own working directory, which the hook does not know.
			if d := str(args[tl.Dir]); tl.Dir != "" && filepath.IsAbs(d) {
				r.Dir = filepath.Clean(d)
			}
			if tl.Shell != "" {
				// A list holds several commands, each run on its own.
				r.Command = strings.Join(list(args[tl.Shell], false), "\n")
				if strings.TrimSpace(r.Command) == "" {
					r.Command = unresolved(tool, "argument "+tl.Shell+" is missing")
				}
				return r, true
			}
			for _, c := range tl.Cases {
				if matches(c.When, args) {
					if why, ok := strings.CutPrefix(c.Command, "?"); ok {
						r.Command = unresolved(tool, expand(strings.TrimSpace(why), args))
					} else {
						r.Command = expand(c.Command, args)
					}
					return r, true
				}
			}
			r.Command = unresolved(tool, "its arguments match no known form")
			return r, true
		}
	}
	return Result{}, false
}

// unresolved is a command the analyzer cannot resolve statically, so the
// call gets the dynamic class (ask, or block where the host cannot ask).
func unresolved(tool, why string) string {
	return fmt.Sprintf(`eval "$APPLYGATE_MCP_UNREADABLE" # MCP tool %s: %s`, tool, why)
}

func expand(tmpl string, args map[string]any) string {
	var words []string
	for _, w := range strings.Fields(tmpl) {
		m := placeholder.FindStringSubmatch(w)
		switch {
		case m == nil:
			words = append(words, w)
		case m[3] != "":
			for _, v := range list(lookup(args, m[1]), true) {
				if v != "|" {
					v = quote(v)
				}
				words = append(words, v)
			}
		default:
			if v := str(lookup(args, m[1])); v != "" {
				switch m[2] {
				case "|kebab":
					v = quote(kebab(v))
				case "|raw":
				default:
					v = quote(v)
				}
				words = append(words, placeholder.ReplaceAllLiteralString(w, v))
			}
		}
	}
	return strings.Join(words, " ")
}

func matches(when map[string][]string, args map[string]any) bool {
	for k, vals := range when {
		v := strings.ToLower(str(lookup(args, k)))
		ok := false
		for _, want := range vals {
			if want == "*" && v != "" || strings.ToLower(want) == v {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// lookup returns the argument at a dotted path; a key that itself contains
// a dot is tried whole first.
func lookup(args map[string]any, key string) any {
	if v, ok := args[key]; ok {
		return v
	}
	head, rest, ok := strings.Cut(key, ".")
	if !ok {
		return nil
	}
	if m, isMap := args[head].(map[string]any); isMap {
		return lookup(m, rest)
	}
	return nil
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%f", x), "0"), ".")
	}
	return ""
}

// list returns an array argument's elements; a string is one element, or
// its words when split is set.
func list(v any, split bool) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			if s := str(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if split {
			return strings.Fields(x)
		}
		return []string{x}
	}
	return nil
}

func kebab(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('-')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`|&;<>()*?[]{}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hasAll(args map[string]any, keys []string) bool {
	for _, k := range keys {
		if _, ok := args[k]; !ok {
			return false
		}
	}
	return true
}
