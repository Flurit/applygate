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
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Flurit/applygate/internal/shell"
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
	// Program is the program the server runs (call_aws runs aws): a
	// translation whose command starts with another program is unresolved,
	// or, with Prepend, gets the program put in front, as the server does.
	Program string `json:"program,omitempty"`
	Prepend bool   `json:"prepend,omitempty"`
	// Stdin are the arguments whose text the server writes to the
	// command's standard input.
	Stdin []string `json:"stdin,omitempty"`
	// ShellArg is the argument naming the program that runs the command
	// (start_process's shell: bash, python3, pwsh).
	ShellArg string `json:"shell_arg,omitempty"`
	// SharedDir is set when another server with this tool name has no
	// directory argument, so the directory argument is not proof of where
	// the command runs; the call is judged as if it named none.
	SharedDir bool `json:"shared_dir,omitempty"`
	// Persistent is set when the input goes to a shell that keeps running
	// between calls, so what one call defines (an alias, a function, an
	// exported variable) applies to the next.
	Persistent bool `json:"persistent,omitempty"`
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
	// Persistent: the input is typed into a shell that keeps its state
	// between calls.
	Persistent bool
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

var placeholder = regexp.MustCompile(`\{([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(\|kebab|\|raw|\|ascii)?(\.\.\.)?\}`)

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
	if parseErr != nil || args == nil {
		// Arguments that are not an object (a JSON string, an array, null)
		// cannot be matched against the table, but a tool that is in it is
		// still known: it is asked about, not allowed as an unknown tool.
		for _, s := range t.Servers {
			for _, tl := range s.Tools {
				if contains(tl.Names, tool) {
					return Result{Server: s.Name, Command: unresolved(tool, "its arguments are not a JSON object"), Note: tl.Note, Persistent: tl.Persistent}, true
				}
			}
		}
	}
	// Every server whose tool this call fits is judged: decoy arguments
	// must not steer the call to the mildest of them.
	var all []Result
	for _, s := range t.Servers {
		for _, tl := range s.Tools {
			if !contains(tl.Names, tool) || !hasAll(args, tl.Requires) {
				continue
			}
			all = append(all, translateOne(s, tl, tool, args, parseErr))
		}
	}
	if len(all) == 0 {
		if r, ok := genericShell(tool, args, parseErr); ok {
			return r, true
		}
		return Result{}, false
	}
	// A tool in the table that is sent a program and an argument list (a
	// server of the same name may take both) is also judged as the joined
	// command.
	if parseErr == nil {
		for _, ak := range argvArgs {
			if _, has := args[ak]; has {
				if r, ok := genericShell(tool, args, nil); ok {
					r.Server = "a server of the same tool name that takes an argument list"
					all = append(all, r)
				}
				break
			}
		}
	}
	if len(all) == 1 {
		return all[0], true
	}
	// Several readings: each runs in a subshell of one command, and the
	// directory is the one they agree on, else unknown.
	var cmds, servers []string
	dir := all[0].Dir
	persistent := false
	for _, r := range all {
		persistent = persistent || r.Persistent
		cmds = append(cmds, "( "+r.Command+"\n)")
		servers = append(servers, r.Server)
		if r.Dir != dir {
			dir = ""
		}
	}
	return Result{Server: strings.Join(servers, " or "), Command: strings.Join(cmds, "\n"), Dir: dir, Persistent: persistent,
		Note: "the tool name and arguments fit several servers; each reading is judged"}, true
}

func translateOne(s Server, tl Tool, tool string, args map[string]any, parseErr error) Result {
	r := Result{Server: s.Name, Note: tl.Note, Persistent: tl.Persistent}
	if parseErr != nil {
		r.Command = unresolved(tool, "its arguments are not a JSON object")
		return r
	}
	// A relative directory is resolved by the server against its
	// own working directory, which the hook does not know.
	if d := str(args[tl.Dir]); tl.Dir != "" && filepath.IsAbs(d) && !tl.SharedDir {
		// The server changes to the path as the OS resolves it: .. after a
		// symlink goes up from the symlink's target.
		r.Dir = shell.PhysicalJoin("", d)
	}
	if tl.Shell != "" {
		// A list holds several commands, each run on its own; a
		// string holding a JSON array of strings is that list.
		v := args[tl.Shell]
		if sv, ok := v.(string); ok && strings.HasPrefix(strings.TrimSpace(sv), "[") {
			var arr []any
			if json.Unmarshal([]byte(sv), &arr) == nil {
				v = arr
			}
		}
		cmds := list(v, false)
		if tl.Program != "" {
			for _, c := range cmds {
				// The server splits the words itself: a # is an argument
				// there, not the comment a shell reads.
				if hashArg.MatchString(c) {
					r.Command = unresolved(tool, "the server passes "+quote(c)+" to "+tl.Program+" word by word, and a # there is an argument, not a comment")
					return r
				}
			}
			for i, c := range cmds {
				// The server splits the words itself, with shell quoting but
				// no shell: a newline or ; is a space or an argument there,
				// so the command is judged as the one argv it becomes (4M1).
				f, why := splitWords(c)
				if why != "" {
					r.Command = unresolved(tool, "the server splits "+quote(c)+" into words itself, and "+why)
					return r
				}
				if len(f) == 0 || f[0] != tl.Program {
					if !tl.Prepend {
						r.Command = unresolved(tool, "the server runs "+tl.Program+", and "+quote(c)+" does not start with it")
						return r
					}
					f = append([]string{tl.Program}, f...)
				}
				for j := range f {
					f[j] = quote(f[j])
				}
				cmds[i] = strings.Join(f, " ")
			}
		}
		r.Command = strings.Join(cmds, "\n")
		if strings.TrimSpace(r.Command) == "" {
			r.Command = unresolved(tool, "argument "+tl.Shell+" is missing")
			return r
		}
		if tl.ShellArg != "" {
			if sh := str(args[tl.ShellArg]); sh != "" {
				r.Command = viaShell(tool, sh, r.Command)
			}
		}
		r.Command = withStdin(tool, r.Command, args, tl.Stdin)
		return r
	}
	// An argument the cases look into must be an object: params
	// sent as a JSON string cannot be read the way the server does.
	for _, c := range tl.Cases {
		for k := range c.When {
			if head, _, nested := strings.Cut(k, "."); nested {
				if v, present := args[head]; present {
					if _, isMap := v.(map[string]any); !isMap {
						r.Command = unresolved(tool, "argument "+head+" is not an object")
						return r
					}
				}
			}
		}
	}
	// Every case the arguments fit is judged, not the first: a decoy field
	// the server ignores must not select the mildest reading.
	var readings []string
	for _, c := range tl.Cases {
		if !matches(c.When, args) {
			continue
		}
		var cmd, op string
		if why, ok := strings.CutPrefix(c.Command, "?"); ok {
			w, _ := expand(strings.TrimSpace(why), args)
			readings = append(readings, unresolved(tool, w))
		} else if cmd, op = expand(c.Command, args); op != "" {
			readings = append(readings, unresolved(tool, "an argument holds the shell operator "+quote(op)))
		} else {
			readings = append(readings, withStdin(tool, cmd, args, tl.Stdin))
		}
	}
	switch len(readings) {
	case 0:
		r.Command = unresolved(tool, "its arguments match no known form")
	case 1:
		r.Command = readings[0]
	default:
		var b strings.Builder
		for _, c := range readings {
			b.WriteString("( " + c + "\n)\n")
		}
		r.Command = b.String()
		r.Note = strings.TrimSpace(r.Note + " (the arguments fit several forms; each is judged)")
	}
	return r
}

// hashArg matches a # that starts a word, which a shell reads as a comment.
var hashArg = regexp.MustCompile(`(^|\s)#`)

// genericShellTools are the names shell tools go by across MCP servers the
// table does not describe; their command argument is judged as shell.
var genericShellTools = map[string]bool{"run_in_terminal": true, "execute_command": true, "bash": true, "shell": true,
	"run_shell_command": true, "run_terminal_command": true, "execute_bash": true, "run_bash": true, "exec": true,
	"execute": true, "terminal": true, "shell_exec": true, "run_shell": true, "execute_shell": true, "bash_command": true,
	"run_command": true, "execute_shell_command": true, "run_process": true, "command": true, "sh": true}

var genericCommandArgs = []string{"command", "cmd", "script", "commandLine", "command_line", "cmdline", "cmd_text", "shell_command", "shellCommand", "code", "input"}

// strongCommandArgs name a shell command whatever the tool is called.
var strongCommandArgs = []string{"command", "cmd", "script", "commandLine", "command_line", "cmdline", "cmd_text", "shell_command", "shellCommand"}

// argvArgs hold the arguments of a program a command argument names.
var argvArgs = []string{"args", "arguments", "argv", "params", "argument_list"}

// shellishName reports a tool name that says it runs a command or code.
func shellishName(tool string) bool {
	n := snakeName(tool)
	if genericShellTools[n] {
		return true
	}
	for _, w := range []string{"exec", "run", "shell", "terminal", "bash", "command", "cmd", "script", "eval", "python", "node", "powershell", "invoke"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// genericShell judges a shell tool of a server the table does not know: one
// whose name says it runs commands, or whose arguments carry a command. Every
// command argument present is judged (a decoy command does not hide a later
// script), with its program's argument list appended. Its directory argument
// is not trusted, since nothing says the server honours it.
func genericShell(tool string, args map[string]any, parseErr error) (Result, bool) {
	strong := false
	for _, k := range strongCommandArgs {
		if v, ok := args[k]; ok && len(list(v, false)) > 0 {
			strong = true
		}
	}
	if !shellishName(tool) && !strong {
		return Result{}, false
	}
	r := Result{Server: "a server applygate does not know", Note: "a shell tool name or command argument; judged as a shell command"}
	if parseErr != nil {
		r.Command = unresolved(tool, "its arguments are not a JSON object")
		return r, true
	}
	var readings []string
	for _, k := range genericCommandArgs {
		v, ok := args[k]
		if !ok {
			continue
		}
		cmds := list(v, false)
		if len(cmds) == 0 {
			if str, isStr := v.(string); isStr && strings.TrimSpace(str) == "" {
				continue // an empty command is not a command
			}
			r.Command = unresolved(tool, "argument "+k+" is not text")
			return r, true
		}
		cmd := strings.Join(cmds, "\n")
		_, isArray := v.([]any)
		// The program's argument list: command "terraform" with args
		// ["destroy"] runs terraform destroy.
		var extra []string
		if !isArray && (k == "command" || k == "cmd") {
			for _, ak := range argvArgs {
				if av, ok := args[ak]; ok {
					if as := list(av, false); len(as) > 0 {
						extra = append(extra, as...)
					} else if str, isStr := av.(string); isStr && strings.TrimSpace(str) != "" {
						extra = append(extra, str)
					} else if _, isMap := av.(map[string]any); isMap {
						r.Command = unresolved(tool, "argument "+ak+" is an object")
						return r, true
					}
				}
			}
		}
		switch {
		case isArray:
			// An array is one command: a program's argv, or words a server
			// joins with spaces for a shell. Both readings are judged, not
			// one line per element.
			q := make([]string, len(cmds))
			for i, c := range cmds {
				q[i] = quote(c)
			}
			cmd = strings.Join(q, " ") + "\n" + strings.Join(cmds, " ")
		case len(extra) > 0:
			q := []string{quote(cmd)}
			for _, e := range extra {
				q = append(q, quote(e))
			}
			cmd = strings.Join(q, " ") + "\n" + cmd + " " + strings.Join(extra, " ")
		}
		readings = append(readings, cmd)
	}
	if len(readings) == 0 {
		r.Command = unresolved(tool, "no command argument applygate knows")
		return r, true
	}
	if len(readings) == 1 {
		r.Command = readings[0]
	} else {
		var b strings.Builder
		for _, c := range readings {
			b.WriteString("( " + c + "\n)\n")
		}
		r.Command = b.String()
	}
	r.Command = withStdin(tool, r.Command, args, []string{"stdin", "stdin_text", "input"})
	if sh := str(args["shell"]); sh != "" {
		r.Command = viaShell(tool, sh, r.Command)
	}
	return r, true
}

// snakeName is a tool name in lower snake case: executeCommand, Execute-Command
// and execute_command are one name.
func snakeName(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '-' || r == '.' || r == ' ':
			b.WriteByte('_')
		case unicode.IsUpper(r):
			if i > 0 && rs[i-1] != '_' && rs[i-1] != '-' && (unicode.IsLower(rs[i-1]) || i+1 < len(rs) && unicode.IsLower(rs[i+1])) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// withStdin adds the text of the stdin arguments as the command's input.
func withStdin(tool, cmd string, args map[string]any, keys []string) string {
	for _, k := range keys {
		in := str(args[k])
		if in == "" {
			continue
		}
		const delim = "APPLYGATE_MCP_STDIN"
		if strings.Contains(in, delim) {
			return unresolved(tool, "argument "+k+" cannot be read")
		}
		if !strings.Contains(cmd, "\n") {
			return cmd + " <<'" + delim + "'\n" + in + "\n" + delim
		}
		return "{ " + cmd + "\n} <<'" + delim + "'\n" + in + "\n" + delim
	}
	return cmd
}

// viaShell runs a command through the program a tool names: a POSIX
// shell, an interpreter's code option, or something applygate cannot read.
func viaShell(tool, sh, cmd string) string {
	base := strings.ToLower(filepath.Base(strings.Fields(sh + " x")[0]))
	base = strings.TrimSuffix(base, ".exe")
	switch {
	case base == "sh" || base == "bash" || base == "zsh" || base == "dash" || base == "ksh":
		return cmd
	case strings.HasPrefix(base, "python") || base == "perl" || base == "ruby":
		return base + " -c " + quote(cmd)
	case base == "node" || base == "deno" || base == "bun":
		return base + " -e " + quote(cmd)
	case base == "pwsh" || base == "powershell":
		return "pwsh -Command " + quote(cmd)
	}
	return unresolved(tool, "the command runs in "+quote(sh)+", which applygate cannot read")
}

// unresolved is a command the analyzer cannot resolve statically, so the
// call gets the dynamic class (ask, or block where the host cannot ask).
func unresolved(tool, why string) string {
	return fmt.Sprintf(`eval "$APPLYGATE_MCP_UNREADABLE" # MCP tool %s: %s`, tool, why)
}

// shellOps are operator tokens that a server building a command line from
// argv may hand to a shell; only a bare "|" is modelled (as a pipe).
var shellOps = map[string]bool{"&&": true, "||": true, ";": true, "&": true, ">": true, ">>": true, "<": true, "|&": true, "<<": true, "2>": true, "&>": true}

// expand fills a template. op is set to the first bare shell operator an
// array argument holds, which the caller treats as unresolved.
func expand(tmpl string, args map[string]any) (cmd, op string) {
	var words []string
	for _, w := range strings.Fields(tmpl) {
		m := placeholder.FindStringSubmatch(w)
		switch {
		case m == nil:
			words = append(words, w)
		case m[3] != "":
			for _, v := range list(lookup(args, m[1]), true) {
				if shellOps[v] && op == "" {
					op = v
				}
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
			} else if m[2] == "|ascii" {
				// Character codes typed into a session (wcgw send_ascii).
				var b strings.Builder
				for _, c := range list(lookup(args, m[1]), false) {
					n, err := strconv.Atoi(c)
					if err != nil || n < 0 || n > 0x10ffff {
						return `eval "$APPLYGATE_MCP_UNREADABLE" # character codes that cannot be read`, ""
					}
					b.WriteRune(rune(n))
				}
				words = append(words, b.String())
			}
		}
	}
	return strings.Join(words, " "), op
}

func matches(when map[string][]string, args map[string]any) bool {
	for k, vals := range when {
		ok := false
		// A dotted key may be read as a nested path or as a top-level key
		// with a dot; the case holds when either reading holds, so a decoy
		// top-level key cannot hide the nested one the server reads.
		for _, raw := range lookupAll(args, k) {
			v := strings.ToLower(str(raw))
			for _, want := range vals {
				// "true" matches any present value that is not a falsy one:
				// servers read is_destroy: 1 or "yes" as true.
				if want == "*" && (v != "" || truthy(raw)) || strings.ToLower(want) == v || want == "true" && truthy(raw) {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// lookupAll returns the values at key read whole and as a dotted path.
func lookupAll(args map[string]any, key string) []any {
	var out []any
	if v, ok := args[key]; ok {
		out = append(out, v)
	}
	if head, rest, ok := strings.Cut(key, "."); ok {
		if m, isMap := args[head].(map[string]any); isMap {
			out = append(out, lookupAll(m, rest)...)
		}
	}
	if len(out) == 0 {
		out = append(out, nil)
	}
	return out
}

// lookup returns the argument at a dotted path, the nested reading first
// (what the servers read), else a top-level key that contains the dot.
func lookup(args map[string]any, key string) any {
	if head, rest, ok := strings.Cut(key, "."); ok {
		if m, isMap := args[head].(map[string]any); isMap {
			if v := lookup(m, rest); v != nil {
				return v
			}
		}
	}
	return args[key]
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

// truthy reports whether a present argument counts as true.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "", "false", "0", "no", "off", "n", "f", "null", "none":
			return false
		}
		return true
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// list returns an array argument's elements; a string is one element, or
// its words when split is set; an object is its entries as --key=value
// flags (true alone is --key).
func list(v any, split bool) []string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			name := "--" + strings.TrimLeft(k, "-")
			switch val := x[k].(type) {
			case bool:
				if val {
					out = append(out, name)
				}
			default:
				if s := str(val); s != "" {
					out = append(out, name+"="+s)
				}
			}
		}
		return out
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

// splitWords splits s as Python's shlex.split does, which is how servers
// that run a CLI without a shell are taken to split its command (not checked
// against each server's source): words are separated by
// space, tab, carriage return or newline; quotes and backslashes group them; nothing
// else is special. A word that is a shell operator is refused, since some
// servers do run pipes, and so is an unclosed quote.
func splitWords(s string) (words []string, why string) {
	var w strings.Builder
	in, quoteCh := false, rune(0)
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quoteCh == '\'':
			if r == '\'' {
				quoteCh = 0
			} else {
				w.WriteRune(r)
			}
		case quoteCh == '"':
			switch {
			case r == '"':
				quoteCh = 0
			case r == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\'):
				i++
				w.WriteRune(rs[i])
			default:
				w.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quoteCh, in = r, true
		case r == '\\':
			if i+1 == len(rs) {
				return nil, "it ends in a backslash"
			}
			i++
			w.WriteRune(rs[i])
			in = true
		case r == ' ' || r == '\t' || r == '\r' || r == '\n':
			if in {
				words = append(words, w.String())
				w.Reset()
				in = false
			}
		default:
			w.WriteRune(r)
			in = true
		}
	}
	if quoteCh != 0 {
		return nil, "it has an unclosed quote"
	}
	if in {
		words = append(words, w.String())
	}
	for _, x := range words {
		switch x {
		case "|", "||", "&&", ";", "&", ">", ">>", "<", "<<":
			return nil, "the word " + quote(x) + " may be a pipe or redirection there"
		}
	}
	return words, ""
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
