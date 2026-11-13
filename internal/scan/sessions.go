// Package scan reads the tool calls coding agents recorded in their own
// session files, so applygate can say what it would decide on them without
// a hook being installed (applygate scan).
//
// Formats, as read on 2026-11-13:
//   - Claude Code 2.1.x writes one JSON object per line under
//     ~/.claude/projects/<project>/<session>.jsonl (subagents under
//     <session>/subagents/). An "assistant" line carries the directory the
//     shell was in (cwd), the time, and message.content[] items of type
//     tool_use with the tool's name and input: the same name and input the
//     PreToolUse hook is sent.
//   - Codex 0.162 to 0.166 writes ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl.
//     An event_msg line of type item_completed holds a CommandExecution
//     (argv and the directory it ran in), a FileChange (paths) or an
//     McpToolCall. Some "codex exec" sessions hold no such record, only
//     the model's tool calls written as JavaScript (a custom_tool_call named
//     exec); the commands are then read from that (jsexec.go). Older
//     versions recorded a response_item of type function_call or
//     local_shell_call; that form is read from its published shape and a
//     fixture, not from sessions of those versions.
package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Call is one tool call an agent made in a recorded session.
type Call struct {
	Agent   string // claude or codex
	Session string
	ID      string // the host's id for the call ("" when it records none)
	Time    time.Time
	// Cwd is the directory the host's hook would have been told. Ran is the
	// directory the call ran in when the session records it separately
	// (Codex), else "".
	Cwd, Ran string
	Tool     string
	Input    json.RawMessage
}

// Dir is the directory the call ran in, as far as the session says.
func (c Call) Dir() string {
	if c.Ran != "" {
		return c.Ran
	}
	return c.Cwd
}

// HookInput is the call as the PreToolUse input its host would have sent.
func (c Call) HookInput() []byte {
	in := c.Input
	if len(in) == 0 {
		in = json.RawMessage("{}")
	}
	b, _ := json.Marshal(map[string]any{
		"session_id":      c.Session,
		"cwd":             c.Cwd,
		"hook_event_name": "PreToolUse",
		"tool_name":       c.Tool,
		"tool_input":      in,
	})
	return b
}

// maxLine is the longest session line read; a longer one is skipped. Lines
// with images or whole API requests run to megabytes.
const maxLine = 64 << 20

// eachLine calls fn with every line of r that fits in maxLine.
func eachLine(r io.Reader, fn func(line []byte)) {
	br := bufio.NewReaderSize(r, 1<<20)
	var buf []byte
	for {
		buf = buf[:0]
		over := false
		for {
			part, more, err := br.ReadLine()
			if err != nil {
				if len(buf) > 0 && !over {
					fn(buf)
				}
				return
			}
			if !over {
				if len(buf)+len(part) > maxLine {
					over = true
				} else {
					buf = append(buf, part...)
				}
			}
			if !more {
				break
			}
		}
		if !over && len(buf) > 0 {
			fn(buf)
		}
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ReadClaude emits the tool calls of one Claude Code session file.
func ReadClaude(r io.Reader, emit func(Call)) {
	marker := []byte(`"tool_use"`)
	eachLine(r, func(line []byte) {
		if !bytes.Contains(line, marker) {
			return
		}
		var l struct {
			Type      string `json:"type"`
			Cwd       string `json:"cwd"`
			SessionID string `json:"sessionId"`
			Timestamp string `json:"timestamp"`
			Message   struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &l) != nil || l.Type != "assistant" {
			return
		}
		var items []struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		if json.Unmarshal(l.Message.Content, &items) != nil {
			return
		}
		for _, it := range items {
			if it.Type != "tool_use" || it.Name == "" {
				continue
			}
			emit(Call{Agent: "claude", Session: l.SessionID, ID: it.ID, Time: parseTime(l.Timestamp), Cwd: l.Cwd, Tool: it.Name, Input: it.Input})
		}
	})
}

// ReadCodex emits the tool calls of one Codex rollout file. Commands are
// taken from the completed-item records when the file has any, and from the
// model's own calls otherwise, so no command is counted twice.
func ReadCodex(r io.Reader, emit func(Call)) {
	var session, sessionCwd, turnCwd string
	var items, calls []Call
	hasExec := false
	eachLine(r, func(line []byte) {
		var l struct {
			Timestamp string          `json:"timestamp"`
			Type      string          `json:"type"`
			Payload   json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(line, &l) != nil {
			return
		}
		at := parseTime(l.Timestamp)
		hookCwd := func() string {
			if turnCwd != "" {
				return turnCwd
			}
			return sessionCwd
		}
		switch l.Type {
		case "session_meta":
			var p struct {
				ID        string `json:"id"`
				SessionID string `json:"session_id"`
				Cwd       string `json:"cwd"`
			}
			if json.Unmarshal(l.Payload, &p) == nil {
				session, sessionCwd = p.ID, pathOf(p.Cwd)
				if session == "" {
					session = p.SessionID
				}
			}
		case "turn_context":
			var p struct {
				Cwd string `json:"cwd"`
			}
			if json.Unmarshal(l.Payload, &p) == nil && p.Cwd != "" {
				turnCwd = pathOf(p.Cwd)
			}
		case "event_msg":
			var p struct {
				Type string `json:"type"`
				Item struct {
					Type      string                     `json:"type"`
					ID        string                     `json:"id"`
					Command   []string                   `json:"command"`
					Cwd       string                     `json:"cwd"`
					Changes   map[string]json.RawMessage `json:"changes"`
					Server    string                     `json:"server"`
					Tool      string                     `json:"tool"`
					Arguments json.RawMessage            `json:"arguments"`
				} `json:"item"`
			}
			if json.Unmarshal(l.Payload, &p) != nil || p.Type != "item_completed" {
				return
			}
			it := p.Item
			base := Call{Agent: "codex", Session: session, ID: it.ID, Time: at, Cwd: hookCwd()}
			switch it.Type {
			case "CommandExecution":
				cmd := shellCommand(it.Command)
				if cmd == "" {
					return
				}
				hasExec = true
				c := base
				// Codex runs the command in the workdir the model chose, but
				// its hook is told the turn's directory and no workdir
				// (docs/limits.md, "Codex working directory"): the call is
				// judged as the hook would see it.
				c.Ran = pathOf(it.Cwd)
				if c.Cwd == "" {
					c.Cwd = c.Ran
				}
				c.Tool, c.Input = "exec_command", mustJSON(map[string]string{"command": cmd})
				items = append(items, c)
			case "FileChange":
				paths := make([]string, 0, len(it.Changes))
				for p := range it.Changes {
					paths = append(paths, p)
				}
				sort.Strings(paths)
				for _, p := range paths {
					c := base
					c.ID = it.ID + ":" + p
					c.Tool, c.Input = "apply_patch", mustJSON(map[string]string{"file_path": p})
					items = append(items, c)
				}
			case "McpToolCall":
				if it.Server == "" || it.Tool == "" {
					return
				}
				c := base
				c.Tool, c.Input = "mcp__"+it.Server+"__"+it.Tool, it.Arguments
				items = append(items, c)
			}
		case "response_item":
			var p struct {
				Type      string `json:"type"`
				Name      string `json:"name"`
				CallID    string `json:"call_id"`
				Arguments string `json:"arguments"`
				Input     string `json:"input"`
				Action    struct {
					Command          []string `json:"command"`
					WorkingDirectory string   `json:"working_directory"`
				} `json:"action"`
			}
			if json.Unmarshal(l.Payload, &p) != nil {
				return
			}
			c := Call{Agent: "codex", Session: session, ID: p.CallID, Time: at, Cwd: hookCwd()}
			switch p.Type {
			case "function_call":
				if !codexShellTools[p.Name] || !json.Valid([]byte(p.Arguments)) {
					return
				}
				c.Tool, c.Input = p.Name, unwrapArgv(json.RawMessage(p.Arguments))
			case "custom_tool_call":
				// The model's tool calls written as JavaScript.
				if p.Name != "exec" {
					return
				}
				for i, js := range jsExecCommands(p.Input) {
					jc := c
					jc.ID = fmt.Sprintf("%s:%d", p.CallID, i)
					jc.Tool, jc.Input = "exec_command", mustJSON(map[string]string{"command": js.cmd})
					switch {
					case js.workdir == "":
					case filepath.IsAbs(js.workdir):
						jc.Ran = js.workdir
					case jc.Cwd != "":
						jc.Ran = filepath.Join(jc.Cwd, js.workdir)
					}
					calls = append(calls, jc)
				}
				return
			case "local_shell_call":
				cmd := shellCommand(p.Action.Command)
				if cmd == "" {
					return
				}
				c.Tool, c.Input = "local_shell", mustJSON(map[string]string{"command": cmd})
				c.Ran = p.Action.WorkingDirectory
			default:
				return
			}
			calls = append(calls, c)
		}
	})
	if !hasExec {
		items = append(items, calls...)
	}
	for _, c := range items {
		emit(c)
	}
}

// codexShellTools are the function names older Codex versions gave a shell
// call.
var codexShellTools = map[string]bool{"shell": true, "exec_command": true, "local_shell": true, "container.exec": true, "unified_exec": true}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// pathOf turns a file:// URL into its path; any other string is returned
// as it is.
func pathOf(s string) string {
	if strings.HasPrefix(s, "file://") {
		if u, err := url.Parse(s); err == nil && u.Path != "" {
			return u.Path
		}
	}
	return s
}

var shellNames = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true}

// shellCommand returns the command line of an argv. Codex records a command
// as the shell it started (zsh -lc CMD), and tells its hook CMD.
func shellCommand(argv []string) string {
	if len(argv) == 3 && shellNames[filepath.Base(argv[0])] && (argv[1] == "-lc" || argv[1] == "-c") {
		return argv[2]
	}
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = quote(a)
	}
	return strings.Join(q, " ")
}

// unwrapArgv rewrites {"command": ["bash","-lc",CMD]} as {"command": CMD},
// leaving the other arguments (workdir) as they are.
func unwrapArgv(args json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil {
		return args
	}
	var argv []string
	if json.Unmarshal(m["command"], &argv) != nil || len(argv) == 0 {
		return args
	}
	m["command"] = mustJSON(shellCommand(argv))
	return mustJSON(m)
}

func quote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:,@%+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Source is one agent's session directory.
type Source struct {
	Agent string
	Root  string
}

// Sources returns where Claude Code and Codex keep their sessions for this
// user. CLAUDE_CONFIG_DIR and CODEX_HOME move them, as they do for the
// agents.
func Sources(home string, env map[string]string) []Source {
	claude := filepath.Join(home, ".claude")
	if d := env["CLAUDE_CONFIG_DIR"]; d != "" {
		claude = d
	}
	codex := filepath.Join(home, ".codex")
	if d := env["CODEX_HOME"]; d != "" {
		codex = d
	}
	return []Source{
		{"claude", filepath.Join(claude, "projects")},
		{"codex", filepath.Join(codex, "sessions")},
		{"codex", filepath.Join(codex, "archived_sessions")},
	}
}

// Stats counts what Walk read.
type Stats struct {
	Sessions   map[string]int // session files with a call in the window, per agent
	Calls      int            // tool calls in the window
	Compressed int            // session files not read because they are compressed
	Unreadable int            // session files that could not be opened
	First      time.Time      // the earliest call read
}

// Walk reads every session file under the sources and emits the calls made
// at or after since (a zero since means all of them). A call recorded in two
// files, as after a resumed session, is emitted once.
func Walk(sources []Source, since time.Time, emit func(Call)) Stats {
	st := Stats{Sessions: map[string]int{}}
	seen := map[string]bool{}
	for _, src := range sources {
		read := ReadClaude
		if src.Agent == "codex" {
			read = ReadCodex
		}
		_ = filepath.WalkDir(src.Root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			switch {
			case strings.HasSuffix(name, ".jsonl.zst"), strings.HasSuffix(name, ".jsonl.gz"):
				st.Compressed++
				return nil
			case !strings.HasSuffix(name, ".jsonl"):
				return nil
			}
			// A file last written before the window holds no call in it.
			if fi, err := d.Info(); err != nil || (!since.IsZero() && fi.ModTime().Before(since)) {
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				st.Unreadable++
				return nil
			}
			defer f.Close()
			n := 0
			read(f, func(c Call) {
				if !since.IsZero() && c.Time.Before(since) {
					return
				}
				if c.ID != "" {
					k := c.Agent + "\x00" + c.ID
					if seen[k] {
						return
					}
					seen[k] = true
				}
				if c.Session == "" {
					c.Session = strings.TrimSuffix(name, ".jsonl")
				}
				if !c.Time.IsZero() && (st.First.IsZero() || c.Time.Before(st.First)) {
					st.First = c.Time
				}
				n++
				emit(c)
			})
			if n > 0 {
				st.Sessions[src.Agent]++
				st.Calls += n
			}
			return nil
		})
	}
	return st
}
