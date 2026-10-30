package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/policy"
)

// The adapters in this file were written from each host's documentation and
// source, read on 2026-10-30/31 and recorded with links in
// review/host-research/2026-10-31-hook-contracts.md. None was tested live;
// docs/hosts.md says so cell by cell.

// call is one tool call in host-neutral form, before it is classified.
type call struct {
	event   string // hook event name; "" when the host sends none
	tool    string
	input   map[string]json.RawMessage
	cwd     string
	session string
	mode    string
}

// parseCall reads every payload shape the adapters accept: snake_case
// tool_name/tool_input (Claude Code, Codex, Gemini CLI, Devin, Cursor
// preToolUse, applygate's OpenCode plugin), Copilot CLI's camelCase
// toolName/toolArgs, Cursor's beforeShellExecution and beforeReadFile, the
// Windsurf Cascade agent_action_name/tool_info form and Cline's
// preToolUse/tool_call form. An argument object sent as a JSON string
// (Copilot toolArgs, Cursor MCP tool_input) is decoded.
func parseCall(raw []byte) (call, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return call{}, fmt.Errorf("malformed hook event: %w", err)
	}
	if top == nil {
		return call{}, errors.New("malformed hook event: not a JSON object")
	}
	c := call{
		event:   firstString(top, "hook_event_name", "hookEventName", "hookName", "agent_action_name"),
		tool:    firstString(top, "tool_name", "toolName"),
		cwd:     stringField(top["cwd"]),
		session: firstString(top, "session_id", "sessionId", "conversation_id", "trajectory_id", "taskId"),
		mode:    stringField(top["permission_mode"]),
	}
	args := top["tool_input"]
	if len(args) == 0 {
		args = top["toolArgs"]
	}
	c.input = argObject(args)
	switch {
	case c.event == "beforeShellExecution":
		// Cursor: the command and cwd are top-level fields.
		c.tool = "Shell"
		c.input = map[string]json.RawMessage{"command": top["command"]}
	case c.event == "beforeReadFile":
		c.tool = "Read"
		c.input = map[string]json.RawMessage{"file_path": top["file_path"]}
	case len(top["tool_info"]) > 0:
		// Windsurf Cascade: the action name is the event and the tool.
		c.tool = c.event
		c.input = argObject(top["tool_info"])
		if c.cwd == "" {
			c.cwd = stringField(c.input["cwd"])
		}
	case len(top["preToolUse"]) > 0 || len(top["tool_call"]) > 0:
		parseCline(top, &c)
	}
	if c.input == nil {
		c.input = map[string]json.RawMessage{}
	}
	return c, nil
}

// parseCline fills c from a Cline hook payload. The CLI's tool_call carries
// the model's raw input; the VS Code extensions send preToolUse.parameters as
// strings, with non-string values JSON-encoded.
func parseCline(top map[string]json.RawMessage, c *call) {
	var pre struct {
		ToolName   string            `json:"toolName"`
		Parameters map[string]string `json:"parameters"`
	}
	var tc struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	json.Unmarshal(top["preToolUse"], &pre)
	json.Unmarshal(top["tool_call"], &tc)
	c.tool = pre.ToolName
	if c.tool == "" {
		c.tool = tc.Name
	}
	if len(tc.Input) > 0 {
		var s string
		var a []json.RawMessage
		switch {
		case json.Unmarshal(tc.Input, &s) == nil:
			c.input = map[string]json.RawMessage{"command": tc.Input}
		case json.Unmarshal(tc.Input, &a) == nil:
			c.input = map[string]json.RawMessage{"commands": tc.Input}
		default:
			c.input = argObject(tc.Input)
		}
	} else {
		c.input = map[string]json.RawMessage{}
		for k, v := range pre.Parameters {
			if t := strings.TrimSpace(v); (strings.HasPrefix(t, "[") || strings.HasPrefix(t, "{")) && json.Valid([]byte(t)) {
				c.input[k] = json.RawMessage(t)
				continue
			}
			b, _ := json.Marshal(v)
			c.input[k] = b
		}
	}
	var roots []string
	if json.Unmarshal(top["workspaceRoots"], &roots) == nil && len(roots) > 0 {
		c.cwd = roots[0]
	}
	if c.event == "tool_call" {
		c.event = "PreToolUse"
	}
}

// argObject decodes a tool's arguments: a JSON object, or a JSON string that
// holds one.
func argObject(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		return m
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && json.Unmarshal([]byte(s), &m) == nil {
		return m
	}
	return nil
}

func firstString(m map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if s := stringField(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func toolSet(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// The tool names each host documents, by what the tool does. A name in no
// set is a tool applygate does not inspect.
var (
	shellTools = toolSet(
		"Bash",               // Claude Code, Codex, Copilot CLI (PascalCase hooks)
		"Shell",              // Cursor
		"exec",               // Devin
		"bash", "powershell", // Copilot CLI; bash is also OpenCode V1
		"run_shell_command",                    // Gemini CLI
		"shell", "local_shell", "exec_command", // Codex; shell is also OpenCode V2
		"unified_exec", "container.exec", // Codex
		"execute_command", "run_commands", // Cline (legacy, next)
		"pre_run_command", // Windsurf Cascade
	)
	writeTools = toolSet(
		"Write", "Edit", "MultiEdit", "NotebookEdit", // Claude Code, Cursor (Write)
		"Delete",                                              // Cursor
		"apply_patch", "create", "edit", "str_replace_editor", // Copilot CLI, Codex
		"write_file", "replace", // Gemini CLI
		"write", "patch", // OpenCode
		"editor", "write_to_file", "replace_in_file", // Cline
		"pre_write_code", // Windsurf Cascade
	)
	readTools = toolSet(
		"Read", "Grep", "Glob", // Claude Code, Cursor
		"view", "glob", "grep", "rg", // Copilot CLI
		"read_file", "read_many_files", "grep_search", // Gemini CLI, Cline legacy
		"read",                                                        // OpenCode
		"read_files", "search_codebase", "search_files", "list_files", // Cline
		"pre_read_code", // Windsurf Cascade
	)
	patchTools = toolSet("apply_patch", "patch")
)

var pathKeys = []string{"file_path", "filePath", "path", "notebook_path", "absolute_path", "target_file", "file"}

// toEvent classifies the call. A shell tool without a command is an error,
// so a payload whose shape applygate misreads fails per on_error instead of
// being allowed as an empty command.
func (c call) toEvent(agent string) (policy.Event, error) {
	ev := policy.Event{Agent: agent, Tool: c.tool, Cwd: c.cwd, Session: c.session, PermissionMode: c.mode}
	switch {
	case isMCPTool(c.tool):
		raw, _ := json.Marshal(c.input)
		ev.Kind, ev.Command = policy.KindMCP, mcpArguments(raw)
	case shellTools[c.tool]:
		cmd := commandOf(c.input)
		if strings.TrimSpace(cmd) == "" {
			return ev, fmt.Errorf("malformed hook event: %s call without a command applygate can read", c.tool)
		}
		ev.Kind, ev.Command = policy.KindShell, cmd
	case writeTools[c.tool]:
		ev.Kind, ev.Paths = policy.KindWrite, filePaths(c.tool, c.input)
	case readTools[c.tool]:
		ev.Kind, ev.Paths = policy.KindRead, filePaths(c.tool, c.input)
	default:
		ev.Kind = policy.KindOther
	}
	return ev, nil
}

// commandOf returns the shell command of a call: command (a string or an
// argv array), cmd, command_line (Windsurf) or commands (Cline, a list of
// strings or {command, args} run one after another).
func commandOf(in map[string]json.RawMessage) string {
	for _, k := range []string{"command", "cmd", "command_line"} {
		if s := commandField(in[k]); s != "" {
			return s
		}
	}
	var list []json.RawMessage
	if json.Unmarshal(in["commands"], &list) != nil {
		return commandField(in["commands"])
	}
	var lines []string
	for _, item := range list {
		var s string
		if json.Unmarshal(item, &s) == nil {
			lines = append(lines, s)
			continue
		}
		var o struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		if json.Unmarshal(item, &o) == nil && o.Command != "" {
			w := []string{o.Command}
			for _, a := range o.Args {
				w = append(w, shellQuote(a))
			}
			lines = append(lines, strings.Join(w, " "))
		}
	}
	return strings.Join(lines, "\n")
}

// filePaths returns the files a write or read names. Hosts document few of
// their file-tool fields, so when none of the known fields is present every
// one-line string argument is taken as a candidate path: a guard file named
// in an unknown field is then still seen, and a string that is not a path
// matches nothing.
func filePaths(tool string, in map[string]json.RawMessage) []string {
	var out []string
	for _, k := range pathKeys {
		if p := stringField(in[k]); p != "" {
			out = append(out, p)
		}
	}
	for _, k := range []string{"paths", "file_paths"} {
		var ps []string
		if json.Unmarshal(in[k], &ps) == nil {
			out = append(out, ps...)
		}
	}
	if patchTools[tool] {
		for _, k := range []string{"command", "input", "patch", "patchText"} {
			out = append(out, classify.PatchPaths(commandField(in[k]))...)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, v := range in {
		if s := stringField(v); s != "" && len(s) < 4096 && !strings.ContainsAny(s, "\n\r") {
			out = append(out, s)
		}
	}
	return out
}

// parseFor is the Parse shared by the hosts below: it accepts the given hook
// event names ("" always), classifies the call and returns the event with
// CanAsk false and the directory unconfirmed; each adapter then sets what
// its host documents.
func parseFor(agent string, raw []byte, events ...string) (policy.Event, call, bool, error) {
	c, err := parseCall(raw)
	if err != nil {
		return policy.Event{}, c, false, err
	}
	if c.event != "" && !contains(events, c.event) {
		return policy.Event{}, c, false, nil
	}
	if c.tool == "" {
		return policy.Event{}, c, false, errors.New("malformed hook event: no tool name")
	}
	ev, err := c.toEvent(agent)
	return ev, c, err == nil, err
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// exit2 is the block every host in this file understands: exit code 2 with
// the reason on stderr.
func exit2(msg string) Output { return Output{Stderr: msg + "\n", Exit: 2} }

// Cursor is the Cursor hooks adapter (editor and cursor-agent), for
// preToolUse, beforeShellExecution and beforeReadFile.
//
// Contract (cursor.com/docs/hooks, read 2026-10-30): exit 0 with
// {"permission": "allow"|"deny", "user_message", "agent_message"}; exit 2
// blocks; for permission hooks invalid JSON or output that does not match the
// schema blocks. applygate installs the hook with failClosed: true, under
// which a crash, timeout, other non-zero exit or no output also blocks, so
// every decision prints a permission. "ask" is not enforced for preToolUse
// and is ignored in Cursor's run-everything modes (Cursor staff on the
// forum), so CanAsk is false. The per-command directory is
// tool_input.working_directory on preToolUse (documented by example);
// beforeShellExecution's cwd is not documented as per-command, so there the
// directory is unconfirmed.
type Cursor struct{}

func (Cursor) Name() string { return "cursor" }

func (Cursor) Parse(raw []byte) (policy.Event, bool, error) {
	ev, c, ok, err := parseFor("cursor", raw, "preToolUse", "beforeShellExecution", "beforeReadFile")
	if !ok || err != nil {
		return ev, ok, err
	}
	if ev.Kind == policy.KindShell && c.event != "beforeShellExecution" {
		ev.Cwd, ev.DirKnown = workDir(c.input, c.cwd)
	}
	return ev, true, nil
}

func (Cursor) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{Stdout: []byte(`{"permission":"allow"}` + "\n")}
	}
	b, _ := json.Marshal(map[string]any{"permission": "deny", "user_message": d.Message, "agent_message": d.Message})
	return Output{Stdout: append(b, '\n')}
}

func (Cursor) Fail(block bool, msg string) Output {
	if block {
		return exit2(msg)
	}
	return Output{Stdout: []byte(`{"permission":"allow"}` + "\n"), Stderr: msg + "\n"}
}

// Copilot is the GitHub Copilot CLI preToolUse adapter.
//
// Contract (docs.github.com Copilot CLI hooks reference, read 2026-10-30):
// {"permissionDecision": "allow"|"deny"|"ask", "permissionDecisionReason"};
// empty output keeps Copilot's own permission flow, so allow prints nothing.
// Exit 2 denies, and so does any other non-zero exit or a crash; a timeout
// fails open. "ask" shows a prompt in the interactive CLI; autopilot and the
// cloud agent turn it into a deny, so CanAsk is true. The input's cwd is not
// documented as the command's directory, so it is unconfirmed.
type Copilot struct{}

func (Copilot) Name() string { return "copilot" }

func (Copilot) Parse(raw []byte) (policy.Event, bool, error) {
	ev, _, ok, err := parseFor("copilot", raw, "preToolUse", "PreToolUse")
	ev.CanAsk = true
	return ev, ok, err
}

func (Copilot) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	pd := "deny"
	if d.Enforced == policy.Ask {
		pd = "ask"
	}
	b, _ := json.Marshal(map[string]any{"permissionDecision": pd, "permissionDecisionReason": d.Message})
	return Output{Stdout: append(b, '\n')}
}

func (Copilot) Fail(block bool, msg string) Output {
	if block {
		return exit2(msg)
	}
	return Output{Stderr: msg + "\n"}
}

// Gemini is the Gemini CLI BeforeTool adapter.
//
// Contract (google-gemini/gemini-cli docs/hooks and packages/core/src/hooks,
// read 2026-10-30): JSON on stdout governs whatever the exit code, so a deny
// is {"decision": "deny", "reason"}; plain text with exit 0 allows. A
// timeout, exit 1 or a crash fails open. "ask" exists in the source but is
// not documented, so CanAsk is false. run_shell_command runs in
// tool_input.dir_path, relative to the project root, which defaults to the
// project root that the input's cwd names, so the directory is known.
type Gemini struct{}

func (Gemini) Name() string { return "gemini" }

func (Gemini) Parse(raw []byte) (policy.Event, bool, error) {
	ev, c, ok, err := parseFor("gemini", raw, "BeforeTool")
	if !ok || err != nil {
		return ev, ok, err
	}
	ev.DirKnown = c.cwd != ""
	if ev.Kind == policy.KindShell {
		if dir, known := workDir(map[string]json.RawMessage{"workdir": c.input["dir_path"]}, c.cwd); known {
			ev.Cwd = dir
		}
	}
	return ev, true, nil
}

func (Gemini) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	return geminiDeny(d.Message)
}

func geminiDeny(msg string) Output {
	b, _ := json.Marshal(map[string]any{"decision": "deny", "reason": msg})
	return Output{Stdout: append(b, '\n')}
}

func (Gemini) Fail(block bool, msg string) Output {
	if !block {
		return Output{Stderr: msg + "\n"}
	}
	// The JSON deny governs; exit 2 with text on stderr denies as well should
	// the JSON ever not be read.
	o := geminiDeny(msg)
	o.Stderr, o.Exit = msg+"\n", 2
	return o
}

// Windsurf is the Windsurf Cascade adapter (pre_run_command, pre_write_code,
// pre_read_code), the legacy agent of what is now Devin Desktop.
//
// Contract (docs.windsurf.com/windsurf/cascade/hooks, archived 2026-05-16):
// exit 2 blocks with stderr shown to the agent; any other exit proceeds, so a
// crash or missing binary fails open. No JSON output and no ask. Whether
// tool_info.cwd is the command's own directory is not documented.
type Windsurf struct{}

func (Windsurf) Name() string { return "windsurf" }

func (Windsurf) Parse(raw []byte) (policy.Event, bool, error) {
	ev, _, ok, err := parseFor("windsurf", raw, "pre_run_command", "pre_write_code", "pre_read_code")
	return ev, ok, err
}

func (Windsurf) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	return exit2(d.Message)
}

func (Windsurf) Fail(block bool, msg string) Output {
	if block {
		return exit2(msg)
	}
	return Output{Stderr: msg + "\n"}
}

// Devin is the Devin CLI and Devin Local PreToolUse adapter.
//
// Contract (docs.devin.ai/cli/extensibility/hooks, read 2026-10-30): exit 2
// or {"decision": "block"} blocks; other exits, timeouts and unreadable
// output do not. No ask. The shell tool is exec with tool_input.command; the
// input names no directory (DEVIN_PROJECT_DIR is set in the environment), so
// the directory is unconfirmed.
type Devin struct{}

func (Devin) Name() string { return "devin" }

func (Devin) Parse(raw []byte) (policy.Event, bool, error) {
	ev, _, ok, err := parseFor("devin", raw, "PreToolUse")
	if ev.Cwd == "" {
		ev.Cwd = os.Getenv("DEVIN_PROJECT_DIR")
	}
	if ev.Cwd == "" {
		ev.Cwd, _ = os.Getwd()
	}
	return ev, ok, err
}

func (Devin) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	return exit2(d.Message)
}

func (Devin) Fail(block bool, msg string) Output {
	if block {
		return exit2(msg)
	}
	return Output{Stderr: msg + "\n"}
}

// OpenCode is the adapter behind applygate's OpenCode plugin. OpenCode has no
// command hooks, so `applygate hook install --agent opencode` writes a plugin
// that sends each tool call here as {hook_event_name, tool_name, tool_input,
// cwd, session_id} and throws, which blocks the call, unless this exits 0.
//
// Contract (sst/opencode v1.19.5 and v2.2.4 source, read 2026-10-30): the
// shell tool is bash (V1) or shell (V2) with command and an optional workdir
// relative to the instance directory, which the plugin sends as cwd. No ask.
type OpenCode struct{}

func (OpenCode) Name() string { return "opencode" }

func (OpenCode) Parse(raw []byte) (policy.Event, bool, error) {
	ev, c, ok, err := parseFor("opencode", raw, "PreToolUse")
	if !ok || err != nil {
		return ev, ok, err
	}
	if ev.Kind == policy.KindShell {
		ev.Cwd, ev.DirKnown = workDir(c.input, c.cwd)
	}
	return ev, true, nil
}

func (OpenCode) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	return exit2(d.Message)
}

func (OpenCode) Fail(block bool, msg string) Output {
	if block {
		return exit2(msg)
	}
	return Output{Stderr: msg + "\n"}
}

// Cline is the Cline PreToolUse adapter (VS Code extensions and CLI).
//
// Contract (cline/cline v4.1.26 and cli-v3.0.74 source, read 2026-10-31):
// {"cancel": bool, "errorMessage"}. Everything that is not that JSON fails
// open, exit codes included, so every outcome, a fail-closed error too, is
// printed as JSON with exit 0. A cancel ends the whole task, not just the
// tool call. Commands run in the primary workspace root, the first of
// workspaceRoots, unless a legacy command names another root with an
// "@name:" prefix; the directory is then unknown.
type Cline struct{}

func (Cline) Name() string { return "cline" }

var clineRootPrefix = regexp.MustCompile(`^@[^:\s]+:\s*`)

func (Cline) Parse(raw []byte) (policy.Event, bool, error) {
	ev, _, ok, err := parseFor("cline", raw, "PreToolUse")
	if !ok || err != nil {
		return ev, ok, err
	}
	ev.DirKnown = ev.Cwd != ""
	if ev.Kind == policy.KindShell && clineRootPrefix.MatchString(ev.Command) {
		ev.Command = clineRootPrefix.ReplaceAllString(ev.Command, "")
		ev.DirKnown = false
	}
	return ev, true, nil
}

func clineOut(cancel bool, msg string) []byte {
	m := map[string]any{"cancel": cancel}
	if cancel {
		m["errorMessage"] = msg
	}
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

func (Cline) Render(d policy.Decision) Output {
	return Output{Stdout: clineOut(d.Enforced != policy.Allow, d.Message)}
}

func (Cline) Fail(block bool, msg string) Output {
	return Output{Stdout: clineOut(block, msg), Stderr: msg + "\n"}
}
