// Package hook adapts agent hook events to policy events and renders
// decisions in each agent's output format.
package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/policy"
)

// Output is what the hook process writes and its exit code.
type Output struct {
	Stdout []byte
	Stderr string
	Exit   int
	// LogPath is the decision log the run appended to ("" when logging was
	// off), so the caller can do after-decision work such as telemetry.
	LogPath string
}

// Adapter converts one agent's hook format.
type Adapter interface {
	Name() string
	// Parse returns the event, or ok=false when the event is not one the
	// applygate checks (for example another hook event); such events are
	// allowed without output.
	Parse(raw []byte) (ev policy.Event, ok bool, err error)
	Render(d policy.Decision) Output
	// Fail renders an internal-error outcome: block or allow.
	Fail(block bool, msg string) Output
}

// ForAgent returns the adapter for an agent name.
func ForAgent(name string) (Adapter, error) {
	switch name {
	case "claude", "claude-code":
		return Claude{}, nil
	case "codex":
		return Codex{}, nil
	case "cursor":
		return Cursor{}, nil
	case "copilot":
		return Copilot{}, nil
	case "gemini":
		return Gemini{}, nil
	case "windsurf":
		return Windsurf{}, nil
	case "devin":
		return Devin{}, nil
	case "opencode":
		return OpenCode{}, nil
	case "cline":
		return Cline{}, nil
	}
	return nil, fmt.Errorf("unknown agent %q (supported: %s)", name, strings.Join(Agents, ", "))
}

// Agents are the adapter names, in the order `applygate hosts` lists them.
var Agents = []string{"claude", "codex", "cursor", "copilot", "gemini", "windsurf", "devin", "opencode", "cline"}

// eventRenderer is implemented by an adapter whose output depends on the
// event as well as the decision.
type eventRenderer interface {
	RenderEvent(ev policy.Event, d policy.Decision) Output
}

// passer is implemented by an adapter whose host needs output even for an
// event applygate does not check (Cursor under failClosed, Cline).
type passer interface{ Pass() Output }

func (Cursor) Pass() Output { return Output{Stdout: []byte(`{"permission":"allow"}` + "\n")} }
func (Cline) Pass() Output  { return Output{Stdout: clineOut(false, "")} }

type hookInput struct {
	SessionID      string          `json:"session_id"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
}

// Claude is the Claude Code PreToolUse adapter.
//
// Output contract (code.claude.com/docs/en/hooks, read 2026-10-28):
// allow returns nothing, because a hook "allow" would skip Claude Code's own
// permission prompt; ask and block return hookSpecificOutput with
// permissionDecision "ask" or "deny". Internal errors that must block exit 2
// with the reason on stderr, which blocks regardless of JSON parsing.
//
// Working directory (same docs, read 2026-10-29): the Bash tool input carries
// command, description, timeout and run_in_background only, no directory, and
// the top-level cwd "follows Claude": it is the shell's directory at the time
// of the call, after any earlier cd. So cwd is the directory the command runs
// in and nothing else needs to be read.
type Claude struct{}

func (Claude) Name() string { return "claude" }

func (Claude) Parse(raw []byte) (policy.Event, bool, error) {
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return policy.Event{}, false, fmt.Errorf("malformed hook event: %w", err)
	}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return policy.Event{}, false, nil
	}
	if in.ToolName == "" {
		return policy.Event{}, false, errors.New("malformed hook event: no tool_name")
	}
	// Claude Code 2.1.312 shows a permission prompt for a hook "ask" even in
	// bypassPermissions (live test T3.2), so only dontAsk converts ask to
	// block. This is observed, not documented; rerun T3.2 on new versions
	// (see docs/limits.md).
	ev := policy.Event{Agent: "claude", Tool: in.ToolName, Cwd: in.Cwd, Session: in.SessionID, PermissionMode: in.PermissionMode,
		CanAsk: in.PermissionMode != "dontAsk", DirKnown: true}
	var ti struct {
		Command      string `json:"command"`
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
	}
	if len(in.ToolInput) > 0 {
		if err := json.Unmarshal(in.ToolInput, &ti); err != nil {
			return policy.Event{}, false, fmt.Errorf("malformed tool_input: %w", err)
		}
	}
	switch in.ToolName {
	case "Bash":
		ev.Kind, ev.Command = policy.KindShell, ti.Command
	case "Write", "Edit", "MultiEdit":
		ev.Kind, ev.Paths = policy.KindWrite, nonEmpty(ti.FilePath)
	case "NotebookEdit":
		ev.Kind, ev.Paths = policy.KindWrite, nonEmpty(ti.NotebookPath, ti.FilePath)
	case "Read", "Grep", "Glob":
		ev.Kind, ev.Paths = policy.KindRead, nonEmpty(ti.FilePath, ti.Path)
	default:
		// Cursor, Copilot CLI and Devin also load hooks from
		// .claude/settings.json and send their own tool names (Shell,
		// exec, ...). Such a call is judged like that host's own: no ask,
		// the directory confirmed only by a working_directory field, and a
		// block rendered as exit 2, which all of them honour.
		c := call{tool: in.ToolName, input: argObject(in.ToolInput), cwd: in.Cwd, session: in.SessionID, mode: in.PermissionMode}
		if c.input == nil {
			c.input = map[string]json.RawMessage{}
		}
		fev, err := c.toEvent("claude")
		if err != nil {
			return policy.Event{}, false, err
		}
		if fev.Kind == policy.KindShell {
			fev.Cwd, fev.DirKnown = workDir(c.input, in.Cwd)
		}
		return fev, true, nil
	}
	return ev, true, nil
}

// claudeTools are the Claude Code tools the Claude adapter judges natively.
var claudeTools = toolSet("Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep", "Glob")

// RenderEvent blocks a call from another host that loaded the Claude hook
// with exit 2, since that host may not read Claude Code's JSON.
func (c Claude) RenderEvent(ev policy.Event, d policy.Decision) Output {
	if d.Enforced == policy.Block && !claudeTools[ev.Tool] {
		return exit2(d.Message)
	}
	return c.Render(d)
}

func (Claude) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	pd := "deny"
	if d.Enforced == policy.Ask {
		pd = "ask"
	}
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "permissionDecision": pd, "permissionDecisionReason": d.Message,
	}})
	return Output{Stdout: append(b, '\n')}
}

func (Claude) Fail(block bool, msg string) Output {
	if !block {
		return Output{Stderr: msg + "\n"}
	}
	return Output{Stderr: msg + "\n", Exit: 2}
}

// Codex is the OpenAI Codex CLI PreToolUse adapter.
//
// Contract (learn.chatgpt.com/docs/hooks, read 2026-10-28): deny with
// hookSpecificOutput.permissionDecision "deny" or exit 2. Codex parses but
// does not support "ask" (it fails the hook and continues the tool call), so
// CanAsk is false and every ask is enforced as a block.
//
// Working directory (openai/codex at rust-v0.165.0, read 2026-10-29): the
// model's exec_command call takes a workdir and Codex runs the command there,
// but the hook input is built from the call as {"command": cmd} only
// (core/src/tools/handlers/unified_exec/exec_command.rs, pre_tool_use_payload)
// and the top-level cwd is the turn's directory (core/src/hook_runtime.rs,
// tool_hook_cwd), so the workdir does not reach the hook; a captured input is
// in review/agent-trial/results/2026-10-29-codex-hook-payload. The adapter reads
// tool_input.workdir, working_directory or cwd when a Codex version sends one
// and otherwise falls back to the top-level cwd; see docs/limits.md.
// apply_patch paths are relative to the turn's cwd in Codex as well
// (handlers/apply_patch.rs), so only shell commands use the field.
type Codex struct{}

func (Codex) Name() string { return "codex" }

func (Codex) Parse(raw []byte) (policy.Event, bool, error) {
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return policy.Event{}, false, fmt.Errorf("malformed hook event: %w", err)
	}
	if in.HookEventName != "" && in.HookEventName != "PreToolUse" {
		return policy.Event{}, false, nil
	}
	if in.ToolName == "" {
		return policy.Event{}, false, errors.New("malformed hook event: no tool_name")
	}
	// File edits are resolved against the turn's cwd by Codex itself, so
	// their directory is known; a shell command's is known only when the
	// event names its workdir.
	ev := policy.Event{Agent: "codex", Tool: in.ToolName, Cwd: in.Cwd, Session: in.SessionID, PermissionMode: in.PermissionMode, CanAsk: false, DirKnown: true}
	var ti map[string]json.RawMessage
	if len(in.ToolInput) > 0 {
		if err := json.Unmarshal(in.ToolInput, &ti); err != nil {
			return policy.Event{}, false, fmt.Errorf("malformed tool_input: %w", err)
		}
	}
	cmd := commandField(ti["command"])
	if cmd == "" {
		cmd = commandField(ti["cmd"])
	}
	switch in.ToolName {
	case "Bash", "shell", "local_shell", "exec_command", "unified_exec", "container.exec":
		ev.Kind, ev.Command = policy.KindShell, cmd
		ev.Cwd, ev.DirKnown = workDir(ti, in.Cwd)
	case "apply_patch", "Edit", "Write":
		patch := cmd
		if patch == "" {
			patch = commandField(ti["input"])
		}
		ev.Kind, ev.Paths = policy.KindWrite, classify.PatchPaths(patch)
		// A Claude-style event shape (file_path) replayed in Codex format,
		// or a future Codex edit tool that names the file directly.
		for _, k := range []string{"file_path", "path"} {
			if p := commandField(ti[k]); p != "" {
				ev.Paths = append(ev.Paths, p)
			}
		}
	default:
		ev.Kind = policy.KindOther
	}
	return ev, true, nil
}

// workDir returns the directory a Codex shell command runs in: the first of
// tool_input.workdir, working_directory and cwd that is a non-empty string,
// resolved against the event's top-level cwd when relative, or that cwd when
// none is present. known is false in the fallback case: the top-level cwd is
// then the session root, not necessarily where the command runs, and the
// policy judges the command at the most protected tier under it.
func workDir(ti map[string]json.RawMessage, cwd string) (dir string, known bool) {
	for _, k := range []string{"workdir", "working_directory", "cwd"} {
		wd := stringField(ti[k])
		if wd == "" {
			continue
		}
		if !filepath.IsAbs(wd) && cwd != "" {
			wd = filepath.Join(cwd, wd)
		}
		return filepath.Clean(wd), true
	}
	return cwd, false
}

// stringField accepts a JSON string only.
func stringField(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// commandField accepts a string or an argv array.
func commandField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		q := make([]string, len(argv))
		for i, a := range argv {
			q[i] = shellQuote(a)
		}
		return strings.Join(q, " ")
	}
	return ""
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:,@%+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (Codex) Render(d policy.Decision) Output {
	if d.Enforced == policy.Allow {
		return Output{}
	}
	b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": d.Message,
	}})
	return Output{Stdout: append(b, '\n')}
}

func (Codex) Fail(block bool, msg string) Output {
	if !block {
		return Output{Stderr: msg + "\n"}
	}
	return Output{Stderr: msg + "\n", Exit: 2}
}

func nonEmpty(ss ...string) []string {
	for _, s := range ss {
		if s != "" {
			return []string{s}
		}
	}
	return nil
}
