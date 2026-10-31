package hook

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// The payloads below follow the shapes in each host's documentation and
// source (review/host-research/2026-10-31-hook-contracts.md). They test the
// adapters' reading and writing of those shapes, not the hosts themselves,
// which were not run.

func runAdapter(t *testing.T, a Adapter, payload any) Output {
	t.Helper()
	var in string
	if s, ok := payload.(string); ok {
		in = s
	} else {
		b, _ := json.Marshal(payload)
		in = string(b)
	}
	return Run(a, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
}

func jsonField(t *testing.T, o Output, key string) any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(o.Stdout, &m); err != nil {
		t.Fatalf("stdout is not JSON: %q (exit %d, stderr %q)", o.Stdout, o.Exit, o.Stderr)
	}
	return m[key]
}

func TestCursorAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	pre := func(tool string, input map[string]any) map[string]any {
		return map[string]any{"hook_event_name": "preToolUse", "conversation_id": "c1", "tool_name": tool, "tool_input": input, "cwd": root}
	}
	o := runAdapter(t, Cursor{}, pre("Shell", map[string]any{"command": "terraform destroy", "working_directory": filepath.Join(root, "prod")}))
	if jsonField(t, o, "permission") != "deny" || o.Exit != 0 || !strings.Contains(jsonField(t, o, "agent_message").(string), "destroy") {
		t.Fatalf("destroy in prod: %q exit %d", o.Stdout, o.Exit)
	}
	o = runAdapter(t, Cursor{}, pre("Shell", map[string]any{"command": "terraform plan", "working_directory": filepath.Join(root, "dev")}))
	if jsonField(t, o, "permission") != "allow" {
		t.Fatalf("plan in dev: %q", o.Stdout)
	}
	// Under failClosed no output is a failure, so a tool applygate does not
	// inspect still gets an explicit allow.
	o = runAdapter(t, Cursor{}, pre("Task", map[string]any{"prompt": "x"}))
	if jsonField(t, o, "permission") != "allow" {
		t.Fatalf("Task: %q", o.Stdout)
	}
	// The Write tool's fields are not documented: a guard file in an unknown
	// field is still seen.
	o = runAdapter(t, Cursor{}, pre("Write", map[string]any{"target": filepath.Join(root, ".cursor", "hooks.json"), "contents": "{}\n"}))
	if jsonField(t, o, "permission") != "deny" {
		t.Fatalf("Write to hooks.json: %q", o.Stdout)
	}
	// beforeShellExecution: top-level command and cwd.
	o = runAdapter(t, Cursor{}, map[string]any{"hook_event_name": "beforeShellExecution", "command": "terraform destroy -auto-approve", "cwd": filepath.Join(root, "prod")})
	if jsonField(t, o, "permission") != "deny" {
		t.Fatalf("beforeShellExecution: %q", o.Stdout)
	}
	// A command applygate cannot read fails closed, with exit 2.
	o = runAdapter(t, Cursor{}, map[string]any{"hook_event_name": "beforeShellExecution", "cwd": root})
	if o.Exit != 2 {
		t.Fatalf("no command: exit %d stdout %q", o.Exit, o.Stdout)
	}
	if o := runAdapter(t, Cursor{}, "{not json"); o.Exit != 2 {
		t.Fatalf("malformed: exit %d", o.Exit)
	}
}

func TestCopilotAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	ev := func(tool, args string, cwd string) map[string]any {
		return map[string]any{"sessionId": "s", "timestamp": 1, "cwd": cwd, "toolName": tool, "toolArgs": args}
	}
	o := runAdapter(t, Copilot{}, ev("bash", `{"command":"terraform destroy"}`, filepath.Join(root, "prod")))
	if jsonField(t, o, "permissionDecision") != "deny" {
		t.Fatalf("destroy: %q", o.Stdout)
	}
	// Copilot can show a prompt, so an ask stays an ask.
	o = runAdapter(t, Copilot{}, ev("bash", `{"command":"sh -c \"$X\""}`, filepath.Join(root, "prod")))
	if jsonField(t, o, "permissionDecision") != "ask" {
		t.Fatalf("dynamic command: %q", o.Stdout)
	}
	// Allow prints nothing, which keeps Copilot's own permission flow.
	o = runAdapter(t, Copilot{}, ev("bash", `{"command":"terraform plan"}`, filepath.Join(root, "dev")))
	if len(o.Stdout) != 0 || o.Exit != 0 {
		t.Fatalf("plan: %q exit %d", o.Stdout, o.Exit)
	}
	// toolArgs as an object is read too.
	o = runAdapter(t, Copilot{}, map[string]any{"cwd": filepath.Join(root, "prod"), "toolName": "create", "toolArgs": map[string]any{"path": filepath.Join(root, ".github", "hooks", "applygate.json")}})
	if jsonField(t, o, "permissionDecision") != "deny" {
		t.Fatalf("create on the hook file: %q", o.Stdout)
	}
}

func TestGeminiAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	ev := func(input map[string]any) map[string]any {
		return map[string]any{"session_id": "s", "cwd": root, "hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": input}
	}
	o := runAdapter(t, Gemini{}, ev(map[string]any{"command": "terraform destroy", "dir_path": "prod"}))
	if jsonField(t, o, "decision") != "deny" || o.Exit != 0 {
		t.Fatalf("destroy in prod: %q exit %d", o.Stdout, o.Exit)
	}
	o = runAdapter(t, Gemini{}, ev(map[string]any{"command": "terraform plan", "dir_path": "dev"}))
	if len(o.Stdout) != 0 || o.Exit != 0 {
		t.Fatalf("plan: %q exit %d", o.Stdout, o.Exit)
	}
	p, ok, err := Gemini{}.Parse(mustJSON(ev(map[string]any{"command": "ls", "dir_path": "prod"})))
	if err != nil || !ok || p.Cwd != filepath.Join(root, "prod") || !p.DirKnown || p.CanAsk {
		t.Fatalf("parse: %+v ok=%v err=%v", p, ok, err)
	}
	// A failure denies through the JSON and through exit 2 with stderr text.
	o = runAdapter(t, Gemini{}, "{not json")
	if o.Exit != 2 || jsonField(t, o, "decision") != "deny" || o.Stderr == "" {
		t.Fatalf("malformed: %q exit %d stderr %q", o.Stdout, o.Exit, o.Stderr)
	}
	// Other events are not checked.
	if o := runAdapter(t, Gemini{}, map[string]any{"hook_event_name": "AfterTool", "tool_name": "run_shell_command"}); o.Exit != 0 || len(o.Stdout) != 0 {
		t.Fatalf("AfterTool: %q exit %d", o.Stdout, o.Exit)
	}
}

func TestWindsurfAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	o := runAdapter(t, Windsurf{}, map[string]any{"agent_action_name": "pre_run_command", "trajectory_id": "t",
		"tool_info": map[string]any{"command_line": "terraform destroy", "cwd": filepath.Join(root, "prod")}})
	if o.Exit != 2 || !strings.Contains(o.Stderr, "destroy") {
		t.Fatalf("destroy: exit %d stderr %q", o.Exit, o.Stderr)
	}
	o = runAdapter(t, Windsurf{}, map[string]any{"agent_action_name": "pre_write_code",
		"tool_info": map[string]any{"file_path": filepath.Join(root, ".windsurf", "hooks.json"), "edits": []any{}}})
	if o.Exit != 2 {
		t.Fatalf("write to hooks.json: exit %d", o.Exit)
	}
	o = runAdapter(t, Windsurf{}, map[string]any{"agent_action_name": "pre_mcp_tool_use", "tool_info": map[string]any{"mcp_server_name": "x"}})
	if o.Exit != 0 {
		t.Fatalf("mcp: exit %d", o.Exit)
	}
	p, _, _ := Windsurf{}.Parse(mustJSON(map[string]any{"agent_action_name": "pre_run_command", "tool_info": map[string]any{"command_line": "ls", "cwd": "/x"}}))
	if p.DirKnown || p.CanAsk || p.Cwd != "/x" {
		t.Fatalf("parse: %+v", p)
	}
}

func TestDevinAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	t.Setenv("DEVIN_PROJECT_DIR", filepath.Join(root, "prod"))
	o := runAdapter(t, Devin{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": map[string]any{"command": "terraform destroy"}, "session_id": "s"})
	if o.Exit != 2 {
		t.Fatalf("destroy: exit %d stderr %q", o.Exit, o.Stderr)
	}
	p, _, _ := Devin{}.Parse(mustJSON(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": map[string]any{"command": "ls"}}))
	if p.Cwd != filepath.Join(root, "prod") || p.DirKnown || p.Kind != policy.KindShell {
		t.Fatalf("parse: %+v", p)
	}
}

func TestOpenCodeAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	for _, tool := range []string{"bash", "shell"} { // V1, V2
		o := runAdapter(t, OpenCode{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": root, "session_id": "s",
			"tool_input": map[string]any{"command": "terraform destroy", "workdir": "prod"}})
		if o.Exit != 2 {
			t.Fatalf("%s destroy: exit %d", tool, o.Exit)
		}
	}
	for _, in := range []map[string]any{{"filePath": filepath.Join(root, ".opencode", "plugins", "applygate.js")}, {"path": filepath.Join(root, ".applygate.yaml")}} {
		o := runAdapter(t, OpenCode{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "write", "cwd": root, "tool_input": in})
		if o.Exit != 2 {
			t.Fatalf("write %v: exit %d", in, o.Exit)
		}
	}
	p, _, _ := OpenCode{}.Parse(mustJSON(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "bash", "cwd": root, "tool_input": map[string]any{"command": "ls", "workdir": "dev"}}))
	if p.Cwd != filepath.Join(root, "dev") || !p.DirKnown {
		t.Fatalf("parse: %+v", p)
	}
}

func TestClineAdapter(t *testing.T) {
	root := setup(t, "enforce", "auto")
	prod := filepath.Join(root, "prod")
	vscode := func(tool string, params map[string]string) map[string]any {
		return map[string]any{"clineVersion": "4.1.26", "hookName": "PreToolUse", "taskId": "t", "workspaceRoots": []string{prod},
			"preToolUse": map[string]any{"toolName": tool, "parameters": params}}
	}
	cancel := func(o Output) bool {
		t.Helper()
		if o.Exit != 0 {
			t.Fatalf("Cline needs exit 0, got %d", o.Exit)
		}
		return jsonField(t, o, "cancel") == true
	}
	if !cancel(runAdapter(t, Cline{}, vscode("execute_command", map[string]string{"command": "terraform destroy", "requires_approval": "false"}))) {
		t.Fatal("legacy execute_command destroy not cancelled")
	}
	// run_commands parameters arrive JSON-encoded.
	if !cancel(runAdapter(t, Cline{}, vscode("run_commands", map[string]string{"commands": `["echo hi","terraform destroy"]`}))) {
		t.Fatal("run_commands destroy not cancelled")
	}
	if cancel(runAdapter(t, Cline{}, vscode("run_commands", map[string]string{"commands": `["terraform plan"]`}))) {
		t.Fatal("plan cancelled")
	}
	// The CLI's raw input: a bare string, or {commands: [{command, args}]}.
	cli := func(input any) map[string]any {
		return map[string]any{"hookName": "tool_call", "workspaceRoots": []string{prod}, "tool_call": map[string]any{"id": "1", "name": "run_commands", "input": input}}
	}
	if !cancel(runAdapter(t, Cline{}, cli("terraform destroy"))) {
		t.Fatal("CLI bare string not cancelled")
	}
	if !cancel(runAdapter(t, Cline{}, cli(map[string]any{"commands": []any{map[string]any{"command": "terraform", "args": []string{"destroy"}}}}))) {
		t.Fatal("CLI {command, args} not cancelled")
	}
	// A shell call whose command applygate cannot read is cancelled.
	if !cancel(runAdapter(t, Cline{}, vscode("run_commands", map[string]string{}))) {
		t.Fatal("unreadable command not cancelled")
	}
	if !cancel(runAdapter(t, Cline{}, "{not json")) {
		t.Fatal("malformed input not cancelled")
	}
	if cancel(runAdapter(t, Cline{}, vscode("use_mcp_tool", map[string]string{"server_name": "x"}))) {
		t.Fatal("an uninspected tool was cancelled")
	}
	p, _, _ := Cline{}.Parse(mustJSON(vscode("execute_command", map[string]string{"command": "@infra: terraform plan"})))
	if p.Command != "terraform plan" || p.DirKnown {
		t.Fatalf("@root prefix: %+v", p)
	}
}

// A Claude Code hook loaded by Cursor or Devin from .claude/settings.json
// receives their tool names; a shell command must not pass as "other".
func TestClaudeHookCrossLoaded(t *testing.T) {
	root := setup(t, "enforce", "auto")
	for _, c := range []struct {
		tool  string
		input map[string]any
	}{
		{"Shell", map[string]any{"command": "terraform destroy", "working_directory": filepath.Join(root, "prod")}},
		{"exec", map[string]any{"command": "terraform destroy"}},
	} {
		in := event(c.tool, filepath.Join(root, "prod"), c.input)
		o := Run(Claude{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
		if o.Exit != 2 || !strings.Contains(o.Stderr, "destroy") {
			t.Fatalf("%s: exit %d stdout %q stderr %q", c.tool, o.Exit, o.Stdout, o.Stderr)
		}
		ev, ok, err := Claude{}.Parse([]byte(in))
		if err != nil || !ok || ev.CanAsk || ev.Kind != policy.KindShell {
			t.Fatalf("%s parse: %+v ok=%v err=%v", c.tool, ev, ok, err)
		}
	}
	// Claude Code's own Bash keeps its JSON deny.
	o := Run(Claude{}, strings.NewReader(event("Bash", filepath.Join(root, "prod"), map[string]any{"command": "terraform destroy"})), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	if decision(t, o) != "deny" {
		t.Fatalf("Bash: %s", decision(t, o))
	}
}

func TestCanAskAndDirKnownPerHost(t *testing.T) {
	shell := map[string]any{"command": "ls"}
	cases := []struct {
		a              Adapter
		payload        map[string]any
		canAsk, dirKno bool
	}{
		{Cursor{}, map[string]any{"hook_event_name": "preToolUse", "tool_name": "Shell", "cwd": "/r", "tool_input": map[string]any{"command": "ls", "working_directory": "/r/a"}}, false, true},
		{Cursor{}, map[string]any{"hook_event_name": "beforeShellExecution", "command": "ls", "cwd": "/r"}, false, false},
		{Copilot{}, map[string]any{"toolName": "bash", "toolArgs": `{"command":"ls"}`, "cwd": "/r"}, true, false},
		{Gemini{}, map[string]any{"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "cwd": "/r", "tool_input": shell}, false, true},
		{Windsurf{}, map[string]any{"agent_action_name": "pre_run_command", "tool_info": map[string]any{"command_line": "ls", "cwd": "/r"}}, false, false},
		{Devin{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": shell}, false, false},
		{OpenCode{}, map[string]any{"hook_event_name": "PreToolUse", "tool_name": "bash", "cwd": "/r", "tool_input": shell}, false, false},
		{Cline{}, map[string]any{"hookName": "PreToolUse", "workspaceRoots": []string{"/r"}, "preToolUse": map[string]any{"toolName": "execute_command", "parameters": map[string]string{"command": "ls"}}}, false, true},
	}
	for _, c := range cases {
		ev, ok, err := c.a.Parse(mustJSON(c.payload))
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", c.a.Name(), ok, err)
		}
		if ev.CanAsk != c.canAsk || ev.DirKnown != c.dirKno || ev.Agent != c.a.Name() || ev.Kind != policy.KindShell {
			t.Errorf("%s %v: got %+v", c.a.Name(), c.payload["hook_event_name"], ev)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
