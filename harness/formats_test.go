package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/hook"
)

// hostFormat turns a pack scenario (a Claude Code tool call) into one host's
// hook payload, following the shapes in
// review/host-research/2026-10-31-hook-contracts.md, and reads that host's
// output back as a verdict. These replays check applygate's adapters against
// the documented contracts; they do not run the hosts.
type hostFormat struct {
	agent string
	// event returns the payload, or nil when the host cannot express the
	// scenario (Devin's file tools are not documented).
	event func(s Scenario, in map[string]any, repo string) map[string]any
	parse func(o hook.Output) (verdict, msg string)
	// dirKnown is whether the payload carries the command's directory; when
	// it does not, applygate judges at the most protected tier under the
	// directory it has, so a verdict may be stricter than expected.
	dirKnown bool
}

func path(in map[string]any) string { s, _ := in["file_path"].(string); return s }

func exit2(o hook.Output, json func() (string, string)) (string, string) {
	switch {
	case o.Exit == 2:
		return "block", o.Stderr
	case o.Exit != 0:
		return "error", o.Stderr
	}
	return json()
}

func jsonOut(o hook.Output, key string, verdicts map[string]string, msgKeys ...string) (string, string) {
	if len(bytes.TrimSpace(o.Stdout)) == 0 {
		return "allow", ""
	}
	var m map[string]any
	if json.Unmarshal(o.Stdout, &m) != nil {
		return "error", string(o.Stdout)
	}
	v, ok := verdicts[fmt.Sprint(m[key])]
	if !ok {
		return "error", string(o.Stdout)
	}
	for _, k := range msgKeys {
		if s, _ := m[k].(string); s != "" {
			return v, s
		}
	}
	return v, ""
}

var hostFormats = []hostFormat{
	{
		agent: "cursor", dirKnown: true,
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			cwd := filepath.Join(repo, s.Cwd)
			ev := map[string]any{"hook_event_name": "preToolUse", "conversation_id": "replay-" + s.ID, "cwd": repo, "workspace_roots": []string{repo}}
			switch s.Tool {
			case "Bash":
				ev["tool_name"], ev["tool_input"] = "Shell", map[string]any{"command": in["command"], "working_directory": cwd}
			case "Read":
				ev["tool_name"], ev["tool_input"] = "Read", map[string]any{"file_path": path(in)}
			default:
				ev["tool_name"], ev["tool_input"] = "Write", map[string]any{"file_path": path(in), "contents": in["content"]}
			}
			return ev
		},
		parse: func(o hook.Output) (string, string) {
			return exit2(o, func() (string, string) {
				return jsonOut(o, "permission", map[string]string{"allow": "allow", "deny": "block", "ask": "ask"}, "agent_message")
			})
		},
	},
	{
		agent: "copilot",
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			tool, args := "bash", map[string]any{"command": in["command"]}
			switch s.Tool {
			case "Read":
				tool, args = "view", map[string]any{"path": path(in)}
			case "Write":
				tool, args = "create", map[string]any{"path": path(in), "file_text": in["content"]}
			case "Edit":
				tool, args = "edit", map[string]any{"path": path(in), "old_str": in["old_string"], "new_str": in["new_string"]}
			}
			b, _ := json.Marshal(args)
			return map[string]any{"sessionId": "replay-" + s.ID, "timestamp": 1, "cwd": filepath.Join(repo, s.Cwd), "toolName": tool, "toolArgs": string(b)}
		},
		parse: func(o hook.Output) (string, string) {
			return exit2(o, func() (string, string) {
				return jsonOut(o, "permissionDecision", map[string]string{"allow": "allow", "deny": "block", "ask": "ask"}, "permissionDecisionReason")
			})
		},
	},
	{
		// The project root is the cwd; the command's directory is dir_path.
		agent: "gemini", dirKnown: true,
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			tool, args := "run_shell_command", map[string]any{"command": in["command"], "dir_path": s.Cwd}
			switch s.Tool {
			case "Read":
				tool, args = "read_file", map[string]any{"file_path": path(in)}
			case "Write":
				tool, args = "write_file", map[string]any{"file_path": path(in), "content": in["content"]}
			case "Edit":
				tool, args = "replace", map[string]any{"file_path": path(in), "old_string": in["old_string"], "new_string": in["new_string"]}
			}
			return map[string]any{"session_id": "replay-" + s.ID, "cwd": repo, "hook_event_name": "BeforeTool", "tool_name": tool, "tool_input": args}
		},
		parse: func(o hook.Output) (string, string) {
			if o.Exit != 0 && o.Exit != 2 {
				return "error", o.Stderr
			}
			return jsonOut(o, "decision", map[string]string{"allow": "allow", "deny": "block", "block": "block"}, "reason")
		},
	},
	{
		agent: "windsurf",
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			action, info := "pre_run_command", map[string]any{"command_line": in["command"], "cwd": filepath.Join(repo, s.Cwd)}
			switch s.Tool {
			case "Read":
				action, info = "pre_read_code", map[string]any{"file_path": path(in)}
			case "Write", "Edit":
				action, info = "pre_write_code", map[string]any{"file_path": path(in), "edits": []any{}}
			}
			return map[string]any{"agent_action_name": action, "trajectory_id": "replay-" + s.ID, "tool_info": info}
		},
		parse: func(o hook.Output) (string, string) { return exit2(o, func() (string, string) { return "allow", "" }) },
	},
	{
		agent: "devin",
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			if s.Tool != "Bash" {
				return nil
			}
			return map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": map[string]any{"command": in["command"]}, "session_id": "replay-" + s.ID}
		},
		parse: func(o hook.Output) (string, string) { return exit2(o, func() (string, string) { return "allow", "" }) },
	},
	{
		// The instance directory is the cwd; the command's directory is the
		// relative workdir, as the OpenCode shell tool takes it.
		agent: "opencode", dirKnown: true,
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			tool, args := "bash", map[string]any{"command": in["command"]}
			if s.Cwd != "" {
				args["workdir"] = s.Cwd
			}
			switch s.Tool {
			case "Read":
				tool, args = "read", map[string]any{"filePath": path(in)}
			case "Write":
				tool, args = "write", map[string]any{"filePath": path(in), "content": in["content"]}
			case "Edit":
				tool, args = "edit", map[string]any{"filePath": path(in), "oldString": in["old_string"], "newString": in["new_string"]}
			}
			return map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args, "cwd": repo, "session_id": "replay-" + s.ID}
		},
		parse: func(o hook.Output) (string, string) { return exit2(o, func() (string, string) { return "allow", "" }) },
	},
	{
		// The VS Code shape, with parameters as strings; shell scenarios
		// alternate between legacy execute_command and next run_commands.
		agent: "cline", dirKnown: true,
		event: func(s Scenario, in map[string]any, repo string) map[string]any {
			tool, params := "execute_command", map[string]string{"command": fmt.Sprint(in["command"]), "requires_approval": "false"}
			switch s.Tool {
			case "Bash":
				if len(s.ID)%2 == 0 {
					b, _ := json.Marshal([]any{in["command"]})
					tool, params = "run_commands", map[string]string{"commands": string(b)}
				}
			case "Read":
				tool, params = "read_file", map[string]string{"path": path(in)}
			case "Write":
				tool, params = "write_to_file", map[string]string{"path": path(in), "content": fmt.Sprint(in["content"])}
			case "Edit":
				tool, params = "replace_in_file", map[string]string{"path": path(in), "diff": "x"}
			}
			return map[string]any{"clineVersion": "4.1.26", "hookName": "PreToolUse", "taskId": "replay-" + s.ID,
				"workspaceRoots": []string{filepath.Join(repo, s.Cwd)}, "preToolUse": map[string]any{"toolName": tool, "parameters": params}}
		},
		parse: func(o hook.Output) (string, string) {
			if o.Exit != 0 {
				return "error", o.Stderr
			}
			return jsonOut(o, "cancel", map[string]string{"false": "allow", "true": "block"}, "errorMessage")
		},
	},
}

var rank = map[string]int{"allow": 0, "ask": 1, "block": 2}

// TestScenarioPackPerHost replays the pack in every host's documented format.
// A host that cannot ask must turn each expected ask into a block; a host
// whose payload carries the command's directory must match the expectation
// exactly; a host whose payload does not may be stricter, never weaker.
// Every dangerous scenario must be caught in every format.
func TestScenarioPackPerHost(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	repo, plans, home, err := Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range hostFormats {
		t.Run(f.agent, func(t *testing.T) {
			a, err := hook.ForAgent(f.agent)
			if err != nil {
				t.Fatal(err)
			}
			host, _ := hook.HostFor(f.agent)
			canAsk := strings.HasPrefix(host.CanAsk, "yes")
			var replayed, stricter, skipped int
			for _, s := range p.Scenarios {
				in := map[string]any{}
				for k, v := range s.ToolInput {
					if str, ok := v.(string); ok {
						v = strings.NewReplacer("{repo}", repo, "{home}", home).Replace(str)
					}
					in[k] = v
				}
				var ev map[string]any
				// MCP calls are replayed in the Claude Code and Codex formats only.
				if !strings.HasPrefix(s.Tool, "mcp__") {
					ev = f.event(s, in, repo)
				}
				if ev == nil {
					skipped++
					continue
				}
				replayed++
				t.Setenv("DEVIN_PROJECT_DIR", filepath.Join(repo, s.Cwd))
				env := map[string]string{"HOME": home, "USER": "agent", "PATH": "/nonexistent"}
				for k, v := range s.Env {
					env[k] = v
				}
				planMap := s.Plans
				opt := hook.Options{NoLog: true, NoGit: true, Env: env, PlanJSON: func(_, _, planfile string) ([]byte, error) {
					fx, ok := planMap[planfile]
					if !ok {
						return nil, fmt.Errorf("no plan fixture for %s", planfile)
					}
					return os.ReadFile(filepath.Join(plans, fx))
				}}
				b, _ := json.Marshal(ev)
				v, msg := f.parse(hook.Run(a, bytes.NewReader(b), opt))
				var want []string
				for _, e := range s.Expect {
					if e == "ask" && (!canAsk || s.PermissionMode == "dontAsk") {
						e = "block"
					}
					want = append(want, e)
				}
				exact := contains(want, v)
				// The reason names the tier, which is the most protected one
				// when the directory is unconfirmed, so the expected mentions
				// are checked only where the payload carries the directory.
				for _, m := range s.MustMention {
					if exact && f.dirKnown && !strings.Contains(msg, m) {
						t.Errorf("%s %s: verdict %s but the message lacks %q:\n%s", s.ID, s.Title, v, m, msg)
					}
				}
				if s.Kind == "dangerous" && v != "block" && v != "ask" {
					t.Errorf("%s %s: dangerous scenario not caught: %s\n%s", s.ID, s.Title, v, msg)
					continue
				}
				if exact {
					continue
				}
				if _, ok := rank[v]; ok && !f.dirKnown && rank[v] > rank[want[len(want)-1]] {
					stricter++
					continue
				}
				t.Errorf("%s %s: got %s, want %v\n%s", s.ID, s.Title, v, want, msg)
			}
			t.Logf("%s: %d replayed, %d skipped (not expressible), %d stricter than expected because the directory is unconfirmed", f.agent, replayed, skipped, stricter)
		})
	}
}

// Every adapter has a replay format here or, for Claude Code and Codex, in
// the Claude Code replay and run.py.
func TestEveryAdapterHasAFormat(t *testing.T) {
	have := map[string]bool{"claude": true, "codex": true}
	for _, f := range hostFormats {
		have[f.agent] = true
	}
	for _, a := range hook.Agents {
		if !have[a] {
			t.Errorf("adapter %s has no replay format", a)
		}
	}
}
