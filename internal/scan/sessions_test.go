package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func collect(read func(func(Call))) []Call {
	var out []Call
	read(func(c Call) { out = append(out, c) })
	return out
}

func command(t *testing.T, c Call) string {
	t.Helper()
	var in struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(c.Input, &in); err != nil {
		t.Fatalf("input %s: %v", c.Input, err)
	}
	return in.Command
}

// The line shapes below are the ones Claude Code 2.1.3xx writes: only the
// keys the reader uses are kept.
const claudeSession = `{"type":"user","cwd":"/repo","message":{"content":"mentions \"tool_use\" in text"}}
{"type":"assistant","cwd":"/repo/envs/prod","sessionId":"s1","timestamp":"2026-11-10T09:00:00.000Z","message":{"content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"terraform destroy -auto-approve"}},{"type":"tool_use","id":"toolu_2","name":"Edit","input":{"file_path":"/repo/main.tf","old_string":"a","new_string":"b"}}]}}
not json at all "tool_use"
{"type":"assistant","cwd":"/repo","sessionId":"s1","timestamp":"bad time","message":{"content":[{"type":"tool_use","id":"toolu_3","name":"mcp__aws__call_aws","input":{"cli_command":"aws s3 ls"}}]}}
`

func TestReadClaude(t *testing.T) {
	got := collect(func(emit func(Call)) { ReadClaude(strings.NewReader(claudeSession), emit) })
	if len(got) != 3 {
		t.Fatalf("got %d calls, want 3: %+v", len(got), got)
	}
	c := got[0]
	if c.Agent != "claude" || c.Session != "s1" || c.ID != "toolu_1" || c.Tool != "Bash" || c.Cwd != "/repo/envs/prod" || c.Dir() != "/repo/envs/prod" {
		t.Errorf("first call: %+v", c)
	}
	if command(t, c) != "terraform destroy -auto-approve" {
		t.Errorf("command: %s", c.Input)
	}
	if want := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC); !c.Time.Equal(want) {
		t.Errorf("time %v, want %v", c.Time, want)
	}
	if got[1].Tool != "Edit" || got[2].Tool != "mcp__aws__call_aws" || !got[2].Time.IsZero() {
		t.Errorf("other calls: %+v %+v", got[1], got[2])
	}
	// The hook input is what Claude Code's PreToolUse hook is sent.
	var in map[string]json.RawMessage
	if err := json.Unmarshal(c.HookInput(), &in); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"tool_name": `"Bash"`, "cwd": `"/repo/envs/prod"`, "hook_event_name": `"PreToolUse"`, "session_id": `"s1"`} {
		if string(in[k]) != want {
			t.Errorf("%s = %s, want %s", k, in[k], want)
		}
	}
}

func TestReadClaudeSkipsALineOverTheLimit(t *testing.T) {
	long := `{"type":"assistant","cwd":"/r","message":{"content":[{"type":"tool_use","id":"big","name":"Bash","input":{"command":"` + strings.Repeat("x", maxLine) + `"}}]}}`
	after := `{"type":"assistant","cwd":"/r","message":{"content":[{"type":"tool_use","id":"small","name":"Bash","input":{"command":"ls"}}]}}`
	got := collect(func(emit func(Call)) { ReadClaude(strings.NewReader(long+"\n"+after+"\n"), emit) })
	if len(got) != 1 || got[0].ID != "small" {
		t.Fatalf("got %d calls: want only the one after the long line", len(got))
	}
}

// Codex 0.166.0: a completed command carries its argv and the directory it
// ran in; the turn's directory is in turn_context.
const codexItems = `{"timestamp":"2026-11-11T10:00:00.000Z","type":"session_meta","payload":{"id":"c1","cwd":"/repo"}}
{"timestamp":"2026-11-11T10:00:01.000Z","type":"turn_context","payload":{"cwd":"/repo"}}
{"timestamp":"2026-11-11T10:00:02.000Z","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","input":"const r = await tools.exec_command({cmd:\"terraform destroy\"});"}}
{"timestamp":"2026-11-11T10:00:03.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-1","command":["/bin/zsh","-lc","terraform destroy -auto-approve"],"cwd":"file:///repo/examples/simple","status":"completed"}}}
{"timestamp":"2026-11-11T10:00:04.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"FileChange","id":"fc-1","changes":{"/repo/b.tf":{"type":"update"},"/repo/a.tf":{"type":"add"}},"status":"completed"}}}
{"timestamp":"2026-11-11T10:00:05.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"McpToolCall","id":"mcp-1","server":"aws","tool":"call_aws","arguments":{"cli_command":"aws s3 rb s3://b"}}}}
{"timestamp":"2026-11-11T10:00:06.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"AgentMessage","id":"m-1","content":"done"}}}
{"timestamp":"2026-11-11T10:00:07.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_9","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls\"]}"}}
`

func TestReadCodexCompletedItems(t *testing.T) {
	got := collect(func(emit func(Call)) { ReadCodex(strings.NewReader(codexItems), emit) })
	if len(got) != 4 {
		t.Fatalf("got %d calls, want 4 (the function call is the same command as a completed item): %+v", len(got), got)
	}
	c := got[0]
	if c.Agent != "codex" || c.Session != "c1" || c.Tool != "exec_command" || command(t, c) != "terraform destroy -auto-approve" {
		t.Errorf("command call: %+v %s", c, c.Input)
	}
	// The hook is told the turn's directory; the command ran elsewhere.
	if c.Cwd != "/repo" || c.Ran != "/repo/examples/simple" || c.Dir() != "/repo/examples/simple" {
		t.Errorf("directories: cwd %q ran %q", c.Cwd, c.Ran)
	}
	if strings.Contains(string(c.Input), "workdir") {
		t.Errorf("the Codex hook gets no workdir, so the replayed input has none: %s", c.Input)
	}
	// One call per changed file, in a fixed order.
	if got[1].Tool != "apply_patch" || string(got[1].Input) != `{"file_path":"/repo/a.tf"}` || string(got[2].Input) != `{"file_path":"/repo/b.tf"}` {
		t.Errorf("file changes: %s %s", got[1].Input, got[2].Input)
	}
	if got[3].Tool != "mcp__aws__call_aws" || string(got[3].Input) != `{"cli_command":"aws s3 rb s3://b"}` {
		t.Errorf("mcp call: %+v %s", got[3], got[3].Input)
	}
}

// Older Codex versions recorded the model's function call and no completed
// item.
const codexFunctionCalls = `{"timestamp":"2026-06-01T10:00:00.000Z","type":"session_meta","payload":{"id":"old","cwd":"/repo"}}
{"timestamp":"2026-06-01T10:00:01.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\"command\":[\"bash\",\"-lc\",\"kubectl delete ns prod\"],\"workdir\":\"/repo/k8s\"}"}}
{"timestamp":"2026-06-01T10:00:02.000Z","type":"response_item","payload":{"type":"function_call","name":"update_plan","call_id":"call_2","arguments":"{\"plan\":[]}"}}
{"timestamp":"2026-06-01T10:00:03.000Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"call_3","action":{"type":"exec","command":["git","commit","-m","a b"],"working_directory":"/repo"}}}
`

func TestReadCodexFunctionCalls(t *testing.T) {
	got := collect(func(emit func(Call)) { ReadCodex(strings.NewReader(codexFunctionCalls), emit) })
	if len(got) != 2 {
		t.Fatalf("got %d calls, want 2: %+v", len(got), got)
	}
	if got[0].Tool != "shell" || string(got[0].Input) != `{"command":"kubectl delete ns prod","workdir":"/repo/k8s"}` {
		t.Errorf("shell call: %s", got[0].Input)
	}
	if got[1].Tool != "local_shell" || command(t, got[1]) != "git commit -m 'a b'" || got[1].Ran != "/repo" {
		t.Errorf("local shell call: %+v %s", got[1], got[1].Input)
	}
}

func TestWalkWindowDuplicatesAndCompressedFiles(t *testing.T) {
	home := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	line := func(id, ts string) string {
		return `{"type":"assistant","cwd":"/r","timestamp":"` + ts + `","message":{"content":[{"type":"tool_use","id":"` + id + `","name":"Bash","input":{"command":"ls"}}]}}` + "\n"
	}
	now := time.Now().UTC()
	recent, old := now.Add(-time.Hour).Format(time.RFC3339), now.AddDate(0, 0, -90).Format(time.RFC3339)
	write(".claude/projects/p/a.jsonl", line("t1", recent)+line("t2", old))
	// A resumed session repeats the calls of the one it continues.
	write(".claude/projects/p/b.jsonl", line("t1", recent)+line("t3", recent))
	write(".claude/projects/p/a/subagents/agent-1.jsonl", line("t4", recent))
	stale := write(".claude/projects/p/stale.jsonl", line("t5", recent))
	past := now.AddDate(0, 0, -60)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatal(err)
	}
	// A Codex session from June: its file is recent, its calls are not.
	write(".codex/sessions/2026/06/01/rollout-x.jsonl", codexFunctionCalls)
	write(".codex/archived_sessions/rollout-y.jsonl.zst", "compressed")
	write(".claude/projects/p/notes.txt", "not a session")

	var ids []string
	st := Walk(Sources(home, nil), now.AddDate(0, 0, -30), func(c Call) { ids = append(ids, c.ID) })
	// Files are read in name order: the subagent directory a/ before a.jsonl.
	if got := strings.Join(ids, " "); got != "t4 t1 t3" {
		t.Errorf("claude and codex calls in the window: %q", got)
	}
	if st.Sessions["claude"] != 3 || st.Sessions["codex"] != 0 || st.Calls != 3 || st.Compressed != 1 {
		t.Errorf("stats: %+v", st)
	}
	// With no window every call is read, the old ones and Codex's included.
	n := 0
	st = Walk(Sources(home, nil), time.Time{}, func(Call) { n++ })
	if n != 5+2 || st.Sessions["codex"] != 1 {
		t.Errorf("all calls: %d, stats %+v", n, st)
	}
	// CODEX_HOME and CLAUDE_CONFIG_DIR move the session directories.
	n = 0
	Walk(Sources(home, map[string]string{"CODEX_HOME": filepath.Join(home, "elsewhere"), "CLAUDE_CONFIG_DIR": filepath.Join(home, "elsewhere")}), time.Time{}, func(Call) { n++ })
	if n != 0 {
		t.Errorf("moved config directories still read %d calls", n)
	}
}
