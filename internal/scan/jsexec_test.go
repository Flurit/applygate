package scan

import (
	"reflect"
	"strings"
	"testing"
)

func TestJSExecCommands(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []jsCommand
	}{
		{"cmd and other arguments",
			`const r = await tools.exec_command({cmd:"pwd && rg --files -g 'AGENTS.md' .", max_output_tokens:2000}); text(r.output);`,
			[]jsCommand{{cmd: "pwd && rg --files -g 'AGENTS.md' ."}}},
		{"workdir after cmd",
			`const r = await tools.exec_command({cmd:"terraform init && terraform destroy -auto-approve", workdir:"/tmp/sb/examples/simple", yield_time_ms:30000}); text(` + "`exit_code=${r.exit_code}`" + `);`,
			[]jsCommand{{cmd: "terraform init && terraform destroy -auto-approve", workdir: "/tmp/sb/examples/simple"}}},
		{"escapes, quoted keys and spacing",
			`tools.exec_command( { "workdir" : '/r', timeout: f(1, {a: "}"}), cmd : "printf \"a\\tb\\n\" \u0041\x42\u{43}" } )`,
			[]jsCommand{{cmd: "printf \"a\\tb\\n\" ABC", workdir: "/r"}}},
		{"a template without substitutions, and two calls",
			"await tools.exec_command({cmd:`ls -la`}); await tools.exec_command({cmd:'git status'});",
			[]jsCommand{{cmd: "ls -la"}, {cmd: "git status"}}},
		{"a value that is not a plain literal is left out",
			"tools.exec_command({cmd: c}); tools.exec_command({cmd:`rm ${f}`}); tools.exec_command({cmd:\"a\" + b}); tools.exec_command({cmd}); tools.exec_command(args); tools.exec_command({cmd:\"unterminated",
			nil},
		{"a workdir that is not a literal drops the call, since its directory is not known",
			`tools.exec_command({cmd:"terraform destroy", workdir: d})`,
			nil},
		{"other tools are not commands",
			`await tools.apply_patch({input:"*** Begin Patch"}); await tools.web__run({q:"tools.exec_command"});`,
			nil},
	} {
		if got := jsExecCommands(tc.src); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// A `codex exec` session can hold the model's JavaScript and no completed
// command record.
const codexJSOnly = `{"timestamp":"2026-10-30T11:45:00.000Z","type":"session_meta","payload":{"id":"js1","cwd":"/repo"}}
{"timestamp":"2026-10-30T11:45:01.000Z","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call_a","input":"const r = await tools.exec_command({cmd:\"terraform destroy -auto-approve\", workdir:\"examples/simple\"}); text(r.output);"}}
{"timestamp":"2026-10-30T11:45:02.000Z","type":"response_item","payload":{"type":"custom_tool_call","name":"exec","call_id":"call_b","input":"await tools.exec_command({cmd:\"ls\"}); await tools.exec_command({cmd:\"pwd\", workdir:\"/elsewhere\"});"}}
{"timestamp":"2026-10-30T11:45:03.000Z","type":"response_item","payload":{"type":"custom_tool_call","name":"other","call_id":"call_c","input":"tools.exec_command({cmd:\"not an exec call\"})"}}
`

func TestReadCodexJavaScriptCalls(t *testing.T) {
	got := collect(func(emit func(Call)) { ReadCodex(strings.NewReader(codexJSOnly), emit) })
	if len(got) != 3 {
		t.Fatalf("got %d calls, want 3: %+v", len(got), got)
	}
	c := got[0]
	if c.Tool != "exec_command" || command(t, c) != "terraform destroy -auto-approve" || c.Cwd != "/repo" || c.Ran != "/repo/examples/simple" || c.ID != "call_a:0" {
		t.Errorf("first call: %+v %s", c, c.Input)
	}
	if got[1].Ran != "" || got[1].Dir() != "/repo" || got[2].Ran != "/elsewhere" || got[2].ID != "call_b:1" {
		t.Errorf("directories: %+v %+v", got[1], got[2])
	}
	// With completed command records in the file, the JavaScript is the
	// same commands again and is not read.
	both := codexJSOnly + `{"timestamp":"2026-10-30T11:45:04.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-1","command":["/bin/zsh","-lc","ls"],"cwd":"/repo"}}}` + "\n"
	got = collect(func(emit func(Call)) { ReadCodex(strings.NewReader(both), emit) })
	if len(got) != 1 || got[0].ID != "exec-1" {
		t.Errorf("with completed items: %+v", got)
	}
}
