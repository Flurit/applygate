package mcpmap

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testTable(t *testing.T) *Table {
	t.Helper()
	var tb Table
	src := `{"servers": [
	 {"name": "shellish", "source": "test", "tools": [
	  {"names": ["run_command"], "requires": ["command"], "shell": "command", "dir": "cwd"}]},
	 {"name": "tf", "source": "test", "tools": [
	  {"names": ["ecs_resource_management"], "requires": ["api_operation"], "cases": [{"command": "aws ecs {api_operation|kebab}"}]},
	  {"names": ["ExecuteTerraformCommand"], "dir": "working_directory", "cases": [
	    {"when": {"command": ["apply", "destroy"]}, "command": "terraform {command} -auto-approve {extra...}"},
	    {"when": {"command": ["init", "plan", "validate"]}, "command": "terraform {command}"}]}]}
	]}`
	if err := json.Unmarshal([]byte(src), &tb); err != nil {
		t.Fatal(err)
	}
	if err := tb.validate(); err != nil {
		t.Fatal(err)
	}
	return &tb
}

func TestTranslate(t *testing.T) {
	tb := testTable(t)
	cases := []struct {
		tool, args, cwd string
		ok              bool
		cmd, dir        string
	}{
		{"mcp__dc__run_command", `{"command": "aws s3 rb s3://x --force", "cwd": "envs/prod"}`, "/r", true, "aws s3 rb s3://x --force", ""},
		{"mcp__dc__run_command", `{"command": ["aws s3 ls", "aws s3 rb s3://x"], "cwd": "/r/envs/prod"}`, "/r", true, "aws s3 ls\naws s3 rb s3://x", "/r/envs/prod"},
		{"mcp__my__server__run_command", `{"command": "ls"}`, "/r", true, "ls", ""},
		{"mcp__other__run_command", `{"cmd": "ls"}`, "/r", false, "", ""},
		{"mcp__tf__ExecuteTerraformCommand", `{"command": "destroy", "working_directory": "/r/prod", "extra": ["-var", "a=b c"]}`, "/r", true, "terraform destroy -auto-approve -var 'a=b c'", "/r/prod"},
		{"mcp__tf__ExecuteTerraformCommand", `{"command": "PLAN"}`, "/r", true, "terraform PLAN", ""},
		{"mcp__tf__ExecuteTerraformCommand", `{"command": "state-rm"}`, "/r", true, "MCP tool ExecuteTerraformCommand: its arguments match no known form", ""},
		{"mcp__tf__ExecuteTerraformCommand", `[1]`, "/r", true, "its arguments are not a JSON object", ""},
		{"mcp__github__create_issue", `{}`, "/r", false, "", ""},
		{"mcp__ecs__ecs_resource_management", `{"api_operation": "DeleteCluster", "api_params": {}}`, "/r", true, "aws ecs delete-cluster", ""},
	}
	for _, c := range cases {
		r, ok := tb.Translate(c.tool, json.RawMessage(c.args), c.cwd)
		if ok != c.ok || (ok && (!strings.Contains(r.Command, c.cmd) || r.Dir != c.dir)) {
			t.Errorf("%s %s: got %v %q dir %q", c.tool, c.args, ok, r.Command, r.Dir)
		}
	}
}

func TestBuiltinRulesValid(t *testing.T) {
	if err := Rules().validate(); err != nil {
		t.Fatal(err)
	}
}

// Every server and tool in the table is listed in docs/mcp.md.
func TestDocsListEveryServer(t *testing.T) {
	b, err := os.ReadFile("../../docs/mcp.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, s := range Rules().Servers {
		for _, tl := range s.Tools {
			for _, n := range tl.Names {
				if !strings.Contains(doc, "`"+n+"`") {
					t.Errorf("docs/mcp.md does not list %s (%s)", n, s.Name)
				}
			}
		}
	}
}
