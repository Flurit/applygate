package mcpmap

import (
	"strings"
	"testing"
)

func tr(t *testing.T, tool, args string) (Result, bool) {
	t.Helper()
	return Rules().Translate("mcp__x__"+tool, []byte(args), "/w")
}

// A shell tool whose program and arguments are separate fields runs the
// joined command, whatever the tool is called.
func TestGenericShellJoinsArgv(t *testing.T) {
	for _, c := range []struct{ tool, args string }{
		{"execute_command", `{"command":"terraform","args":["destroy","-auto-approve"]}`},
		{"run_command", `{"command":"terraform","arguments":["destroy","-auto-approve"]}`},
		{"exec", `{"cmd":"terraform","argv":["destroy","-auto-approve"]}`},
		{"execute_command", `{"command":"terraform","args":"destroy -auto-approve"}`},
		{"run_script", `{"script":"terraform destroy -auto-approve"}`},
		{"bash_exec", `{"command":"terraform destroy -auto-approve"}`},
		{"some_unrelated_name", `{"command":"terraform destroy -auto-approve"}`},
		// a decoy command does not hide a later script
		{"execute_command", `{"command":"true","script":"terraform destroy -auto-approve"}`},
		{"execute_command", `{"command":"","script":"terraform destroy -auto-approve"}`},
	} {
		r, ok := tr(t, c.tool, c.args)
		if !ok || !strings.Contains(r.Command, "destroy") || strings.Contains(r.Command, "APPLYGATE_MCP_UNREADABLE") && !strings.Contains(r.Command, "destroy") {
			t.Errorf("%s %s: ok=%v command=%q", c.tool, c.args, ok, r.Command)
		}
	}
	// A tool with nothing command-like in it stays unknown.
	if _, ok := tr(t, "post_message", `{"text":"hello"}`); ok {
		t.Error("a message tool is not a shell tool")
	}
}

// Every reading a known tool's arguments fit is judged, not the first.
func TestEveryMatchingCaseIsJudged(t *testing.T) {
	r, ok := tr(t, "BashCommand", `{"type":"command","command":"echo hi","action_json":{"type":"command","command":"terraform destroy -auto-approve"}}`)
	if !ok {
		t.Skip("wcgw is not in the table")
	}
	if !strings.Contains(r.Command, "destroy") {
		t.Errorf("the nested reading was dropped: %q", r.Command)
	}
}

func TestNonObjectArgumentsOfKnownToolAreAsked(t *testing.T) {
	for _, args := range []string{`"{\"cli_command\":\"aws s3 rb s3://prod --force\"}"`, `["aws s3 rb s3://prod --force"]`, `null`} {
		r, ok := Rules().Translate("mcp__aws__call_aws", []byte(args), "/w")
		if !ok || !strings.Contains(r.Command, "APPLYGATE_MCP_UNREADABLE") {
			t.Errorf("%s: ok=%v command=%q", args, ok, r.Command)
		}
	}
}
