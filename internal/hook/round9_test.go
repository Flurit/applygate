package hook

import (
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// A tool applygate has no table for is looked into: a command in any field
// is judged as shell, and every other call is scanned for guard files and
// logged. Only the host's bookkeeping tools pass unseen.
func TestUnknownToolsAreLookedInto(t *testing.T) {
	cases := []struct {
		tool  string
		input map[string]any
		kind  policy.EventKind
		cmd   string
	}{
		{"PowerShell", map[string]any{"script": "terraform destroy"}, policy.KindShell, "destroy"},
		{"Monitor", map[string]any{"cmdline": "terraform destroy"}, policy.KindShell, "destroy"},
		{"terminal_run", map[string]any{"cmd_text": "terraform destroy"}, policy.KindShell, "destroy"},
		{"future_tool", map[string]any{"opts": map[string]any{"line": "kubectl delete ns prod"}}, policy.KindShell, "kubectl delete"},
		{"save_file", map[string]any{"target": "/home/u/.claude/settings.json", "data": "{}"}, policy.KindMCP, ""},
		{"TodoWrite", map[string]any{"todos": []any{map[string]any{"content": "run terraform destroy later"}}}, policy.KindOther, ""},
		{"WebFetch", map[string]any{"url": "https://example.com", "prompt": "terraform destroy"}, policy.KindOther, ""},
	}
	for _, c := range cases {
		ev, ok, err := Claude{}.Parse([]byte(event(c.tool, "/w", c.input)))
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", c.tool, ok, err)
		}
		if ev.Kind != c.kind || c.cmd != "" && !strings.Contains(ev.Command, c.cmd) {
			t.Errorf("%s: kind %s command %q, want %s with %q", c.tool, ev.Kind, ev.Command, c.kind, c.cmd)
		}
	}
}
