package decisionlog

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

func TestReportCountsMCPCallsPerServer(t *testing.T) {
	entries := []Entry{
		{Tool: "Bash", Verdict: policy.Allow, Enforced: policy.Allow},
		{Tool: "mcp__terraform__destroy_workspace", Verdict: policy.Allow, Enforced: policy.Allow},
		{Tool: "mcp__terraform__plan", Verdict: policy.Allow, Enforced: policy.Allow},
		{Tool: "mcp__github__create_issue", Verdict: policy.Allow, Enforced: policy.Allow},
	}
	var b bytes.Buffer
	Report(&b, entries, 0)
	if !strings.Contains(b.String(), "MCP tool calls (logged, not judged): 3 (github 1, terraform 2)") {
		t.Fatalf("report:\n%s", b.String())
	}
	b.Reset()
	Report(&b, entries[:1], 0)
	if strings.Contains(b.String(), "MCP") {
		t.Fatalf("no MCP line without MCP calls:\n%s", b.String())
	}
}

// Ordinary commands keep their text.
func TestRedactLeavesOrdinaryCommands(t *testing.T) {
	for _, c := range []string{
		"terraform plan -out=tfplan",
		"kubectl get secret app-tls -n prod",
		"git commit -m 'reset password flow'",
		"docker run -p 8080:80 nginx",
		"curl -u admin https://example.com",
		"aws s3 ls s3://acme-prod-data",
	} {
		if got := Redact(c); got != c {
			t.Errorf("%q became %q", c, got)
		}
	}
}
