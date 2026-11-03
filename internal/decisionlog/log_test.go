package decisionlog

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

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

// A huge entry is redacted within a bounded time, and a private key cut at
// the redaction limit is still redacted (4H3, R5-2).
func TestRedactBounded(t *testing.T) {
	big := strings.Repeat("mysql -h x ", 6000)
	e := Entry{Command: big}
	for i := 0; i < 400; i++ {
		e.Actions = append(e.Actions, policy.ActionResult{Command: big + strconv.Itoa(i)})
	}
	start := time.Now()
	redactEntry(&e)
	// The budget is what bounds the work; the time is loose for the race
	// detector, which is ten times slower.
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("redacting took %s", d)
	}
	if !strings.Contains(e.Actions[399].Command, "redaction budget") {
		t.Fatalf("last action not cut: %.80q", e.Actions[399].Command)
	}
	key := "x -----BEGIN RSA PRIVATE KEY-----" + strings.Repeat("A", 3*maxField) + "-----END RSA PRIVATE KEY-----"
	if got := RedactCut(key, maxField); strings.Contains(got, "AAAA") {
		t.Fatalf("key body kept: %.80q", got)
	}
}
