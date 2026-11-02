package mcpmap

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func translate(t *testing.T, tool, args string) string {
	t.Helper()
	r, ok := Rules().Translate(tool, json.RawMessage(args), "/repo")
	if !ok {
		t.Fatalf("%s not in the table", tool)
	}
	return r.Command
}

func TestReviewF5CreateRunTruthiness(t *testing.T) {
	var bad []string
	for _, args := range []string{
		`{"workspace_id":"ws-1","params":{"is_destroy":1}}`,
		`{"workspace_id":"ws-1","params":{"is_destroy":"yes"}}`,
		`{"workspace_id":"ws-1","params":"{\"is_destroy\":true,\"auto_apply\":true}"}`,
	} {
		if c := translate(t, "mcp__tfc__create_run", args); !strings.Contains(c, "destroy") && !strings.Contains(c, "APPLYGATE_MCP_UNREADABLE") {
			bad = append(bad, args+" -> "+c)
		}
	}
	reviewgap.Check(t, "F5", len(bad) == 0, "judged as something milder: %q", bad)
}

func TestReviewF6NamedClusterKept(t *testing.T) {
	c := translate(t, "mcp__eks__apply_yaml", `{"yaml_path":"/x.yaml","cluster_name":"prod-eks"}`)
	ok := strings.Contains(c, "prod-eks") || strings.Contains(c, "APPLYGATE_MCP_UNREADABLE")
	reviewgap.Check(t, "F6", ok, "the named cluster is dropped: %q", c)
}

func TestReviewF9CallAWSMustBeAWS(t *testing.T) {
	c := translate(t, "mcp__aws__call_aws", `{"cli_command":"[\"aws s3 rb s3://acme-prod-data --force\"]"}`)
	ok := strings.HasPrefix(strings.TrimSpace(c), "aws ") || strings.Contains(c, "APPLYGATE_MCP_UNREADABLE")
	reviewgap.Check(t, "F9", ok, "translated to a non-aws command: %q", c)
}
