package mcpmap

import (
	"encoding/json"
	"strings"
	"testing"
)

// A shell-like tool of a server the table does not know may take the
// program's argument list under any of several names, or as an array.
func TestUnknownShellToolArgumentListNames(t *testing.T) {
	for _, args := range []string{
		`{"command":"terraform","options":["destroy","-auto-approve"]}`,
		`{"command":"terraform","parameters":["destroy","-auto-approve"]}`,
		`{"command":"terraform","extra_args":["destroy","-auto-approve"]}`,
		`{"command":"terraform","flags":["destroy","-auto-approve"]}`,
		`{"command":"terraform","subcommand":"destroy","flags":["-auto-approve"]}`,
		`{"command":["terraform"],"args":["destroy","-auto-approve"]}`,
	} {
		r, ok := Rules().Translate("mcp__x__run_in_terminal", json.RawMessage(args), "/repo")
		if !ok || !strings.Contains(r.Command, "destroy") {
			t.Errorf("%s: command %q (ok %v)", args, r.Command, ok)
		}
	}
}
