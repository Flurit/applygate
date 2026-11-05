package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// A program and its arguments in separate fields of a tool no table knows
// are one command.
func TestUnknownToolArgumentFields(t *testing.T) {
	for _, in := range []string{
		`{"command":"terraform","args":["destroy","-auto-approve"]}`,
		`{"executable":"terraform","arguments":["-chdir=../prod","destroy","-auto-approve"]}`,
		`{"program":"terraform","argv":["destroy"]}`,
	} {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(in), &m); err != nil {
			t.Fatal(err)
		}
		var ev policy.Event
		classifyUnknown(&ev, "SomeNewTool", m)
		if ev.Kind != policy.KindShell || !strings.Contains(ev.Command, "destroy") {
			t.Errorf("%s: kind %v command %q", in, ev.Kind, ev.Command)
		}
	}
}
