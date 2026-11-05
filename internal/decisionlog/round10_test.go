package decisionlog

import (
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

func TestUnclosedKeyMarker(t *testing.T) {
	closed := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
	if UnclosedKeyMarker(closed) {
		t.Error("a complete key is closed")
	}
	if !UnclosedKeyMarker("echo a '-----BEGIN PRIVATE KEY-----'; pulumi destroy --yes") {
		t.Error("a header with no end marker hides what follows")
	}
	if UnclosedKeyMarker("echo hello") {
		t.Error("no marker")
	}
}

func TestRedactActionFields(t *testing.T) {
	e := &Entry{Actions: []policy.ActionResult{{Backend: "https://deploy:Hunter2SuperSecret@state.example.com/dev"}}}
	redactEntry(e)
	if strings.Contains(e.Actions[0].Backend, "Hunter2SuperSecret") {
		t.Errorf("backend address kept its password: %s", e.Actions[0].Backend)
	}
}
