package hook

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestHostsDocCurrent fails when docs/hosts.md no longer matches the table in
// capabilities.go. Regenerate with: go generate ./internal/hook
func TestHostsDocCurrent(t *testing.T) {
	want := HostsMarkdown()
	got, err := os.ReadFile("../../docs/hosts.md")
	if err != nil {
		t.Fatalf("docs/hosts.md: %v (run: go generate ./internal/hook)", err)
	}
	if string(got) != want {
		t.Fatal("docs/hosts.md is stale; run: go generate ./internal/hook")
	}
}

func TestHostsTableComplete(t *testing.T) {
	for _, h := range Hosts {
		if !h.Supported {
			continue
		}
		for _, c := range cells {
			if strings.TrimSpace(c.get(h)) == "" {
				t.Errorf("%s: empty cell %q", h.Name, c.label)
			}
		}
		if len(h.Evidence) == 0 {
			t.Errorf("%s: no evidence file", h.Name)
		}
		for _, e := range h.Evidence {
			if _, err := os.Stat("../../" + e); err != nil {
				t.Errorf("%s: evidence file %s: %v", h.Name, e, err)
			}
		}
	}
	var buf bytes.Buffer
	HostsText(&buf)
	for _, want := range []string{"Claude Code (seatbelt hook claude)", "Codex (seatbelt hook codex)", "fails open", "Cursor, Copilot CLI, OpenCode: not supported"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text table lacks %q:\n%s", want, buf.String())
		}
	}
	notes := InstallNotes("codex")
	if len(notes) < 2 || !strings.Contains(strings.Join(notes, "\n"), "fails open") {
		t.Errorf("codex install notes should state the fail-open path: %v", notes)
	}
	if n := InstallNotes("cursor"); n != nil {
		t.Errorf("unsupported host should have no notes: %v", n)
	}
}
