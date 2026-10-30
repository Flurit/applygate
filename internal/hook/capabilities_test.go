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
	for _, want := range []string{"Claude Code (applygate hook claude)", "Codex (applygate hook codex)", "fails open", "Cursor (applygate hook cursor, from docs, not tested live)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("text table lacks %q:\n%s", want, buf.String())
		}
	}
	notes := InstallNotes("codex")
	if len(notes) < 2 || !strings.Contains(strings.Join(notes, "\n"), "fails open") {
		t.Errorf("codex install notes should state the fail-open path: %v", notes)
	}
	if n := InstallNotes("no-such-host"); n != nil {
		t.Errorf("unknown host should have no notes: %v", n)
	}
}

// TestDocsOnlyHostsSayNotTested holds the rule that protection is never
// claimed without a live test: every cell of a host whose adapter was written
// from documentation says it was not tested, and its install notes say so.
func TestDocsOnlyHostsSayNotTested(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range Hosts {
		if !h.DocsOnly {
			continue
		}
		seen[h.Agent] = true
		if !strings.HasPrefix(h.Verified, "not verified live") {
			t.Errorf("%s: Verified must start with \"not verified live\": %q", h.Name, h.Verified)
		}
		for _, c := range cells {
			switch c.label {
			case "Verified on", "Evidence", "Live tests pending":
				continue
			}
			if !strings.Contains(c.get(h), "not tested") {
				t.Errorf("%s: cell %q does not say it was not tested: %q", h.Name, c.label, c.get(h))
			}
		}
		if n := strings.Join(InstallNotes(h.Agent), "\n"); !strings.Contains(n, "not been tested live") {
			t.Errorf("%s: install notes do not say the adapter is untested: %s", h.Name, n)
		}
		if _, err := ForAgent(h.Agent); err != nil {
			t.Errorf("%s: no adapter: %v", h.Name, err)
		}
	}
	for _, a := range Agents {
		if _, ok := HostFor(a); !ok {
			t.Errorf("adapter %s has no host row", a)
		}
	}
	if len(seen) != 7 {
		t.Errorf("want 7 documentation-only hosts, got %v", seen)
	}
}
