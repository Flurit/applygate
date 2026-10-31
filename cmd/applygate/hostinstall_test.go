package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/hook"
)

// Every agent installs at both scopes, is recognised as an applygate hook
// with this binary, and is removed again.
func TestInstallRemoveEveryAgent(t *testing.T) {
	for _, agent := range hook.Agents {
		t.Run(agent, func(t *testing.T) {
			t.Chdir(t.TempDir())
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("COPILOT_HOME", "")
			for _, scope := range []string{"project", "user"} {
				var out, errb bytes.Buffer
				if rc := cmdInstall("install", []string{"--agent", agent, "--scope", scope}, &out, &errb); rc != 0 {
					t.Fatalf("%s install rc=%d: %s", scope, rc, errb.String())
				}
				p, _ := settingsPath(agent, scope)
				if scope == "user" && !strings.HasPrefix(p, home) {
					t.Fatalf("user path %s is not under HOME", p)
				}
				b, err := os.ReadFile(p)
				if err != nil || !fileHasApplygate(agent, b) {
					t.Fatalf("%s: %s has no applygate hook: %v\n%s", scope, p, err, b)
				}
				bins, ok := hookBinaries(agent, b)
				if !ok || len(bins) == 0 || bins[0] != selfPath() {
					t.Fatalf("%s: binaries %v, want %s", scope, bins, selfPath())
				}
				// A second install replaces the entry instead of adding one.
				cmdInstall("install", []string{"--agent", agent, "--scope", scope}, &out, &errb)
				b, _ = os.ReadFile(p)
				if spec, _ := specFor(agent); spec.kind == "json" {
					// One entry per event the spec writes, not two.
					var doc map[string]any
					json.Unmarshal(b, &doc)
					n := 0
					for _, list := range hookLists(doc) {
						for _, e := range list {
							if isApplygateEntry(e) {
								n++
							}
						}
					}
					if n != len(spec.entries("x")) {
						t.Fatalf("%s: reinstall left %d applygate entries, want %d", scope, n, len(spec.entries("x")))
					}
				}
			}
			var out, errb bytes.Buffer
			if rc := cmdInstall("remove", []string{"--agent", agent}, &out, &errb); rc != 0 {
				t.Fatalf("remove rc=%d: %s", rc, errb.String())
			}
			for _, scope := range []string{"project", "user"} {
				p, _ := settingsPath(agent, scope)
				if b, err := os.ReadFile(p); err == nil && fileHasApplygate(agent, b) {
					t.Fatalf("%s: hook still in %s after remove", scope, p)
				}
			}
		})
	}
}

func readDoc(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return doc
}

func install(t *testing.T, agent string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if rc := cmdInstall("install", []string{"--agent", agent}, &out, &errb); rc != 0 {
		t.Fatalf("install %s rc=%d: %s", agent, rc, errb.String())
	}
	if !strings.Contains(out.String(), "not been tested live") {
		t.Fatalf("install %s should say the adapter is untested: %s", agent, out.String())
	}
	p, _ := settingsPath(agent, "project")
	return p
}

// The entry shapes follow each host's documented configuration format.
func TestInstallEntryShapes(t *testing.T) {
	t.Chdir(t.TempDir())
	cursor := readDoc(t, install(t, "cursor"))
	e := cursor["hooks"].(map[string]any)["preToolUse"].([]any)[0].(map[string]any)
	if cursor["version"] != float64(1) || e["failClosed"] != true || e["matcher"] != "Shell|Write|Delete|Read|Grep" || e["timeout"] != float64(30) {
		t.Fatalf("cursor: %v", cursor)
	}
	copilot := readDoc(t, install(t, "copilot"))
	e = copilot["hooks"].(map[string]any)["preToolUse"].([]any)[0].(map[string]any)
	if copilot["version"] != float64(1) || e["type"] != "command" || !strings.HasSuffix(e["bash"].(string), " hook copilot") || e["timeoutSec"] != float64(30) {
		t.Fatalf("copilot: %v", copilot)
	}
	gemini := readDoc(t, install(t, "gemini"))
	e = gemini["hooks"].(map[string]any)["BeforeTool"].([]any)[0].(map[string]any)
	if e["hooks"].([]any)[0].(map[string]any)["timeout"] != float64(30000) {
		t.Fatalf("gemini: %v", gemini)
	}
	windsurf := readDoc(t, install(t, "windsurf"))
	for _, ev := range []string{"pre_run_command", "pre_write_code", "pre_read_code"} {
		if l, _ := windsurf["hooks"].(map[string]any)[ev].([]any); len(l) != 1 {
			t.Fatalf("windsurf %s: %v", ev, windsurf)
		}
	}
	devin := readDoc(t, install(t, "devin"))
	e = devin["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if e["matcher"] != "^exec$" {
		t.Fatalf("devin: %v", devin)
	}
	cline := install(t, "cline")
	if fi, err := os.Stat(cline); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("cline hook must be executable: %v %v", fi, err)
	}
}

// Copilot's applygate.json is applygate's own file: remove deletes it.
func TestCopilotRemoveDeletesOwnFile(t *testing.T) {
	t.Chdir(t.TempDir())
	p := install(t, "copilot")
	var out, errb bytes.Buffer
	cmdInstall("remove", []string{"--agent", "copilot", "--scope", "project"}, &out, &errb)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s should be gone: %v", p, err)
	}
}

// A Cline hook script or OpenCode plugin applygate did not write is never
// overwritten or removed.
func TestScriptHooksKeepForeignFiles(t *testing.T) {
	for _, agent := range []string{"cline", "opencode"} {
		t.Chdir(t.TempDir())
		p, _ := settingsPath(agent, "project")
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("#!/bin/sh\necho mine\n"), 0o755)
		var out, errb bytes.Buffer
		if rc := cmdInstall("install", []string{"--agent", agent}, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "not written by applygate") {
			t.Fatalf("%s: install over a foreign file: rc=%d %s", agent, rc, errb.String())
		}
		cmdInstall("remove", []string{"--agent", agent}, &out, &errb)
		if b, _ := os.ReadFile(p); string(b) != "#!/bin/sh\necho mine\n" {
			t.Fatalf("%s: foreign file changed: %q", agent, b)
		}
	}
}

// The Cline script prints a cancel when applygate does not run, because Cline
// lets the tool run on any other output.
func TestClineScriptCancelsWhenBinaryMissing(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "PreToolUse")
	os.WriteFile(script, []byte(clineScriptFor("/nonexistent/it's/applygate")), 0o755)
	if bins := scriptBinaries([]byte(clineScriptFor("/nonexistent/it's/applygate"))); len(bins) != 1 || bins[0] != "/nonexistent/it's/applygate" {
		t.Fatalf("binary not read back: %v", bins)
	}
	out, err := exec.Command(sh, script).Output()
	if err != nil {
		t.Fatalf("script failed: %v", err)
	}
	var r struct{ Cancel bool }
	if json.Unmarshal(out, &r) != nil || !r.Cancel {
		t.Fatalf("want a cancel, got %q", out)
	}
}

// The OpenCode plugin is valid JavaScript (checked when node is installed).
func TestOpenCodePluginParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	p := filepath.Join(t.TempDir(), "applygate.mjs")
	os.WriteFile(p, []byte(opencodePluginFor(`/opt/apply"gate`)), 0o644)
	if out, err := exec.Command(node, "--check", p).CombinedOutput(); err != nil {
		t.Fatalf("node --check: %v\n%s", err, out)
	}
	if bins := scriptBinaries([]byte(opencodePluginFor(`/opt/apply"gate`))); len(bins) != 1 || bins[0] != `/opt/apply"gate` {
		t.Fatalf("binary not read back: %v", bins)
	}
}

func TestFlatEntriesRecognised(t *testing.T) {
	for _, e := range []string{
		`{"command": "\"/usr/bin/applygate\" hook cursor", "failClosed": true}`,
		`{"type": "command", "bash": "\"/usr/bin/applygate\" hook copilot"}`,
	} {
		var v any
		json.Unmarshal([]byte(e), &v)
		if !isApplygateEntry(v) || entryBinary(v) != "/usr/bin/applygate" {
			t.Fatalf("not recognised: %s", e)
		}
	}
}

// init installs only adapters verified live; the others are named with the
// command that installs them.
func TestInitSkipsDocsOnlyAgents(t *testing.T) {
	wd := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	os.MkdirAll(filepath.Join(home, ".cursor"), 0o755)
	t.Chdir(wd)
	var out, errb bytes.Buffer
	if rc := cmdInit(nil, &out, &errb); rc != 0 {
		t.Fatalf("init rc %d: %s", rc, errb.String())
	}
	if !strings.Contains(out.String(), "cursor: not installed by init") || !strings.Contains(out.String(), "hook install --agent cursor --scope user") {
		t.Fatalf("init output: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "hooks.json")); err == nil {
		t.Fatal("init installed the cursor hook")
	}
	if b, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err != nil || !settingsHasApplygate(b) {
		t.Fatalf("init did not install the claude hook: %v", err)
	}
}
