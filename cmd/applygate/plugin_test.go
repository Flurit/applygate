package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// The Claude Code plugin runs plugin/claude-code/scripts/applygate-hook, a
// POSIX sh launcher that finds or downloads the applygate binary. These tests
// run it against a fake release served locally, with a PATH that holds only
// the tools it needs.

const pluginDir = "../../plugin/claude-code"

// launcherTools builds a PATH directory with the programs the launcher uses
// and, unlike the test machine's PATH, no applygate.
func launcherTools(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"curl", "wget", "tar", "gzip", "sha256sum", "shasum", "awk", "mkdir", "mktemp", "mv", "rm", "chmod", "uname", "dirname", "tr", "head", "cat", "sh"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeRelease is a release archive whose applygate prints a marker, its
// arguments and its stdin.
func fakeRelease(t *testing.T, marker string) (name string, archive []byte, sum string) {
	t.Helper()
	arch := runtime.GOARCH
	name = fmt.Sprintf("applygate_9.9.9_%s_%s.tar.gz", runtime.GOOS, arch)
	script := "#!/bin/sh\necho \"" + marker + " $*\"\ncat\n"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "applygate", Mode: 0o755, Size: int64(len(script))}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(script))
	tw.Close()
	gz.Close()
	h := sha256.Sum256(buf.Bytes())
	return name, buf.Bytes(), hex.EncodeToString(h[:])
}

// pluginCopy is a copy of the launcher next to a pinned-release.txt naming
// the fake release with the given sha256.
func pluginCopy(t *testing.T, name, sum string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "scripts")
	os.MkdirAll(dir, 0o755)
	b, err := os.ReadFile(filepath.Join(pluginDir, "scripts", "applygate-hook"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "applygate-hook"), b, 0o644)
	os.WriteFile(filepath.Join(dir, "pinned-release.txt"), []byte("# test pin\n"+sum+"  "+name+"\n"), 0o644)
	return filepath.Join(dir, "applygate-hook")
}

func serveRelease(t *testing.T, name string, archive []byte) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/v9.9.9/"+name {
			http.NotFound(w, r)
			return
		}
		w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

type launch struct {
	stdout, stderr string
	exit           int
}

func runLauncher(t *testing.T, script string, env []string, stdin string, args ...string) launch {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cmd := exec.Command(sh, append([]string{script}, args...)...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return launch{out.String(), errb.String(), code}
}

func launcherEnv(t *testing.T, tools string, extra ...string) []string {
	return append([]string{"PATH=" + tools, "HOME=" + t.TempDir()}, extra...)
}

func skipUnlessReleasePlatform(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("releases are built for linux and darwin")
	}
}

func TestPluginLauncherPrefersInstalledBinary(t *testing.T) {
	skipUnlessReleasePlatform(t)
	tools := launcherTools(t)
	name, archive, sum := fakeRelease(t, "downloaded")
	srv, hits := serveRelease(t, name, archive)
	script := pluginCopy(t, name, sum)

	onPath := t.TempDir()
	os.WriteFile(filepath.Join(onPath, "applygate"), []byte("#!/bin/sh\necho \"from PATH $*\"\n"), 0o755)
	r := runLauncher(t, script, launcherEnv(t, onPath+":"+tools, "APPLYGATE_PLUGIN_RELEASE_URL="+srv.URL, "CLAUDE_PLUGIN_DATA="+t.TempDir()), "", "hook", "claude")
	if r.exit != 0 || r.stdout != "from PATH hook claude\n" {
		t.Fatalf("PATH binary: %+v", r)
	}

	explicit := filepath.Join(t.TempDir(), "my-applygate")
	os.WriteFile(explicit, []byte("#!/bin/sh\necho \"explicit $*\"\n"), 0o755)
	r = runLauncher(t, script, launcherEnv(t, onPath+":"+tools, "APPLYGATE_BIN="+explicit), "", "hook", "claude")
	if r.exit != 0 || r.stdout != "explicit hook claude\n" {
		t.Fatalf("APPLYGATE_BIN: %+v", r)
	}
	r = runLauncher(t, script, launcherEnv(t, tools, "APPLYGATE_BIN=/nonexistent/applygate"), "", "hook", "claude")
	if r.exit != 2 || !strings.Contains(r.stderr, "APPLYGATE_BIN") {
		t.Fatalf("bad APPLYGATE_BIN must block: %+v", r)
	}
	if *hits != 0 {
		t.Fatalf("downloaded although a binary was installed (%d requests)", *hits)
	}
}

func TestPluginLauncherDownloadsPinnedRelease(t *testing.T) {
	skipUnlessReleasePlatform(t)
	tools := launcherTools(t)
	name, archive, sum := fakeRelease(t, "downloaded")
	srv, hits := serveRelease(t, name, archive)
	script := pluginCopy(t, name, sum)
	data := t.TempDir()
	env := launcherEnv(t, tools, "APPLYGATE_PLUGIN_RELEASE_URL="+srv.URL, "CLAUDE_PLUGIN_DATA="+data)

	// The hook's stdin reaches the binary and only the binary writes stdout.
	r := runLauncher(t, script, env, `{"tool_name":"Bash"}`, "hook", "claude")
	if r.exit != 0 || r.stdout != "downloaded hook claude\n{\"tool_name\":\"Bash\"}" {
		t.Fatalf("first run: %+v", r)
	}
	cached := filepath.Join(data, "v9.9.9", runtime.GOOS+"_"+runtime.GOARCH, "applygate")
	if _, err := os.Stat(cached); err != nil {
		t.Fatalf("not cached: %v", err)
	}
	// The cached copy runs without the network.
	srv.Close()
	r = runLauncher(t, script, env, "", "hook", "claude")
	if r.exit != 0 || r.stdout != "downloaded hook claude\n" {
		t.Fatalf("cached run: %+v", r)
	}
	if *hits != 1 {
		t.Fatalf("want one download, got %d", *hits)
	}
}

func TestPluginLauncherFetchMode(t *testing.T) {
	skipUnlessReleasePlatform(t)
	tools := launcherTools(t)
	name, archive, sum := fakeRelease(t, "downloaded")
	srv, _ := serveRelease(t, name, archive)
	script := pluginCopy(t, name, sum)

	// Without CLAUDE_PLUGIN_DATA the binary goes to the XDG cache.
	xdg := t.TempDir()
	r := runLauncher(t, script, launcherEnv(t, tools, "APPLYGATE_PLUGIN_RELEASE_URL="+srv.URL, "XDG_CACHE_HOME="+xdg), "", "--fetch")
	if r.exit != 0 || r.stdout != "" {
		t.Fatalf("fetch: %+v (SessionStart stdout would become session context)", r)
	}
	if _, err := os.Stat(filepath.Join(xdg, "applygate", "plugin", "v9.9.9", runtime.GOOS+"_"+runtime.GOARCH, "applygate")); err != nil {
		t.Fatalf("fetch did not cache: %v", err)
	}

	// A failed fetch is a visible hook error (exit 1) but does not stop the
	// session; the same failure in the hook blocks the tool call (exit 2).
	bad := pluginCopy(t, strings.Replace(name, "9.9.9", "9.9.8", 1), sum)
	for _, c := range []struct {
		args []string
		exit int
	}{{[]string{"--fetch"}, 1}, {[]string{"hook", "claude"}, 2}} {
		r = runLauncher(t, bad, launcherEnv(t, tools, "APPLYGATE_PLUGIN_RELEASE_URL="+srv.URL, "CLAUDE_PLUGIN_DATA="+t.TempDir()), "", c.args...)
		if r.exit != c.exit || r.stdout != "" || !strings.Contains(r.stderr, "downloading v9.9.8 failed") {
			t.Fatalf("%v with a missing release: %+v", c.args, r)
		}
	}
}

func TestPluginLauncherRejectsWrongChecksum(t *testing.T) {
	skipUnlessReleasePlatform(t)
	tools := launcherTools(t)
	name, archive, _ := fakeRelease(t, "tampered")
	srv, _ := serveRelease(t, name, archive)
	script := pluginCopy(t, name, strings.Repeat("0", 64))
	data := t.TempDir()
	r := runLauncher(t, script, launcherEnv(t, tools, "APPLYGATE_PLUGIN_RELEASE_URL="+srv.URL, "CLAUDE_PLUGIN_DATA="+data), "", "hook", "claude")
	if r.exit != 2 || r.stdout != "" || !strings.Contains(r.stderr, "sha256 mismatch") {
		t.Fatalf("wrong checksum must block: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(data, "v9.9.9")); !os.IsNotExist(err) {
		t.Fatalf("a rejected download was cached: %v", err)
	}
}

// The committed pin covers every release platform, for the version in the
// plugin manifest, so a plugin update and its binary move together.
func TestPluginPinMatchesManifest(t *testing.T) {
	var manifest struct{ Version string }
	b, err := os.ReadFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(filepath.Join(pluginDir, "scripts", "pinned-release.txt"))
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`^([0-9a-f]{64})  applygate_([0-9A-Za-z.-]+)_(linux|darwin)_(amd64|arm64)\.tar\.gz$`)
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(pin)), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		m := line.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("bad pin line %q", l)
		}
		if m[2] != manifest.Version {
			t.Errorf("pin %q is for %s, plugin.json says %s", l, m[2], manifest.Version)
		}
		seen[m[3]+"_"+m[4]] = true
	}
	for _, p := range []string{"darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64"} {
		if !seen[p] {
			t.Errorf("no pin for %s", p)
		}
	}
}

// The plugin's hooks go through the launcher, and the PreToolUse hook fails
// closed.
func TestPluginHooksUseLauncher(t *testing.T) {
	var hooks struct {
		Hooks map[string][]struct {
			Matcher string
			Hooks   []struct {
				Type, Command, OnFailure string
				Timeout                  int
			}
		}
	}
	b, err := os.ReadFile(filepath.Join(pluginDir, "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &hooks); err != nil {
		t.Fatal(err)
	}
	pre := hooks.Hooks["PreToolUse"]
	if len(pre) != 1 || len(pre[0].Hooks) != 1 {
		t.Fatalf("PreToolUse: %+v", pre)
	}
	h := pre[0].Hooks[0]
	if h.Command != `sh "${CLAUDE_PLUGIN_ROOT}/scripts/applygate-hook" hook claude` || h.OnFailure != "block" || h.Timeout != 30 {
		t.Fatalf("PreToolUse hook: %+v", h)
	}
	start := hooks.Hooks["SessionStart"]
	if len(start) != 1 || len(start[0].Hooks) != 1 || start[0].Hooks[0].Command != `sh "${CLAUDE_PLUGIN_ROOT}/scripts/applygate-hook" --fetch` {
		t.Fatalf("SessionStart: %+v", start)
	}
}
