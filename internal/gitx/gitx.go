// Package gitx runs the hook's own git: one from a system directory, with
// no system or global config and with the config keys that start programs
// (fsmonitor, hooks, pagers, ssh, askpass) overridden. Callers use plumbing
// that runs no filters, diff drivers or textconv.
package gitx

import (
	"context"
	"os"
	"os/exec"
	"sync"
)

// RequireRoot is set under a managed install: the hook then runs only a git
// that root owns, in a directory root owns, so the agent's user cannot
// replace it (a Homebrew git under /usr/local or /opt/homebrew is the
// user's).
var RequireRoot bool

var candidates = []string{"/Library/Developer/CommandLineTools/usr/bin/git", "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
	"/usr/bin/git", "/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git"}

var found struct {
	once       sync.Once
	path, root string
}

// Path is git from the system directories first, so a git the agent put
// earlier on PATH is not the one the hook runs. Under RequireRoot it is
// the first one root owns, or "" when there is none.
func Path() string {
	found.once.Do(func() {
		// On macOS /usr/bin/git is a shim that looks the real one up with
		// xcrun, which can be slow; the real binaries come first.
		for _, p := range candidates {
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if found.path == "" {
				found.path = p
			}
			if found.root == "" && rootOwned(p, fi) {
				found.root = p
			}
		}
		if found.path == "" {
			found.path, _ = exec.LookPath("git")
		}
	})
	if RequireRoot {
		return found.root
	}
	if found.path == "" {
		return "git"
	}
	return found.path
}

// Command is the hook's git in dir with args.
func Command(ctx context.Context, dir string, args ...string) *exec.Cmd {
	base := []string{"-C", dir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
		"-c", "core.sshCommand=false", "-c", "core.askPass=", "--no-pager"}
	p := Path()
	if p == "" {
		p = "/nonexistent/git" // under a managed install with no root-owned git: fails
	}
	cmd := exec.CommandContext(ctx, p, append(base, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.TempDir(), "LANG=C", "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_OPTIONAL_LOCKS=0", "GIT_ATTR_NOSYSTEM=1"}
	return cmd
}
