package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Flurit/applygate/internal/config"
)

// euid is the effective user, a variable so tests can run the managed
// install without root.
var euid = os.Geteuid

const systemConfig = `# applygate system config, written by "applygate install --managed".
# Root owns it, and what it sets wins over the user config
# (~/.config/applygate/config.yaml). Repository configs are read only when
# trusted with "/usr/bin/sudo /usr/local/libexec/applygate/applygate trust".
version: 1
mode: enforce
approvals: false
`

// cmdManaged installs or removes the managed install: a guard the agent's
// user cannot change, because root owns every part of it (docs/managed.md).
func cmdManaged(verb string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	managed := fs.Bool("managed", false, "the root-owned install (the only kind this command makes)")
	exclusive := fs.Bool("exclusive", false, "also set Claude Code's allowManagedHooksOnly, which turns off every user, project and plugin hook")
	purge := fs.Bool("purge", false, "uninstall: also remove the system config and its trust store")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*managed {
		fmt.Fprintf(stderr, "applygate %s needs --managed; for a per-user install use applygate init or applygate hook install\n", verb)
		return 2
	}
	if runtime.GOOS == "windows" || config.SystemDir == "" {
		fmt.Fprintln(stderr, "applygate: the managed install is not supported on this system yet")
		return 2
	}
	if euid() != 0 {
		fmt.Fprintf(stderr, "applygate: the managed install writes root-owned files: run /usr/bin/sudo with this binary's full path: /usr/bin/sudo %s %s --managed\n", selfPath(), verb)
		return 2
	}
	if verb == "uninstall" {
		return managedUninstall(*purge, stdout, stderr)
	}
	return managedInstall(*exclusive, stdout, stderr)
}

func managedInstall(exclusive bool, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "applygate:", err)
		return 1
	}
	// 1. The binary, copied from the running one.
	bin := config.ManagedBinary()
	src := selfPath()
	b, err := os.ReadFile(src)
	if err != nil {
		return fail(err)
	}
	if err := rootDir(config.ManagedBinDir); err != nil {
		return fail(err)
	}
	if err := writeRootFile(bin, b, 0o755); err != nil {
		return fail(err)
	}
	if got, err := os.ReadFile(bin); err != nil || sha256.Sum256(got) != sha256.Sum256(b) {
		return fail(fmt.Errorf("%s does not match %s after copying", bin, src))
	}
	fmt.Fprintf(stdout, "binary:        %s (copied from %s)\n", bin, src)

	// 2. The system config, kept if one is there.
	if err := rootDir(config.SystemDir); err != nil {
		return fail(err)
	}
	sp := config.SystemPath()
	if _, err := os.Lstat(sp); errors.Is(err, os.ErrNotExist) {
		if err := writeRootFile(sp, []byte(systemConfig), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "system config: %s (mode: enforce, approvals: false)\n", sp)
	} else {
		fmt.Fprintf(stdout, "system config: %s (kept as it is)\n", sp)
	}
	if err := config.CheckSystemFile(sp); err != nil {
		return fail(err)
	}

	// 3. Claude Code's managed settings, as a drop-in file so an
	// organisation's own managed-settings.json is left alone.
	if config.ClaudeManagedDir != "" {
		dir := filepath.Join(config.ClaudeManagedDir, "managed-settings.d")
		if err := rootDir(config.ClaudeManagedDir); err != nil {
			return fail(err)
		}
		if err := rootDir(dir); err != nil {
			return fail(err)
		}
		p := filepath.Join(dir, "applygate.json")
		if old, err := os.ReadFile(p); err == nil && !exclusive && bytes.Contains(old, []byte(`"allowManagedHooksOnly": true`)) {
			// An upgrade keeps what the install it replaces had: running the
			// documented upgrade command must not turn user, project and
			// plugin hooks back on.
			exclusive = true
			fmt.Fprintln(stdout, "exclusive:     kept from the existing install (managed hooks only)")
		}
		out, err := json.MarshalIndent(claudeManaged(bin, exclusive), "", "  ")
		if err != nil {
			return fail(err)
		}
		if err := writeRootFile(p, append(out, '\n'), 0o644); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "Claude Code:   %s (hook, bypass mode off", p)
		if exclusive {
			fmt.Fprint(stdout, ", managed hooks only")
		}
		fmt.Fprintln(stdout, ")")
	}

	// 4. Codex: printed, not written. Its requirements.toml is
	// organisation policy, and the hook table is from the docs only.
	fmt.Fprintf(stdout, "\nCodex: add this to %s (from the Codex docs, not tested live):\n\n%s\n",
		filepath.Join(config.CodexManagedDir, "requirements.toml"), codexManaged(bin))

	fmt.Fprintf(stdout, "Repository configs trusted before are not carried over. In each repository, run:\n\n  %s\n\nThen check the install with: %s doctor\n", config.TrustCommand(), bin)
	return 0
}

func managedUninstall(purge bool, stdout, stderr io.Writer) int {
	paths := []string{config.ManagedBinary()}
	if config.ClaudeManagedDir != "" {
		paths = append(paths, filepath.Join(config.ClaudeManagedDir, "managed-settings.d", "applygate.json"))
	}
	if purge {
		paths = append(paths, config.SystemPath(), config.SystemTrustPath())
	}
	code := 0
	for _, p := range paths {
		switch err := os.Remove(p); {
		case err == nil:
			fmt.Fprintln(stdout, "removed", p)
		case errors.Is(err, os.ErrNotExist):
		default:
			fmt.Fprintln(stderr, "applygate:", err)
			code = 1
		}
	}
	if purge {
		os.Remove(config.SystemDir)
	} else {
		fmt.Fprintf(stdout, "kept %s; repository configs stay judged by its trust store (--purge removes it)\n", config.SystemDir)
	}
	fmt.Fprintf(stdout, "Codex: remove applygate's hook from %s yourself\n", filepath.Join(config.CodexManagedDir, "requirements.toml"))
	return code
}

// claudeManaged is the drop-in managed settings file: the hook, with bypass
// mode turned off, and with exclusive, no hooks but managed ones. The keys
// are from the Claude Code docs, read 2026-11-03.
func claudeManaged(bin string, exclusive bool) map[string]any {
	h := cmdEntry(fmt.Sprintf("%q hook claude", bin))
	h["onFailure"] = "block"
	doc := map[string]any{
		"hooks":       map[string]any{"PreToolUse": []any{map[string]any{"matcher": claudeMatcher, "hooks": []any{h}}}},
		"permissions": map[string]any{"disableBypassPermissionsMode": "disable"},
	}
	if exclusive {
		doc["allowManagedHooksOnly"] = true
	}
	return doc
}

// codexManaged is the requirements.toml snippet for Codex.
func codexManaged(bin string) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "[features]\nhooks = true\n\n[hooks]\nallow_managed_hooks_only = true\n\n")
	fmt.Fprintf(&b, "[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = '%q hook codex'\ntimeout = 30\n", bin)
	return b.String()
}

// rootDir creates dir, or takes over one that is already there: owned by
// root (when the install runs as root) and writable by root only. A
// directory others can write would let them replace the files in it.
func rootDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 0, 0); err != nil {
			return err
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	// The directories above must be root's too: one the agent's user can
	// write lets it rename this one aside and plant its own.
	if parent := filepath.Dir(dir); parent != dir {
		if err := config.CheckSystemDirs(parent); err != nil {
			return fmt.Errorf("%s cannot hold the managed install: %w", dir, err)
		}
	}
	return nil
}

// writeRootFile writes a file atomically with exactly this mode.
func writeRootFile(path string, b []byte, mode os.FileMode) error {
	if err := writeAtomic(path, b, mode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

// doctorManaged reports the managed install's state.
func doctorManaged(say func(bool, string, ...any)) {
	if !config.Managed() {
		say(true, "no managed install: an agent with your shell can change what you can (docs/managed.md)")
		return
	}
	check := func(what, p string) {
		err := config.CheckSystemFile(p)
		if err != nil {
			say(false, "managed %s: %v", what, err)
			return
		}
		say(true, "managed %s: %s, root-owned", what, p)
	}
	check("system config", config.SystemPath())
	bin := config.ManagedBinary()
	check("binary", bin)
	if self := selfPath(); self != bin {
		say(false, "this is %s, not the managed binary the managed hooks run (%s)", self, bin)
	}
	if config.ClaudeManagedDir != "" {
		p := filepath.Join(config.ClaudeManagedDir, "managed-settings.d", "applygate.json")
		check("Claude Code settings", p)
		if b, err := os.ReadFile(p); err == nil && !bytes.Contains(b, []byte(bin)) {
			say(false, "%s does not run %s", p, bin)
		} else if err == nil && !bytes.Contains(b, []byte(`"allowManagedHooksOnly": true`)) {
			say(false, "Claude Code runs user, project and plugin hooks next to the managed one, and one of them can change a call after applygate allowed it (run install --managed --exclusive)")
		}
	}
	if tp := config.SystemTrustPath(); fileExists(tp) {
		check("trust store", tp)
	} else {
		say(true, "managed trust store: no repository config trusted yet ("+config.TrustCommand()+")")
	}
	// The agent CLIs read the managed settings: one the agent's user can
	// replace (a native install in the home directory, a user-owned npm or
	// Homebrew prefix) can be swapped for a wrapper that turns the hook
	// off. The hook blocks the routes it sees; a root-owned install closes
	// the rest.
	for _, name := range []string{"claude", "codex"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if err := config.CheckSystemFile(real); err != nil {
			say(false, "%s at %s can be replaced by your user (%v): install it root-owned so the managed settings it reads hold (docs/managed.md)", name, real, err)
		} else {
			say(true, "%s: %s, root-owned", name, real)
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
