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
# trusted with "sudo applygate trust".
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
		fmt.Fprintf(stderr, "applygate: the managed install writes root-owned files: run sudo applygate %s --managed\n", verb)
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
	if err := os.MkdirAll(config.ManagedBinDir, 0o755); err != nil {
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
	if err := os.MkdirAll(config.SystemDir, 0o755); err != nil {
		return fail(err)
	}
	if err := os.Chmod(config.SystemDir, 0o755); err != nil {
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
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fail(err)
		}
		p := filepath.Join(dir, "applygate.json")
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

	fmt.Fprintf(stdout, "Repository configs trusted before are not carried over. In each repository, run:\n\n  sudo %s trust\n\nThen check the install with: %s doctor\n", bin, bin)
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

// writeRootFile writes a file atomically with exactly this mode.
func writeRootFile(path string, b []byte, mode os.FileMode) error {
	if err := writeAtomic(path, b, mode); err != nil {
		return err
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
		}
	}
	if tp := config.SystemTrustPath(); fileExists(tp) {
		check("trust store", tp)
	} else {
		say(true, "managed trust store: no repository config trusted yet (sudo applygate trust)")
	}
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}
