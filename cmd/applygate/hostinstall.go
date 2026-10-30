package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Flurit/applygate/internal/hook"
)

// installSpec says where and how `hook install` writes one agent's hook. The
// paths and entry shapes come from each host's documentation, recorded in
// review/host-research/2026-10-31-hook-contracts.md for the hosts other than
// Claude Code and Codex.
type installSpec struct {
	agent   string
	project string                   // relative to the current directory
	user    func(home string) string // user scope
	// kind is "json" for a settings file whose hooks object holds event
	// arrays, "opencode" for a plugin module and "cline" for a hook script.
	kind string
	// entries returns the entries to add per event, for kind json.
	entries func(cmd string) map[string]any
	version bool // the file needs a top-level "version": 1 (Cursor, Copilot)
	ownFile bool // applygate owns the whole file; remove deletes it when empty
	// Detection: directories under home and under the current directory, and
	// binaries on PATH, that show the agent is installed.
	homeDirs, projectDirs, bins []string
}

func cmdEntry(cmd string) map[string]any {
	return map[string]any{"type": "command", "command": cmd, "timeout": 30}
}

var installSpecs = []installSpec{
	{
		agent: "claude", project: filepath.Join(".claude", "settings.json"), kind: "json",
		user: func(h string) string { return filepath.Join(h, ".claude", "settings.json") },
		entries: func(cmd string) map[string]any {
			h := cmdEntry(cmd)
			// Block the tool call if the hook crashes or times out
			// (Claude Code v2.1.295+; older versions fail open).
			h["onFailure"] = "block"
			return map[string]any{"PreToolUse": map[string]any{"matcher": claudeMatcher, "hooks": []any{h}}}
		},
		homeDirs: []string{".claude"}, projectDirs: []string{".claude"}, bins: []string{"claude"},
	},
	{
		agent: "codex", project: filepath.Join(".codex", "hooks.json"), kind: "json",
		user: func(h string) string { return filepath.Join(h, ".codex", "hooks.json") },
		entries: func(cmd string) map[string]any {
			return map[string]any{"PreToolUse": map[string]any{"matcher": "*", "hooks": []any{cmdEntry(cmd)}}}
		},
		homeDirs: []string{".codex"}, projectDirs: []string{".codex"}, bins: []string{"codex"},
	},
	{
		// One preToolUse hook for shell, file and read tools. failClosed
		// makes a crash, timeout or missing binary block.
		agent: "cursor", project: filepath.Join(".cursor", "hooks.json"), kind: "json", version: true,
		user: func(h string) string { return filepath.Join(h, ".cursor", "hooks.json") },
		entries: func(cmd string) map[string]any {
			e := cmdEntry(cmd)
			e["matcher"], e["failClosed"] = "Shell|Write|Delete|Read|Grep", true
			return map[string]any{"preToolUse": e}
		},
		homeDirs: []string{".cursor"}, projectDirs: []string{".cursor"}, bins: []string{"cursor-agent"},
	},
	{
		// No matcher: every tool call reaches the hook, as with Codex.
		agent: "copilot", project: filepath.Join(".github", "hooks", "applygate.json"), kind: "json", version: true, ownFile: true,
		user: func(h string) string {
			if ch := os.Getenv("COPILOT_HOME"); ch != "" {
				return filepath.Join(ch, "hooks", "applygate.json")
			}
			return filepath.Join(h, ".copilot", "hooks", "applygate.json")
		},
		entries: func(cmd string) map[string]any {
			return map[string]any{"preToolUse": map[string]any{"type": "command", "bash": cmd, "powershell": "& " + cmd, "timeoutSec": 30}}
		},
		homeDirs: []string{".copilot"}, bins: []string{"copilot"},
	},
	{
		// Gemini matchers are unanchored regular expressions; the timeout is
		// in milliseconds.
		agent: "gemini", project: filepath.Join(".gemini", "settings.json"), kind: "json",
		user: func(h string) string { return filepath.Join(h, ".gemini", "settings.json") },
		entries: func(cmd string) map[string]any {
			h := map[string]any{"name": "applygate", "type": "command", "command": cmd, "timeout": 30000}
			return map[string]any{"BeforeTool": map[string]any{"matcher": "^(run_shell_command|write_file|replace|read_file|read_many_files)$", "hooks": []any{h}}}
		},
		homeDirs: []string{".gemini"}, projectDirs: []string{".gemini"}, bins: []string{"gemini"},
	},
	{
		agent: "windsurf", project: filepath.Join(".windsurf", "hooks.json"), kind: "json",
		user: func(h string) string { return filepath.Join(h, ".codeium", "windsurf", "hooks.json") },
		entries: func(cmd string) map[string]any {
			e := map[string]any{"command": cmd, "show_output": true}
			return map[string]any{"pre_run_command": e, "pre_write_code": e, "pre_read_code": e}
		},
		homeDirs: []string{filepath.Join(".codeium", "windsurf")}, projectDirs: []string{".windsurf"}, bins: []string{"windsurf"},
	},
	{
		// The matcher is the documented one: exec is the shell tool; the
		// names of Devin's file tools are not documented.
		agent: "devin", project: filepath.Join(".devin", "config.json"), kind: "json",
		user: func(h string) string { return filepath.Join(h, ".config", "devin", "config.json") },
		entries: func(cmd string) map[string]any {
			return map[string]any{"PreToolUse": map[string]any{"matcher": "^exec$", "hooks": []any{cmdEntry(cmd)}}}
		},
		homeDirs: []string{filepath.Join(".config", "devin")}, projectDirs: []string{".devin"}, bins: []string{"devin"},
	},
	{
		agent: "opencode", project: filepath.Join(".opencode", "plugins", "applygate.js"), kind: "opencode",
		user:     func(h string) string { return filepath.Join(h, ".config", "opencode", "plugins", "applygate.js") },
		homeDirs: []string{filepath.Join(".config", "opencode")}, projectDirs: []string{".opencode"}, bins: []string{"opencode"},
	},
	{
		agent: "cline", project: filepath.Join(".clinerules", "hooks", "PreToolUse"), kind: "cline",
		user:     func(h string) string { return filepath.Join(h, "Documents", "Cline", "Hooks", "PreToolUse") },
		homeDirs: []string{filepath.Join("Documents", "Cline")}, projectDirs: []string{".clinerules"}, bins: []string{"cline"},
	},
}

func specFor(agent string) (installSpec, bool) {
	for _, s := range installSpecs {
		if s.agent == agent {
			return s, true
		}
	}
	return installSpec{}, false
}

func settingsPath(agent, scope string) (string, error) {
	s, ok := specFor(agent)
	if ok {
		switch scope {
		case "project":
			return s.project, nil
		case "user":
			home, _ := os.UserHomeDir()
			return s.user(home), nil
		}
	}
	return "", fmt.Errorf("unsupported agent/scope %s/%s", agent, scope)
}

// opencodePlugin is the OpenCode plugin applygate installs. One default
// export serves both plugin APIs: OpenCode V1 (1.18.29 and later) calls
// server(), V2 calls setup(). Each tool call is sent to `applygate hook
// opencode`; anything but exit 0, a failure to start the binary included,
// throws, which blocks the call.
const opencodePlugin = `// applygate guard for OpenCode, written by "applygate hook install --agent opencode".
// Every tool call is checked by applygate before it runs; anything but exit 0 blocks it.
import { spawnSync } from "node:child_process"

// applygate-bin
const BIN = %s

function check(tool, sessionID, args, directory) {
  const event = { hook_event_name: "PreToolUse", tool_name: tool, tool_input: args ?? {}, cwd: directory, session_id: sessionID }
  const r = spawnSync(BIN, ["hook", "opencode"], { input: JSON.stringify(event), encoding: "utf8", timeout: 30000 })
  if (r.error) throw new Error("applygate: could not run the hook (" + r.error.message + "); blocked to fail closed")
  if (r.status !== 0) throw new Error((r.stderr || "").trim() || "applygate: hook exited " + r.status + "; blocked")
}

export default {
  id: "applygate",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", (event) => {
      check(event.tool, event.sessionID, event.input, ctx.location.directory)
    })
  },
  async server(input) {
    return {
      "tool.execute.before": async (i, o) => {
        check(i.tool, i.sessionID, o.args, input.directory)
      },
    }
  },
}
`

// clineScript is the Cline hook script. Cline lets a tool call run on any
// output that is not its JSON, so when applygate itself does not run (binary
// missing or killed) the script prints a cancel.
const clineScript = `#!/bin/sh
# applygate guard for Cline, written by "applygate hook install --agent cline".
# applygate-bin
%s hook cline && exit 0
printf '%%s\n' '{"cancel":true,"errorMessage":"applygate: the hook did not run (binary missing or crashed); cancelled to fail closed"}'
`

// The line after the applygate-bin marker names the binary: a JSON string in
// the OpenCode plugin, a single-quoted shell word in the Cline script.
var (
	pluginBin = regexp.MustCompile(`^const BIN = ("(?:[^"\\]|\\.)*")`)
	clineBin  = regexp.MustCompile(`^('(?:[^']|'\\'')*') hook cline`)
)

func scriptBinaries(b []byte) []string {
	s := string(b)
	i := strings.Index(s, "applygate-bin\n")
	if i < 0 {
		return nil
	}
	line := s[i+len("applygate-bin\n"):]
	if m := pluginBin.FindStringSubmatch(line); m != nil {
		var bin string
		if json.Unmarshal([]byte(m[1]), &bin) == nil {
			return []string{bin}
		}
	}
	if m := clineBin.FindStringSubmatch(line); m != nil {
		q := m[1][1 : len(m[1])-1]
		return []string{strings.ReplaceAll(q, `'\''`, `'`)}
	}
	return nil
}

func opencodePluginFor(bin string) string {
	q, _ := json.Marshal(bin)
	return fmt.Sprintf(opencodePlugin, q)
}

func clineScriptFor(bin string) string { return fmt.Sprintf(clineScript, shellSingleQuote(bin)) }

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isApplygateScript reports whether a plugin or hook script was written by
// applygate.
func isApplygateScript(b []byte) bool {
	return strings.Contains(string(b), "applygate-bin\n")
}

// fileHasApplygate reports whether an agent's hook file holds an applygate
// hook, whatever its kind.
func fileHasApplygate(agent string, b []byte) bool {
	if s, ok := specFor(agent); ok && s.kind != "json" {
		return isApplygateScript(b)
	}
	return settingsHasApplygate(b)
}

// hookBinaries returns the applygate binaries an agent's hook file calls.
func hookBinaries(agent string, b []byte) ([]string, bool) {
	if s, ok := specFor(agent); ok && s.kind != "json" {
		return scriptBinaries(b), true
	}
	scan, ok := scanHooks(b)
	// One file can hold an applygate entry per event (Windsurf has three).
	var bins []string
	for _, bin := range scan.applygateBins {
		if !contains(bins, bin) {
			bins = append(bins, bin)
		}
	}
	return bins, ok
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hookEntry(verb, agent, scope string, stdout, stderr io.Writer) int {
	spec, ok := specFor(agent)
	if !ok {
		fmt.Fprintf(stderr, "unsupported agent %q (supported: %s)\n", agent, strings.Join(hook.Agents, ", "))
		return 2
	}
	path, err := settingsPath(agent, scope)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if spec.kind != "json" {
		return scriptEntry(verb, spec, path, stdout, stderr)
	}
	doc := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &doc); err != nil {
			fmt.Fprintf(stderr, "%s is not valid JSON: %v\n", path, err)
			return 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	removed := 0
	for event, v := range hooks {
		list, isList := v.([]any)
		if !isList {
			continue
		}
		var kept []any
		for _, e := range list {
			if isApplygateEntry(e) {
				removed++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) > 0 {
			hooks[event] = kept
		} else {
			delete(hooks, event)
		}
	}
	if verb == "install" {
		for event, e := range spec.entries(fmt.Sprintf("%q hook %s", selfPath(), agent)) {
			list, _ := hooks[event].([]any)
			hooks[event] = append(list, e)
		}
		if spec.version {
			if _, has := doc["version"]; !has {
				doc["version"] = 1
			}
		}
	}
	if len(hooks) > 0 {
		doc["hooks"] = hooks
	} else {
		delete(doc, "hooks")
	}
	if verb != "install" {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return 0 // nothing to clean, nothing to write
		}
		if spec.ownFile && len(hooks) == 0 {
			if err := os.Remove(path); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			fmt.Fprintf(stdout, "removed %s (%d applygate hook entr%s)\n", path, removed, plural(removed))
			return 0
		}
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if verb == "install" {
		fmt.Fprintf(stdout, "installed applygate hook for %s in %s (replaced %d old entr%s)\n", agent, path, removed, plural(removed))
		for _, n := range hook.InstallNotes(agent) {
			fmt.Fprintln(stdout, n)
		}
	} else {
		fmt.Fprintf(stdout, "removed %d applygate hook entr%s from %s\n", removed, plural(removed), path)
	}
	return 0
}

// scriptEntry installs or removes the OpenCode plugin or the Cline hook
// script. A file at that path that applygate did not write is left alone.
func scriptEntry(verb string, spec installSpec, path string, stdout, stderr io.Writer) int {
	b, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ours := exists && isApplygateScript(b)
	if verb != "install" {
		if !ours {
			return 0
		}
		if err := os.Remove(path); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "removed applygate hook %s\n", path)
		return 0
	}
	if exists && !ours {
		fmt.Fprintf(stderr, "%s exists and was not written by applygate; not overwriting. Add a call to %q hook %s to it by hand, or move it aside and run install again\n", path, selfPath(), spec.agent)
		return 1
	}
	content, mode := opencodePluginFor(selfPath()), os.FileMode(0o644)
	if spec.kind == "cline" {
		content, mode = clineScriptFor(selfPath()), 0o755
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.Chmod(path, mode); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "installed applygate hook for %s in %s\n", spec.agent, path)
	for _, n := range hook.InstallNotes(spec.agent) {
		fmt.Fprintln(stdout, n)
	}
	return 0
}
