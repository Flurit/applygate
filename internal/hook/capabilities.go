package hook

//go:generate go run ../../cmd/gendocs -out ../../docs/hosts.md

import (
	"fmt"
	"io"
	"strings"
)

// Host records what one agent host can and cannot do with applygate's
// hook, as verified live or, for a DocsOnly host, as its documentation says. It is the single source for `applygate hosts`,
// docs/hosts.md (generated; TestHostsDocCurrent fails when it is stale) and
// the lines `hook install` and `init` print. A cell that was not verified
// says "not tested"; nothing here is a guess. Test numbers (T3.x) refer to
// review/manual_agent_tests.md and the results in review/T3_RESULTS.md.
type Host struct {
	Name      string // display name
	Agent     string // adapter name for `applygate hook <agent>`; "" when unsupported
	Supported bool

	CanAsk     string // can the host show an approval prompt for "ask"
	Failure    string // what happens when the hook crashes, times out or the binary is missing
	Tools      string // which tool calls the installed matcher sees
	CommandDir string // does the per-command working directory reach the hook
	Settings   string // where project settings are read from; user and managed levels
	Trust      string // trust step needed before the hook runs
	AskModes   string // behaviour of "ask" under the host's permission modes
	Verified   string // versions, platform and date of the live verification
	Evidence   []string
	Pending    string // live tests written but not yet run on this host
	// DocsOnly marks an adapter written from the host's documentation and
	// source without a live test. init does not install it on its own, and
	// every cell says "not tested live".
	DocsOnly bool
}

// Hosts is the capability table, in display order.
var Hosts = []Host{
	{
		Name: "Claude Code", Agent: "claude", Supported: true,
		CanAsk:     `yes: a hook "ask" shows Claude Code's permission prompt with applygate's reason (T3.1)`,
		Failure:    `fails closed: the installed hook carries onFailure: "block", so a crashed, timed-out (30 s) or missing hook blocks the tool call (T3.4 missing binary, T3.5 timeout, T3.6 killed by a signal); needs Claude Code 2.1.295 or later, older versions fail open`,
		Tools:      `shell: Bash; file writes: Write, Edit, MultiEdit, NotebookEdit; reads: Read, Grep; MCP calls: mcp__.* is in the matcher, each call is logged with its arguments (redacted, capped at 4 KB) and never judged; a hook installed before MCP logging lacks it and doctor says so. Cursor, Copilot CLI and Devin also load hooks from .claude/settings.json and may send their own tool names (Shell, exec); applygate judges those like that host's own calls: no ask, a block as exit 2 (from their docs, not tested live)`,
		CommandDir: `yes: the top-level cwd is the shell's directory at the time of the call and follows an earlier cd (hooks docs, read 2026-10-29); not tested live`,
		Settings:   `project: <session cwd>/.claude/settings.json and settings.local.json, read from the launch directory only, not from ancestors (T3.1: launched from a subdirectory the hook never ran); user: ~/.claude/settings.json (hook install --scope user); managed: managed-settings.json (docs; not tested)`,
		Trust:      `none observed for a project hook (T3.1); not tested further`,
		AskModes:   `default: prompt shown (T3.1); bypassPermissions: prompt still shown on 2.1.312, which is undocumented (T3.2b); dontAsk: no prompt can be shown, so applygate enforces ask as block (T3.2c); acceptEdits, plan: not tested`,
		Verified:   `Claude Code 2.1.312 on Linux, 2026-10-28; user-scope hook from a subdirectory (T3.9) on 2.1.314 on macOS 26.7.1, 2026-10-30`,
		Evidence:   []string{"review/T3_RESULTS.md", "docs/project/ACCEPTANCE.md"},
		Pending:    `none`,
	},
	{
		Name: "Codex", Agent: "codex", Supported: true,
		CanAsk:     `no: Codex parses but does not support "ask" (it fails the hook and runs the tool), so applygate enforces every ask as a block (T3.7 on 0.159.2 and 0.165.0)`,
		Failure:    `fails open: Codex has no onFailure setting; a missing hook binary (exit 127) and a hook killed by a signal both let the command run (T3.8 chaos on 0.165.0); timeout: not tested. applygate recovers panics inside its own process and blocks, so the remaining fail-open case is a hook that does not start; use Codex's sandbox and approval settings as the backstop and run applygate doctor`,
		Tools:      `matcher "*": shell: Bash with tool_input.command (captured); file writes: apply_patch with the patch text in tool_input.command (captured); reads: no separate read tool seen, Codex reads files through shell commands (not tested); MCP calls: mcp__<server>__<tool> with the raw arguments (from the source, not captured), logged with its arguments and never judged`,
		CommandDir: `no on 0.165.0 and 0.166.0; on 0.166.0 (captured 2026-10-30) a shell command's top-level cwd is its own directory, but tool_input still holds only command and the event names no version, so applygate keeps treating cwd as unconfirmed, which is correct for both versions; on 0.165.0: the top-level cwd is the session root and tool_input holds only command; the workdir the model passes to exec_command is dropped (captured 2026-10-29; source: exec_command.rs pre_tool_use_payload, hook_runtime.rs tool_hook_cwd). applygate reads tool_input.workdir, working_directory or cwd when a version sends one; otherwise it judges the command at the most protected tier under the session root (unknown_dir: most_protected, the default) and a cd or -chdir inside the command establishes the directory`,
		Settings:   `project: <session cwd>/.codex/hooks.json (hooks docs, read 2026-10-28; launching from a subdirectory not tested); user: ~/.codex/hooks.json (hook install --scope user; docs, not tested); managed: not tested`,
		Trust:      `yes: hooks must be reviewed and trusted with /hooks in Codex before they run (T3.7); codex exec has --dangerously-bypass-hook-trust (source, not tested)`,
		AskModes:   `no ask in any mode: every ask is enforced as a block (T3.7); permission_mode under codex exec arrives as bypassPermissions (captured)`,
		Verified:   `Codex 0.159.2 (T3.7) and 0.165.0 (chaos tests, clean re-run, hook input capture) on Linux, 2026-10-28 and 2026-10-29; 0.166.0 on macOS 26.7.1, 2026-10-30 (user-scope hooks.json loaded and fired, launched from the session root; the decision log's cwd followed the command's directory)`,
		Evidence:   []string{"review/T3_RESULTS.md", "review/agent-trial/results/2026-10-29-codex-hook-payload/README.md", "review/agent-trial/results/2026-10-30-codex-0.166.0-hook-payload/README.md", "docs/project/ACCEPTANCE.md"},
		Pending:    `T3.9 user-scope hook launched from a subdirectory: not tested; T3.10 verified on 0.166.0 only for a command run at the session root (blocked as protected); the subdirectory form arrives with the command's directory as cwd and is allowed as disposable; T3.11 planfile search: not exercised on 0.166.0 (the planfile was in the command's directory); hook timeout: not tested`,
	},
	{
		Name: "Cursor", Agent: "cursor", Supported: true, DocsOnly: true,
		CanAsk:     `no: "ask" is not enforced for preToolUse (docs) and is ignored in Cursor's run-everything modes (Cursor staff on the forum), so applygate enforces every ask as a block; from docs, not tested live`,
		Failure:    `fails closed by configuration: applygate installs the hook with failClosed: true, under which a crash, a timeout (30 s), a non-zero exit other than 2 or no output blocks; without failClosed these fail open (docs); not tested live. Open forum reports: hooks failing silently in cursor-agent on Linux, and never running (a hard deny) on Windows with Git Bash`,
		Tools:      `preToolUse with matcher Shell|Write|Delete|Read|Grep: shell: Shell with tool_input.command (documented by example); writes: Write, Delete (input fields not documented: applygate reads file_path, path and similar fields, else every one-line string argument); reads: Read, Grep; MCP calls: no; from docs, not tested live`,
		CommandDir: `yes on preToolUse: tool_input.working_directory (documented by example); a beforeShellExecution event's cwd is not documented as per-command and is treated as unconfirmed; from docs, not tested live`,
		Settings:   `project: <project root>/.cursor/hooks.json, run from the project root; user: ~/.cursor/hooks.json; enterprise: /Library/Application Support/Cursor/hooks.json, /etc/cursor/hooks.json; Cursor also runs hooks from Claude Code settings files while third-party hooks are on (the default); from docs, not tested live`,
		Trust:      `project hooks run only in a trusted workspace; cloud agents run project hooks only (docs); not tested live`,
		AskModes:   `no ask in any mode: every ask is enforced as a block. Whether a hook "allow" also skips Cursor's own approval prompt is not documented; applygate prints allow because failClosed treats no output as a failure; not tested live`,
		Verified:   `not verified live: written from cursor.com/docs/hooks, read 2026-10-30`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires, deny blocks, failClosed on a missing binary and on a timeout, working_directory, the Write tool's field names, the cursor-agent CLI`,
	},
	{
		Name: "Copilot CLI", Agent: "copilot", Supported: true, DocsOnly: true,
		CanAsk:     `yes in the interactive CLI (1.0.4 and later): "ask" shows Copilot's prompt; autopilot and the cloud agent turn ask into a deny (docs); not tested live`,
		Failure:    `fails closed except on timeout: exit 2 denies, and any other non-zero exit or a crash also denies (1.0.57 and later); a timeout (timeoutSec 30) fails open (docs); not tested live`,
		Tools:      `no matcher, every tool reaches the hook: shell: bash, powershell (toolArgs.command; PowerShell is parsed as POSIX shell); writes: create, edit, apply_patch, str_replace_editor; reads: view, glob, grep, rg; MCP and other tools: not inspected. toolArgs is a JSON string in the examples and is read either way; from docs, not tested live`,
		CommandDir: `no: the input's cwd is not documented as the command's directory, so applygate judges a command at the most protected tier under it (unknown_dir); from docs, not tested live`,
		Settings:   `project: .github/hooks/*.json (applygate writes .github/hooks/applygate.json; the cloud agent reads it from the default branch); user: ~/.copilot/hooks/*.json or $COPILOT_HOME/hooks; policy: /etc/github-copilot/policy.d/*.json; Copilot also reads hooks from .claude/settings*.json; from docs, not tested live`,
		Trust:      `repository hooks load only after folder trust (1.0.8 and later); disableAllHooks in repository settings turns off all but policy hooks (docs); not tested live`,
		AskModes:   `interactive: prompt shown; autopilot and the cloud agent: ask becomes deny (docs); not tested live`,
		Verified:   `not verified live: written from the docs.github.com Copilot CLI hooks reference and the changelog up to 1.0.105, read 2026-10-30`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires, deny and ask, a missing binary, a timeout, toolArgs as a string, the meaning of cwd, the cloud agent`,
	},
	{
		Name: "Gemini CLI", Agent: "gemini", Supported: true, DocsOnly: true,
		CanAsk:     `no: "ask" exists in the source but is not documented, so applygate enforces every ask as a block; from docs and source, not tested live`,
		Failure:    `fails open: a timeout, exit 1, a signal or a spawn error lets the tool run; a missing command (exit 127 with stderr) denies (source). applygate recovers panics in its own process and denies; not tested live`,
		Tools:      `BeforeTool with matcher ^(run_shell_command|write_file|replace|read_file|read_many_files)$: shell: run_shell_command (command, dir_path); writes: write_file, replace (file_path); reads: read_file, read_many_files; MCP calls: no; from docs and source, not tested live`,
		CommandDir: `yes: run_shell_command runs in tool_input.dir_path, relative to the project root, or else in the project root, which the input's cwd names (source); not tested live`,
		Settings:   `project: .gemini/settings.json; user: ~/.gemini/settings.json; system: /etc/gemini-cli/settings.json or /Library/Application Support/GeminiCli/settings.json; hooks from every level run; on by default since v0.27.0; from docs, not tested live`,
		Trust:      `hooks from settings files, user scope included, run only in trusted folders (folder trust is on by default); a new hook gets a one-time warning (source); not tested live`,
		AskModes:   `no ask in any mode: every ask is enforced as a block; not tested live`,
		Verified:   `not verified live: written from google-gemini/gemini-cli at a60946692b11 (main, 2026-10-30; the same contracts as v0.66.0)`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires in a trusted folder, deny blocks, dir_path, a missing binary, a timeout`,
	},
	{
		Name: "Windsurf (Cascade)", Agent: "windsurf", Supported: true, DocsOnly: true,
		CanAsk:     `no: Cascade hooks have no ask and no JSON output, so applygate enforces every ask as a block (docs); not tested live`,
		Failure:    `fails open: only exit 2 blocks; a crash, a missing binary or any other exit lets the action run; no timeout is documented (docs); not tested live`,
		Tools:      `pre_run_command (tool_info.command_line), pre_write_code (file_path), pre_read_code (file_path); MCP calls: no; from docs, not tested live`,
		CommandDir: `unconfirmed: tool_info.cwd is not documented as the command's own directory, so applygate judges a command at the most protected tier under it; from docs, not tested live`,
		Settings:   `project: .windsurf/hooks.json; user: ~/.codeium/windsurf/hooks.json (JetBrains: ~/.codeium/hooks.json, not written by applygate); system: /etc/windsurf/hooks.json; merged. Windsurf is now Devin Desktop and Cascade its legacy agent; Devin's own agent uses applygate hook devin; from docs, not tested live`,
		Trust:      `not documented; not tested`,
		AskModes:   `no ask in any mode: every ask is enforced as a block; not tested live`,
		Verified:   `not verified live: written from docs.windsurf.com/windsurf/cascade/hooks (archived copy of 2026-05-16)`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires, exit 2 blocks with the reason shown, tool_info.cwd`,
	},
	{
		Name: "Devin", Agent: "devin", Supported: true, DocsOnly: true,
		CanAsk:     `no: Devin hooks block or approve and have no ask (docs), so applygate enforces every ask as a block; not tested live`,
		Failure:    `fails open: exit 2 or {"decision": "block"} blocks; other exits, timeouts and unreadable output are logged and do not block (docs); not tested live`,
		Tools:      `PreToolUse with matcher ^exec$ (the documented example): shell: exec with tool_input.command; file writes and reads: not covered, their tool names are not documented; from docs, not tested live`,
		CommandDir: `no: the input names no directory; applygate uses DEVIN_PROJECT_DIR, else the hook's working directory, and judges a command at the most protected tier under it; from docs, not tested live`,
		Settings:   `project: .devin/config.json (the hooks key; .devin/hooks.v1.json also works and is not written by applygate); user: ~/.config/devin/config.json; Devin also reads hooks from .claude/settings*.json; from docs, not tested live`,
		Trust:      `hooks do not load in Restricted Mode, an untrusted workspace (docs); not tested live`,
		AskModes:   `no ask in any mode: every ask is enforced as a block; not tested live`,
		Verified:   `not verified live: written from docs.devin.ai/cli/extensibility/hooks, read 2026-10-30`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires in Devin CLI and Devin Local, exit 2 blocks, the hook's working directory`,
	},
	{
		Name: "OpenCode", Agent: "opencode", Supported: true, DocsOnly: true,
		CanAsk:     `no: the plugin can only let a call run or throw, so applygate enforces every ask as a block; from source, not tested live`,
		Failure:    `fails closed while the plugin is loaded: anything but exit 0 from applygate, a missing binary or a 30 s timeout throws, which blocks the call (source); a plugin that fails to load is logged and skipped, and then nothing is checked (fails open); not tested live`,
		Tools:      `every tool call goes to applygate: shell: bash (V1) or shell (V2) with command and workdir; writes: edit, write (filePath or path), apply_patch or patch (patchText); reads: read; MCP calls: not inspected; from source, not tested live`,
		CommandDir: `yes when the call names a workdir, resolved against the instance directory; otherwise the instance directory, unconfirmed; from source, not tested live`,
		Settings:   `project: .opencode/plugins/applygate.js; user: ~/.config/opencode/plugins/applygate.js; loaded at startup; one module serves the V1 (1.18.29 and later) and V2 plugin APIs; from source, not tested live`,
		Trust:      `none documented: local plugins load automatically; not tested`,
		AskModes:   `no ask in any mode: every ask is enforced as a block; not tested live`,
		Verified:   `not verified live: written from sst/opencode v1.19.5 and v2.2.4 source, read 2026-10-30`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the plugin loads in V1 and V2, a throw blocks, workdir, a missing binary`,
	},
	{
		Name: "Cline", Agent: "cline", Supported: true, DocsOnly: true,
		CanAsk:     `no: a hook can only cancel, so applygate enforces every ask as a block; from source, not tested live`,
		Failure:    `fails open on timeout (30 s in VS Code, 120 s in the CLI) and when the hook script is missing or not executable (source); the installed script turns a missing or crashed applygate binary into a cancel, and applygate prints a cancel for its own errors; not tested live. A cancel ends the whole task, not just the tool call`,
		Tools:      `every tool: shell: run_commands (commands) and legacy execute_command (command); writes: editor, apply_patch, write_to_file, replace_in_file; reads: read_files, read_file, search_codebase, search_files, list_files; MCP calls: not inspected; from source, not tested live`,
		CommandDir: `yes: commands run in the primary workspace root, the first of workspaceRoots; a legacy command that names another root with an "@name:" prefix is judged at the most protected tier; from source, not tested live`,
		Settings:   `project: .clinerules/hooks/PreToolUse, an executable file with no extension; user: ~/Documents/Cline/Hooks/PreToolUse; the CLI also scans ~/.cline/hooks and .cline/hooks; Windows (PreToolUse.ps1) is not supported by applygate's script; from source, not tested live`,
		Trust:      `none found in the source; hooks are on by default; not tested`,
		AskModes:   `no ask; the hook runs whether or not the call is auto-approved (source); not tested live`,
		Verified:   `not verified live: written from cline/cline v4.1.26 and cli-v3.0.74 source, read 2026-10-31`,
		Evidence:   []string{"review/host-research/2026-10-31-hook-contracts.md"},
		Pending:    `every live test: the hook fires in the VS Code extension and the CLI, cancel, a missing binary, the run_commands input shape`,
	},
}

// cells lists the capability rows in display order.
var cells = []struct {
	label string
	get   func(Host) string
}{
	{"Can ask", func(h Host) string { return h.CanAsk }},
	{"Hook crashes, times out or binary missing", func(h Host) string { return h.Failure }},
	{"Tools the installed matcher sees", func(h Host) string { return h.Tools }},
	{"Per-command working directory reaches the hook", func(h Host) string { return h.CommandDir }},
	{"Where settings are read from", func(h Host) string { return h.Settings }},
	{"Trust step", func(h Host) string { return h.Trust }},
	{"Ask under permission modes", func(h Host) string { return h.AskModes }},
	{"Verified on", func(h Host) string { return h.Verified }},
	{"Evidence", func(h Host) string { return strings.Join(h.Evidence, ", ") }},
	{"Live tests pending", func(h Host) string { return h.Pending }},
}

const notSupported = "not supported: no adapter, no hook format; nothing tested"

// HostFor returns the table entry for an adapter name.
func HostFor(agent string) (Host, bool) {
	for _, h := range Hosts {
		if h.Supported && h.Agent == agent {
			return h, true
		}
	}
	return Host{}, false
}

// InstallNotes are the lines `hook install` and `init` print after installing
// a hook for agent, taken from the table so the install output and the docs
// cannot drift apart.
func InstallNotes(agent string) []string {
	h, ok := HostFor(agent)
	if !ok {
		return nil
	}
	var out []string
	if h.DocsOnly {
		out = append(out, h.Name+": this adapter was written from "+h.Name+"'s documentation and has not been tested live. Check it once: ask the agent to run `terraform destroy -auto-approve` in an empty directory; applygate should block it (if it runs anyway, terraform finds nothing to destroy).")
	}
	if h.Agent == "codex" {
		out = append(out, "Codex asks you to review and trust new hooks: run /hooks in Codex once.")
	}
	out = append(out, h.Name+" when the hook crashes, times out or the binary is missing: "+h.Failure+".")
	if h.Agent == "codex" {
		out = append(out, "Codex command directory: "+h.CommandDir+".")
	}
	return out
}

// HostsText writes the table as plain text: one block per supported host,
// then the unsupported hosts.
func HostsText(w io.Writer) {
	for _, h := range Hosts {
		if !h.Supported {
			continue
		}
		note := ""
		if h.DocsOnly {
			note = ", from docs, not tested live"
		}
		fmt.Fprintf(w, "%s (applygate hook %s%s)\n", h.Name, h.Agent, note)
		for _, c := range cells {
			fmt.Fprintf(w, "  %-48s %s\n", c.label, wrap(c.get(h), 100, strings.Repeat(" ", 51)))
		}
		fmt.Fprintln(w)
	}
	var ns []string
	for _, h := range Hosts {
		if !h.Supported {
			ns = append(ns, h.Name)
		}
	}
	if len(ns) > 0 {
		fmt.Fprintf(w, "%s: %s.\n", strings.Join(ns, ", "), notSupported)
	}
	fmt.Fprintln(w, "Cells marked \"not tested\" were not verified live. The same table is docs/hosts.md.")
}

// HostsMarkdown renders docs/hosts.md: one table for the hosts verified live,
// then a section per host whose adapter was written from documentation.
func HostsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Host capabilities\n\n")
	b.WriteString("<!-- Generated from internal/hook/capabilities.go by `go generate ./internal/hook`. Do not edit by hand; TestHostsDocCurrent fails when this file is stale. -->\n\n")
	b.WriteString("What each agent host does with applygate's hook. `applygate hosts` prints the same table. A cell that says \"not tested\" was not verified; nothing in this table is a guess. T3 numbers refer to the cases in [review/manual_agent_tests.md](../review/manual_agent_tests.md) and the results in [review/T3_RESULTS.md](../review/T3_RESULTS.md).\n\n")
	var live, docs []Host
	for _, h := range Hosts {
		switch {
		case h.Supported && h.DocsOnly:
			docs = append(docs, h)
		case h.Supported:
			live = append(live, h)
		}
	}
	b.WriteString("## Verified live\n\n| Capability |")
	for _, h := range live {
		fmt.Fprintf(&b, " %s (`applygate hook %s`) |", h.Name, h.Agent)
	}
	b.WriteString("\n|---|")
	for range live {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s |", c.label)
		for _, h := range live {
			fmt.Fprintf(&b, " %s |", mdCell(c.get(h)))
		}
		b.WriteString("\n")
	}
	if len(docs) > 0 {
		b.WriteString("\n## From documentation, not tested live\n\n")
		b.WriteString("These adapters were written from each host's documentation and, where it is open source, its source code, read on 2026-10-30 and 2026-10-31 and recorded with links in [review/host-research/2026-10-31-hook-contracts.md](../review/host-research/2026-10-31-hook-contracts.md). None has been run inside its host. `applygate init` does not install them on its own; install one with `applygate hook install --agent NAME`. A cell moves to verified only with a live test recorded in review/T3_RESULTS.md.\n")
		for _, h := range docs {
			fmt.Fprintf(&b, "\n### %s (`applygate hook %s`)\n\n| Capability | |\n|---|---|\n", h.Name, h.Agent)
			for _, c := range cells {
				fmt.Fprintf(&b, "| %s | %s |\n", c.label, mdCell(c.get(h)))
			}
		}
	}
	var ns []string
	for _, h := range Hosts {
		if !h.Supported {
			ns = append(ns, h.Name)
		}
	}
	if len(ns) > 0 {
		b.WriteString("\n## Not supported\n\n| Host | Status |\n|---|---|\n")
		for _, n := range ns {
			fmt.Fprintf(&b, "| %s | %s |\n", n, notSupported)
		}
	}
	b.WriteString("\nHow applygate handles an unknown command directory is in [policy.md](policy.md) (step 4) and [config.md](config.md) (`unknown_dir`); the launch-directory and fail-open limits are in [limits.md](limits.md).\n")
	return b.String()
}

func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

// wrap breaks s into lines of at most width characters at spaces and indents
// every line but the first.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for i, w := range words {
		if i > 0 && line+1+len(w) > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}
