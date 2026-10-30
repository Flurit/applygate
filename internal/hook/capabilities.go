package hook

//go:generate go run ../../cmd/gendocs -out ../../docs/hosts.md

import (
	"fmt"
	"io"
	"strings"
)

// Host records what one agent host can and cannot do with a PreToolUse
// hook, as verified live. It is the single source for `applygate hosts`,
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
}

// Hosts is the capability table, in display order.
var Hosts = []Host{
	{
		Name: "Claude Code", Agent: "claude", Supported: true,
		CanAsk:     `yes: a hook "ask" shows Claude Code's permission prompt with applygate's reason (T3.1)`,
		Failure:    `fails closed: the installed hook carries onFailure: "block", so a crashed, timed-out (30 s) or missing hook blocks the tool call (T3.4 missing binary, T3.5 timeout, T3.6 killed by a signal); needs Claude Code 2.1.295 or later, older versions fail open`,
		Tools:      `shell: Bash; file writes: Write, Edit, MultiEdit, NotebookEdit; reads: Read, Grep; MCP calls: no (not in the matcher, not inspected)`,
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
		Tools:      `matcher "*": shell: Bash with tool_input.command (captured); file writes: apply_patch with the patch text in tool_input.command (captured); reads: no separate read tool seen, Codex reads files through shell commands (not tested); MCP calls: mcp__<server>__<tool> with the raw arguments (from the source, not captured), not inspected`,
		CommandDir: `no on 0.165.0 and 0.166.0; on 0.166.0 (captured 2026-10-30) a shell command's top-level cwd is its own directory, but tool_input still holds only command and the event names no version, so applygate keeps treating cwd as unconfirmed, which is correct for both versions; on 0.165.0: the top-level cwd is the session root and tool_input holds only command; the workdir the model passes to exec_command is dropped (captured 2026-10-29; source: exec_command.rs pre_tool_use_payload, hook_runtime.rs tool_hook_cwd). applygate reads tool_input.workdir, working_directory or cwd when a version sends one; otherwise it judges the command at the most protected tier under the session root (unknown_dir: most_protected, the default) and a cd or -chdir inside the command establishes the directory`,
		Settings:   `project: <session cwd>/.codex/hooks.json (hooks docs, read 2026-10-28; launching from a subdirectory not tested); user: ~/.codex/hooks.json (hook install --scope user; docs, not tested); managed: not tested`,
		Trust:      `yes: hooks must be reviewed and trusted with /hooks in Codex before they run (T3.7); codex exec has --dangerously-bypass-hook-trust (source, not tested)`,
		AskModes:   `no ask in any mode: every ask is enforced as a block (T3.7); permission_mode under codex exec arrives as bypassPermissions (captured)`,
		Verified:   `Codex 0.159.2 (T3.7) and 0.165.0 (chaos tests, clean re-run, hook input capture) on Linux, 2026-10-28 and 2026-10-29; 0.166.0 on macOS 26.7.1, 2026-10-30 (user-scope hooks.json loaded and fired, launched from the session root; the decision log's cwd followed the command's directory)`,
		Evidence:   []string{"review/T3_RESULTS.md", "review/agent-trial/results/2026-10-29-codex-hook-payload/README.md", "review/agent-trial/results/2026-10-30-codex-0.166.0-hook-payload/README.md", "docs/project/ACCEPTANCE.md"},
		Pending:    `T3.9 user-scope hook launched from a subdirectory: not tested; T3.10 bare command in a disposable subdirectory under a root with a protected directory: not reproduced on 0.166.0 (the command's directory reached the hook), not tested on 0.141.0; T3.11 planfile search: not exercised on 0.166.0 (the planfile was in the command's directory); hook timeout: not tested`,
	},
	{Name: "Cursor", Supported: false},
	{Name: "Copilot CLI", Supported: false},
	{Name: "OpenCode", Supported: false},
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
		fmt.Fprintf(w, "%s (applygate hook %s)\n", h.Name, h.Agent)
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
	fmt.Fprintf(w, "%s: %s.\n", strings.Join(ns, ", "), notSupported)
	fmt.Fprintln(w, "Cells marked \"not tested\" were not verified live. The same table is docs/hosts.md.")
}

// HostsMarkdown renders docs/hosts.md.
func HostsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Host capabilities\n\n")
	b.WriteString("<!-- Generated from internal/hook/capabilities.go by `go generate ./internal/hook`. Do not edit by hand; TestHostsDocCurrent fails when this file is stale. -->\n\n")
	b.WriteString("What each agent host does with applygate's PreToolUse hook, as verified live. `applygate hosts` prints the same table. A cell that says \"not tested\" was not verified; nothing in this table is a guess. T3 numbers refer to the cases in [review/manual_agent_tests.md](../review/manual_agent_tests.md) and the results in [review/T3_RESULTS.md](../review/T3_RESULTS.md).\n\n")
	var sup []Host
	for _, h := range Hosts {
		if h.Supported {
			sup = append(sup, h)
		}
	}
	b.WriteString("| Capability |")
	for _, h := range sup {
		fmt.Fprintf(&b, " %s (`applygate hook %s`) |", h.Name, h.Agent)
	}
	b.WriteString("\n|---|")
	for range sup {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s |", c.label)
		for _, h := range sup {
			fmt.Fprintf(&b, " %s |", mdCell(c.get(h)))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Not supported\n\n| Host | Status |\n|---|---|\n")
	for _, h := range Hosts {
		if !h.Supported {
			fmt.Fprintf(&b, "| %s | %s |\n", h.Name, notSupported)
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
