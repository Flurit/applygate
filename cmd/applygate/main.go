// Command applygate is a deterministic pre-execution check for coding agents
// that touch Terraform or OpenTofu infrastructure.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/harness"
	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/hook"
	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
	"github.com/Flurit/applygate/internal/telemetry"
)

const usage = `applygate: allow / ask / block for agent actions on Terraform and OpenTofu

Usage:
  applygate hook AGENT                 read one hook event on stdin (used by the agent); AGENT is
                                      claude, codex, cursor, copilot, gemini, windsurf, devin, opencode
                                      or cline (applygate hosts says what each was verified on)
  applygate check [--cwd DIR] [--dir-unknown] [--json] "<command>"
                                      dry-run a command through the policy
  applygate explain [--cwd DIR] [--dir-unknown] "<command>"
                                      show the parse, classification and decision trace
  applygate plan-check [--tier T] [--cwd DIR] <plan.json>
                                      evaluate "terraform show -json" output
  applygate apply [--cwd DIR] [--engine terraform|tofu] [--yes] <planfile> [args]
                                      judge a saved plan as the hooks would, confirm an ask by typing the
                                      environment name, then run the engine's apply (the human door)
  applygate approve [ID]               allow one call an agent was stopped on because it could not ask you;
                                      without ID, list the pending requests (a person at a terminal only)
  applygate report [--log FILE]        summarize the decision log
  applygate suggest [--log FILE] [--root DIR] [--out FILE]
                                      propose a .applygate.yaml from the observe-mode log: environments
                                      from the directories and signals seen, asks and blocks to review
  applygate selftest [-v]              run the scenario pack against this binary
  applygate init [--no-hooks] [--scope user|project]
                                      write a starter .applygate.yaml, detect agents, install their hooks (user scope)
  applygate hook install|remove --agent AGENT [--scope project|user]
                                      install defaults to project scope; remove cleans both scopes
  applygate doctor                     check config, hooks, launch directory and versions (exit 1 on a problem)
  applygate hosts [--markdown]         what each agent host can do with the hook (same table as docs/hosts.md)
  applygate telemetry status|on|off|send
                                      anonymous usage counts, off unless you turn them on (docs/telemetry.md)
  applygate version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "hook":
		if len(args) > 1 && (args[1] == "install" || args[1] == "remove" || args[1] == "uninstall") {
			return cmdInstall(args[1], args[2:], stdout, stderr)
		}
		return cmdHook(args[1:], stdin, stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr, false)
	case "explain":
		return cmdCheck(args[1:], stdout, stderr, true)
	case "plan-check":
		return cmdPlanCheck(args[1:], stdout, stderr)
	case "apply":
		return cmdApply(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "approve":
		return cmdApprove(args[1:], stdin, stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "suggest":
		return cmdSuggest(args[1:], stdout, stderr)
	case "selftest":
		return cmdSelftest(args[1:], stdout, stderr)
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "doctor":
		return cmdDoctor(stdout, stderr)
	case "telemetry":
		return cmdTelemetry(args[1:], stdout, stderr)
	case "hosts":
		if len(args) > 1 && args[1] == "--markdown" {
			io.WriteString(stdout, hook.HostsMarkdown())
			return 0
		}
		hook.HostsText(stdout)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "applygate", hook.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var planJSON multiFlag
	fs.Var(&planJSON, "plan-json", "PLANFILE=JSON: use this JSON for a saved plan (replay/testing only)")
	noLog := fs.Bool("no-log", false, "do not write the decision log (testing only)")
	if len(args) == 0 {
		fmt.Fprintf(stderr, "applygate hook: agent name required (%s)\n", strings.Join(hook.Agents, ", "))
		return 2
	}
	agent := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	a, err := hook.ForAgent(agent)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	opt := hook.Options{UserConfig: config.UserPath(), Env: hook.EnvMap(), NoLog: *noLog}
	if !*noLog {
		opt.Approvals = config.ApprovalsPath()
	}
	if len(planJSON) > 0 {
		m := map[string]string{}
		for _, kv := range planJSON {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		opt.PlanJSON = func(engine, dir, planfile string) ([]byte, error) {
			p, ok := m[planfile]
			if !ok {
				return nil, fmt.Errorf("no --plan-json for %s", planfile)
			}
			return os.ReadFile(p)
		}
	}
	o := hook.Run(a, stdin, opt)
	stdout.Write(o.Stdout)
	io.WriteString(stderr, o.Stderr)
	// The verdict is out. Usage counts, if the person turned them on, go
	// after it and are bounded, so they can neither delay nor change it.
	if o.LogPath != "" {
		telemetry.AfterDecision(o.LogPath, hook.Version, opt.Env)
	}
	return o.Exit
}

func cmdCheck(args []string, stdout, stderr io.Writer, explain bool) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "working directory the command runs in (default: current)")
	dirUnknown := fs.Bool("dir-unknown", false, "treat --cwd as the session root only, as a host that does not report the command directory would (Codex 0.165.0); see docs/hosts.md")
	agent := fs.String("agent", "cli", "host name recorded in the decision (claude, codex, cursor, ...)")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	noJudge := fs.Bool("no-judge", false, "do not ask the model judge even when the user config turns it on")
	var planJSON multiFlag
	fs.Var(&planJSON, "plan-json", "PLANFILE=JSON: use this JSON for a saved plan instead of running show")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "expected exactly one quoted command")
		return 2
	}
	dir := *cwd
	if dir == "" {
		dir, _ = os.Getwd()
	}
	dir, _ = filepath.Abs(dir)
	cfg, err := config.Load(config.UserPath(), dir)
	if err != nil {
		fmt.Fprintln(stderr, "config error:", err)
		return 2
	}
	opt := hook.Options{Env: hook.EnvMap()}
	if len(planJSON) > 0 {
		m := map[string]string{}
		for _, kv := range planJSON {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		opt.PlanJSON = func(_, _, planfile string) ([]byte, error) {
			if p, ok := m[planfile]; ok {
				return os.ReadFile(p)
			}
			return nil, fmt.Errorf("no --plan-json for %s", planfile)
		}
	}
	ev := policy.Event{Agent: *agent, Tool: "Bash", Kind: policy.KindShell, Command: fs.Arg(0), Cwd: dir, CanAsk: true, DirKnown: !*dirUnknown}
	deps := hook.Deps(context.Background(), cfg, opt)
	if explain {
		res := shell.Analyze(ev.Command, shell.Options{Dir: dir, Env: opt.Env, Aliases: cfg.Aliases, Wrappers: cfg.ShellWrappers(), ProtectedPaths: cfg.GuardPaths(), ProtectedPath: func(p string) bool { return classify.IsProtectedPath(p, cfg.GuardPaths()) }})
		fmt.Fprintf(stdout, "config: %s\n", orNone(strings.Join(cfg.Sources, ", ")))
		for _, d := range cfg.Deprecations {
			fmt.Fprintf(stdout, "note: %s\n", d)
		}
		fmt.Fprintf(stdout, "mode: %s, strict: %v\n\n1. parse: %d invocation(s), %d unresolved construct(s)\n", cfg.Mode, cfg.IsStrict(), len(res.Invocations), len(res.Problems))
		for _, inv := range res.Invocations {
			var ws []string
			for _, w := range inv.Args {
				if w.Resolved {
					ws = append(ws, fmt.Sprintf("%q", w.Text))
				} else {
					ws = append(ws, "<unresolved "+fmt.Sprintf("%q", w.Prefix)+"...>")
				}
			}
			fmt.Fprintf(stdout, "   - [%s] in %s", strings.Join(ws, " "), orNone(inv.Dir))
			if len(inv.Via) > 0 {
				fmt.Fprintf(stdout, " via %s", strings.Join(inv.Via, " > "))
			}
			fmt.Fprintln(stdout)
		}
		for _, p := range res.Problems {
			fmt.Fprintf(stdout, "   - UNRESOLVED: %s: %s\n", p.Reason, p.Text)
		}
		for _, n := range res.Notes {
			fmt.Fprintf(stdout, "   - NOTE: %s\n", n)
		}
		acts := classify.Invocations(res, classify.Options{ProtectedPaths: cfg.GuardPaths(), Home: opt.Env["HOME"]})
		fmt.Fprintf(stdout, "\n2. classify: %d policy-relevant action(s)\n", len(acts))
		for _, a := range acts {
			fmt.Fprintf(stdout, "   - %s: %s (%s)\n", a.Class, a.Command, a.Why)
		}
		fmt.Fprintln(stdout, "\n3. decide:")
	}
	d := policy.Decide(ev, cfg, deps)
	if !*noJudge {
		var jr *decisionlog.Judge
		jctx, cancel := context.WithTimeout(context.Background(), cfg.JudgeTimeout()+time.Second)
		d, jr = hook.Judge(jctx, ev, d, cfg, opt)
		cancel()
		if jr != nil {
			if explain {
				fmt.Fprintf(stdout, "   model judge (%s): %s %s%s\n", orNone(jr.Model), orNone(string(jr.Verdict)), jr.Reason, jr.Error)
			} else if jr.Error != "" {
				fmt.Fprintln(stderr, "model judge:", jr.Error)
			}
		}
	}
	if *asJSON || explain {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(d)
	} else {
		fmt.Fprintf(stdout, "%s\n", d.Enforced)
		if d.Message != "" {
			fmt.Fprintln(stdout, d.Message)
		}
	}
	switch d.Enforced {
	case policy.Block:
		return 3
	case policy.Ask:
		return 4
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func cmdPlanCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tier := fs.String("tier", "", "tier to evaluate for (default: resolved from --cwd)")
	cwd := fs.String("cwd", "", "directory for tier and backend resolution (default: current)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "expected a plan JSON file (terraform show -json tfplan > plan.json)")
		return 2
	}
	js, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	dir := *cwd
	if dir == "" {
		dir, _ = os.Getwd()
	}
	dir, _ = filepath.Abs(dir)
	cfg, err := config.Load(config.UserPath(), dir)
	if err != nil {
		fmt.Fprintln(stderr, "config error:", err)
		return 2
	}
	t := config.Tier(*tier)
	if t == "" {
		t = cfg.Resolve(config.Signals{Dir: dir}).Tier
	}
	res, err := plangate.Evaluate(plangate.Input{PlanJSON: js, MaxDestroy: cfg.MaxDestroy(t), Scope: cfg.PlanGate.Scope, Protected: cfg.ProtectedResources, Backend: preflight.InitBackend(dir)}, plangate.DefaultRules())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	v := policy.Allow
	if len(res.Deletes) > 0 {
		v = policy.Table["destroy"][t]
	}
	for _, f := range res.Findings {
		v = policy.Max(v, policy.FindingVerdict(f.Severity, t))
	}
	fmt.Fprintf(stdout, "tier %s: %s (%d changes, %d deletes, %d replaces)\n", t, v, res.Changes, len(res.Deletes), len(res.Replaces))
	for _, f := range res.Findings {
		fmt.Fprintf(stdout, "- %s %s: %s\n", f.Severity, f.Rule, f.Message)
		for _, e := range f.Evidence {
			fmt.Fprintf(stdout, "    %s\n", e)
		}
	}
	switch v {
	case policy.Block:
		return 3
	case policy.Ask:
		return 4
	}
	return 0
}

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("log", "", "decision log (default: from config)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p := *path
	if p == "" {
		cfg, err := config.Load(config.UserPath(), "")
		if err == nil && cfg.LogPath != "" {
			p = cfg.LogPath
		} else {
			p = config.DefaultLogPath()
		}
	}
	f, err := os.Open(p)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer f.Close()
	fmt.Fprintf(stdout, "log: %s\n", p)
	entries, bad := decisionlog.Read(f)
	decisionlog.Report(stdout, entries, bad)
	return 0
}

func cmdSelftest(args []string, stdout, stderr io.Writer) int {
	verbose := len(args) > 0 && args[0] == "-v"
	p, err := harness.Load()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	dir, err := os.MkdirTemp("", "applygate-selftest-")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	start := time.Now()
	out, err := harness.Replay(p, dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	failed := 0
	for _, o := range out {
		mark := "ok  "
		if !o.Pass {
			mark = "FAIL"
			failed++
		}
		if verbose || !o.Pass {
			fmt.Fprintf(stdout, "%s %s %-5s %s\n", mark, o.Scenario.ID, o.Verdict, o.Scenario.Title)
		}
	}
	s := harness.Score(out)
	fmt.Fprintf(stdout, "scenario pack v%d: dangerous caught %d/%d, benign flagged %d/%d, exact expectation %d/%d, %s\n",
		p.Version, s.DangerousCaught, s.Dangerous, s.BenignFlagged, s.Benign, s.DangerousExact+s.BenignExact, len(out), time.Since(start).Round(time.Millisecond))
	if failed > 0 {
		return 1
	}
	return 0
}

const starterConfig = `# applygate config. https://github.com/Flurit/applygate/blob/main/docs/config.md
version: 1
# Start in observe mode: decisions are logged but nothing is blocked.
# Run "applygate report" after a few days, then switch to enforce.
mode: observe
# Unknown environments are treated as protected.
strict: true
# What happens when applygate itself fails: auto blocks in protected tiers.
on_error: auto
environments:
  - name: prod
    tier: protected
    match:
      paths: ["envs/prod/**"]
      workspaces: ["prod", "production"]
      aws_profiles: ["prod*"]
  - name: staging
    tier: standard
    match:
      paths: ["envs/staging/**"]
      workspaces: ["staging"]
  - name: dev
    tier: disposable
    match:
      paths: ["envs/dev/**"]
      workspaces: ["dev"]
plan_gate:
  max_destroy: {protected: 0}
# Resource addresses whose destroy or replace is always critical, whatever
# their type (globs on the Terraform address).
# protected_resources: ["aws_instance.bastion", "module.data.*"]
`

// cmdInit writes the starter config, detects installed agents and installs
// their hooks at user scope (the spec's "init" command), so the hook fires
// whichever directory of the repository the agent is launched from.
// --scope project keeps the old behaviour; --no-hooks skips the hook step.
func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	noHooks := fs.Bool("no-hooks", false, "write the config only; do not detect agents or install hooks")
	scope := fs.String("scope", "user", "where to install the hooks: user (fires from any directory) or project (this directory's settings only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scope != "user" && *scope != "project" {
		fmt.Fprintf(stderr, "--scope must be user or project, not %q\n", *scope)
		return 2
	}
	if _, err := os.Stat(config.FileName); err == nil {
		fmt.Fprintf(stderr, "%s already exists; not overwriting\n", config.FileName)
		return 1
	}
	if err := os.WriteFile(config.FileName, []byte(starterConfig), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (observe mode). Edit the environments to match this repository.\n", config.FileName)
	if *noHooks {
		fmt.Fprintln(stdout, "hooks not installed (--no-hooks). Later: applygate hook install --agent AGENT")
		return 0
	}
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	detected := detectAgents(home, wd, exec.LookPath)
	if len(detected) == 0 {
		fmt.Fprintf(stdout, "no coding agent detected (looked for %s). Install a hook later with: applygate hook install --agent AGENT\n", strings.Join(hook.Agents, ", "))
		return 0
	}
	fmt.Fprintf(stdout, "detected agents: %s\n", strings.Join(detected, ", "))
	// init installs only hooks verified live. An adapter written from a
	// host's documentation is installed on request, so a mistake in it
	// cannot block a host the person did not choose to guard.
	var agents []string
	for _, a := range detected {
		if h, ok := hook.HostFor(a); ok && h.DocsOnly {
			fmt.Fprintf(stdout, "%s: not installed by init, because its adapter was written from %s's documentation and not tested live. Install it with: applygate hook install --agent %s --scope %s\n", a, h.Name, a, *scope)
			continue
		}
		agents = append(agents, a)
	}
	if *scope == "user" && len(agents) > 0 {
		fmt.Fprintln(stdout, "installing the hooks at user scope (~/.claude/settings.json, ~/.codex/hooks.json): a project-scope hook is loaded only when the agent is launched from this directory, a user-scope hook fires from any directory of any repository. Repositories without a .applygate.yaml are judged by the user config or the defaults (enforce, strict). Use --scope project for a hook that lives in this repository only.")
	}
	rc := 0
	for _, a := range agents {
		if r := cmdInstall("install", []string{"--agent", a, "--scope", *scope}, stdout, stderr); r != 0 {
			rc = r
		}
		if *scope == "user" {
			if rel, err := settingsPath(a, "project"); err == nil {
				if b, err := os.ReadFile(rel); err == nil && settingsHasApplygate(b) {
					fmt.Fprintf(stdout, "note: %s also has a project-scope applygate hook; both will run here. Remove one with: applygate hook remove --agent %s --scope project\n", rel, a)
				}
			}
		}
	}
	fmt.Fprintln(stdout, "run: applygate doctor")
	return rc
}

// detectAgents returns the agents that look installed for this user or
// repository: a user or project settings directory, or the CLI on PATH.
func detectAgents(home, wd string, lookPath func(string) (string, error)) []string {
	isDir := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.IsDir()
	}
	var out []string
	for _, s := range installSpecs {
		found := false
		for _, d := range s.homeDirs {
			found = found || isDir(filepath.Join(home, d))
		}
		for _, d := range s.projectDirs {
			found = found || isDir(filepath.Join(wd, d))
		}
		for _, b := range s.bins {
			if !found && lookPath != nil {
				if _, err := lookPath(b); err == nil {
					found = true
				}
			}
		}
		if found {
			out = append(out, s.agent)
		}
	}
	return out
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return "applygate"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// cmdInstall installs or removes the hook entry. install defaults to project
// scope (the settings file in the current directory; see docs/limits.md for
// why init prefers user scope); remove without --scope cleans both scopes.
func cmdInstall(verb string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "claude", strings.Join(hook.Agents, ", "))
	scope := fs.String("scope", "", "project (the hook file in this directory, the default for install) or user (the agent's home configuration, fires from any directory); remove without --scope cleans both")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if verb != "install" && *scope == "" {
		rc := 0
		for _, sc := range []string{"project", "user"} {
			if r := hookEntry(verb, *agent, sc, stdout, stderr); r != 0 {
				rc = r
			}
		}
		return rc
	}
	if *scope == "" {
		*scope = "project"
	}
	return hookEntry(verb, *agent, *scope, stdout, stderr)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// entryCommands returns the commands of a hook entry: the nested
// hooks[].command form (Claude Code, Codex, Gemini CLI, Devin) and the flat
// command, bash or powershell fields (Cursor, Copilot CLI, Windsurf).
func entryCommands(e any) []string {
	m, _ := e.(map[string]any)
	var out []string
	add := func(h map[string]any) {
		for _, k := range []string{"command", "bash", "powershell"} {
			if c, _ := h[k].(string); c != "" {
				out = append(out, c)
			}
		}
	}
	add(m)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		add(hm)
	}
	return out
}

func isApplygateEntry(e any) bool {
	for _, c := range entryCommands(e) {
		if (strings.Contains(c, "applygate") || strings.Contains(c, "seatbelt")) && strings.Contains(c, " hook ") {
			return true
		}
	}
	return false
}

// hookLists returns the event arrays of a settings document's hooks object.
func hookLists(doc map[string]any) map[string][]any {
	out := map[string][]any{}
	hooks, _ := doc["hooks"].(map[string]any)
	for event, v := range hooks {
		if list, ok := v.([]any); ok {
			out[event] = list
		}
	}
	return out
}

// settingsHasApplygate reports whether a settings file's hooks include an
// applygate entry, under any event.
func settingsHasApplygate(b []byte) bool {
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	for _, list := range hookLists(doc) {
		for _, e := range list {
			if isApplygateEntry(e) {
				return true
			}
		}
	}
	return false
}

// applygateHookDir searches cwd and its ancestors for a project settings file
// (rel, e.g. .claude/settings.json) that contains a applygate hook, and returns
// the directory that holds it, or "" if none is found.
func applygateHookDir(cwd, rel string) string {
	dir := cwd
	for {
		if b, err := os.ReadFile(filepath.Join(dir, rel)); err == nil && settingsHasApplygate(b) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// launchDirCheck is one finding of launchDirChecks.
type launchDirCheck struct {
	fail bool
	msg  string
}

// launchDirChecks looks at where each agent's applygate hook lives relative to
// cwd. Claude Code and Codex read project settings only from the directory
// the session is launched in, so a project-scope hook in an ancestor of cwd
// is silent for a session started in cwd: that is a failure unless a
// user-scope hook (userHas) covers the agent. A project hook in cwd next to
// a user-scope hook runs twice, which is a warning.
func launchDirChecks(cwd string, userHas map[string]bool) []launchDirCheck {
	var out []launchDirCheck
	for _, agent := range []string{"claude", "codex"} {
		rel, err := settingsPath(agent, "project")
		if err != nil {
			continue
		}
		dir := applygateHookDir(cwd, rel)
		switch {
		case dir == "":
		case dir != cwd && !userHas[agent]:
			out = append(out, launchDirCheck{fail: true, msg: fmt.Sprintf(
				"%s: the project hook is in %s, not here, and %s loads project settings only from the directory it is launched in, so a session started here runs without applygate. Fix: applygate hook install --agent %s --scope user (fires from any directory), or launch %s from %s",
				agent, dir, agent, agent, agent, dir)})
		case dir != cwd:
			out = append(out, launchDirCheck{msg: fmt.Sprintf("%s: user-scope hook covers this directory (the project hook in %s is not loaded from here)", agent, dir)})
		case userHas[agent]:
			out = append(out, launchDirCheck{msg: fmt.Sprintf(
				"%s: both a project hook (%s) and a user-scope hook are installed, so applygate runs twice per tool call here; remove one with: applygate hook remove --agent %s --scope project",
				agent, filepath.Join(dir, rel), agent)})
		}
	}
	return out
}

// hasUserHook reports whether the user-scope settings file of agent holds a
// applygate hook.
func hasUserHook(agent string) bool {
	p, err := settingsPath(agent, "user")
	if err != nil {
		return false
	}
	b, err := os.ReadFile(p)
	return err == nil && settingsHasApplygate(b)
}

// hookScan summarizes one settings file's PreToolUse hooks.
// claudeMatcher is the PreToolUse matcher hook install writes for Claude
// Code: the tools applygate judges, and MCP tools (mcp__<server>__<tool>),
// which it logs without judging. Codex gets "*", which includes MCP calls.
const claudeMatcher = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|mcp__.*"

type hookScan struct {
	applygateBins []string // command binaries of applygate entries
	matchers      []string // matchers of applygate entries
	unrecognised  []string // short summaries of entries applygate did not install
}

func scanHooks(b []byte) (hookScan, bool) {
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return hookScan{}, false
	}
	var s hookScan
	for event, list := range hookLists(doc) {
		for _, e := range list {
			if isApplygateEntry(e) {
				s.applygateBins = append(s.applygateBins, entryBinary(e))
				m, _ := e.(map[string]any)
				matcher, _ := m["matcher"].(string)
				s.matchers = append(s.matchers, matcher)
				continue
			}
			if event == "PreToolUse" {
				s.unrecognised = append(s.unrecognised, entrySummary(e))
			}
		}
	}
	return s, true
}

// entryBinary returns the binary of the first command in an entry.
func entryBinary(e any) string {
	for _, c := range entryCommands(e) {
		if f := strings.Fields(c); len(f) > 0 {
			return strings.Trim(f[0], `"`)
		}
	}
	return ""
}

// entrySummary is a short "matcher -> command" label for doctor output.
func entrySummary(e any) string {
	m, _ := e.(map[string]any)
	matcher, _ := m["matcher"].(string)
	if matcher == "" {
		matcher = "(no matcher)"
	}
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if c, _ := hm["command"].(string); c != "" {
			return matcher + " -> " + c
		}
	}
	return matcher
}

// binExecutable reports whether path is a runnable file.
func binExecutable(path string) (bool, string) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, "not found"
	}
	if fi.IsDir() {
		return false, "is a directory"
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return false, "not executable"
	}
	return true, ""
}

// doctorJudge reports the model judge's setup without calling the model.
func doctorJudge(cfg *config.Config, say func(bool, string, ...any), stdout io.Writer) {
	if !cfg.JudgeOn() {
		fmt.Fprintln(stdout, "     model judge off (docs/judge.md)")
		return
	}
	j, err := judge.New(cfg, hook.EnvMap())
	if err != nil {
		say(false, "model judge on but cannot be asked: %v", err)
		return
	}
	where := cfg.Judge.BaseURL
	if cfg.Judge.Backend == config.JudgeBackendCommand {
		where = strings.Join(cfg.Judge.Command, " ")
	} else if where == "" {
		where = config.DefaultJudgeBaseURL
	}
	say(true, "model judge on: %s via %s, timeout %s; calls the rules do not recognize leave this machine (docs/judge.md)", j.Name(), where, cfg.JudgeTimeout())
}

func cmdDoctor(stdout, stderr io.Writer) int {
	problems := 0
	say := func(ok bool, format string, a ...any) {
		mark := "ok  "
		if !ok {
			mark = "WARN"
			problems++
		}
		fmt.Fprintf(stdout, "%s %s\n", mark, fmt.Sprintf(format, a...))
	}
	fail := func(format string, a ...any) {
		problems++
		fmt.Fprintf(stdout, "FAIL %s\n", fmt.Sprintf(format, a...))
	}
	fmt.Fprintf(stdout, "applygate %s at %s\n", hook.Version, selfPath())
	wd, _ := os.Getwd()
	cfg, err := config.Load(config.UserPath(), wd)
	say(err == nil, "config loads (%s)", orNone(func() string {
		if cfg == nil {
			return ""
		}
		return strings.Join(cfg.Sources, ", ")
	}()))
	if err != nil {
		fmt.Fprintln(stdout, "     ", err)
	} else {
		say(cfg.Root != "", "repository config found (%s)", orNone(cfg.Root))
		for _, d := range cfg.Deprecations {
			say(false, "%s", d)
		}
		say(len(cfg.Environments) > 0, "%d environment(s) configured", len(cfg.Environments))
		fmt.Fprintf(stdout, "     mode %s, strict %v, on_error %s, log %s\n", cfg.Mode, cfg.IsStrict(), cfg.OnError, func() string {
			if cfg.LogPath != "" {
				return cfg.LogPath
			}
			return config.DefaultLogPath()
		}())
	}
	if cfg != nil {
		doctorJudge(cfg, say, stdout)
	}
	if st := telemetry.Effective(hook.EnvMap()); st.On {
		fmt.Fprintf(stdout, "     telemetry on: anonymous counts to %s at most once a day (applygate telemetry status)\n", st.Endpoint)
	} else {
		fmt.Fprintf(stdout, "     telemetry off (%s)\n", st.Reason)
	}
	found := 0
	var where []string
	for _, agent := range hook.Agents {
		for _, scope := range []string{"project", "user"} {
			p, _ := settingsPath(agent, scope)
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			bins, ok := hookBinaries(agent, b)
			if !ok {
				say(false, "%s is not valid JSON", p)
				continue
			}
			scan, _ := scanHooks(b)
			if len(bins) > 0 {
				found++
				where = append(where, agent+" ("+p+")")
				if h, ok := hook.HostFor(agent); ok && h.DocsOnly {
					fmt.Fprintf(stdout, "     %s: adapter written from %s's documentation, not tested live (applygate hosts)\n", agent, h.Name)
				}
				for _, bin := range bins {
					ok, why := binExecutable(bin)
					if ok {
						say(true, "%s hook command binary is executable: %s", agent, bin)
					} else {
						say(false, "%s hook command binary %s: %s", agent, why, bin)
					}
					if filepath.Base(bin) == "seatbelt" {
						say(false, "%s hook still calls the pre-rename seatbelt binary (works for one release); run: applygate hook install --agent %s --scope %s", agent, agent, scope)
					}
				}
			} else if agent == "codex" {
				say(false, "codex settings %s has no applygate hook entry (run: applygate hook install --agent codex)", p)
			}
			if agent == "claude" {
				for _, m := range scan.matchers {
					if m != "*" && !strings.Contains(m, "mcp__") {
						say(false, "claude hook in %s does not see MCP tool calls (matcher %q, installed before MCP logging); run: applygate hook install --agent claude --scope %s", p, m, scope)
					}
				}
			}
			if agent == "codex" {
				for _, u := range scan.unrecognised {
					say(false, "codex: unrecognised PreToolUse hook entry in %s (Codex runs trusted hooks; review it): %s", p, u)
				}
			}
		}
	}
	sort.Strings(where)
	say(found > 0, "hooks installed: %s", orNone(strings.Join(where, ", ")))
	userHas := map[string]bool{"claude": hasUserHook("claude"), "codex": hasUserHook("codex")}
	for _, c := range launchDirChecks(wd, userHas) {
		switch {
		case c.fail:
			fail("%s", c.msg)
		case strings.Contains(c.msg, "runs twice"):
			say(false, "%s", c.msg)
		default:
			say(true, "%s", c.msg)
		}
	}
	var buf bytes.Buffer
	rc := cmdSelftest(nil, &buf, &buf)
	say(rc == 0, "selftest: %s", strings.TrimSpace(lastLine(buf.String())))
	if problems > 0 {
		return 1
	}
	return 0
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
