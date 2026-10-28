// Command seatbelt is a deterministic pre-execution check for coding agents
// that touch Terraform or OpenTofu infrastructure.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/seatbelt/harness"
	"github.com/Flurit/seatbelt/internal/classify"
	"github.com/Flurit/seatbelt/internal/config"
	"github.com/Flurit/seatbelt/internal/decisionlog"
	"github.com/Flurit/seatbelt/internal/hook"
	"github.com/Flurit/seatbelt/internal/plangate"
	"github.com/Flurit/seatbelt/internal/policy"
	"github.com/Flurit/seatbelt/internal/shell"
)

const usage = `seatbelt: allow / ask / block for agent actions on Terraform and OpenTofu

Usage:
  seatbelt hook claude|codex          read one PreToolUse event on stdin (used by the agent)
  seatbelt check [--cwd DIR] [--json] "<command>"
                                      dry-run a command through the policy
  seatbelt explain [--cwd DIR] "<command>"
                                      show the parse, classification and decision trace
  seatbelt plan-check [--tier T] [--cwd DIR] <plan.json>
                                      evaluate "terraform show -json" output
  seatbelt report [--log FILE]        summarize the decision log
  seatbelt selftest [-v]              run the scenario pack against this binary
  seatbelt init                       write a starter .seatbelt.yaml in the current directory
  seatbelt hook install|remove --agent claude|codex [--scope project|user]
  seatbelt doctor                     check config, hooks and versions
  seatbelt version
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
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "selftest":
		return cmdSelftest(args[1:], stdout, stderr)
	case "init":
		return cmdInit(stdout, stderr)
	case "doctor":
		return cmdDoctor(stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "seatbelt", hook.Version)
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
		fmt.Fprintln(stderr, "seatbelt hook: agent name required (claude or codex)")
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
	return o.Exit
}

func cmdCheck(args []string, stdout, stderr io.Writer, explain bool) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "working directory the command runs in (default: current)")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
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
	ev := policy.Event{Agent: "cli", Tool: "Bash", Kind: policy.KindShell, Command: fs.Arg(0), Cwd: dir, CanAsk: true}
	deps := hook.Deps(cfg, opt)
	if explain {
		res := shell.Analyze(ev.Command, shell.Options{Dir: dir, Env: opt.Env, Aliases: cfg.Aliases})
		fmt.Fprintf(stdout, "config: %s\n", orNone(strings.Join(cfg.Sources, ", ")))
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
		acts := classify.Invocations(res, classify.Options{ProtectedPaths: cfg.GuardPaths(), Home: opt.Env["HOME"]})
		fmt.Fprintf(stdout, "\n2. classify: %d policy-relevant action(s)\n", len(acts))
		for _, a := range acts {
			fmt.Fprintf(stdout, "   - %s: %s (%s)\n", a.Class, a.Command, a.Why)
		}
		fmt.Fprintln(stdout, "\n3. decide:")
	}
	d := policy.Decide(ev, cfg, deps)
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
	res, err := plangate.Evaluate(plangate.Input{PlanJSON: js, MaxDestroy: cfg.MaxDestroy(t), Scope: cfg.PlanGate.Scope}, plangate.DefaultRules())
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
	dir, err := os.MkdirTemp("", "seatbelt-selftest-")
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

const starterConfig = `# seatbelt config. https://github.com/Flurit/seatbelt/blob/main/docs/config.md
version: 1
# Start in observe mode: decisions are logged but nothing is blocked.
# Run "seatbelt report" after a few days, then switch to enforce.
mode: observe
# Unknown environments are treated as protected.
strict: true
# What happens when seatbelt itself fails: auto blocks in protected tiers.
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
`

func cmdInit(stdout, stderr io.Writer) int {
	if _, err := os.Stat(config.FileName); err == nil {
		fmt.Fprintf(stderr, "%s already exists; not overwriting\n", config.FileName)
		return 1
	}
	if err := os.WriteFile(config.FileName, []byte(starterConfig), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (observe mode). Edit the environments, then run:\n  seatbelt hook install --agent claude\n", config.FileName)
	return 0
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return "seatbelt"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func settingsPath(agent, scope string) (string, error) {
	home, _ := os.UserHomeDir()
	switch agent + "/" + scope {
	case "claude/project":
		return filepath.Join(".claude", "settings.json"), nil
	case "claude/user":
		return filepath.Join(home, ".claude", "settings.json"), nil
	case "codex/project":
		return filepath.Join(".codex", "hooks.json"), nil
	case "codex/user":
		return filepath.Join(home, ".codex", "hooks.json"), nil
	}
	return "", fmt.Errorf("unsupported agent/scope %s/%s", agent, scope)
}

func cmdInstall(verb string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "claude", "claude or codex")
	scope := fs.String("scope", "project", "project or user")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path, err := settingsPath(*agent, *scope)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
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
	pre, _ := hooks["PreToolUse"].([]any)
	var kept []any
	removed := 0
	for _, e := range pre {
		if isSeatbeltEntry(e) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	if verb == "install" {
		cmd := fmt.Sprintf("%q hook %s", selfPath(), *agent)
		h := map[string]any{"type": "command", "command": cmd, "timeout": 30}
		matcher := "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep"
		if *agent == "claude" {
			// Block the tool call if the hook crashes or times out
			// (Claude Code v2.1.295+; older versions fail open).
			h["onFailure"] = "block"
		} else {
			matcher = "*"
		}
		kept = append(kept, map[string]any{"matcher": matcher, "hooks": []any{h}})
	}
	if len(kept) > 0 {
		hooks["PreToolUse"] = kept
	} else {
		delete(hooks, "PreToolUse")
	}
	if len(hooks) > 0 {
		doc["hooks"] = hooks
	} else {
		delete(doc, "hooks")
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
		fmt.Fprintf(stdout, "installed seatbelt PreToolUse hook for %s in %s (replaced %d old entr%s)\n", *agent, path, removed, plural(removed))
		if *agent == "codex" {
			fmt.Fprintln(stdout, "Codex asks you to review and trust new hooks: run /hooks in Codex once.")
		}
	} else {
		fmt.Fprintf(stdout, "removed %d seatbelt hook entr%s from %s\n", removed, plural(removed), path)
	}
	return 0
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func isSeatbeltEntry(e any) bool {
	m, _ := e.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if c, _ := hm["command"].(string); strings.Contains(c, "seatbelt") && strings.Contains(c, " hook ") {
			return true
		}
	}
	return false
}

// settingsHasSeatbelt reports whether a settings file's PreToolUse hooks
// include a seatbelt entry.
func settingsHasSeatbelt(b []byte) bool {
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return false
	}
	hooks, _ := doc["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	for _, e := range pre {
		if isSeatbeltEntry(e) {
			return true
		}
	}
	return false
}

// seatbeltHookDir searches cwd and its ancestors for a project settings file
// (rel, e.g. .claude/settings.json) that contains a seatbelt hook, and returns
// the directory that holds it, or "" if none is found.
func seatbeltHookDir(cwd, rel string) string {
	dir := cwd
	for {
		if b, err := os.ReadFile(filepath.Join(dir, rel)); err == nil && settingsHasSeatbelt(b) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// launchDirWarnings warns when a project-scope seatbelt hook lives in an
// ancestor of cwd. Claude Code and Codex read project settings only from the
// directory the session is launched in, so a hook in an ancestor is not loaded
// when the agent starts in cwd.
func launchDirWarnings(cwd string) []string {
	var warns []string
	for _, agent := range []string{"claude", "codex"} {
		rel, err := settingsPath(agent, "project")
		if err != nil {
			continue
		}
		if dir := seatbeltHookDir(cwd, rel); dir != "" && dir != cwd {
			warns = append(warns, fmt.Sprintf(
				"%s project hook is in %s, not the current directory; %s reads project settings only from the directory it is launched in, so starting it here will not apply the hook — launch from %s, or install at user scope (--scope user)",
				agent, dir, agent, dir))
		}
	}
	return warns
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
	fmt.Fprintf(stdout, "seatbelt %s at %s\n", hook.Version, selfPath())
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
		say(len(cfg.Environments) > 0, "%d environment(s) configured", len(cfg.Environments))
		fmt.Fprintf(stdout, "     mode %s, strict %v, on_error %s, log %s\n", cfg.Mode, cfg.IsStrict(), cfg.OnError, func() string {
			if cfg.LogPath != "" {
				return cfg.LogPath
			}
			return config.DefaultLogPath()
		}())
	}
	found := 0
	var where []string
	for _, agent := range []string{"claude", "codex"} {
		for _, scope := range []string{"project", "user"} {
			p, _ := settingsPath(agent, scope)
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var doc map[string]any
			if json.Unmarshal(b, &doc) != nil {
				say(false, "%s is not valid JSON", p)
				continue
			}
			hooks, _ := doc["hooks"].(map[string]any)
			pre, _ := hooks["PreToolUse"].([]any)
			for _, e := range pre {
				if isSeatbeltEntry(e) {
					found++
					where = append(where, agent+" ("+p+")")
					cmd := e.(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
					bin := strings.Trim(strings.Fields(cmd)[0], `"`)
					_, serr := os.Stat(bin)
					say(serr == nil, "%s hook command binary exists: %s", agent, bin)
				}
			}
		}
	}
	sort.Strings(where)
	say(found > 0, "hooks installed: %s", orNone(strings.Join(where, ", ")))
	for _, w := range launchDirWarnings(wd) {
		say(false, "%s", w)
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
