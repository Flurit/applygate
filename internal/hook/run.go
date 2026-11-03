package hook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Flurit/applygate/internal/approval"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/judge"
	"github.com/Flurit/applygate/internal/mcpmap"
	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/preflight"
)

// Version is set at build time by the release's -ldflags. A binary built
// with `go install ...@vX.Y.Z` has no ldflags, so init falls back to the
// module version the Go toolchain embeds.
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := moduleVersion(bi.Main.Version); v != "" {
			Version = v
		}
	}
}

// moduleVersion turns a Go module version into a release version: v0.3.0 ->
// 0.3.0. A local build reports "(devel)" or a pseudo-version, both of which
// stay "dev".
func moduleVersion(v string) string {
	if v == "" || v == "(devel)" || strings.Contains(v, "-") || strings.Contains(v, "+") {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// Options configure one hook run.
type Options struct {
	UserConfig string            // "" disables the user-level config
	LogPath    string            // overrides config and default
	NoLog      bool              // tests and selftest
	Env        map[string]string // process environment
	Timeout    time.Duration     // internal decision deadline
	// Budget is how long the whole run may take, judge, approvals, log and
	// telemetry included: under the host's own hook timeout (30 s in the
	// Claude Code plugin). Zero means DefaultBudget.
	Budget time.Duration
	// PlanJSON overrides how saved plans are read (tests, harness replay).
	PlanJSON func(engine, dir, planfile string) ([]byte, error)
	// NoGit disables the git lockfile check (tests).
	NoGit bool
	// Approvals is the one-time approval store ("" disables approvals).
	Approvals string
	// Now is the clock for approvals (tests); nil means time.Now.
	Now func() time.Time
	// Judge replaces the configured model judge (tests). JudgeCache is the
	// verdict cache path: "" for the default, "-" for none.
	Judge      judge.Judge
	JudgeCache string
}

// EnvMap returns the process environment as a map.
func EnvMap() map[string]string {
	m := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// ShowPlan runs "terraform show -json <planfile>" (tofu for OpenTofu) in
// dir. show never plans or applies, but it starts the provider plugins in
// the data directory to load their schemas, and the agent can write that
// directory: every provider must first match .terraform.lock.hcl as git
// HEAD has it (preflight.VerifyProviders), and the user's CLI configuration
// (dev_overrides) is not read. Terragrunt's own show is never run, since it
// evaluates run_cmd() and hooks: the plan is shown with terraform in the
// Terragrunt cache directory that holds it. The subprocess is cancelled
// when parent is done (the internal deadline) or after timeout, whichever
// comes first.
func ShowPlan(parent context.Context, timeout time.Duration, engineBin func(string) (string, error)) func(engine, dir, planfile string) ([]byte, error) {
	return func(engine, dir, planfile string) ([]byte, error) {
		name := engine
		switch name {
		case "", "terraform":
			name = "terraform"
		case "terragrunt":
			name = "terraform"
			d, err := terragruntCacheDir(dir, planfile)
			if err != nil {
				return nil, err
			}
			dir = d
		}
		bin, err := engineBin(name)
		if engine == "terragrunt" && err == nil {
			// Terragrunt runs the binary TG_TF_PATH names; it is not
			// trusted under a managed install.
			if p := os.Getenv("TG_TF_PATH"); p != "" {
				bin, err = engineBin(p)
			} else if p := os.Getenv("TERRAGRUNT_TFPATH"); p != "" {
				bin, err = engineBin(p)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s show not run: %v", name, err)
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		if err := preflight.VerifyProviders(ctx, dir, preflight.DataDir(dir, map[string]string{"TF_DATA_DIR": os.Getenv("TF_DATA_DIR")})); err != nil {
			return nil, fmt.Errorf("%s show not run: %v", bin, err)
		}
		cmd := exec.CommandContext(ctx, bin, "show", "-json", "-no-color", planfile)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1", "TF_CLI_CONFIG_FILE="+os.DevNull)
		// On cancel, don't wait forever for output: terraform's provider
		// plugins can hold the stdout pipe open after terraform itself is
		// killed. WaitDelay force-closes the pipe so cmd.Output returns.
		cmd.WaitDelay = 2 * time.Second
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s show cancelled or timed out after %s", bin, timeout)
		}
		if err != nil {
			return nil, fmt.Errorf("%s show failed: %v: %s", bin, err, firstLine(stderr.String()))
		}
		return out, nil
	}
}

// terragruntCacheDir finds the Terragrunt cache directory a saved plan
// belongs to: terragrunt plan -out=F writes F in the working copy under
// .terragrunt-cache, next to its .terraform. Exactly one must exist.
func terragruntCacheDir(dir, planfile string) (string, error) {
	if filepath.IsAbs(planfile) {
		if d := filepath.Dir(planfile); isDir(filepath.Join(d, ".terraform")) {
			return d, nil
		}
	}
	if _, err := os.Stat(filepath.Join(dir, planfile)); err == nil && isDir(filepath.Join(dir, ".terraform")) {
		return dir, nil
	}
	cache := filepath.Join(dir, ".terragrunt-cache")
	var found []string
	_ = filepath.WalkDir(cache, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if rel, _ := filepath.Rel(cache, p); strings.Count(rel, string(filepath.Separator)) > 8 || d.Name() == ".terraform" {
			return filepath.SkipDir
		}
		if _, err := os.Stat(filepath.Join(p, planfile)); err == nil && isDir(filepath.Join(p, ".terraform")) {
			found = append(found, p)
		}
		return nil
	})
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("the plan %s is not in %s or its .terragrunt-cache, and terragrunt show is not run (it evaluates run_cmd and hooks)", planfile, dir)
	}
	return "", fmt.Errorf("the plan %s is in %d Terragrunt cache directories under %s; which one would be applied is not known", planfile, len(found), cache)
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Deps builds policy dependencies for a config. ctx is cancelled on the
// internal deadline; the plan gate's show subprocess is bound to it.
func Deps(ctx context.Context, cfg *config.Config, opt Options) policy.Deps {
	d := policy.Deps{Env: opt.Env, PlanJSON: opt.PlanJSON,
		LoadConfig: func(dir string) (*config.Config, error) { return config.Load(opt.UserConfig, dir) }}
	if d.PlanJSON == nil && cfg.RunShow() {
		d.PlanJSON = ShowPlan(ctx, cfg.ShowTimeout(), cfg.EngineBinary)
	}
	if !opt.NoGit {
		// One git check per directory: a command with hundreds of destroys
		// in one directory used to run it per action (finding I6).
		var mu sync.Mutex
		seen := map[string]*preflight.Finding{}
		d.Lockfile = func(dir string) *preflight.Finding {
			mu.Lock()
			defer mu.Unlock()
			if f, ok := seen[dir]; ok {
				return f
			}
			f := preflight.LockfileDrift(dir)
			seen[dir] = f
			return f
		}
	}
	if cfg.Preflight.LiveIdentity {
		d.Account = func(p string) (string, error) {
			bin, err := cfg.EngineBinary("aws")
			if err != nil {
				return "", err
			}
			return preflight.CallerAccount(bin, p, 5*time.Second)
		}
	}
	if cfg.Preflight.LiveState {
		d.StatePull = func(engine, dir string) ([]byte, error) {
			name := engine
			if name == "" || name == "terragrunt" {
				name = "terraform"
			}
			bin, err := cfg.EngineBinary(name)
			if err != nil {
				return nil, err
			}
			return preflight.PullState(ctx, bin, dir, cfg.ShowTimeout())
		}
	}
	return d
}

// Run processes one hook event from in and returns the output to write.
//
// A panic anywhere in the run is recovered and turned into a fail-closed block
// (except in observe mode). This matters most for Codex, which has no
// onFailure equivalent: a hook process that panics and exits non-cleanly would
// otherwise let the tool call run. With this recovery the only remaining
// Codex fail-open case is the binary not starting at all.
// DefaultBudget is the whole run's time limit, one second under the
// Claude Code plugin's 30-second hook timeout.
const DefaultBudget = 29 * time.Second

// judgeReserve is kept back from the budget when the judge is asked: the
// command backend's WaitDelay (1 s) and a 2 s margin for the log and
// rendering.
const judgeReserve = 3 * time.Second

// failureBlocks decides, for every way a run can fail (an error, a panic,
// the internal deadline), whether the call is blocked. Observe mode never
// blocks; without a config the guard fails closed. A timeout blocks in
// every tier, because the call was never analyzed. Other failures follow
// on_error, where auto judges the call at the most protected tier under the
// repository root, since a command that was not analyzed could run anywhere
// under it.
func failureBlocks(cfg *config.Config, cwd string, timeout bool) bool {
	switch {
	case cfg == nil:
		return true
	case cfg.Observe():
		return false
	case timeout:
		return true
	}
	switch cfg.OnError {
	case "allow":
		return false
	case "auto":
		root := cfg.Root
		if root == "" {
			root = cwd
		}
		if root == "" {
			return true
		}
		return cfg.ResolveUnder(root, config.Signals{}, "applygate could not decide").Tier == config.Protected
	}
	return true
}

// RunWithin is Run with a watchdog: when the run is not done shortly after
// its budget, the hook answers with a fail-closed block itself, whatever is
// still running (reading a huge file, a slow judge, an expansion), so it
// never reaches the host's own timeout, which some hosts treat as allow.
// Observe mode cannot be honoured then, because the config may not be read.
func RunWithin(a Adapter, in io.Reader, opt Options) Output {
	budget := opt.Budget
	if budget == 0 {
		budget = DefaultBudget
	}
	done := make(chan Output, 1)
	go func() { done <- Run(a, in, opt) }()
	t := time.NewTimer(budget + watchdogSlack)
	defer t.Stop()
	select {
	case o := <-done:
		return o
	case <-t.C:
		o := a.Fail(true, fmt.Sprintf("applygate: the decision did not finish within %s, so the call is blocked (applygate fails closed when it runs out of time)", budget))
		o.Deadline = time.Now()
		return o
	}
}

// watchdogSlack lets a run that finishes at its budget write its own answer
// before the watchdog writes one.
const watchdogSlack = 300 * time.Millisecond

func Run(a Adapter, in io.Reader, opt Options) (out Output) {
	start := time.Now()
	if config.Managed() {
		// The agent's user sets this process's environment. Certificate
		// files named there would let a proxy answer for an HTTPS judge.
		os.Unsetenv("SSL_CERT_FILE")
		os.Unsetenv("SSL_CERT_DIR")
	}
	if opt.Timeout == 0 {
		opt.Timeout = 25 * time.Second
	}
	if opt.Budget == 0 {
		opt.Budget = DefaultBudget
	}
	deadline := start.Add(opt.Budget)
	cwd := ""
	raw, err := io.ReadAll(io.LimitReader(in, 8<<20))
	entry := decisionlog.Entry{Time: start.UTC(), Version: Version, Agent: a.Name()}
	userCfg, uerr := config.Load(opt.UserConfig, "")
	// recoverCfg is the most specific config known when a panic is recovered;
	// it decides whether observe mode suppresses the block.
	var recoverCfg *config.Config = userCfg
	logPath := func(cfg *config.Config) string {
		switch {
		case opt.LogPath != "":
			return opt.LogPath
		case cfg != nil && cfg.LogPath != "":
			return cfg.LogPath
		}
		return config.DefaultLogPath()
	}
	finish := func(cfg *config.Config, o Output) Output {
		o.Deadline = deadline
		entry.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		if !opt.NoLog && filepath.IsAbs(logPath(cfg)) {
			o.LogPath = logPath(cfg)
			if err := decisionlog.Append(o.LogPath, entry); err != nil {
				o.Stderr += "applygate: could not write decision log: " + err.Error() + "\n"
			}
		}
		return o
	}
	// fail applies the error behavior. Without a usable config the guard
	// fails closed: an unknown environment is treated as protected.
	fail := func(cfg *config.Config, cwd, msg string) Output {
		block := failureBlocks(cfg, cwd, false)
		mode := "enforce"
		if cfg != nil {
			mode = cfg.Mode
		}
		entry.Error, entry.Mode = msg, mode
		entry.Verdict = policy.Block
		entry.Enforced = policy.Allow
		if block {
			entry.Enforced = policy.Block
			msg += " (applygate fails closed here; fix the problem or set on_error in the user config)"
		} else {
			msg += " (applygate fails open here per on_error/mode)"
		}
		return finish(cfg, a.Fail(block, "applygate: "+msg))
	}
	// A panic that escapes the normal paths (including policy.Run's own
	// recover) is a failure like any other. This is what makes a Codex hook
	// that panics block rather than fail open.
	defer func() {
		if p := recover(); p != nil {
			out = fail(recoverCfg, cwd, fmt.Sprintf("internal error: %v", p))
		}
	}()
	if err != nil {
		return fail(userCfg, "", "could not read hook input: "+err.Error())
	}
	if p := config.HomeProblem(); p != "" {
		return fail(nil, "", p)
	}
	if uerr != nil {
		return fail(nil, "", "user config error: "+uerr.Error())
	}
	ev, ok, err := a.Parse(raw)
	if err != nil {
		return fail(userCfg, "", err.Error())
	}
	pass := Output{}
	if p, isPasser := a.(passer); isPasser {
		pass = p.Pass()
	}
	if !ok {
		return pass // not an event we check; nothing to log
	}
	entry.Session, entry.Tool, entry.Cwd, entry.Command, entry.Paths = ev.Session, ev.Tool, ev.Cwd, ev.Command, ev.Paths
	cwd = ev.Cwd
	if ev.Kind == policy.KindOther {
		return pass // tools applygate does not inspect are not logged
	}
	var mcpNote string
	var tr mcpmap.Result
	if ev.Kind == policy.KindMCP {
		var known bool
		tr, known = mcpmap.Rules().Translate(ev.Tool, ev.Args, ev.Cwd)
		if !known {
			// A tool outside the table that names a guard file is judged
			// as a write to it, so it is blocked like the Write tool.
			if gcfg, err := config.Load(opt.UserConfig, ev.Cwd); err == nil {
				if p := policy.MCPGuardPath(gcfg, opt.Env, ev.Tool, ev.Cwd, ev.Args); p != "" {
					ev.Kind, ev.Paths = policy.KindWrite, []string{p}
					known = true
					mcpNote = fmt.Sprintf("MCP tool %s names the guard file %s; judged as a write to it", mcpmap.ToolName(ev.Tool), p)
				}
			}
		}
		if !known {
			// Other MCP calls are recorded, not judged, so nothing about
			// them may block: a broken repository config still logs (to
			// the user-level or default log) and allows.
			cfg, err := config.Load(opt.UserConfig, ev.Cwd)
			if err != nil {
				cfg = userCfg
				entry.Error = "config error (MCP call logged, not judged): " + err.Error()
			}
			entry.Mode = cfg.Mode
			entry.Verdict, entry.Enforced = policy.Allow, policy.Allow
			entry.Notes = []string{"MCP tool call: logged, not judged by the rules"}
			if err != nil {
				return finish(cfg, pass)
			}
			d := policy.Decision{Verdict: policy.Allow, Enforced: policy.Allow, Mode: cfg.Mode, Notes: entry.Notes}
			jctx, cancel := judgeContext(deadline)
			d, entry.Judge = Judge(jctx, ev, d, cfg, opt)
			cancel()
			if d.Verdict == policy.Allow {
				return finish(cfg, pass)
			}
			return finish(cfg, decided(a, ev, d, cfg, opt, &entry))
		}
		// A known infrastructure tool is judged as the command it runs.
		// The server runs it in its own working directory, so without a
		// directory argument the command's directory is unknown.
	}
	if ev.Kind == policy.KindMCP {
		ev.Kind, ev.Command = policy.KindShell, tr.Command
		ev.DirKnown = tr.Dir != ""
		if tr.Dir != "" {
			ev.Cwd = tr.Dir
		}
		mcpNote = fmt.Sprintf("MCP tool %s (%s) judged as the equivalent of: %s", mcpmap.ToolName(ev.Tool), tr.Server, tr.Command)
		if tr.Note != "" {
			mcpNote += " (" + tr.Note + ")"
		}
	}
	cfg, err := config.Load(opt.UserConfig, ev.Cwd)
	if err != nil {
		// A broken repository config: on_error and observe mode come from
		// the user config, as for any other error.
		return fail(userCfg, ev.Cwd, "config error: "+err.Error())
	}
	recoverCfg = cfg
	entry.Mode = cfg.Mode
	d, err := policy.Run(opt.Timeout, func(ctx context.Context) policy.Decision {
		d := policy.Decide(ev, cfg, Deps(ctx, cfg, opt))
		if mcpNote != "" {
			d = withMCPNote(d, mcpNote)
		}
		return d
	})
	if err != nil {
		if errors.Is(err, policy.ErrTimeout) {
			// A timeout means the decision could not be reached. Fail closed
			// in every tier (not just protected), because an unchecked command
			// in a disposable tier can still reach a protected one. Observe
			// mode still never blocks. In-flight work was cancelled via ctx.
			block := failureBlocks(cfg, ev.Cwd, true)
			msg := fmt.Sprintf("decision timed out after %s; cancelled in-flight plan/subprocess work", opt.Timeout)
			entry.Error, entry.Verdict, entry.Enforced = msg, policy.Block, policy.Allow
			if block {
				entry.Enforced = policy.Block
				msg += " (applygate fails closed here in every tier)"
			} else {
				msg += " (observe mode: allowed)"
			}
			return finish(cfg, a.Fail(block, "applygate: "+msg))
		}
		return fail(cfg, ev.Cwd, err.Error())
	}
	jctx, cancel := judgeContext(deadline)
	defer cancel()
	d, entry.Judge = Judge(jctx, ev, d, cfg, opt)
	return finish(cfg, decided(a, ev, d, cfg, opt, &entry))
}

// judgeContext gives the judge what is left of the run's budget, less the
// reserve for its process to exit and for the log; the judge's own timeout
// applies within it.
func judgeContext(deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.Background(), deadline.Add(-judgeReserve))
}

// decided applies one-time approvals, records the decision and renders it.
func decided(a Adapter, ev policy.Event, d policy.Decision, cfg *config.Config, opt Options, entry *decisionlog.Entry) Output {
	if opt.Approvals != "" && approvable(d) && !cfg.Observe() && cfg.ApprovalsOn() {
		now := time.Now
		if opt.Now != nil {
			now = opt.Now
		}
		d = withApproval(opt.Approvals, ev, d, now())
	}
	entry.Verdict, entry.Enforced, entry.Actions, entry.Notes = d.Verdict, d.Enforced, d.Actions, d.Notes
	if er, isEventRenderer := a.(eventRenderer); isEventRenderer {
		return er.RenderEvent(ev, d)
	}
	return a.Render(d)
}

// approvable reports whether a person may allow the call once: an ask, or a
// block that only the model judge gave. A rule's block never is.
func approvable(d policy.Decision) bool {
	switch d.Verdict {
	case policy.Ask:
		return true
	case policy.Block:
		for _, a := range d.Actions {
			if a.Verdict == policy.Block && string(a.Class) != judge.Class {
				return false
			}
		}
		return true
	}
	return false
}

// withApproval applies a person's one-time approval to an asked decision, or,
// when the ask is enforced as a block, records a request the person can
// approve and tells the agent how. A store error leaves the decision as it is.
func withApproval(path string, ev policy.Event, d policy.Decision, now time.Time) policy.Decision {
	key := approval.Key(ev, d)
	rec, ok, err := approval.Consume(path, key, now)
	if err != nil {
		d.Notes = append(d.Notes, "approvals unavailable: "+err.Error())
		return d
	}
	if ok {
		d.Enforced, d.Message = policy.Allow, ""
		d.Notes = append(d.Notes, fmt.Sprintf("allowed once: a person approved this exact call with `applygate approve %s` at %s", rec.ID, rec.ApprovedAt.UTC().Format(time.RFC3339)))
		return d
	}
	if d.Enforced != policy.Block {
		return d // the host shows its own prompt
	}
	rec, err = approval.Request(path, approval.NewRequest(ev, d), now)
	if err != nil {
		d.Notes = append(d.Notes, "approvals unavailable: "+err.Error())
		return d
	}
	d.Notes = append(d.Notes, "approval requested: "+rec.ID)
	d.Message += fmt.Sprintf("\nApproval: if the user wants this to run, they can allow this exact call once by running `applygate approve %s` in their own terminal within the next hour. Tell the user that, and after they confirm, retry the same call unchanged. You cannot approve it yourself; applygate blocks that.", rec.ID)
	return d
}

// withMCPNote records that the decision is for an MCP call and, when the call
// is stopped, says so first in the message, so the agent knows which tool was
// judged.
func withMCPNote(d policy.Decision, note string) policy.Decision {
	d.Notes = append([]string{note}, d.Notes...)
	if d.Message != "" {
		d.Message += "\nNote: " + note
	}
	return d
}
