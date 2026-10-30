package hook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
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
	// PlanJSON overrides how saved plans are read (tests, harness replay).
	PlanJSON func(engine, dir, planfile string) ([]byte, error)
	// NoGit disables the git lockfile check (tests).
	NoGit bool
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

// ShowPlan runs "<engine> show -json <planfile>" in dir. It is read-only:
// show never plans or applies, though it starts provider plugins to load
// their schemas. The subprocess is cancelled when parent is done (the internal
// deadline) or after timeout, whichever comes first.
func ShowPlan(parent context.Context, timeout time.Duration) func(engine, dir, planfile string) ([]byte, error) {
	return func(engine, dir, planfile string) ([]byte, error) {
		bin := engine
		if bin == "" {
			bin = "terraform"
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "show", "-json", "-no-color", planfile)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
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
	d := policy.Deps{Env: opt.Env, PlanJSON: opt.PlanJSON}
	if d.PlanJSON == nil && cfg.RunShow() {
		d.PlanJSON = ShowPlan(ctx, cfg.ShowTimeout())
	}
	if !opt.NoGit {
		d.Lockfile = preflight.LockfileDrift
	}
	if cfg.Preflight.LiveIdentity {
		d.Account = func(p string) (string, error) { return preflight.CallerAccount(p, 5*time.Second) }
	}
	if cfg.Preflight.LiveState {
		d.StatePull = func(engine, dir string) ([]byte, error) {
			return preflight.PullState(ctx, engine, dir, cfg.ShowTimeout())
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
func Run(a Adapter, in io.Reader, opt Options) (out Output) {
	start := time.Now()
	if opt.Timeout == 0 {
		opt.Timeout = 25 * time.Second
	}
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
		entry.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		if !opt.NoLog {
			o.LogPath = logPath(cfg)
			if err := decisionlog.Append(o.LogPath, entry); err != nil {
				o.Stderr += "applygate: could not write decision log: " + err.Error() + "\n"
			}
		}
		return o
	}
	// dirKnown is whether the parsed event's cwd is the command's directory;
	// until an event is parsed nothing is known.
	dirKnown := false
	// fail applies the error behavior. Without a usable config the guard
	// fails closed: an unknown environment is treated as protected.
	fail := func(cfg *config.Config, cwd, msg string) Output {
		block := true
		mode := "enforce"
		if cfg != nil {
			mode = cfg.Mode
			switch cfg.OnError {
			case "allow":
				block = false
			case "auto":
				tier := config.Protected
				switch {
				case cwd == "":
				case dirKnown || !cfg.UnknownDirMostProtected():
					tier = cfg.Resolve(config.Signals{Dir: cwd}).Tier
				default:
					tier = cfg.ResolveUnknownDir(a.Name(), cwd, config.Signals{}).Tier
				}
				block = tier == config.Protected
			}
			if cfg.Observe() {
				block = false
			}
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
	// recover) still fails closed: block unless observe mode is in effect.
	// This is what makes a Codex hook that panics block rather than fail open.
	defer func() {
		if p := recover(); p != nil {
			msg := fmt.Sprintf("internal error: %v", p)
			block := recoverCfg == nil || !recoverCfg.Observe()
			entry.Error = msg
			entry.Verdict = policy.Block
			entry.Enforced = policy.Allow
			if block {
				entry.Enforced = policy.Block
				msg += " (applygate fails closed here)"
			} else {
				msg += " (observe mode: allowed)"
			}
			out = finish(recoverCfg, a.Fail(block, "applygate: "+msg))
		}
	}()
	if err != nil {
		return fail(userCfg, "", "could not read hook input: "+err.Error())
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
	dirKnown = ev.DirKnown
	if ev.Kind == policy.KindOther {
		return pass // tools applygate does not inspect are not logged
	}
	if ev.Kind == policy.KindMCP {
		// MCP calls are recorded, not judged, so nothing about them may
		// block: a broken repository config still logs (to the user-level
		// or default log) and allows.
		cfg, err := config.Load(opt.UserConfig, ev.Cwd)
		if err != nil {
			cfg = userCfg
			entry.Error = "config error (MCP call logged, not judged): " + err.Error()
		}
		entry.Mode = cfg.Mode
		entry.Verdict, entry.Enforced = policy.Allow, policy.Allow
		entry.Notes = []string{"MCP tool call: logged, not judged"}
		return finish(cfg, pass)
	}
	cfg, err := config.Load(opt.UserConfig, ev.Cwd)
	if err != nil {
		return fail(nil, ev.Cwd, "config error: "+err.Error())
	}
	recoverCfg = cfg
	entry.Mode = cfg.Mode
	d, err := policy.Run(opt.Timeout, func(ctx context.Context) policy.Decision {
		return policy.Decide(ev, cfg, Deps(ctx, cfg, opt))
	})
	if err != nil {
		if errors.Is(err, policy.ErrTimeout) {
			// A timeout means the decision could not be reached. Fail closed
			// in every tier (not just protected), because an unchecked command
			// in a disposable tier can still reach a protected one. Observe
			// mode still never blocks. In-flight work was cancelled via ctx.
			block := !cfg.Observe()
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
	entry.Verdict, entry.Enforced, entry.Actions, entry.Notes = d.Verdict, d.Enforced, d.Actions, d.Notes
	if er, isEventRenderer := a.(eventRenderer); isEventRenderer {
		return finish(cfg, er.RenderEvent(ev, d))
	}
	return finish(cfg, a.Render(d))
}
