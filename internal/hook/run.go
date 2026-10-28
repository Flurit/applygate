package hook

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Flurit/seatbelt/internal/config"
	"github.com/Flurit/seatbelt/internal/decisionlog"
	"github.com/Flurit/seatbelt/internal/policy"
	"github.com/Flurit/seatbelt/internal/preflight"
)

// Version is set at build time.
var Version = "dev"

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
// their schemas.
func ShowPlan(timeout time.Duration) func(engine, dir, planfile string) ([]byte, error) {
	return func(engine, dir, planfile string) ([]byte, error) {
		bin := engine
		if bin == "" {
			bin = "terraform"
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "show", "-json", "-no-color", planfile)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s show timed out after %s", bin, timeout)
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

// Deps builds policy dependencies for a config.
func Deps(cfg *config.Config, opt Options) policy.Deps {
	d := policy.Deps{Env: opt.Env, PlanJSON: opt.PlanJSON}
	if d.PlanJSON == nil && cfg.RunShow() {
		d.PlanJSON = ShowPlan(cfg.ShowTimeout())
	}
	if !opt.NoGit {
		d.Lockfile = preflight.LockfileDrift
	}
	if cfg.Preflight.LiveIdentity {
		d.Account = func(p string) (string, error) { return preflight.CallerAccount(p, 5*time.Second) }
	}
	return d
}

// Run processes one hook event from in and returns the output to write.
func Run(a Adapter, in io.Reader, opt Options) Output {
	start := time.Now()
	if opt.Timeout == 0 {
		opt.Timeout = 25 * time.Second
	}
	raw, err := io.ReadAll(io.LimitReader(in, 8<<20))
	entry := decisionlog.Entry{Time: start.UTC(), Version: Version, Agent: a.Name()}
	userCfg, uerr := config.Load(opt.UserConfig, "")
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
			if err := decisionlog.Append(logPath(cfg), entry); err != nil {
				o.Stderr += "seatbelt: could not write decision log: " + err.Error() + "\n"
			}
		}
		return o
	}
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
				block = cwd == "" || cfg.Resolve(config.Signals{Dir: cwd}).Tier == config.Protected
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
			msg += " (seatbelt fails closed here; fix the problem or set on_error in the user config)"
		} else {
			msg += " (seatbelt fails open here per on_error/mode)"
		}
		return finish(cfg, a.Fail(block, "seatbelt: "+msg))
	}
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
	if !ok {
		return Output{} // not an event we check; nothing to log
	}
	entry.Session, entry.Tool, entry.Cwd, entry.Command, entry.Paths = ev.Session, ev.Tool, ev.Cwd, ev.Command, ev.Paths
	if ev.Kind == policy.KindOther {
		return Output{} // tools seatbelt does not inspect are not logged
	}
	cfg, err := config.Load(opt.UserConfig, ev.Cwd)
	if err != nil {
		return fail(nil, ev.Cwd, "config error: "+err.Error())
	}
	entry.Mode = cfg.Mode
	d, err := policy.Run(opt.Timeout, func() policy.Decision { return policy.Decide(ev, cfg, Deps(cfg, opt)) })
	if err != nil {
		return fail(cfg, ev.Cwd, err.Error())
	}
	entry.Verdict, entry.Enforced, entry.Actions, entry.Notes = d.Verdict, d.Enforced, d.Actions, d.Notes
	return finish(cfg, a.Render(d))
}
