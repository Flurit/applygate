package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/hook"
	"github.com/Flurit/applygate/internal/policy"
)

// The human door. "applygate apply <planfile>" judges the saved plan exactly
// as the agent hooks judge "terraform apply <planfile>" (tier, preflight,
// plan gate), records the decision in the decision log with agent "human",
// and only then runs the engine. A block refuses; an ask needs the person to
// type the environment's name back, which Terraform's own "yes" prompt does
// not require and which keeps the prompt rare and content-bearing. Outside a
// terminal an ask is refused unless --yes is given and the tier is not
// protected, so a pipeline never hangs and a protected environment never
// skips the human.

// applyExec runs the engine; tests replace it.
var applyExec = func(bin string, args []string, dir string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintf(stderr, "applygate: cannot run %s: %v\n", bin, err)
		return 2
	}
	return 0
}

// isTerminal reports whether r is an interactive terminal; tests replace it.
var isTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func cmdApply(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "directory the plan belongs to (default: current)")
	engine := fs.String("engine", "terraform", "binary that applies the plan: terraform, tofu or a path")
	yes := fs.Bool("yes", false, "outside a terminal, approve an ask verdict without a prompt (never in a protected tier)")
	noLog := fs.Bool("no-log", false, "do not write the decision log")
	var planJSON multiFlag
	fs.Var(&planJSON, "plan-json", "PLANFILE=JSON: use this JSON for the saved plan instead of running show (tests)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: applygate apply [--cwd DIR] [--engine terraform|tofu] [--yes] <planfile> [engine apply arguments]")
		return 2
	}
	planfile, extra := fs.Arg(0), fs.Args()[1:]
	dir := *cwd
	if dir == "" {
		dir, _ = os.Getwd()
	}
	dir, _ = filepath.Abs(dir)
	start := time.Now()
	cfg, err := config.Load(config.UserPath(), dir)
	if err != nil {
		fmt.Fprintln(stderr, "applygate: config error:", err)
		return 2
	}
	for _, d := range cfg.Deprecations {
		fmt.Fprintln(stderr, "applygate: note:", d)
	}
	opt := hook.Options{Env: hook.EnvMap()}
	if len(planJSON) > 0 {
		m := map[string]string{}
		for _, kv := range planJSON {
			k, v, _ := strings.Cut(kv, "=")
			m[k] = v
		}
		opt.PlanJSON = func(_, _, pf string) ([]byte, error) {
			if p, ok := m[pf]; ok {
				return os.ReadFile(p)
			}
			return nil, fmt.Errorf("no --plan-json for %s", pf)
		}
	}
	// The policy judges the engine by name (terraform, tofu, terragrunt); the
	// path given to --engine is only what gets executed.
	engineName := filepath.Base(*engine)
	switch engineName {
	case "terraform", "tofu", "terragrunt":
	default:
		fmt.Fprintf(stderr, "applygate: --engine must be terraform, tofu or terragrunt (or a path to one), not %q\n", *engine)
		return 2
	}
	engineArgs := append([]string{"apply", planfile}, extra...)
	cmdline := quoteCommand(append([]string{engineName}, engineArgs...))
	ev := policy.Event{Agent: "human", Tool: "Bash", Kind: policy.KindShell, Command: cmdline, Cwd: dir, CanAsk: true, DirKnown: true}
	d := policy.Decide(ev, cfg, hook.Deps(context.Background(), cfg, opt))

	entry := decisionlog.Entry{Time: start.UTC(), Version: hook.Version, Agent: "human", Tool: "Bash", Cwd: dir, Command: cmdline,
		Mode: d.Mode, Verdict: d.Verdict, Enforced: d.Enforced, Actions: d.Actions, Notes: d.Notes}
	logIt := func(note string) {
		if note != "" {
			entry.Notes = append(entry.Notes, note)
		}
		entry.DurationMS = float64(time.Since(start).Microseconds()) / 1000
		if *noLog {
			return
		}
		p := cfg.LogPath
		if p == "" {
			p = config.DefaultLogPath()
		}
		if err := decisionlog.Append(p, entry); err != nil {
			fmt.Fprintln(stderr, "applygate: could not write decision log:", err)
		}
	}

	if d.Message != "" {
		fmt.Fprintln(stderr, d.Message)
	}
	switch d.Enforced {
	case policy.Block:
		logIt("")
		return 3
	case policy.Ask:
		token, tier := confirmToken(d)
		switch {
		case isTerminal(stdin):
			fmt.Fprintf(stderr, "\napplygate: this apply needs your confirmation. Type the environment name %q to continue, anything else to abort: ", token)
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			if strings.TrimSpace(line) != token {
				fmt.Fprintln(stderr, "applygate: not confirmed; nothing applied")
				logIt("ask: not confirmed at the terminal")
				return 4
			}
			logIt("ask: confirmed at the terminal by typing " + token)
		case *yes && tier != config.Protected:
			fmt.Fprintf(stderr, "applygate: ask approved with --yes (tier %s)\n", tier)
			logIt("ask: approved non-interactively with --yes")
		case *yes:
			fmt.Fprintln(stderr, "applygate: --yes cannot approve an apply in a protected tier; run this in a terminal")
			logIt("ask: --yes refused in a protected tier")
			return 4
		default:
			fmt.Fprintln(stderr, "applygate: this apply needs an interactive confirmation; run it in a terminal (or pass --yes outside protected tiers)")
			logIt("ask: no terminal to confirm")
			return 4
		}
	default:
		if d.Verdict != policy.Allow {
			fmt.Fprintf(stderr, "applygate: observe mode, would have returned %s; applying\n", d.Verdict)
		}
		logIt("")
	}
	return applyExec(*engine, engineArgs, dir, stdin, stdout, stderr)
}

// confirmToken is what the person must type: the environment name of the
// action that asked, or its tier when the environment is unnamed; and the
// most protected tier among the actions that asked.
func confirmToken(d policy.Decision) (string, config.Tier) {
	token := ""
	var tier config.Tier
	for _, a := range d.Actions {
		if a.Verdict == policy.Allow {
			continue
		}
		if tier == "" || a.Tier.Rank() > tier.Rank() {
			tier = a.Tier
			if a.Env != "" && !strings.HasPrefix(a.Env, "unknown") {
				token = a.Env
			} else {
				token = string(a.Tier)
			}
		}
	}
	if token == "" {
		token = "yes"
	}
	return token, tier
}

// quoteCommand renders argv as a shell command line the analyzer parses back
// to the same words.
func quoteCommand(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		if a != "" && !strings.ContainsAny(a, " \t\n'\"\\$`|&;<>()*?[]{}!#~") {
			q[i] = a
			continue
		}
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}
