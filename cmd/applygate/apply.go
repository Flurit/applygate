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

	"github.com/Flurit/applygate/internal/approval"
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
// It asks the terminal driver (isatty; the console mode on Windows), so
// /dev/null and other character devices do not count.
var isTerminal = terminal

// applyPlanJSON replaces how apply reads a saved plan's JSON (tests only).
var applyPlanJSON func(engine, dir, planfile string) ([]byte, error)

func cmdApply(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "directory the plan belongs to (default: current)")
	engine := fs.String("engine", "terraform", "binary that applies the plan: terraform, tofu or a path")
	noLog := fs.Bool("no-log", false, "do not write the decision log")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: applygate apply [--cwd DIR] [--engine terraform|tofu] <planfile> [engine apply arguments]")
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
	// The plan is always read with the engine's own show: there is no flag
	// that substitutes it, because an agent could use one to have a harmless
	// plan judged and a destructive one applied. Tests set applyPlanJSON.
	opt := hook.Options{Env: hook.EnvMap(), PlanJSON: applyPlanJSON}
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
		token, tier := approval.ConfirmToken(d)
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
		default:
			// There is no non-interactive approval: in CI, gate with
			// applygate plan-check and run the engine yourself.
			fmt.Fprintf(stderr, "applygate: this apply needs an interactive confirmation (tier %s); run it in a terminal, or in CI use applygate plan-check before terraform apply\n", tier)
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
