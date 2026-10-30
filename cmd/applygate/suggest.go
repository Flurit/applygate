package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/suggest"
)

// cmdSuggest proposes a .applygate.yaml from the decision log: environments
// from the directories, workspaces, backends and profiles the engine was
// seen with, and the asks and blocks to review before enforce. It reads the
// log and prints YAML; it changes nothing unless --out names a file that
// does not exist yet.
func cmdSuggest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "decision log (default: from config)")
	root := fs.String("root", "", "repository root whose decisions to use (default: the directory of the nearest .applygate.yaml, else the working directory)")
	out := fs.String("out", "", "write the proposal to this file instead of stdout; refuses to overwrite")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "suggest takes no positional arguments, got %q\n", fs.Args())
		return 2
	}

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var existing *config.Config
	r := *root
	if r == "" {
		if p := config.FindRepoConfig(wd); p != "" {
			r = filepath.Dir(p)
		} else {
			r = wd
		}
	}
	r, err = filepath.Abs(r)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if p := config.FindRepoConfig(r); p != "" && filepath.Dir(p) == r {
		existing, err = config.LoadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "existing config: %v\n", err)
			return 1
		}
	}

	p := *logPath
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
	entries, bad := decisionlog.Read(f)
	f.Close()

	prop := suggest.Build(entries, suggest.Options{Root: r, Existing: existing})
	if prop.InScope == 0 {
		fmt.Fprintf(stderr, "suggest: %d decisions in %s, none under %s\n", len(entries), p, r)
		fmt.Fprintln(stderr, "run the agent in observe mode in this repository first, or pass --root for the repository the log is about")
		return 1
	}
	if err := prop.Check(); err != nil {
		fmt.Fprintf(stderr, "suggest: the proposal does not parse as a config, which is a bug: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "suggest: %d decisions read from %s (%d malformed), %d in %s\n", len(entries), p, bad, prop.InScope, r)
	if *out == "" {
		io.WriteString(stdout, prop.YAML())
		return 0
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(stderr, "%s exists; not overwriting (print to stdout and merge by hand)\n", *out)
		return 1
	}
	if err := os.WriteFile(*out, []byte(prop.YAML()), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s; review every tier, then run applygate doctor\n", *out)
	return 0
}
