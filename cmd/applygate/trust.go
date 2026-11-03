package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/safefile"
)

// cmdTrust is how a person approves a repository config. applygate reads a
// repository .applygate.yaml only when its exact content was trusted, so a
// config an agent planted or rewrote decides nothing until a person has
// read it here. Like approve, it needs a terminal, and an agent that runs it
// is blocked as guard tampering.
func cmdTrust(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cwd := fs.String("cwd", "", "directory whose repository configs to trust (default: current)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dir := *cwd
	if dir == "" {
		dir, _ = os.Getwd()
	}
	dir, _ = filepath.Abs(dir)
	var pending []string
	for _, p := range config.RepoConfigs(dir) {
		b, err := safefile.ReadFile(p)
		if err != nil {
			fmt.Fprintln(stderr, "applygate:", err)
			return 1
		}
		if config.Trusted(p, b) {
			fmt.Fprintf(stdout, "trusted already: %s\n", p)
			continue
		}
		pending = append(pending, p)
		fmt.Fprintf(stdout, "\n--- %s (not trusted) ---\n%s\n--- end of %s ---\n", p, printable(string(b)), p)
	}
	if len(pending) == 0 {
		if len(config.RepoConfigs(dir)) == 0 {
			fmt.Fprintln(stdout, "no .applygate.yaml in", dir, "or its parents")
		}
		return 0
	}
	if !isTerminal(stdin) {
		fmt.Fprintln(stderr, "applygate trust needs a person at a terminal: read the config above and run it yourself")
		return 2
	}
	fmt.Fprintf(stdout, "\nThese files decide which directories are production. Type \"trust\" to trust %d config(s) as shown: ", len(pending))
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "trust" {
		fmt.Fprintln(stdout, "not trusted")
		return 1
	}
	if err := config.Trust(pending); err != nil {
		fmt.Fprintln(stderr, "applygate:", err)
		return 1
	}
	fmt.Fprintf(stdout, "trusted %d config(s)\n", len(pending))
	return 0
}
