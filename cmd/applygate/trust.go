package main

import (
	"bufio"
	"bytes"
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
	shown := map[string][]byte{}
	for _, p := range config.RepoConfigs(dir) {
		// Only a regular file can be trusted: a symlink would be read at
		// one place and checked against another.
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			fmt.Fprintf(stderr, "applygate: %s is not a regular file (a symlink?); replace it with the file itself\n", p)
			return 1
		}
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
		shown[p] = b
		fmt.Fprintf(stdout, "\n--- %s (not trusted) ---\n%s\n--- end of %s ---\n", p, printableLines(string(b)), p)
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
	// Trust what was shown, and only if it is still what is on disk: a
	// file changed while the person read it is not what they approved.
	for _, p := range pending {
		b, err := safefile.ReadFile(p)
		if err != nil || !bytes.Equal(b, shown[p]) {
			fmt.Fprintf(stderr, "applygate: %s changed while it was shown; nothing trusted. Run applygate trust again.\n", p)
			return 1
		}
	}
	if err := config.TrustContent(shown); err != nil {
		fmt.Fprintln(stderr, "applygate:", err)
		return 1
	}
	fmt.Fprintf(stdout, "trusted %d config(s)\n", len(pending))
	return 0
}
