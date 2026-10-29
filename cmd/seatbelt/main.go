// Command seatbelt is the compatibility entry point kept for one release
// after the project was renamed to applygate (2026-10-29). Hook entries
// written by older installs call "<path>/seatbelt hook claude|codex"; this
// binary prints a one-line deprecation notice to stderr and runs the
// applygate binary next to it (or the first one on PATH) with the same
// arguments, passing stdin, stdout, stderr and the exit code through.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

func main() {
	fmt.Fprintln(os.Stderr, "seatbelt: this project is now applygate; the seatbelt name keeps working for one release. Run \"applygate hook install\" to update hook entries.")
	target := findApplygate()
	if target == "" {
		fmt.Fprintln(os.Stderr, "seatbelt: applygate binary not found next to this binary or on PATH")
		os.Exit(2)
	}
	cmd := exec.Command(target, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	// Forward termination signals so a host that kills the hook kills the
	// real process too; interrupts from a terminal already reach both.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "seatbelt: cannot run %s: %v\n", target, err)
		os.Exit(2)
	}
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	if ee, ok := err.(*exec.ExitError); ok {
		os.Exit(ee.ExitCode())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "seatbelt: %v\n", err)
		os.Exit(2)
	}
}

// findApplygate prefers the applygate binary in this binary's own directory,
// which is where install.sh and the release archive put both.
func findApplygate() string {
	if self, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(self); err == nil {
			self = r
		}
		p := filepath.Join(filepath.Dir(self), "applygate")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("applygate"); err == nil {
		return p
	}
	return ""
}
