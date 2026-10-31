package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/approval"
	"github.com/Flurit/applygate/internal/config"
)

// approvalsPath and approveNow are replaced by tests.
var (
	approvalsPath = config.ApprovalsPath
	approveNow    = time.Now
)

// cmdApprove lets a person allow one call that an agent was stopped on
// because it could not show an ask prompt. Without an ID it lists the
// pending requests. Approving needs a terminal and the environment name typed
// back, so an agent cannot do it (applygate also blocks agents from running
// this command at all).
func cmdApprove(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path, now := approvalsPath(), approveNow()
	if fs.NArg() == 0 {
		recs, err := approval.List(path, now)
		if err != nil {
			fmt.Fprintln(stderr, "applygate:", err)
			return 1
		}
		n := 0
		for _, r := range recs {
			if r.Status != "pending" {
				continue
			}
			n++
			fmt.Fprintf(stdout, "%s  %s ago  %s  %s  %s\n", r.ID, now.Sub(r.Created).Round(time.Second), r.Agent, r.Tier, r.Command)
		}
		if n == 0 {
			fmt.Fprintln(stdout, "no pending requests")
		}
		return 0
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: applygate approve [ID]")
		return 2
	}
	id := fs.Arg(0)
	r, err := approval.Find(path, id, now)
	if err != nil {
		fmt.Fprintf(stderr, "applygate: %s: %v\n", id, err)
		return 1
	}
	fmt.Fprintf(stdout, "Request %s from %s, %s ago\n", r.ID, r.Agent, now.Sub(r.Created).Round(time.Second))
	fmt.Fprintf(stdout, "  directory: %s\n  call:      %s\n", r.Cwd, r.Command)
	for _, why := range r.Reasons {
		fmt.Fprintf(stdout, "  - %s\n", why)
	}
	if !isTerminal(stdin) {
		fmt.Fprintln(stderr, "applygate: approving needs a person at a terminal; run this in your own shell, not through an agent")
		return 4
	}
	fmt.Fprintf(stderr, "\nAllow this exact call once? Type the environment name %q to approve, anything else to leave it blocked: ", r.Token)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != r.Token {
		fmt.Fprintln(stderr, "applygate: not approved")
		return 4
	}
	if _, err := approval.Approve(path, id, approveNow()); err != nil {
		fmt.Fprintf(stderr, "applygate: %s: %v\n", id, err)
		return 1
	}
	fmt.Fprintf(stdout, "Approved. The agent may make this call once in the next %s; tell it to retry the same call unchanged.\n", approval.ApprovedTTL)
	return 0
}
