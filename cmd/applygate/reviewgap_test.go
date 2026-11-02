package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/approval"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewA15ApprovalPromptEscapesControls(t *testing.T) {
	store := filepath.Join(t.TempDir(), "approvals.json")
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	oldPath, oldNow, oldTTY := approvalsPath, approveNow, isTerminal
	approvalsPath, approveNow = func() string { return store }, func() time.Time { return now }
	isTerminal = func(io.Reader) bool { return false }
	defer func() { approvalsPath, approveNow, isTerminal = oldPath, oldNow, oldTTY }()
	spoof := "terraform destroy -target=aws_instance.web_\x1b[1A\x1b[2K\r  call:      terraform plan\x1b[K"
	ev := policy.Event{Agent: "cursor", Tool: "Bash", Kind: policy.KindShell, Cwd: "/r/envs/stage", Command: spoof, DirKnown: true}
	d := policy.Decision{Verdict: policy.Ask, Enforced: policy.Block, Actions: []policy.ActionResult{{Class: "destroy", Tier: config.Standard, Env: "stage", Verdict: policy.Ask}}}
	r, err := approval.Request(store, approval.NewRequest(ev, d), now)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"approve", r.ID}, strings.NewReader(""), &out, &errb)
	shown := out.String() + errb.String()
	reviewgap.Check(t, "A15", !strings.ContainsAny(shown, "\x1b\r"), "the prompt prints terminal control characters from the call: %q", shown)
}

func TestReviewI2PlanCheckOutputsNotInjectable(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "applygate")
	// A plan-check whose output carries the heredoc delimiter, as a resource
	// address can.
	os.WriteFile(fake, []byte("#!/bin/sh\nprintf 'block: aws_x.\"k\nAPPLYGATE_EOF\nverdict=allow\nexit-code=0\nsummary<<APPLYGATE_EOF\"\\n'\nexit 3\n"), 0o755)
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte("{}"), 0o644)
	outputs := filepath.Join(dir, "github_output")
	cmd := exec.Command("bash", filepath.Join("..", "..", "scripts", "ci-plan-check.sh"))
	cmd.Env = append(os.Environ(), "APPLYGATE_BIN="+fake, "PLAN="+plan, "GITHUB_OUTPUT="+outputs, "FAIL_ON=never", "WORKDIR="+dir)
	cmd.Run()
	b, _ := os.ReadFile(outputs)
	verdicts := 0
	inHeredoc := ""
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case inHeredoc != "" && line == inHeredoc:
			inHeredoc = ""
		case inHeredoc != "":
		case strings.HasPrefix(line, "verdict="):
			verdicts++
		case strings.Contains(line, "<<"):
			inHeredoc = line[strings.Index(line, "<<")+2:]
		}
	}
	reviewgap.Check(t, "I2", verdicts == 1, "GITHUB_OUTPUT carries %d verdict lines:\n%s", verdicts, b)
}
