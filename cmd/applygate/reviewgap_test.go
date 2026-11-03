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

func TestReviewA1ApplyHasNoTestFlags(t *testing.T) {
	// The release build has no --plan-json (it replaced the plan the gate
	// judged) and no --yes (it approved an ask without a person).
	var out, errb bytes.Buffer
	rc1 := cmdApply([]string{"--plan-json", "tfplan=/dev/null", "tfplan"}, strings.NewReader(""), &out, &errb)
	planJSON := rc1 == 2 && strings.Contains(errb.String(), "flag provided but not defined")
	errb.Reset()
	rc2 := cmdApply([]string{"--yes", "tfplan"}, strings.NewReader(""), &out, &errb)
	yes := rc2 == 2 && strings.Contains(errb.String(), "flag provided but not defined")
	reviewgap.Check(t, "A1", planJSON && yes, "apply still accepts --plan-json (%v, exit %d) or --yes (%v, exit %d): %s", !planJSON, rc1, !yes, rc2, errb.String())
}

// plan-check, which the Action and the Terragrunt gate run, must judge a
// replace like the hook does (finding 2T12) and refuse a tier it does not
// know (finding 2T14).
func TestReview2T12PlanCheckReplaceIsADestroy(t *testing.T) {
	var out, errb bytes.Buffer
	rc := cmdPlanCheck([]string{"--tier", "standard", "../../harness/pack/plans/replace_stateless.json"}, &out, &errb)
	reviewgap.Check(t, "2T12", rc != 0, "plan-check allowed a replace in a standard tier (the hook asks): %s", out.String())
}

func TestReview2T14PlanCheckRejectsUnknownTier(t *testing.T) {
	var out, errb bytes.Buffer
	rc := cmdPlanCheck([]string{"--tier", "prod", "../../harness/pack/plans/s5_replace_db.json"}, &out, &errb)
	reviewgap.Check(t, "2T14", rc == 2, "plan-check --tier prod exited %d: %s", rc, out.String())
}

// plan-check resolves the tier from the backend and workspace too, as the
// hook does (finding 2T13).
func TestReview2T13PlanCheckReadsTheBackend(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte("version: 1\nstrict: false\nenvironments:\n  - {name: dev, tier: disposable, match: {paths: [\"dev/**\"]}}\n"), 0o644)
	dev := filepath.Join(root, "dev")
	os.MkdirAll(dev, 0o755)
	os.WriteFile(filepath.Join(dev, "backend.tf"), []byte("terraform {\n  backend \"s3\" {\n    bucket = \"acme-prod-tfstate\"\n    key    = \"app/terraform.tfstate\"\n  }\n}\n"), 0o644)
	var out, errb bytes.Buffer
	rc := cmdPlanCheck([]string{"--cwd", dev, "../../harness/pack/plans/replace_stateless.json"}, &out, &errb)
	if rc != 3 || !strings.Contains(out.String(), "tier protected") {
		t.Fatalf("plan-check judged a prod backend in a dev path at rc %d: %s%s", rc, out.String(), errb.String())
	}
}
