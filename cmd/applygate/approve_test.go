package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/approval"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/policy"
)

func TestApproveCommand(t *testing.T) {
	store := filepath.Join(t.TempDir(), "approvals.json")
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	oldPath, oldNow, oldTTY := approvalsPath, approveNow, isTerminal
	approvalsPath, approveNow = func() string { return store }, func() time.Time { return now }
	defer func() { approvalsPath, approveNow, isTerminal = oldPath, oldNow, oldTTY }()

	ev := policy.Event{Agent: "codex", Tool: "Bash", Kind: policy.KindShell, Cwd: "/r/envs/stage", Command: "terraform state rm x", DirKnown: true}
	d := policy.Decision{Verdict: policy.Ask, Enforced: policy.Block, Actions: []policy.ActionResult{
		{Class: "state-surgery", Tier: config.Standard, Env: "stage", Verdict: policy.Ask, Why: "state rm"}}}
	r, err := approval.Request(store, approval.NewRequest(ev, d), now)
	if err != nil {
		t.Fatal(err)
	}
	approve := func(tty bool, typed string, args ...string) (int, string) {
		isTerminal = func(io.Reader) bool { return tty }
		var out, errb bytes.Buffer
		rc := run(append([]string{"approve"}, args...), strings.NewReader(typed), &out, &errb)
		return rc, out.String() + errb.String()
	}
	if rc, out := approve(false, ""); rc != 0 || !strings.Contains(out, r.ID) || !strings.Contains(out, "terraform state rm x") {
		t.Fatalf("list: exit %d\n%s", rc, out)
	}
	if rc, out := approve(false, "stage\n", r.ID); rc != 4 || !strings.Contains(out, "terminal") {
		t.Fatalf("without a terminal: exit %d\n%s", rc, out)
	}
	if rc, out := approve(true, "yes\n", r.ID); rc != 4 {
		t.Fatalf("wrong confirmation: exit %d\n%s", rc, out)
	}
	if rc, out := approve(true, "stage\n", r.ID); rc != 0 || !strings.Contains(out, "Approved") {
		t.Fatalf("approve: exit %d\n%s", rc, out)
	}
	if _, ok, _ := approval.Consume(store, r.Key, now); !ok {
		t.Fatal("approval not stored")
	}
	if rc, _ := approve(true, "stage\n", "deadbeef"); rc != 1 {
		t.Fatalf("unknown ID: exit %d", rc)
	}
	// An agent may not approve: it is guard tampering in every tier.
	var out, errb bytes.Buffer
	// Also through a pseudo-terminal wrapper or another language.
	for _, c := range []string{
		"applygate approve " + r.ID,
		"script -q /dev/null applygate approve " + r.ID,
		"script -qc 'applygate approve " + r.ID + "' /dev/null",
		`python3 -c 'import pty; pty.spawn(["applygate", "approve", "` + r.ID + `"])'`,
		`expect -c 'spawn applygate approve ` + r.ID + `; send "stage\r"; expect eof'`,
	} {
		out.Reset()
		if rc := run([]string{"check", "--cwd", t.TempDir(), c}, nil, &out, &errb); rc != 3 || !strings.Contains(out.String(), "guard-tampering") {
			t.Fatalf("agent approve %q: exit %d\n%s", c, rc, out.String())
		}
	}
}
