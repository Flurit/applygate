package approval

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/policy"
)

func asked(plan string) (policy.Event, policy.Decision) {
	ev := policy.Event{Agent: "codex", Session: "s1", Tool: "Bash", Kind: policy.KindShell, Cwd: "/r/envs/stage", Command: "terraform apply tfplan", DirKnown: true}
	d := policy.Decision{Verdict: policy.Ask, Enforced: policy.Block, Actions: []policy.ActionResult{
		{Class: "destroy", Engine: "terraform", Command: ev.Command, Dir: ev.Cwd, Tier: config.Standard, Env: "stage", PlanSHA256: plan, Verdict: policy.Ask, Why: "destroys 1 resource"},
	}}
	return ev, d
}

func TestRequestApproveConsume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	ev, d := asked("aaa")
	r1, err := Request(path, NewRequest(ev, d), now)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Token != "stage" || r1.Tier != "standard" || len(r1.ID) != 8 {
		t.Fatalf("request: %+v", r1)
	}
	// A repeated call keeps its ID instead of piling up requests.
	r2, _ := Request(path, NewRequest(ev, d), now.Add(time.Minute))
	if r2.ID != r1.ID {
		t.Fatalf("repeat got a new ID: %s vs %s", r2.ID, r1.ID)
	}
	if recs, _ := List(path, now); len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	// Nothing to consume before a person approves.
	if _, ok, _ := Consume(path, Key(ev, d), now); ok {
		t.Fatal("consumed a pending request")
	}
	if _, err := Approve(path, r1.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A different plan does not match the approval.
	ev2, d2 := asked("bbb")
	if _, ok, _ := Consume(path, Key(ev2, d2), now.Add(3*time.Minute)); ok {
		t.Fatal("approval matched a changed plan")
	}
	if _, ok, _ := Consume(path, Key(ev, d), now.Add(3*time.Minute)); !ok {
		t.Fatal("approved call not allowed")
	}
	// Single use.
	if _, ok, _ := Consume(path, Key(ev, d), now.Add(4*time.Minute)); ok {
		t.Fatal("approval used twice")
	}
}

func TestExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	ev, d := asked("aaa")
	r, _ := Request(path, NewRequest(ev, d), now)
	if _, err := Approve(path, r.ID, now.Add(PendingTTL+time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approved an expired request: %v", err)
	}
	r, _ = Request(path, NewRequest(ev, d), now.Add(2*PendingTTL))
	if _, err := Approve(path, r.ID, now.Add(2*PendingTTL)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := Consume(path, Key(ev, d), now.Add(2*PendingTTL+ApprovedTTL+time.Second)); ok {
		t.Fatal("used an expired approval")
	}
}

func TestKeyBindsContext(t *testing.T) {
	ev, d := asked("aaa")
	base := Key(ev, d)
	for name, change := range map[string]func(*policy.Event, *policy.Decision){
		"command":      func(e *policy.Event, _ *policy.Decision) { e.Command += " -lock=false" },
		"cwd":          func(e *policy.Event, _ *policy.Decision) { e.Cwd = "/r/envs/prod" },
		"session":      func(e *policy.Event, _ *policy.Decision) { e.Session = "s2" },
		"agent":        func(e *policy.Event, _ *policy.Decision) { e.Agent = "cursor" },
		"tier":         func(_ *policy.Event, d *policy.Decision) { d.Actions[0].Tier = config.Protected },
		"profile":      func(_ *policy.Event, d *policy.Decision) { d.Actions[0].Profile = "prod-admin" },
		"kube context": func(_ *policy.Event, d *policy.Decision) { d.Actions[0].KubeContext = "prod-eks" },
		"gcp project":  func(_ *policy.Event, d *policy.Decision) { d.Actions[0].GCPProject = "acme-prod" },
	} {
		e, dd := asked("aaa")
		change(&e, &dd)
		if Key(e, dd) == base {
			t.Errorf("%s change kept the same key", name)
		}
	}
}
