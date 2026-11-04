package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewA12KeyBindsContentAndArgs(t *testing.T) {
	d := policy.Decision{Verdict: policy.Block}
	edit := policy.Event{Agent: "claude", Session: "s", Tool: "Edit", Kind: policy.KindWrite, Cwd: "/r", Paths: []string{"/r/ci/deploy.yml"}, Content: "replicas: 5"}
	edit2 := edit
	edit2.Content = "replicas: 0"
	mcp := policy.Event{Agent: "claude", Session: "s", Tool: "mcp__db__run", Kind: policy.KindMCP, Cwd: "/r", Command: "mcp__db__run {...}", Args: json.RawMessage(`{"sql":"select 1"}`)}
	mcp2 := mcp
	mcp2.Args = json.RawMessage(`{"sql":"drop table orders"}`)
	ok := Key(edit, d) != Key(edit2, d) && Key(mcp, d) != Key(mcp2, d)
	reviewgap.Check(t, "A12", ok, "an approval for one write or MCP call matches another with different content or arguments")
}

func TestReviewA14HeldLockDoesNotHang(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := tryLock(lock); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		Request(path, Record{Key: "k", Created: time.Now()}, time.Now())
		close(done)
	}()
	returned := true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		returned = false
	}
	unlock(lock)
	<-done
	reviewgap.Check(t, "A14", returned, "a held approvals lock blocked Request for more than 2 s")
}
