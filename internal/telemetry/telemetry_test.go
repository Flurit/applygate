package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/decisionlog"
)

const trialLog = "../../review/agent-trial/results/2026-10-29-both/decisions.jsonl"

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

type collector struct {
	srv    *httptest.Server
	n      atomic.Int32
	bodies chan []byte
	status int
}

func newCollector(t *testing.T, status int) *collector {
	t.Helper()
	c := &collector{bodies: make(chan []byte, 8), status: status}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.n.Add(1)
		b, _ := io.ReadAll(r.Body)
		c.bodies <- b
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header.Get("User-Agent"), "applygate/") {
			t.Errorf("request shape: %s %s %s", r.Method, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"))
		}
		if c.status == http.StatusFound {
			w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
		}
		w.WriteHeader(c.status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func TestOffByDefaultAndForcedOffByEnvironment(t *testing.T) {
	isolate(t)
	st := Effective(nil)
	if st.On || !strings.Contains(st.Reason, "not turned on") {
		t.Fatalf("%+v", st)
	}
	if _, err := TurnOn("https://collector.example/v1"); err != nil {
		t.Fatal(err)
	}
	if st := Effective(nil); !st.On || st.Endpoint != "https://collector.example/v1" {
		t.Fatalf("%+v", st)
	}
	for _, env := range []map[string]string{{"APPLYGATE_TELEMETRY": "0"}, {"APPLYGATE_TELEMETRY": "off"}, {"DO_NOT_TRACK": "1"}} {
		if st := Effective(env); st.On || !strings.Contains(st.Reason, "forced off") {
			t.Fatalf("env %v: %+v", env, st)
		}
	}
	if _, err := TurnOff(); err != nil {
		t.Fatal(err)
	}
	if st := Effective(nil); st.On {
		t.Fatalf("still on after off: %+v", st)
	}
}

func TestTurnOnNeedsAnEndpointAndHTTPS(t *testing.T) {
	isolate(t)
	if _, err := TurnOn(""); err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("a build without a default endpoint must refuse: %v", err)
	}
	if _, err := TurnOn("http://example.com/x"); err == nil || !strings.Contains(err.Error(), "only accepted on localhost") {
		t.Fatalf("plain http off the machine must be refused: %v", err)
	}
	if _, err := TurnOn("ftp://x"); err == nil {
		t.Fatal("other schemes must be refused")
	}
	if _, err := TurnOn("http://127.0.0.1:9/x"); err != nil {
		t.Fatalf("localhost http is for tests and local collectors: %v", err)
	}
	if st := Effective(nil); st.On {
		// enabled, but nothing has been sent; the switch is honoured
		if st.Endpoint != "http://127.0.0.1:9/x" {
			t.Fatal(st.Endpoint)
		}
	}
	env := map[string]string{"APPLYGATE_TELEMETRY_ENDPOINT": "https://other.example/v1"}
	if st := Effective(env); st.Endpoint != "https://other.example/v1" {
		t.Fatalf("the environment may redirect reports (self-hosting): %+v", st)
	}
}

func TestPendingCountsOnlyAndFoldsTheLegacyVersionKey(t *testing.T) {
	f, err := os.Open(trialLog)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, _ := decisionlog.Read(f)
	p := Pending(entries, time.Time{}, "0.3.0")
	if p.Decisions != 169 || p.Errors != 0 || p.Schema != 1 || p.Applygate != "0.3.0" {
		t.Fatalf("%+v", p)
	}
	total := 0
	for _, c := range p.Counts {
		total += c.N
		if c.Version != "0.1.3" {
			t.Fatalf("the trial log was written as seatbelt_version 0.1.3; got %q", c.Version)
		}
		if c.Agent == "" || c.Mode == "" || c.Verdict == "" {
			t.Fatalf("incomplete row %+v", c)
		}
	}
	if total != 169 {
		t.Fatalf("rows sum to %d", total)
	}
	b, _ := json.Marshal(p)
	for _, leak := range []string{"/work", "terraform", "command", "cwd", "session", "path", "hostname"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("payload carries %q:\n%s", leak, b)
		}
	}
	if later := Pending(entries, p.To, "x"); later.Decisions != 0 {
		t.Fatalf("everything up to To is covered; %d left", later.Decisions)
	}
}

func TestFlushSendsOnceThenNothingNew(t *testing.T) {
	isolate(t)
	c := newCollector(t, http.StatusAccepted)
	if _, err := TurnOn(c.srv.URL + "/v1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := Flush(ctx, trialLog, "0.3.0", nil, false)
	if err != nil || !res.Sent || res.Payload.Decisions != 169 {
		t.Fatalf("%+v %v", res, err)
	}
	body := <-c.bodies
	var got Payload
	if err := json.Unmarshal(body, &got); err != nil || got.Schema != 1 || got.Decisions != 169 || got.SentAt.IsZero() {
		t.Fatalf("body %s: %v", body, err)
	}
	if strings.Contains(string(body), "/work") {
		t.Fatalf("a path leaked: %s", body)
	}
	s, _ := Load()
	if s.ReportsSent != 1 || !s.LastSent.Equal(got.To) || s.LastError != "" {
		t.Fatalf("settings after send: %+v", s)
	}
	res, err = Flush(ctx, trialLog, "0.3.0", nil, false)
	if err != nil || res.Sent || !strings.Contains(res.Reason, "nothing logged") || c.n.Load() != 1 {
		t.Fatalf("second flush: %+v %v, requests %d", res, err, c.n.Load())
	}
	res, err = Flush(ctx, trialLog, "0.3.0", nil, true)
	if err != nil || res.Sent || res.Reason != "dry run" || c.n.Load() != 1 {
		t.Fatalf("dry run must not send: %+v %v", res, err)
	}
}

func TestFlushFailureKeepsTheDecisionsPending(t *testing.T) {
	isolate(t)
	c := newCollector(t, http.StatusInternalServerError)
	if _, err := TurnOn(c.srv.URL); err != nil {
		t.Fatal(err)
	}
	res, err := Flush(context.Background(), trialLog, "0.3.0", nil, false)
	if err == nil || res.Sent || !strings.Contains(err.Error(), "500") {
		t.Fatalf("%+v %v", res, err)
	}
	s, _ := Load()
	if !s.LastSent.IsZero() || s.ReportsSent != 0 || !strings.Contains(s.LastError, "500") || s.LastAttempt.IsZero() {
		t.Fatalf("%+v", s)
	}
	if p := Pending(readLog(t), s.LastSent, "x"); p.Decisions != 169 {
		t.Fatalf("still pending: %d", p.Decisions)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	isolate(t)
	c := newCollector(t, http.StatusFound)
	if _, err := TurnOn(c.srv.URL); err != nil {
		t.Fatal(err)
	}
	_, err := Flush(context.Background(), trialLog, "0.3.0", nil, false)
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("a redirect must be an error, not a second destination: %v", err)
	}
	if c.n.Load() != 1 {
		t.Fatalf("%d requests", c.n.Load())
	}
}

func TestAfterDecisionSendsAtMostOnceADayAndNeverFails(t *testing.T) {
	isolate(t)
	c := newCollector(t, http.StatusOK)
	if _, err := TurnOn(c.srv.URL); err != nil {
		t.Fatal(err)
	}
	AfterDecision(trialLog, "0.3.0", nil)
	AfterDecision(trialLog, "0.3.0", nil)
	if c.n.Load() != 1 {
		t.Fatalf("%d requests; the second call is inside the interval", c.n.Load())
	}
	s, _ := Load()
	s.LastAttempt = time.Now().Add(-25 * time.Hour)
	s.LastSent = time.Time{}
	if err := Save(s); err != nil {
		t.Fatal(err)
	}
	AfterDecision(trialLog, "0.3.0", nil)
	if c.n.Load() != 2 {
		t.Fatalf("%d requests; after the interval it sends again", c.n.Load())
	}
	// Off: no read of the log, no request, no panic, whatever the paths.
	if _, err := TurnOff(); err != nil {
		t.Fatal(err)
	}
	AfterDecision("/nonexistent/log", "0.3.0", nil)
	if c.n.Load() != 2 {
		t.Fatal("sent while off")
	}
}

func TestLockFileSerialisesSends(t *testing.T) {
	isolate(t)
	c := newCollector(t, http.StatusOK)
	if _, err := TurnOn(c.srv.URL); err != nil {
		t.Fatal(err)
	}
	lockPath := Path() + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Flush(context.Background(), trialLog, "x", nil, false)
	if err != nil || res.Sent || !strings.Contains(res.Reason, "another send") {
		t.Fatalf("%+v %v", res, err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	res, err = Flush(context.Background(), trialLog, "x", nil, false)
	if err != nil || !res.Sent {
		t.Fatalf("a stale lock must be taken over: %+v %v", res, err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock left behind")
	}
}

func readLog(t *testing.T) []decisionlog.Entry {
	t.Helper()
	f, err := os.Open(trialLog)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, _ := decisionlog.Read(f)
	return entries
}
