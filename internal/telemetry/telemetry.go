// Package telemetry sends anonymous usage counts, and only after a person
// has turned it on with "applygate telemetry on". Off, it reads one small
// file and does nothing else; the gate's "no network by default" holds.
//
// What is sent (schema 1): the applygate version, operating system and
// architecture, the period covered, and for each (version, agent, mode,
// verdict) the number of decisions, plus the number of internal errors. No
// commands, paths, repository or host names, user names, machine ids or
// install ids of any kind. The counts are derived from the local decision
// log at send time, so "applygate telemetry status --payload" shows exactly
// what the next report contains.
//
// When: at most once every 24 hours, from the hook after it has written
// its verdict (bounded to 3 seconds), or on "applygate telemetry send".
// Settings and send state live in one file under the user config directory,
// which the agent may not edit (it is a guard path), and the environment can
// force telemetry off (APPLYGATE_TELEMETRY=0 or DO_NOT_TRACK=1).
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

// Schema is the payload version.
const Schema = 1

// DefaultEndpoint is the endpoint a release build is given at link time
// (-X github.com/Flurit/applygate/internal/telemetry.DefaultEndpoint=URL).
// Empty means there is none, and "telemetry on" then needs --endpoint.
var DefaultEndpoint = ""

const (
	// MinInterval is the least time between two sends from the hook.
	MinInterval = 24 * time.Hour
	// SendTimeout bounds a send started by "applygate telemetry send".
	SendTimeout = 5 * time.Second
	// HookTimeout bounds a send started from the hook.
	HookTimeout = 3 * time.Second
	lockStale   = 10 * time.Minute
	fileName    = "telemetry.json"
)

// Settings is the on/off switch and the send state, one file.
type Settings struct {
	Enabled     bool      `json:"enabled"`
	Endpoint    string    `json:"endpoint,omitempty"`
	EnabledAt   time.Time `json:"enabled_at"`
	LastSent    time.Time `json:"last_sent"`
	LastAttempt time.Time `json:"last_attempt"`
	LastError   string    `json:"last_error,omitempty"`
	ReportsSent int       `json:"reports_sent"`
}

// Path is the settings file, under the applygate user config directory.
func Path() string { return filepath.Join(config.UserDir(), fileName) }

// Load reads the settings. A missing file means off.
func Load() (Settings, error) {
	var s Settings
	b, err := os.ReadFile(Path())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", Path(), err)
	}
	return s, nil
}

// Save writes the settings with private permissions.
func Save(s Settings) error {
	if err := os.MkdirAll(filepath.Dir(Path()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(Path(), append(b, '\n'), 0o600)
}

// EnvOff reports whether the environment forces telemetry off, and which
// variable does.
func EnvOff(env map[string]string) (bool, string) {
	switch strings.ToLower(env["APPLYGATE_TELEMETRY"]) {
	case "0", "false", "off", "no":
		return true, "APPLYGATE_TELEMETRY=" + env["APPLYGATE_TELEMETRY"]
	}
	switch strings.ToLower(env["DO_NOT_TRACK"]) {
	case "1", "true", "yes":
		return true, "DO_NOT_TRACK=" + env["DO_NOT_TRACK"]
	}
	return false, ""
}

// State is the effective switch: whether a send can happen now and why not.
type State struct {
	Settings
	On       bool
	Reason   string // why it is off, or "" when on
	Endpoint string // the endpoint a send would use
}

// Effective resolves the settings, the environment and the built-in
// endpoint into one answer.
func Effective(env map[string]string) State {
	s, err := Load()
	st := State{Settings: s}
	if err != nil {
		st.Reason = "settings unreadable: " + err.Error()
		return st
	}
	if off, why := EnvOff(env); off {
		st.Reason = "forced off by " + why
		return st
	}
	if !s.Enabled {
		st.Reason = "not turned on (applygate telemetry on)"
		return st
	}
	st.Endpoint = firstNonEmpty(env["APPLYGATE_TELEMETRY_ENDPOINT"], s.Endpoint, DefaultEndpoint)
	if st.Endpoint == "" {
		st.Reason = "no endpoint: this build has none and none was given with --endpoint"
		return st
	}
	if err := checkEndpoint(st.Endpoint); err != nil {
		st.Reason = err.Error()
		return st
	}
	st.On = true
	return st
}

// TurnOn enables telemetry towards endpoint (empty: the build's default).
func TurnOn(endpoint string) (Settings, error) {
	s, err := Load()
	if err != nil {
		return s, err
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if endpoint == "" {
		return s, errors.New("no endpoint: this build has no built-in telemetry endpoint, so pass --endpoint URL (https)")
	}
	if err := checkEndpoint(endpoint); err != nil {
		return s, err
	}
	s.Enabled = true
	s.EnabledAt = time.Now().UTC()
	if endpoint != DefaultEndpoint {
		s.Endpoint = endpoint
	} else {
		s.Endpoint = ""
	}
	s.LastError = ""
	return s, Save(s)
}

// TurnOff disables telemetry. The file stays, so the send history is kept.
func TurnOff() (Settings, error) {
	s, err := Load()
	if err != nil {
		return s, err
	}
	s.Enabled = false
	return s, Save(s)
}

// checkEndpoint accepts https anywhere and plain http only on the local
// machine (tests, a self-hosted collector on localhost).
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("endpoint %q is not a URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "::1" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
			return nil
		}
		return fmt.Errorf("endpoint %q: plain http is only accepted on localhost", raw)
	}
	return fmt.Errorf("endpoint %q: scheme must be https", raw)
}

// Count is one row of the payload.
type Count struct {
	Version string         `json:"version"`
	Agent   string         `json:"agent"`
	Mode    string         `json:"mode"`
	Verdict policy.Verdict `json:"verdict"`
	N       int            `json:"n"`
}

// Payload is one report.
type Payload struct {
	Schema    int       `json:"schema"`
	SentAt    time.Time `json:"sent_at"`
	Applygate string    `json:"applygate"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Decisions int       `json:"decisions"`
	Errors    int       `json:"errors"`
	Counts    []Count   `json:"counts"`
}

// Pending aggregates the decisions logged after a given time.
func Pending(entries []decisionlog.Entry, after time.Time, version string) Payload {
	p := Payload{Schema: Schema, SentAt: time.Now().UTC(), Applygate: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Counts: []Count{}}
	type key struct {
		version, agent, mode string
		verdict              policy.Verdict
	}
	counts := map[key]int{}
	for _, e := range entries {
		if !e.Time.After(after) {
			continue
		}
		p.Decisions++
		if e.Error != "" {
			p.Errors++
		}
		if p.From.IsZero() || e.Time.Before(p.From) {
			p.From = e.Time
		}
		if e.Time.After(p.To) {
			p.To = e.Time
		}
		counts[key{e.Version, e.Agent, e.Mode, e.Verdict}]++
	}
	for k, n := range counts {
		p.Counts = append(p.Counts, Count{Version: k.version, Agent: k.agent, Mode: k.mode, Verdict: k.verdict, N: n})
	}
	sort.Slice(p.Counts, func(i, j int) bool {
		a, b := p.Counts[i], p.Counts[j]
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.Mode != b.Mode {
			return a.Mode < b.Mode
		}
		return a.Verdict < b.Verdict
	})
	return p
}

// Send posts one payload. Redirects are not followed, so a report never
// goes anywhere but the configured endpoint.
func Send(ctx context.Context, endpoint string, p Payload) error {
	if err := checkEndpoint(endpoint); err != nil {
		return err
	}
	p.SentAt = time.Now().UTC()
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "applygate/"+p.Applygate)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("endpoint returned %s", resp.Status)
	}
	return nil
}

// Result says what Flush did.
type Result struct {
	Sent    bool
	Payload Payload
	Reason  string // why nothing was sent
}

// Flush sends the decisions logged since the last send, if telemetry is on
// and no other send is running. With dryRun it returns the payload and
// sends nothing. A refusal to send is a Reason, not an error; an error is a
// failed send or an unwritable settings file.
func Flush(ctx context.Context, logPath, version string, env map[string]string, dryRun bool) (Result, error) {
	st := Effective(env)
	if !st.On {
		return Result{Reason: st.Reason}, nil
	}
	unlock, ok := lock()
	if !ok {
		return Result{Reason: "another send is running"}, nil
	}
	defer unlock()

	var entries []decisionlog.Entry
	if f, err := os.Open(logPath); err == nil {
		entries, _ = decisionlog.Read(f)
		f.Close()
	}
	p := Pending(entries, st.LastSent, version)
	if dryRun {
		return Result{Payload: p, Reason: "dry run"}, nil
	}
	s := st.Settings
	s.LastAttempt = time.Now().UTC()
	if p.Decisions == 0 {
		return Result{Payload: p, Reason: "nothing logged since the last send"}, Save(s)
	}
	if err := Send(ctx, st.Endpoint, p); err != nil {
		s.LastError = err.Error()
		if serr := Save(s); serr != nil {
			return Result{Payload: p}, serr
		}
		return Result{Payload: p}, err
	}
	s.LastSent = p.To
	s.LastError = ""
	s.ReportsSent++
	return Result{Sent: true, Payload: p}, Save(s)
}

// AfterDecision is what the hook calls once its verdict is written. It is
// cheap when telemetry is off (one small file read) and never panics or
// returns an error: a decision has been made and nothing here may change
// it.
func AfterDecision(logPath, version string, env map[string]string) {
	defer func() { _ = recover() }()
	st := Effective(env)
	if !st.On || time.Since(st.LastAttempt) < MinInterval {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), HookTimeout)
	defer cancel()
	_, _ = Flush(ctx, logPath, version, env, false)
}

// lock takes an exclusive lock file next to the settings; a lock older than
// lockStale is treated as left behind by a killed process.
func lock() (func(), bool) {
	path := Path() + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, true
		}
		fi, serr := os.Stat(path)
		if serr != nil || time.Since(fi.ModTime()) < lockStale {
			return nil, false
		}
		os.Remove(path)
	}
	return nil, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
