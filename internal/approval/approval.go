// Package approval keeps one-time approvals for asked commands.
//
// Most agents cannot show an ask prompt, so an ask is enforced as a block.
// The hook then records a pending request, and a person can allow that one
// command by running `applygate approve ID` at a terminal. The agent's next
// identical call consumes the approval and is allowed; a later one is judged
// again. An approval is bound to the event and to what the decision found
// (classes, environments, plan hashes), so a changed command, directory,
// environment or plan does not match it. Only asks can be approved; a block
// stays a block.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

const (
	// PendingTTL is how long a person has to approve a request.
	PendingTTL = time.Hour
	// ApprovedTTL is how long the agent has to retry after the approval.
	ApprovedTTL = 15 * time.Minute
	maxRecords  = 200
)

// Record is one request or approval.
type Record struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Status     string    `json:"status"` // pending | approved
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	Agent      string    `json:"agent"`
	Session    string    `json:"session,omitempty"`
	Cwd        string    `json:"cwd"`
	Command    string    `json:"command"` // redacted, for display
	Reasons    []string  `json:"reasons"`
	Tier       string    `json:"tier"`
	Token      string    `json:"token"` // what the person types to approve
}

// ErrNotFound is returned by Approve for an unknown or expired ID.
var ErrNotFound = errors.New("no pending request with that ID (it may have expired; retry the command to get a new one)")

// Key binds an approval to the event and to the decision's findings.
func Key(ev policy.Event, d policy.Decision) string {
	type act struct{ Class, Engine, Command, Dir, Tier, Env, Workspace, Backend, Profile, PlanSHA256 string }
	b := struct {
		Agent, Session, Tool, Kind, Cwd, Command string
		DirKnown                                 bool
		Paths                                    []string
		Actions                                  []act
	}{ev.Agent, ev.Session, ev.Tool, string(ev.Kind), ev.Cwd, ev.Command, ev.DirKnown, ev.Paths, nil}
	for _, a := range d.Actions {
		b.Actions = append(b.Actions, act{string(a.Class), a.Engine, a.Command, a.Dir, string(a.Tier), a.Env, a.Workspace, a.Backend, a.Profile, a.PlanSHA256})
	}
	js, _ := json.Marshal(b)
	sum := sha256.Sum256(js)
	return hex.EncodeToString(sum[:])
}

// NewRequest describes a decision as a pending request.
func NewRequest(ev policy.Event, d policy.Decision) Record {
	key := Key(ev, d)
	r := Record{ID: key[:8], Key: key, Status: "pending", Agent: ev.Agent, Session: ev.Session, Cwd: ev.Cwd,
		Command: decisionlog.Redact(ev.Command)}
	if r.Command == "" {
		r.Command = ev.Tool + " " + strings.Join(ev.Paths, " ")
	}
	var token string
	var tier config.Tier
	token, tier = ConfirmToken(d)
	r.Token, r.Tier = token, string(tier)
	for _, a := range d.Actions {
		if a.Verdict == policy.Allow {
			continue
		}
		line := fmt.Sprintf("%s: %s", a.Class, decisionlog.Redact(a.Why))
		if a.Tier != "" {
			line += fmt.Sprintf(" (environment %s, tier %s)", a.Env, a.Tier)
		}
		if a.PlanSHA256 != "" {
			line += " plan sha256 " + a.PlanSHA256
		}
		r.Reasons = append(r.Reasons, line)
	}
	return r
}

// ConfirmToken is what the person must type: the environment name of the
// action that asked, or its tier when the environment is unnamed; and the
// most protected tier among the actions that asked.
func ConfirmToken(d policy.Decision) (string, config.Tier) {
	token := ""
	var tier config.Tier
	for _, a := range d.Actions {
		if a.Verdict == policy.Allow {
			continue
		}
		if tier == "" || a.Tier.Rank() > tier.Rank() {
			tier = a.Tier
			if a.Env != "" && !strings.HasPrefix(a.Env, "unknown") {
				token = a.Env
			} else {
				token = string(a.Tier)
			}
		}
	}
	if token == "" {
		token = "yes"
	}
	return token, tier
}

// Request records r as pending, or returns the live record with the same
// key, so a repeated call keeps its ID.
func Request(path string, r Record, now time.Time) (Record, error) {
	var out Record
	err := update(path, now, func(recs []Record) []Record {
		for i := range recs {
			if recs[i].Key == r.Key {
				if recs[i].Status == "pending" {
					recs[i].Expires = now.Add(PendingTTL)
				}
				out = recs[i]
				return recs
			}
		}
		r.Created, r.Expires = now, now.Add(PendingTTL)
		out = r
		return append(recs, r)
	})
	return out, err
}

// Approve marks the pending request id as approved for ApprovedTTL.
func Approve(path, id string, now time.Time) (Record, error) {
	var out Record
	found := false
	err := update(path, now, func(recs []Record) []Record {
		for i := range recs {
			if recs[i].ID == id && recs[i].Status == "pending" {
				recs[i].Status, recs[i].ApprovedAt, recs[i].Expires = "approved", now, now.Add(ApprovedTTL)
				out, found = recs[i], true
				return recs
			}
		}
		return recs
	})
	if err == nil && !found {
		err = ErrNotFound
	}
	return out, err
}

// Consume removes and returns a live approval for key.
func Consume(path, key string, now time.Time) (Record, bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	var out Record
	found := false
	err := update(path, now, func(recs []Record) []Record {
		for i := range recs {
			if recs[i].Key == key && recs[i].Status == "approved" {
				out, found = recs[i], true
				return append(recs[:i], recs[i+1:]...)
			}
		}
		return recs
	})
	return out, found, err
}

// Find returns the live pending request id.
func Find(path, id string, now time.Time) (Record, error) {
	recs, err := List(path, now)
	if err != nil {
		return Record{}, err
	}
	for _, r := range recs {
		if r.ID == id && r.Status == "pending" {
			return r, nil
		}
	}
	return Record{}, ErrNotFound
}

// List returns the live records, oldest first.
func List(path string, now time.Time) ([]Record, error) {
	recs, err := read(path)
	return live(recs, now), err
}

func live(recs []Record, now time.Time) []Record {
	var out []Record
	for _, r := range recs {
		if now.Before(r.Expires) {
			out = append(out, r)
		}
	}
	return out
}

func read(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []Record
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return recs, nil
}

// update applies f to the live records under an exclusive lock and writes
// the result atomically.
func update(path string, now time.Time, f func([]Record) []Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	recs, err := read(path)
	if err != nil {
		return err
	}
	recs = f(live(recs, now))
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	if len(recs) > maxRecords {
		recs = recs[len(recs)-maxRecords:]
	}
	js, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(js, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
