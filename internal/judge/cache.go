package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/safefile"
)

// Cache keeps recent escalations (ask and block) so a call the agent
// repeats does not pay the model again. An allow is never kept: the cache
// lives where the agent can write, so an entry can only make a verdict
// stricter, never skip the judge. Errors are not kept either. Concurrent
// hooks may race; the last writer wins, which only costs a repeated call.
type Cache struct {
	Path string
	TTL  time.Duration
	Max  int
}

type cached struct {
	Verdict policy.Verdict `json:"verdict"`
	Reason  string         `json:"reason"`
	Model   string         `json:"model"`
	At      time.Time      `json:"at"`
}

// DefaultCache is the cache the hook uses.
func DefaultCache(path string) Cache { return Cache{Path: path, TTL: 24 * time.Hour, Max: 2000} }

func (c Cache) load() map[string]cached {
	m := map[string]cached{}
	if b, err := safefile.ReadFile(c.Path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// Get returns a cached verdict for key that is younger than the TTL.
func (c Cache) Get(key string, now time.Time) (Result, bool) {
	if c.Path == "" {
		return Result{}, false
	}
	e, ok := c.load()[key]
	// An entry dated in the future (beyond a minute of clock skew) was not
	// written by this machine's hook.
	if !ok || now.Sub(e.At) > c.TTL || e.At.After(now.Add(time.Minute)) || e.Verdict == "" || e.Verdict == policy.Allow {
		return Result{}, false
	}
	return Result{Verdict: e.Verdict, Reason: e.Reason, Model: e.Model, Cached: true}, true
}

// Put stores a verdict, dropping expired entries and the oldest beyond Max.
func (c Cache) Put(key string, r Result, now time.Time) error {
	if c.Path == "" || r.Err != "" || r.Verdict == "" || r.Verdict == policy.Allow {
		return nil
	}
	m := c.load()
	for k, e := range m {
		if now.Sub(e.At) > c.TTL || e.At.After(now.Add(time.Minute)) || e.Verdict == policy.Allow {
			delete(m, k)
		}
	}
	m[key] = cached{Verdict: r.Verdict, Reason: r.Reason, Model: r.Model, At: now}
	if c.Max > 0 && len(m) > c.Max {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]].At.Before(m[keys[j]].At) })
		for _, k := range keys[:len(m)-c.Max] {
			delete(m, k)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.Path), ".judge-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.Path)
}
