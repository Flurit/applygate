package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Flurit/applygate/internal/policy"
)

// Cache keeps recent verdicts so a call the agent repeats does not pay the
// model again. Only answers are kept, never errors. Concurrent hooks may
// race; the last writer wins, which only costs a repeated model call.
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
	if b, err := os.ReadFile(c.Path); err == nil {
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
	if !ok || now.Sub(e.At) > c.TTL || e.Verdict == "" {
		return Result{}, false
	}
	return Result{Verdict: e.Verdict, Reason: e.Reason, Model: e.Model, Cached: true}, true
}

// Put stores a verdict, dropping expired entries and the oldest beyond Max.
func (c Cache) Put(key string, r Result, now time.Time) error {
	if c.Path == "" || r.Err != "" || r.Verdict == "" {
		return nil
	}
	m := c.load()
	for k, e := range m {
		if now.Sub(e.At) > c.TTL {
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
