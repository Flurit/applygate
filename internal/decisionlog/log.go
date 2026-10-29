// Package decisionlog appends decisions to a local JSON Lines file, with
// secrets redacted, and summarizes it for "applygate report".
package decisionlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/policy"
)

// Entry is one logged decision.
type Entry struct {
	Time       time.Time             `json:"time"`
	Version    string                `json:"applygate_version"`
	Agent      string                `json:"agent"`
	Session    string                `json:"session,omitempty"`
	Tool       string                `json:"tool"`
	Cwd        string                `json:"cwd"`
	Command    string                `json:"command,omitempty"`
	Paths      []string              `json:"paths,omitempty"`
	Mode       string                `json:"mode"`
	Verdict    policy.Verdict        `json:"verdict"`
	Enforced   policy.Verdict        `json:"enforced"`
	Actions    []policy.ActionResult `json:"actions,omitempty"`
	Notes      []string              `json:"notes,omitempty"`
	Error      string                `json:"error,omitempty"`
	DurationMS float64               `json:"duration_ms"`
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)((?:aws_)?secret_access_key|aws_session_token|password|passwd|token|secret|api[_-]?key|private[_-]?key)(["']?\s*[=:]\s*["']?)([^\s"'&]+)`),
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)(\S+)`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// Redact removes likely secrets from s.
func Redact(s string) string {
	for i, re := range secretPatterns {
		switch i {
		case 1:
			s = re.ReplaceAllString(s, "${1}${2}[REDACTED]")
		case 2:
			s = re.ReplaceAllString(s, "${1}[REDACTED]")
		default:
			s = re.ReplaceAllString(s, "[REDACTED]")
		}
	}
	return s
}

func redactEntry(e *Entry) {
	e.Command = Redact(e.Command)
	for i := range e.Actions {
		e.Actions[i].Command = Redact(e.Actions[i].Command)
		e.Actions[i].Why = Redact(e.Actions[i].Why)
		for j := range e.Actions[i].Findings {
			f := &e.Actions[i].Findings[j]
			f.Message = Redact(f.Message)
			for k := range f.Evidence {
				f.Evidence[k] = Redact(f.Evidence[k])
			}
		}
	}
	e.Error = Redact(e.Error)
}

// Append writes e to path, creating the directory with private permissions.
func Append(path string, e Entry) error {
	redactEntry(&e)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read loads all entries; malformed lines are counted, not fatal.
func Read(r io.Reader) ([]Entry, int) {
	var out []Entry
	bad := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			bad++
			continue
		}
		out = append(out, e)
	}
	return out, bad
}

// Report writes a summary of entries.
func Report(w io.Writer, entries []Entry, bad int) {
	counts := map[policy.Verdict]int{}
	enforced := map[policy.Verdict]int{}
	observeWould := 0
	byClass := map[string]int{}
	type key struct{ verdict, class, cmd string }
	seen := map[key]int{}
	errors := 0
	var durs []float64
	for _, e := range entries {
		counts[e.Verdict]++
		enforced[e.Enforced]++
		durs = append(durs, e.DurationMS)
		if e.Error != "" {
			errors++
		}
		if e.Mode == "observe" && e.Verdict != policy.Allow {
			observeWould++
		}
		for _, a := range e.Actions {
			if a.Verdict == policy.Allow {
				continue
			}
			byClass[string(a.Class)]++
			seen[key{string(a.Verdict), string(a.Class), a.Command}]++
		}
	}
	fmt.Fprintf(w, "decisions: %d (malformed lines: %d, internal errors: %d)\n", len(entries), bad, errors)
	fmt.Fprintf(w, "policy verdicts:   allow %d, ask %d, block %d\n", counts[policy.Allow], counts[policy.Ask], counts[policy.Block])
	fmt.Fprintf(w, "enforced verdicts: allow %d, ask %d, block %d\n", enforced[policy.Allow], enforced[policy.Ask], enforced[policy.Block])
	fmt.Fprintf(w, "observe mode, would have asked or blocked: %d\n", observeWould)
	if len(durs) > 0 {
		sort.Float64s(durs)
		fmt.Fprintf(w, "latency ms: p50 %.1f, p95 %.1f, max %.1f\n", pct(durs, 50), pct(durs, 95), durs[len(durs)-1])
	}
	if len(byClass) > 0 {
		fmt.Fprintln(w, "\nask or block by class:")
		var cs []string
		for c := range byClass {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		for _, c := range cs {
			fmt.Fprintf(w, "  %-18s %d\n", c, byClass[c])
		}
	}
	if len(seen) > 0 {
		fmt.Fprintln(w, "\nmost frequent ask/block commands (repeats are worth reviewing as possible false positives):")
		type kv struct {
			k key
			n int
		}
		var list []kv
		for k, n := range seen {
			list = append(list, kv{k, n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].k.cmd < list[j].k.cmd
		})
		for i, x := range list {
			if i == 20 {
				break
			}
			fmt.Fprintf(w, "  %4dx %-5s %-18s %s\n", x.n, x.k.verdict, x.k.class, shorten(x.k.cmd, 100))
		}
	}
}

func pct(sorted []float64, p int) float64 {
	i := (len(sorted)*p + 99) / 100
	if i < 1 {
		i = 1
	}
	return sorted[i-1]
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
