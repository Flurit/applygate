// Package decisionlog appends decisions to a local JSON Lines file, with
// secrets redacted, and summarizes it for "applygate report".
package decisionlog

import (
	"bufio"
	"bytes"
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
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/safefile"
)

// Entry is one logged decision.
type Entry struct {
	Time    time.Time `json:"time"`
	Version string    `json:"applygate_version"`
	// LegacyVersion is the key entries carried before the rename; Read
	// folds it into Version so an older log keeps its version counts.
	LegacyVersion string                `json:"seatbelt_version,omitempty"`
	Agent         string                `json:"agent"`
	Session       string                `json:"session,omitempty"`
	Tool          string                `json:"tool"`
	Cwd           string                `json:"cwd"`
	Command       string                `json:"command,omitempty"`
	Paths         []string              `json:"paths,omitempty"`
	Mode          string                `json:"mode"`
	Verdict       policy.Verdict        `json:"verdict"`
	Enforced      policy.Verdict        `json:"enforced"`
	Actions       []policy.ActionResult `json:"actions,omitempty"`
	Notes         []string              `json:"notes,omitempty"`
	Error         string                `json:"error,omitempty"`
	DurationMS    float64               `json:"duration_ms"`
	// Judge is the model judge's answer, when it was asked.
	Judge *Judge `json:"judge,omitempty"`
}

// Judge records one model judge call.
type Judge struct {
	Model   string         `json:"model"`
	Verdict policy.Verdict `json:"verdict,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	MS      float64        `json:"ms"`
	Cached  bool           `json:"cached,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Values stop at whitespace, quotes and the shell's separators. A $ inside
// a value is part of it; one at the start is a variable, not a secret.
const secretValue = `[^\s"'&;|$][^\s"'&;|]*`

// quotedValue is a whole quoted value, spaces included.
const quotedValue = `(?:"[^"\n]*"|'[^'\n]*')`

// secretName matches names of settings, flags and variables that hold a
// secret: db_pass, aws_secret_access_key, API_TOKEN, client-secret.
const secretName = `[A-Za-z0-9_.-]*(?:pass|passwd|password|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credentials?)[A-Za-z0-9_-]*`

// redaction is one pattern and what replaces a match; group 1, when
// present, is kept (the name or flag before the value).
type redaction struct {
	re   *regexp.Regexp
	keep bool
}

var secretPatterns = []redaction{
	// Private keys first: the name=value pattern would otherwise eat the
	// -----BEGIN line and leave the key body.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----`), false},
	// Token formats.
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), false},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), false},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), false},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{16,}`), false},
	{regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}`), false},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), false},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), false},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), false},
	{regexp.MustCompile(`\bhv[sbr]\.[A-Za-z0-9_-]{20,}`), false},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`), false},
	// Azure storage keys and SAS signatures.
	{regexp.MustCompile(`(?i)((?:AccountKey|SharedAccessKey|[?&]sig)=)[^;&\s"']+`), true},
	// Credentials in a URL: scheme://user:PASSWORD@host.
	{regexp.MustCompile(`(://[^/\s:@]+:)[^@\s/]+(@)`), true},
	{regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)?\s*)[^\s"']+`), true},
	// curl -u user:PASSWORD, --user user:PASSWORD.
	{regexp.MustCompile(`((?:^|\s)(?:-u|--user)(?:\s+|=)[^\s:"']+:)` + secretValue), true},
	// mysql -pPASSWORD and -p'PASSWORD' (attached, as the client takes it),
	// docker login -p, redis-cli -a, sshpass -p.
	{regexp.MustCompile(`(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^|;&\n]*?\s-p)` + quotedValue), true},
	{regexp.MustCompile(`(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^|;&\n]*?\s-p)` + secretValue), true},
	{regexp.MustCompile(`(\b(?:docker|podman|nerdctl)\s+login\b[^|;&\n]*?\s-p\s*)(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`(\bredis-cli\b[^|;&\n]*?\s-a\s*)(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`(\bsshpass\b[^|;&\n]*?\s-p\s*)(?:` + quotedValue + `|` + secretValue + `)`), true},
	// name="value with spaces" and name='value': the whole quoted value.
	{regexp.MustCompile(`(?i)(` + secretName + `["']?\s*[=:]\s*)` + quotedValue), true},
	{regexp.MustCompile(`(?i)((?:^|\s)--?` + secretName + `(?:\s+|=))` + quotedValue), true},
	// name=value and name: value, quoted or not ("password": "x").
	{regexp.MustCompile(`(?i)(` + secretName + `["']?\s*[=:]\s*["']?)` + secretValue), true},
	// --token VALUE, --password VALUE: a secret-named flag and the next word.
	{regexp.MustCompile(`(?i)((?:^|\s)--?` + secretName + `\s+)` + secretValue), true},
	// aws configure set aws_secret_access_key VALUE, vault write k token VALUE.
	{regexp.MustCompile(`(?i)(\bset\s+` + secretName + `\s+)` + secretValue), true},
}

// Redact removes likely secrets from s.
func Redact(s string) string {
	for _, r := range secretPatterns {
		if r.keep {
			s = r.re.ReplaceAllStringFunc(s, func(m string) string {
				sub := r.re.FindStringSubmatch(m)
				out := sub[1] + "[REDACTED]"
				if len(sub) > 2 {
					out += sub[2]
				}
				return out
			})
		} else {
			s = r.re.ReplaceAllString(s, "[REDACTED]")
		}
	}
	return s
}

func redactEntry(e *Entry) {
	// The actions are shared with the caller's decision: redact copies.
	e.Actions = append([]policy.ActionResult(nil), e.Actions...)
	for i := range e.Actions {
		e.Actions[i].Via = append([]string(nil), e.Actions[i].Via...)
		e.Actions[i].Findings = append([]preflight.Finding(nil), e.Actions[i].Findings...)
		for j := range e.Actions[i].Findings {
			e.Actions[i].Findings[j].Evidence = append([]string(nil), e.Actions[i].Findings[j].Evidence...)
		}
	}
	e.Command = Redact(e.Command)
	for i := range e.Actions {
		e.Actions[i].Command = Redact(e.Actions[i].Command)
		e.Actions[i].Why = Redact(e.Actions[i].Why)
		for j := range e.Actions[i].Via {
			e.Actions[i].Via[j] = Redact(e.Actions[i].Via[j])
		}
		for j := range e.Actions[i].Findings {
			f := &e.Actions[i].Findings[j]
			f.Message = Redact(f.Message)
			for k := range f.Evidence {
				f.Evidence[k] = Redact(f.Evidence[k])
			}
		}
	}
	e.Error = Redact(e.Error)
	// Notes quote commands too (the MCP note holds the translated one).
	e.Notes = append([]string(nil), e.Notes...)
	for i := range e.Notes {
		e.Notes[i] = Redact(e.Notes[i])
	}
	for i := range e.Actions {
		e.Actions[i].Matched = append([]string(nil), e.Actions[i].Matched...)
		for j := range e.Actions[i].Matched {
			e.Actions[i].Matched[j] = Redact(e.Actions[i].Matched[j])
		}
	}
	if e.Judge != nil {
		j := *e.Judge
		j.Reason, j.Error = Redact(j.Reason), Redact(j.Error)
		e.Judge = &j
	}
}

// Append writes e to path, creating the directory with private permissions.
func Append(path string, e Entry) error {
	redactEntry(&e)
	e.LegacyVersion = ""

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := safefile.OpenAppend(path, 0o600)
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
	// A line over the cap is counted as bad and skipped; it must not hide
	// the entries after it.
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, over, err := readLine(br, maxLine)
		if err != nil && len(line) == 0 && !over {
			break
		}
		if over {
			bad++
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) != nil {
			bad++
			continue
		}
		if e.Version == "" && e.LegacyVersion != "" {
			e.Version, e.LegacyVersion = e.LegacyVersion, ""
		}
		out = append(out, e)
	}
	return out, bad
}

// maxLine caps one log line.
const maxLine = 16 << 20

// readLine reads one line of at most max bytes; over is set when the line
// was longer, and the rest of it has been read past.
func readLine(br *bufio.Reader, max int) (line []byte, over bool, err error) {
	for {
		chunk, err := br.ReadSlice('\n')
		if !over {
			if len(line)+len(chunk) > max {
				over, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, over, err
	}
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
	mcp := map[string]int{} // MCP calls per server
	var durs []float64
	for _, e := range entries {
		if strings.HasPrefix(e.Tool, "mcp__") {
			mcp[mcpServer(e.Tool)]++
		}
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
	if len(mcp) > 0 {
		var servers []string
		n := 0
		for s, c := range mcp {
			servers = append(servers, fmt.Sprintf("%s %d", s, c))
			n += c
		}
		sort.Strings(servers)
		fmt.Fprintf(w, "MCP tool calls (logged, not judged): %d (%s)\n", n, strings.Join(servers, ", "))
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

// mcpServer is the server part of an mcp__<server>__<tool> tool name.
func mcpServer(tool string) string {
	s := strings.TrimPrefix(tool, "mcp__")
	if i := strings.Index(s, "__"); i > 0 {
		return s[:i]
	}
	return s
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
