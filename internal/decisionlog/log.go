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
	"unicode/utf8"

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
const secretName = `(?:[A-Za-z0-9_.-]*(?:passwd|password|passphrase|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credentials?)[A-Za-z0-9_-]*|(?:[A-Za-z0-9_.-]*[_.-])?pass(?:[_-][A-Za-z0-9_-]*)?)`

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
	// A key whose END was cut off: everything after its BEGIN.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----.*`), false},
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
	// Secret stores' own value options: aws ssm put-parameter --value,
	// kubectl create secret --from-literal=k=v, gh secret set --body,
	// az login -p, and text piped into one of them.
	{regexp.MustCompile(`(\bput-parameter\b[^|;&\n]*?\s--value(?:\s+|=))(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`(--from-literal=[^=\s]+=)(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`(\bgh\s+secret\s+set\b[^|;&\n]*?\s(?:-b|--body)(?:\s+|=))(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`(\baz\s+login\b[^|;&\n]*?\s-p(?:\s+|=))(?:` + quotedValue + `|` + secretValue + `)`), true},
	{regexp.MustCompile(`((?:\becho|\bprintf)\s+(?:-[ne]+\s+)?)(?:` + quotedValue + `|` + secretValue + `)(\s*\|\s*(?:docker\s+secret\s+create|gh\s+secret\s+set|kubectl\s+create\s+secret|vault\s|aws\s+ssm\s|aws\s+secretsmanager\s))`), true},
	// vault kv put PATH k=v ... and vault write PATH k=v ...: every value.
	{regexp.MustCompile(`(\bvault\s+(?:kv\s+(?:put|patch)|write)\b[^|;&\n]*?\s[A-Za-z0-9_.-]+=)(?:` + quotedValue + `|` + secretValue + `)`), true},
	// SQL: ALTER USER bob PASSWORD 'x', CREATE USER ... IDENTIFIED BY 'x'.
	{regexp.MustCompile(`(?i)(\b(?:password|identified\s+by)\s+)` + quotedValue), true},
	// Tools whose password option is -P or -w: sqlcmd, ldapsearch, zip, unzip.
	{regexp.MustCompile(`(\b(?:sqlcmd|ldapsearch|ldapadd|ldapmodify|zip|unzip)\b[^|;&\n]*?\s-[Pw]\s*)(?:` + quotedValue + `|` + secretValue + `)`), true},
	// A JWT, and a SigV4 signature in a query string or header.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), false},
	{regexp.MustCompile(`(?i)((?:X-Amz-)?Signature=)[0-9a-f]{16,}`), true},
	// Cookie headers and Slack webhook URLs.
	{regexp.MustCompile(`(?i)(\bcookie["']?\s*:\s*["']?)[^"'\n]+`), true},
	{regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+`), false},
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

// RedactJSONCut redacts a JSON document's string values and the values of
// keys that name a secret, as JSON, then cuts the text to max bytes. Redacting
// the JSON text itself misses a value whose quotes are escaped inside a
// string ("export P=\"x\"", a nested JSON body). A document that is not
// JSON, or is large, is redacted as text.
func RedactJSONCut(raw string, max int) string {
	if len(raw) > 256<<10 {
		return RedactCut(raw, max)
	}
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return RedactCut(raw, max)
	}
	keyRe := regexp.MustCompile(`(?i)^` + secretName + `$`)
	var walk func(x any, key string) any
	walk = func(x any, key string) any {
		switch t := x.(type) {
		case string:
			if key != "" && keyRe.MatchString(key) && t != "" {
				return "[REDACTED]"
			}
			return Redact(t)
		case []any:
			for i := range t {
				t[i] = walk(t[i], key)
			}
		case map[string]any:
			for k, e := range t {
				t[k] = walk(e, k)
			}
		}
		return x
	}
	b, err := json.Marshal(walk(v, ""))
	if err != nil {
		return RedactCut(raw, max)
	}
	return RedactCut(string(b), max)
}

// maxField caps a text field of a log entry, and maxRedact the text one
// entry redacts in all: redacting megabytes of command text would take
// seconds the hook does not have (4H3), and one call must not fill the log.
const (
	maxField  = 64 << 10
	maxRedact = 512 << 10
)

// RedactCut redacts s and cuts it to max bytes at a rune boundary, saying
// how much was left out. The redaction runs before the cut, so a cut cannot
// split a secret out of the pattern that finds it, on at most 2*max bytes,
// so its work is bounded; a private key cut there is redacted to the end.
func RedactCut(s string, max int) string {
	n := len(s)
	s = Redact(cutRunes(s, 2*max))
	if n <= max && len(s) <= max {
		return s
	}
	return cutRunes(s, max) + fmt.Sprintf(" …(%d bytes, cut for the log)", n)
}

func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// redactor redacts an entry's fields within maxRedact bytes in all; the
// same text is redacted once. A field past the budget is not logged.
type redactor struct {
	left int
	done map[string]string
}

func (r *redactor) field(s string) string {
	if s == "" {
		return s
	}
	if out, ok := r.done[s]; ok {
		return out
	}
	cost := min(len(s), 2*maxField)
	var out string
	if cost > r.left {
		out = fmt.Sprintf("[%d bytes, not logged: the entry is over the log's redaction budget]", len(s))
	} else {
		r.left -= cost
		out = RedactCut(s, maxField)
	}
	r.done[s] = out
	return out
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
	r := &redactor{left: maxRedact, done: map[string]string{}}
	e.Command = r.field(e.Command)
	e.Error = r.field(e.Error)
	// A tool whose input names no path key has its text fields taken as
	// paths, so a secret can sit in one; the working directory and session
	// can carry one too.
	e.Paths = append([]string(nil), e.Paths...)
	for i := range e.Paths {
		e.Paths[i] = r.field(e.Paths[i])
	}
	e.Cwd = r.field(e.Cwd)
	for i := range e.Actions {
		e.Actions[i].Command = r.field(e.Actions[i].Command)
		e.Actions[i].Why = r.field(e.Actions[i].Why)
		// A backend address, a profile or a plan path can carry a credential
		// (https://user:pass@host, a token in a path).
		a := &e.Actions[i]
		for _, f := range []*string{&a.Backend, &a.Dir, &a.Workspace, &a.Profile, &a.KubeContext, &a.GCPProject, &a.AzureSubscription, &a.PlanFile, &a.NextStep} {
			*f = r.field(*f)
		}
		for j := range e.Actions[i].Via {
			e.Actions[i].Via[j] = r.field(e.Actions[i].Via[j])
		}
		for j := range e.Actions[i].Findings {
			f := &e.Actions[i].Findings[j]
			f.Message = r.field(f.Message)
			for k := range f.Evidence {
				f.Evidence[k] = r.field(f.Evidence[k])
			}
		}
	}
	// Notes quote commands too (the MCP note holds the translated one).
	e.Notes = append([]string(nil), e.Notes...)
	for i := range e.Notes {
		e.Notes[i] = r.field(e.Notes[i])
	}
	for i := range e.Actions {
		e.Actions[i].Matched = append([]string(nil), e.Actions[i].Matched...)
		for j := range e.Actions[i].Matched {
			e.Actions[i].Matched[j] = r.field(e.Actions[i].Matched[j])
		}
	}
	if e.Judge != nil {
		j := *e.Judge
		j.Reason, j.Error = r.field(j.Reason), r.field(j.Error)
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
	rotate(path)
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

// maxLog is the size at which the log is rotated to path.1, which replaces
// the previous one.
const maxLog = 64 << 20

// rotate moves a log over maxLog aside, so it cannot grow without bound.
func rotate(path string) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size() > maxLog {
		_ = os.Rename(path, path+".1")
	}
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

var (
	keyBlock    = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----.*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----`)
	keyOpenOnly = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----`)
)

// UnclosedKeyMarker reports whether s has a private-key header with no end
// marker. Redaction then removes everything after the header, whatever it is,
// so a copy for the judge would not show the text that follows.
func UnclosedKeyMarker(s string) bool {
	return keyOpenOnly.MatchString(keyBlock.ReplaceAllString(s, ""))
}
