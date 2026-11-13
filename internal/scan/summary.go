package scan

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

// A judged call falls in one group, which decides where the report shows it.
const (
	// GroupInfra: an infrastructure command the rules recognized.
	GroupInfra = "infrastructure"
	// GroupGuard: asked about or blocked for touching agent settings or
	// applygate's own files.
	GroupGuard = "guard"
	// GroupPlan: applies a saved plan. The verdict depends on what the plan
	// holds, and a past plan is not there to read.
	GroupPlan = "plan"
	// GroupGeneral: asked about, with no infrastructure tool or guard file
	// recognized: a command that is not plain, or one that cannot be
	// resolved, in a directory that counts as protected.
	GroupGeneral = "general"
	// GroupOther: allowed, nothing recognized.
	GroupOther = "other"
	// GroupFailed: the decision failed (a config error, a timeout).
	GroupFailed = "failed"
)

var infraClasses = map[classify.Class]bool{
	classify.ReadOnly: true, classify.Mutating: true, classify.CloudWrite: true, classify.ApplySavedPlan: true,
	classify.UnreviewedApply: true, classify.Destroy: true, classify.StateSurgery: true, classify.CloudDestructive: true,
	classify.CredentialAccess: true, classify.UnknownWrapper: true,
}

var guardClasses = map[classify.Class]bool{classify.Tampering: true, classify.HookRewrite: true}

// Row is one judged call, with secrets already redacted.
type Row struct {
	Time    time.Time `json:"time"`
	Agent   string    `json:"agent"`
	Session string    `json:"session,omitempty"`
	Dir     string    `json:"dir"`
	// Repo is the root of the git repository Dir is in, or Dir itself.
	Repo string `json:"repo,omitempty"`
	Tool string `json:"tool"`
	// Kind is shell, file or mcp.
	Kind    string         `json:"kind"`
	Command string         `json:"command,omitempty"`
	Paths   []string       `json:"paths,omitempty"`
	Verdict policy.Verdict `json:"verdict"`
	Group   string         `json:"group"`
	Classes []string       `json:"classes,omitempty"`
	Tier    string         `json:"tier,omitempty"`
	Why     string         `json:"why,omitempty"`
	Error   string         `json:"error,omitempty"`
	// NoConfig is true when no trusted .applygate.yaml covers the
	// directory, so the user config or the defaults judged the call.
	NoConfig bool `json:"no_config,omitempty"`
}

// NewRow builds the row for a call from the entry the hook would have
// logged. Unless full is set, a row the report only counts keeps no command
// text, which also spares redacting it.
func NewRow(c Call, e decisionlog.Entry, repo string, noConfig, full bool) Row {
	r := Row{Time: c.Time, Agent: c.Agent, Session: c.Session, Dir: c.Dir(), Repo: repo, Tool: e.Tool, Verdict: e.Verdict, NoConfig: noConfig}
	switch {
	case strings.HasPrefix(e.Tool, "mcp__"):
		r.Kind = "mcp"
	case e.Command != "":
		r.Kind = "shell"
	default:
		r.Kind = "file"
	}
	// The actions that carry the call's verdict say why it was decided.
	var why *policy.ActionResult
	rank := func(c classify.Class) int {
		switch {
		case infraClasses[c]:
			return 3
		case guardClasses[c]:
			return 2
		}
		return 1
	}
	best, plan := 0, false
	seen := map[classify.Class]bool{}
	for i, a := range e.Actions {
		if e.Verdict == policy.Allow {
			if infraClasses[a.Class] {
				best = 3
			}
			continue
		}
		if a.Verdict != e.Verdict {
			continue
		}
		plan = plan || a.Class == classify.ApplySavedPlan
		if !seen[a.Class] {
			seen[a.Class] = true
			r.Classes = append(r.Classes, string(a.Class))
		}
		if k := rank(a.Class); k > best {
			best, why = k, &e.Actions[i]
		}
	}
	switch {
	case e.Error != "":
		r.Group = GroupFailed
	case e.Verdict == policy.Allow && best == 3:
		r.Group = GroupInfra
	case e.Verdict == policy.Allow:
		r.Group = GroupOther
	case plan:
		r.Group = GroupPlan
	case best == 3:
		r.Group = GroupInfra
	case best == 2:
		r.Group = GroupGuard
	default:
		r.Group = GroupGeneral
	}
	listed := r.Group != GroupOther && r.Group != GroupGeneral
	if full || listed {
		e = decisionlog.Redacted(e)
		r.Command, r.Paths, r.Error = e.Command, e.Paths, e.Error
		if why != nil {
			// Redacted copied the actions, in the same order.
			for _, a := range e.Actions {
				if a.Class == why.Class && a.Verdict == e.Verdict {
					r.Why, r.Tier = a.Why, string(a.Tier)
					break
				}
			}
		}
	}
	if r.Group == GroupGeneral && why != nil && r.Why == "" {
		r.Why = decisionlog.Redact(why.Why)
	}
	return r
}

const shapePrefix = "strict shapes: the command is not a plain list or pipeline of known programs ("

// Reason is the short form of why a command with no infrastructure tool in
// it is asked about: what kept it from being a plain command.
func Reason(why string) string {
	s := why
	if strings.HasPrefix(s, shapePrefix) {
		s = strings.TrimSuffix(strings.TrimPrefix(s, shapePrefix), ")")
		if rest, ok := strings.CutPrefix(s, "a part the analyzer cannot resolve ("); ok {
			s = rest
		}
	}
	switch {
	case strings.HasPrefix(s, "the variable "):
		return "a variable set in the command (X=... cmd)"
	case strings.HasPrefix(s, "the subcommand "):
		// "the subcommand build ./...": keep the subcommand, drop its arguments.
		if f := strings.Fields(s); len(f) >= 3 {
			return "a subcommand that is not listed (" + f[2] + ")"
		}
	}
	if i := strings.Index(s, ": "); i > 0 {
		s = s[:i]
	}
	return cut(oneLine(s), 70)
}

// what is the text that identifies a call in a listing: its command, or
// the files it writes.
func (r Row) what() string {
	if r.Command != "" {
		return oneLine(r.Command)
	}
	return r.Tool + " " + strings.Join(r.Paths, " ")
}

// Summary collects the rows of a scan.
type Summary struct {
	Stats Stats
	// Unchecked counts calls to tools applygate does not inspect; Gone
	// counts calls whose directory no longer exists.
	Unchecked, Gone int
	Rows            []Row
}

type listing struct {
	row   Row
	n     int
	first time.Time
}

// grouped merges rows that are the same call in the same directory.
func grouped(rows []Row) []listing {
	idx := map[string]int{}
	var out []listing
	for _, r := range rows {
		k := r.Dir + "\x00" + r.what() + "\x00" + strings.Join(r.Classes, ",")
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, listing{row: r, n: 1, first: r.Time})
			continue
		}
		out[i].n++
		if r.Time.After(out[i].row.Time) {
			out[i].row.Time = r.Time
		}
		if r.Time.Before(out[i].first) {
			out[i].first = r.Time
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].row.Time.After(out[j].row.Time) })
	return out
}

// RenderOptions shape the text report.
type RenderOptions struct {
	Version string
	Days    int    // 0: every session kept
	Home    string // shown as ~
	All     bool   // list every call, not the latest Limit of each kind
	Limit   int
}

// Render writes the report a person reads.
func (s Summary) Render(w io.Writer, o RenderOptions) {
	if o.Limit == 0 {
		o.Limit = 5
	}
	window := "every session kept"
	if o.Days > 0 {
		window = fmt.Sprintf("the last %d days", o.Days)
	}
	fmt.Fprintf(w, "applygate %s: what it would decide today on the calls your agents already made\n\n", o.Version)
	var agents []string
	sessions := 0
	for _, a := range []string{"claude", "codex"} {
		if n := s.Stats.Sessions[a]; n > 0 {
			agents = append(agents, fmt.Sprintf("%s %s", a, num(n)))
			sessions += n
		}
	}
	compressed := func(indent string) {
		if n := s.Stats.Compressed; n > 0 {
			fmt.Fprintf(w, "%s%s archived session file%s compressed and not read.\n", indent, num(n), isAre(n))
		}
	}
	if sessions == 0 {
		fmt.Fprintf(w, "No Claude Code or Codex session with a tool call was found in %s.\n", window)
		compressed("")
		return
	}
	by := map[string][]Row{}
	for _, r := range s.Rows {
		by[r.Group] = append(by[r.Group], r)
	}
	fmt.Fprintf(w, "sessions read  %s from %s (%s)\n", num(sessions), window, strings.Join(agents, ", "))
	fmt.Fprintf(w, "tool calls     %s, of which %s are of a kind applygate looks at: shell commands, file reads and edits, MCP tools\n",
		num(s.Stats.Calls), num(len(s.Rows)+s.Gone))
	if s.Gone > 0 {
		fmt.Fprintf(w, "not judged     %s made in a directory that no longer exists\n", num(s.Gone))
	}
	if n := len(by[GroupFailed]); n > 0 {
		fmt.Fprintf(w, "not judged     %s where the decision failed (%s)\n", num(n), cut(oneLine(by[GroupFailed][0].Error), 120))
	}

	split := func(rows []Row) map[policy.Verdict][]Row {
		m := map[policy.Verdict][]Row{}
		for _, r := range rows {
			m[r.Verdict] = append(m[r.Verdict], r)
		}
		return m
	}
	list := func(title string, rows []Row) {
		if len(rows) == 0 {
			return
		}
		ls := grouped(rows)
		fmt.Fprintf(w, "\n  %s\n", title)
		for i, l := range ls {
			if !o.All && i == o.Limit {
				fmt.Fprintf(w, "    ... and %s more (applygate scan --all)\n", num(len(ls)-i))
				break
			}
			times := ""
			if l.n > 1 {
				times = fmt.Sprintf(", %s times", num(l.n))
			}
			fmt.Fprintf(w, "    %s  %s  %s%s\n", l.row.Time.Local().Format("2006-01-02"), l.row.Agent, tilde(l.row.Dir, o.Home), times)
			fmt.Fprintf(w, "        %s\n", cut(l.row.what(), 150))
			why := oneLine(l.row.Why)
			if why == "" {
				why = strings.Join(l.row.Classes, ", ")
			}
			fmt.Fprintf(w, "        %s\n", cut(why, 200))
		}
	}

	infra := split(by[GroupInfra])
	fmt.Fprintf(w, "\nInfrastructure commands: %s\n", num(len(by[GroupInfra])+len(by[GroupPlan])))
	fmt.Fprintf(w, "  would block  %s\n", num(len(infra[policy.Block])))
	fmt.Fprintf(w, "  would ask    %s\n", num(len(infra[policy.Ask])))
	fmt.Fprintf(w, "  allowed      %s\n", num(len(infra[policy.Allow])))
	if n := len(by[GroupPlan]); n > 0 {
		fmt.Fprintf(w, "  saved plans  %s applied: the verdict depends on what the plan held, and a past plan is not kept to read\n", num(n))
	}
	list("Would block:", infra[policy.Block])
	list("Would ask:", infra[policy.Ask])

	if guard := split(by[GroupGuard]); len(by[GroupGuard]) > 0 {
		fmt.Fprintf(w, "\nChanges to agent settings and applygate's own files: %s\n", num(len(by[GroupGuard])))
		fmt.Fprintf(w, "  would block  %s\n", num(len(guard[policy.Block])))
		fmt.Fprintf(w, "  would ask    %s\n", num(len(guard[policy.Ask])))
		list("Would block:", guard[policy.Block])
		list("Would ask:", guard[policy.Ask])
	}

	// The rest: nothing in the call was recognized. File reads and edits and
	// MCP calls are allowed there; the asks are shell commands.
	general := by[GroupGeneral]
	shell, asked := 0, 0
	for _, r := range by[GroupOther] {
		if r.Kind == "shell" {
			shell++
		}
	}
	noCfg := 0
	reasons := map[string]int{}
	for _, r := range general {
		if r.Kind != "shell" {
			continue
		}
		shell++
		asked++
		if r.NoConfig {
			noCfg++
		}
		reasons[Reason(r.Why)]++
	}
	fmt.Fprintf(w, "\nOther shell commands: %s\n", num(shell))
	if shell > 0 {
		fmt.Fprintf(w, "  would ask    %s (%d%%)\n", num(asked), 100*asked/shell)
		fmt.Fprintf(w, "  allowed      %s\n", num(shell-asked))
	}
	if asked > 0 {
		fmt.Fprintln(w, "\n  These asks name no infrastructure tool. They are commands applygate does not follow in full")
		fmt.Fprintln(w, "  (a loop, a script, a program it has no option list for), run where the directory counts as protected.")
		if noCfg > 0 {
			fmt.Fprintf(w, "  %s of them ran where no trusted .applygate.yaml covers the directory, and an unknown directory counts as protected.\n", num(noCfg))
			fmt.Fprintln(w, "  A config that marks such a repository standard or disposable removes them (applygate init, docs/config.md).")
		}
		fmt.Fprintln(w, "\n  What kept them from being plain commands, most frequent first:")
		for _, kv := range topN(reasons, 8) {
			fmt.Fprintf(w, "    %6s  %s\n", num(kv.n), kv.k)
		}
	}

	s.renderRepos(w, o)

	fmt.Fprintln(w, "\nHow to read this")
	fmt.Fprintln(w, "  - Verdicts use today's config and today's files. A script or directory that has changed or gone since")
	fmt.Fprintln(w, "    is judged as it is now, which is usually stricter than it was.")
	fmt.Fprintln(w, "  - Nothing was run, written, or sent to a model or a cloud account.")
	codexAsks := 0
	for _, r := range s.Rows {
		if r.Agent == "codex" && r.Verdict == policy.Ask {
			codexAsks++
		}
	}
	if codexAsks > 0 {
		fmt.Fprintf(w, "  - Codex cannot show an ask prompt: its %s asked call%s would have been blocked.\n", num(codexAsks), plural(codexAsks))
	}
	compressed("  - ")
	fmt.Fprintln(w, "  - To judge calls as they happen: applygate init. It starts in observe mode and blocks nothing.")
}

// renderRepos writes one line per repository, the busiest first, so a
// person sees which ones a config would change the most.
func (s Summary) renderRepos(w io.Writer, o RenderOptions) {
	type repo struct {
		name                       string
		calls, block, ask, general int
		noConfig                   bool
	}
	idx := map[string]*repo{}
	var repos []*repo
	for _, r := range s.Rows {
		p := idx[r.Repo]
		if p == nil {
			p = &repo{name: r.Repo}
			idx[r.Repo] = p
			repos = append(repos, p)
		}
		p.calls++
		p.noConfig = p.noConfig || r.NoConfig
		switch {
		case r.Group == GroupGeneral:
			p.general++
		case r.Group != GroupInfra && r.Group != GroupGuard:
		case r.Verdict == policy.Block:
			p.block++
		case r.Verdict == policy.Ask:
			p.ask++
		}
	}
	if len(repos) < 2 {
		return
	}
	sort.SliceStable(repos, func(i, j int) bool { return repos[i].calls > repos[j].calls })
	limit := 8
	if o.All {
		limit = len(repos)
	}
	fmt.Fprintln(w, "\nBy repository")
	fmt.Fprintln(w, "     calls   block     ask  other asks  config   repository")
	for i, p := range repos {
		if i == limit {
			fmt.Fprintf(w, "  ... and %s more (applygate scan --all)\n", num(len(repos)-i))
			break
		}
		cfg := "trusted"
		if p.noConfig {
			cfg = "none"
		}
		fmt.Fprintf(w, "  %8s  %6s  %6s  %10s  %-7s  %s\n", num(p.calls), num(p.block), num(p.ask), num(p.general), cfg, tilde(p.name, o.Home))
	}
}

// num writes n with thousands separators.
func num(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

type count struct {
	k string
	n int
}

func topN(counts map[string]int, n int) []count {
	var l []count
	for k, c := range counts {
		l = append(l, count{k, c})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].n != l[j].n {
			return l[i].n > l[j].n
		}
		return l[i].k < l[j].k
	})
	if len(l) > n {
		l = l[:n]
	}
	return l
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isAre(n int) string {
	if n == 1 {
		return " is"
	}
	return "s are"
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func tilde(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}
