// Package plancomment renders the verdict of a plan check as the Markdown of
// a pull-request comment. Everything that comes from the plan or from the
// repository (resource addresses, evidence, environment names, paths) is
// untrusted text: it is written only inside code spans, with control and
// formatting characters removed, so it cannot add markup, links, mentions or
// HTML of its own.
package plancomment

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/policy"
)

// Input is what a comment says.
type Input struct {
	// Key names what was judged: the plan's path, or a name the workflow
	// chose.
	Key string
	// Workspace is the Terraform workspace, shown when it is not default.
	Workspace string
	// Commit is the commit the plan was made from, and Job the workflow
	// and job that judged it; both optional.
	Commit  string
	Job     string
	Version string

	Tier config.Tier
	// TierSet says the tier was given (--tier), not resolved.
	TierSet bool
	// Env and Matched are the resolution: the environment's name and the
	// signals that matched it.
	Env     string
	Matched []string
	// Untrusted are config files that were not read.
	Untrusted []string

	Verdict policy.Verdict
	Result  *plangate.Result

	// Err is set when the plan could not be judged: the comment then says
	// so and nothing else.
	Err string
}

const (
	// maxInline is how many resources a reason lists before the rest go to
	// the collapsed block.
	maxInline = 5
	// maxItem cuts one quoted piece of plan text, in bytes; itemHead of
	// them are kept from its start and the rest from its end.
	maxItem  = 300
	itemHead = 100
	// detailsBudget is where the collapsed block stops adding lines, and
	// maxBody the size no comment exceeds: GitHub refuses a body over
	// 65536 characters, and the step that posts it adds two short lines.
	detailsBudget = 40000
	maxBody       = 60000
)

var (
	commitRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	// versionRe is a release tag or a build's version, which the footer
	// shows as it is; anything else is left out.
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)
)

// ValidCommit reports whether s can be shown as a commit.
func ValidCommit(s string) bool { return commitRe.MatchString(s) }

// rulePriority orders the reasons: stateful resources that are destroyed or
// replaced come first, then the other losses of data, then the rest in the
// order the plan gate reports them.
var rulePriority = map[string]int{
	"stateful-destroyed":   0,
	"protected-resource":   1,
	"protection-removed":   3, // 2 is the destroy or replace itself
	"state-infrastructure": 4,
	"plan-errored":         5,
	"plan-too-large":       5,
}

const destroyPriority = 2

type reason struct {
	prio int
	head string // Markdown, already escaped
	// items are listed under the reason, the first maxInline of them, and
	// below are listed only in the collapsed block. Both are plan text, not
	// yet escaped.
	items []string
	below []string
}

// Render returns the comment body.
func Render(in Input) string {
	var b strings.Builder
	if in.Err != "" {
		b.WriteString("### applygate plan check: ❌ error\n\n")
		b.WriteString(subject(in) + "\n\n")
		b.WriteString("applygate could not judge this plan, so the check fails closed and says nothing about what the plan does.\n\n")
		b.WriteString("- " + code(in.Err) + "\n\n")
		b.WriteString(footer(in))
		return b.String()
	}
	res := in.Result
	if res == nil {
		res = &plangate.Result{}
	}
	fmt.Fprintf(&b, "### applygate plan check: %s\n\n", verdictTitle(in.Verdict))
	b.WriteString(subject(in) + " · " + counts(res) + "\n\n")
	b.WriteString(meaning(in) + "\n\n")
	for _, u := range in.Untrusted {
		note := "> The config " + code(u) + " has no trust record, so it was not read: its environments and `protected_resources` are not applied"
		if !in.TierSet {
			note += ", and the tier is protected"
		}
		b.WriteString(note + ". In CI, set `trust-config: true` (or pass `--trust-config`) to read the checked-out config.\n\n")
	}

	drivers, others, destroyShown := reasons(in, res)
	var full []reason // what the collapsed block lists
	if len(drivers) > 0 {
		fmt.Fprintf(&b, "**Why %s**\n\n", in.Verdict)
		for _, r := range drivers {
			b.WriteString("- " + r.head + "\n")
			for i, it := range r.items {
				if i == maxInline {
					fmt.Fprintf(&b, "  - and %d more, in the list below\n", len(r.items)-maxInline)
					full = append(full, reason{head: r.head, below: r.items})
					break
				}
				b.WriteString("  - " + code(it) + "\n")
			}
		}
		b.WriteString("\n")
	}
	if len(others) > 0 {
		if in.Verdict == policy.Allow {
			b.WriteString("**Found, and allowed in this tier**\n\n")
		} else {
			b.WriteString("**Also found**\n\n")
		}
		for _, r := range others {
			b.WriteString("- " + r.head)
			if n := len(r.below); n > 0 {
				fmt.Fprintf(&b, ": %s in the list below", plural(n, "item"))
				full = append(full, r)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	// The destroyed and replaced addresses are listed in full unless the
	// destroy is one of the reasons: then each is under the reason that
	// names it, or in that reason's full list.
	if !destroyShown {
		full = append(full,
			reason{head: fmt.Sprintf("Destroyed (%d)", len(res.Deletes)), below: res.Deletes},
			reason{head: fmt.Sprintf("Replaced (%d)", len(res.Replaces)), below: res.Replaces})
	}
	b.WriteString(details(full))
	b.WriteString(footer(in))
	if b.Len() > maxBody {
		// Not reachable with the limits above; a comment GitHub refuses
		// would leave the last one in place, which may say allow.
		var s strings.Builder
		fmt.Fprintf(&s, "### applygate plan check: %s\n\n", verdictTitle(in.Verdict))
		s.WriteString(subject(in) + " · " + counts(res) + "\n\n" + meaning(in) + "\n\nThe findings are too long for a comment; the job log has them.\n\n" + footer(in))
		return s.String()
	}
	return b.String()
}

func verdictTitle(v policy.Verdict) string {
	switch v {
	case policy.Block:
		return "⛔ block"
	case policy.Ask:
		return "⚠️ ask"
	}
	return "✅ allow"
}

// subject is the line that says what was judged and as what.
func subject(in Input) string {
	parts := []string{"Plan " + code(in.Key)}
	if in.Workspace != "" && in.Workspace != "default" {
		parts = append(parts, "workspace "+code(in.Workspace))
	}
	if in.Err != "" && in.Tier == "" {
		return strings.Join(parts, " · ")
	}
	// "unknown" is the resolution's name for a directory no environment
	// matches; its reason says what was done about it.
	why := ""
	if len(in.Matched) > 0 {
		why = " (" + code(in.Matched[0]) + ")"
	}
	tier := "tier **" + string(in.Tier) + "**"
	switch {
	case in.TierSet:
		tier += " (set for this check)"
	case len(in.Untrusted) > 0:
		tier += " (the config was not read)"
	case in.Env != "" && in.Env != "unknown":
		parts = append(parts, "environment "+code(in.Env)+why)
	case why != "":
		tier += why
	default:
		tier += " (no environment in the config matches this directory)"
	}
	return strings.Join(append(parts, tier), " · ")
}

func counts(res *plangate.Result) string {
	return fmt.Sprintf("%s, %d destroyed, %d replaced", plural(res.Changes, "change"), len(res.Deletes), len(res.Replaces))
}

func meaning(in Input) string {
	switch in.Verdict {
	case policy.Block:
		return fmt.Sprintf("The rules for a %s tier say this plan should not be applied as it is.", in.Tier)
	case policy.Ask:
		return fmt.Sprintf("The rules for a %s tier say a person should review this plan before it is applied.", in.Tier)
	}
	return fmt.Sprintf("Nothing in this plan needs a review under the rules for a %s tier.", in.Tier)
}

// reasons splits what the plan gate found into what decided the verdict and
// the rest. A destroy or replace is a reason of its own: it is what the
// decision table judges before any finding.
//
// destroyShown reports that the destroy or replace is one of the reasons, so
// its addresses are under it or under the reasons that name them.
func reasons(in Input, res *plangate.Result) (drivers, others []reason, destroyShown bool) {
	named := map[string]bool{}
	for i, f := range res.Findings {
		r := reason{
			prio: 100 + i,
			head: fmt.Sprintf("**%s** %s (%s)", text(string(f.Severity)), text(f.Message), code(f.Rule)),
		}
		if p, ok := rulePriority[f.Rule]; ok {
			r.prio = p
		}
		drives := in.Verdict != policy.Allow && policy.FindingVerdict(f.Severity, in.Tier) == in.Verdict
		if drives {
			r.items = f.Evidence
			if f.Rule == "stateful-destroyed" || f.Rule == "protected-resource" {
				for _, e := range f.Evidence {
					noteNamed(named, e)
				}
			}
			drivers = append(drivers, r)
		} else {
			// destroy-count's evidence is the destroyed and replaced
			// addresses, which the collapsed block lists anyway.
			if f.Rule != "destroy-count" {
				r.below = f.Evidence
			}
			others = append(others, r)
		}
	}
	n := len(res.Deletes) + len(res.Replaces)
	// The class the plan has, not destroy: a plan whose replaces are all
	// routine is not asked about for them, so an ask beside them has
	// another reason and they are not it.
	class := policy.SavedPlanClass(res)
	drives := in.Verdict != policy.Allow && class != classify.ApplySavedPlan && policy.Table[class][in.Tier] == in.Verdict
	if class == classify.RoutineReplace && !drives {
		others = append(others, reason{
			head:  fmt.Sprintf("%s replaced, of types that hold no data and are replaced on routine change (%s); a protected tier blocks these", plural(n, "resource"), code(string(class))),
			below: res.Replaces,
		})
		destroyShown = true
	}
	if n > 0 && drives {
		// The resources the reasons above already name are not repeated.
		var rest []string
		for _, a := range res.Deletes {
			if !named[a+"\x00destroyed"] {
				rest = append(rest, a+" is destroyed")
			}
		}
		for _, a := range res.Replaces {
			if !named[a+"\x00replaced"] {
				rest = append(rest, a+" is replaced")
			}
		}
		what := "asks about"
		if in.Verdict == policy.Block {
			what = "blocks"
		}
		head := fmt.Sprintf("A %s tier %s any destroy or replace; this plan has %d", in.Tier, what, n)
		if len(rest) < n {
			head += fmt.Sprintf(" (%d named above)", n-len(rest))
		}
		drivers = append(drivers, reason{prio: destroyPriority, head: head, items: rest})
		destroyShown = true
	}
	sort.SliceStable(drivers, func(i, j int) bool { return drivers[i].prio < drivers[j].prio })
	return drivers, others, destroyShown
}

// noteNamed records the address and verb of one line of stateful or
// protected-resource evidence, in the two forms the plan gate writes:
// "ADDR (TYPE) is destroyed" and "ADDR is replaced (listed in ...)".
func noteNamed(named map[string]bool, evidence string) {
	for _, verb := range []string{"destroyed", "replaced"} {
		if rest, ok := strings.CutSuffix(evidence, ") is "+verb); ok {
			if i := strings.LastIndex(rest, " ("); i >= 0 {
				named[rest[:i]+"\x00"+verb] = true
			}
		}
		if i := strings.LastIndex(evidence, " is "+verb+" ("); i >= 0 {
			named[evidence[:i]+"\x00"+verb] = true
		}
	}
}

// details is the collapsed block: the lists too long to show under a
// reason, the items of what did not decide the verdict, and the destroyed
// and replaced addresses, up to a size limit.
func details(rs []reason) string {
	total := 0
	for _, r := range rs {
		total += len(r.below)
	}
	if total == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<details>\n<summary>The full lists (%s)</summary>\n\n", plural(total, "line"))
	left := 0
	for _, r := range rs {
		if len(r.below) == 0 {
			continue
		}
		b.WriteString(r.head + "\n\n")
		for i, it := range r.below {
			if b.Len() > detailsBudget {
				left += len(r.below) - i
				break
			}
			b.WriteString("- " + code(it) + "\n")
		}
		b.WriteString("\n")
	}
	if left > 0 {
		fmt.Fprintf(&b, "%s more: too long for a comment, the job log has them all.\n\n", plural(left, "line"))
	}
	b.WriteString("</details>\n\n")
	return b.String()
}

func footer(in Input) string {
	s := "<sub>applygate"
	if versionRe.MatchString(in.Version) {
		s += " " + in.Version
	}
	s += " · deterministic rules, no model"
	if in.Job != "" {
		s += " · job " + code(in.Job)
	}
	if ValidCommit(in.Commit) {
		c := in.Commit
		if len(c) > 12 {
			c = c[:12]
		}
		s += " · judged at " + code(c)
	}
	return s + " · this comment is updated on each run</sub>\n"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// clean makes untrusted text one printable line: invalid UTF-8, control
// characters (newlines included) and formatting characters (zero-width and
// direction marks, which can hide or reorder text) are removed or made
// spaces, and a long value is cut in its middle. The text is what plan-check
// prints in the job log: addresses, attribute names and the rules' wording,
// which quote no attribute values beyond the action names of a flagged IAM
// policy and the name of a state bucket. The decision log's command-line
// redaction is not run on it: it would cut the message after an address
// such as aws_secretsmanager_secret.token.
func clean(s string) string {
	// Bound the work on a very long value before looking at its characters.
	s = cutMiddle(s, 4*maxItem, 4*maxItem)
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r):
			return -1
		}
		return r
	}, s)
	return cutMiddle(strings.TrimSpace(s), itemHead, maxItem-itemHead)
}

// cutMiddle keeps the first head and the last tail bytes of s (whole runes)
// and puts an ellipsis for what is between. The end is kept because it says
// the most: an address ends with the resource's type and name, and evidence
// with what happens to it, so a module path or a for_each key padded to
// thousands of characters cannot push "aws_db_instance.main is destroyed"
// out of the comment.
func cutMiddle(s string, head, tail int) string {
	if len(s) <= head+tail {
		return s
	}
	h, t := head, len(s)-tail
	for h > 0 && !utf8.RuneStart(s[h]) {
		h--
	}
	for t < len(s) && !utf8.RuneStart(s[t]) {
		t++
	}
	return s[:h] + " … " + s[t:]
}

// code writes untrusted text as a code span. Inside one, Markdown reads
// nothing: no HTML, link, image, mention, issue reference or emphasis. The
// span is fenced with more backticks than the text has in a row, so the text
// cannot close it.
func code(s string) string {
	s = clean(s)
	if s == "" {
		return "`(empty)`"
	}
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		// A space on each side keeps the text's own backticks apart from
		// the fence; Markdown drops the pair.
		s = " " + s + " "
	}
	return fence + s + fence
}

// text escapes a line of applygate's own wording (a rule's message, a
// severity) for use outside a code span: Markdown punctuation is escaped and
// HTML is written as entities. Plan text does not go through here; this is
// the second line of defence for a message that quotes some.
func text(s string) string {
	s = clean(s)
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '@', '#':
			// A zero-width space after it: no mention, no issue reference.
			b.WriteRune(r)
			b.WriteRune('​')
		case '\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '!', '|', '~', ':', '/', '.':
			// The dot too: GitHub makes a link of a bare www.example.com,
			// and of nothing in www\.example\.com.
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
