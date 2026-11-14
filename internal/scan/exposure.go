package scan

import (
	"fmt"
	"io"
	"strings"
)

// Exposure is what the boundary checks found on this machine: what an agent
// that runs as this user can reach when a verdict is wrong or a call never
// passes the hook. The command fills it from the checks applygate doctor
// --boundary makes (docs/boundary.md).
type Exposure struct {
	// Audited is set when the cloud and the clusters were asked what the
	// credentials here can do (applygate scan --boundary). Without it only
	// the checks that read this machine ran, and L2 is not reached.
	Audited bool
	// Level is the assurance level reached, 0 to 3.
	Level  int
	Checks []Check
	// The audited credentials: with no destructive path to production
	// without a person, with one, and the findings that show neither (not
	// checked, or in no environment the config names).
	CredsOK, CredsFail, CredsUnclear int
	// Error is why the checks could not be made at all.
	Error string
}

// Check is one boundary check: the level it is part of, "ok", "FAIL",
// "attested" or "not verified", and what was found.
type Check struct {
	Level  int
	Status string
	Text   string
}

var levelNames = []string{
	"the hook is the only check",
	"the hook, in a managed install the agent's user cannot change",
	"a managed install, and credentials that cannot change production without a person",
	"a managed install, such credentials, a host sandbox and a reviewed apply path",
}

// changes counts the calls that would change infrastructure, and those of
// them aimed at an environment that is protected or that no config names.
func (s Summary) changes() (all, protected int) {
	for _, r := range s.Rows {
		if r.Change == "" {
			continue
		}
		all++
		if r.Change != "standard" && r.Change != "disposable" {
			protected++
		}
	}
	return all, protected
}

// renderExposure opens the report: what the agents can reach comes before
// what applygate would have decided.
func (s Summary) renderExposure(w io.Writer, o RenderOptions, sessions int) {
	x := s.Exposure
	if x == nil {
		return
	}
	fmt.Fprintln(w, "What your agents can reach")
	if x.Error != "" {
		fmt.Fprintf(w, "  not checked: %s\n\n", x.Error)
		return
	}
	switch {
	case !x.Audited:
		fmt.Fprintln(w, "  credentials  not audited: this report contacts nothing. applygate scan --boundary asks AWS, Google Cloud,")
		fmt.Fprintln(w, "               Azure and the clusters whether the credentials here can change production without a person.")
	case x.CredsFail > 0:
		fmt.Fprintf(w, "  credentials  %s can change production without a person\n", num(x.CredsFail))
	case x.CredsOK > 0 && x.CredsUnclear == 0:
		fmt.Fprintf(w, "  credentials  none of the %s audited can change production without a person\n", num(x.CredsOK))
	case x.CredsOK > 0:
		fmt.Fprintf(w, "  credentials  %s audited with no destructive path to production; %s finding%s could not be checked or placed\n",
			num(x.CredsOK), num(x.CredsUnclear), plural(x.CredsUnclear))
	default:
		fmt.Fprintln(w, "  credentials  none could be audited, so nothing shows whether an agent can change production")
	}
	level := min(max(x.Level, 0), 3)
	sofar := ""
	if !x.Audited {
		sofar = ", as far as this machine shows without the audit"
	}
	fmt.Fprintf(w, "  boundary     L%d of L3%s: %s\n", level, sofar, levelNames[level])

	fmt.Fprintln(w, "\n  The checks, the same ones applygate doctor --boundary makes (docs/boundary.md):")
	for lvl := 1; lvl <= 3; lvl++ {
		for _, c := range x.Checks {
			if c.Level == lvl {
				fmt.Fprintf(w, "    L%d %-12s %s\n", lvl, c.Status, homeAsTilde(c.Text, o.Home))
			}
		}
	}

	switch {
	case !x.Audited:
	case x.CredsFail > 0:
		fmt.Fprintln(w, "\n  A wrong verdict, or a call the hook never sees, reaches whatever these credentials allow.")
		fmt.Fprintln(w, "  docs/credentials.md shows how to give the agent read-only access and keep writes behind MFA.")
	case x.CredsOK > 0 && x.CredsUnclear == 0:
		fmt.Fprintln(w, "\n  If these are all the credentials your agents can use, you do not need the hook to protect production:")
		fmt.Fprintln(w, "  that path is already closed, and the hook is a second check on it. What fits a setup like this is the")
		fmt.Fprintln(w, "  plan check in your pipeline (docs/ci.md).")
	default:
		fmt.Fprintln(w, "\n  Until every credential is checked and placed in an environment, this does not show that production is")
		fmt.Fprintln(w, "  out of reach. Name your environments in .applygate.yaml (applygate init), then run it again.")
	}

	if sessions > 0 {
		switch all, protected := s.changes(); {
		case all == 0:
			fmt.Fprintln(w, "\n  In the sessions read, your agents issued no command that changes infrastructure.")
		default:
			fmt.Fprintf(w, "\n  In the sessions read, your agents issued %s command%s that change%s infrastructure (an apply, a destroy,\n", num(all), plural(all), singular(all))
			fmt.Fprintf(w, "  a state change, a cloud write), %s of them aimed at an environment that is protected or that no config names.\n", num(protected))
		}
	}
	fmt.Fprintln(w)
}

func singular(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

func homeAsTilde(s, home string) string {
	if home == "" {
		return s
	}
	return strings.ReplaceAll(s, home+"/", "~/")
}

// ShareReason puts the reason for an ask in one of a fixed set of kinds. A
// reason can name a program, a file or a subcommand; a kind names none, so
// the summary a person sends to someone else carries no text of theirs.
func ShareReason(why string) string {
	s := why
	if strings.HasPrefix(s, shapePrefix) {
		s = strings.TrimSuffix(strings.TrimPrefix(s, shapePrefix), ")")
		if rest, ok := strings.CutPrefix(s, "a part the analyzer cannot resolve ("); ok {
			s = rest
		}
	}
	has := func(prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
		return false
	}
	switch {
	case has("the variable "):
		return "a variable set in the command (X=... cmd)"
	case has("the program "):
		return "a program with no option list"
	case has("the subcommand ", "the option ", "the git option") || has("the ") && strings.Contains(s, " subcommand "):
		return "a subcommand or option that is not listed"
	case has("source of a file that cannot be read", "script cannot be read"):
		return "a sourced file or script that cannot be read"
	case has("a loop or conditional", "a command substitution", "a declaration", "a subshell or block", "a function",
		"a parameter expansion", "a background or negated statement", "a process substitution", "a redirection target",
		"arithmetic ", "could not parse as shell", "TimeClause"):
		return "shell syntax beyond a plain command"
	case has("program name cannot be resolved", "a program named by a path") || strings.Contains(s, "a word the analysis cannot resolve"):
		return "a program or file named by something that cannot be resolved"
	case has("eval of ", "sh -c ", "bash -c ") || strings.Contains(s, " runs ") || strings.Contains(s, " code "):
		return "code that an interpreter runs"
	case has("git ", "a git ", "a path in a git "):
		return "git state or configuration"
	}
	return "another reason"
}

// RenderShare writes the counts of a scan and nothing else: no command, no
// path, no repository, account or program name. It is what a person can send
// to someone outside their organization.
func (s Summary) RenderShare(w io.Writer, o RenderOptions) {
	window := "every session kept"
	if o.Days > 0 {
		window = fmt.Sprintf("the last %d days", o.Days)
	}
	fmt.Fprintf(w, "applygate %s scan summary, %s\n", o.Version, window)
	fmt.Fprintln(w, "Counts only: no command, path, repository, account or program name is in this text.")

	by := map[string]map[string]int{} // group -> verdict -> calls
	for _, r := range s.Rows {
		if by[r.Group] == nil {
			by[r.Group] = map[string]int{}
		}
		by[r.Group][string(r.Verdict)]++
		by[r.Group][""]++
	}
	fmt.Fprintf(w, "\nsessions           %s (claude %s, codex %s)\n", num(s.Stats.Sessions["claude"]+s.Stats.Sessions["codex"]), num(s.Stats.Sessions["claude"]), num(s.Stats.Sessions["codex"]))
	fmt.Fprintf(w, "tool calls         %s; judged %s; directory gone %s; decision failed %s\n", num(s.Stats.Calls), num(len(s.Rows)-by[GroupFailed][""]), num(s.Gone), num(by[GroupFailed][""]))

	repos, covered := map[string]bool{}, 0
	for _, r := range s.Rows {
		repos[r.Repo] = repos[r.Repo] || r.NoConfig
	}
	for _, noConfig := range repos {
		if !noConfig {
			covered++
		}
	}
	fmt.Fprintf(w, "repositories       %s, %s with a trusted config\n", num(len(repos)), num(covered))

	all, protected := s.changes()
	fmt.Fprintf(w, "\ninfrastructure     %s: block %s, ask %s, allow %s, saved plans %s\n", num(by[GroupInfra][""]+by[GroupPlan][""]),
		num(by[GroupInfra]["block"]), num(by[GroupInfra]["ask"]), num(by[GroupInfra]["allow"]), num(by[GroupPlan][""]))
	fmt.Fprintf(w, "  changes issued   %s, %s in a protected or unnamed environment\n", num(all), num(protected))
	fmt.Fprintf(w, "guard files        %s: block %s, ask %s\n", num(by[GroupGuard][""]), num(by[GroupGuard]["block"]), num(by[GroupGuard]["ask"]))

	shell, asked, noCfg := 0, 0, 0
	agents, reasons := map[string]int{}, map[string]int{}
	for _, r := range s.Rows {
		if r.Kind != "shell" {
			continue
		}
		switch r.Group {
		case GroupOther:
			shell++
		case GroupGeneral:
			shell++
			asked++
			agents[r.Agent]++
			reasons[ShareReason(r.Why)]++
			if r.NoConfig {
				noCfg++
			}
		}
	}
	pct := 0
	if shell > 0 {
		pct = 100 * asked / shell
	}
	fmt.Fprintf(w, "other shell        %s: ask %s (%d%%), allow %s\n", num(shell), num(asked), pct, num(shell-asked))
	if asked > 0 {
		fmt.Fprintf(w, "  asks, no config  %s\n", num(noCfg))
		fmt.Fprintf(w, "  asks by agent    claude %s, codex %s (an ask is a block on Codex)\n", num(agents["claude"]), num(agents["codex"]))
		fmt.Fprintln(w, "  asks by reason")
		for _, kv := range topN(reasons, len(reasons)) {
			fmt.Fprintf(w, "    %8s  %s\n", num(kv.n), kv.k)
		}
	}

	x := s.Exposure
	switch {
	case x == nil:
	case x.Error != "":
		fmt.Fprintln(w, "\nboundary           not checked")
	default:
		audit := "credentials not audited"
		if x.Audited {
			audit = fmt.Sprintf("credentials audited: %s with no destructive path to production, %s with one, %s unclear", num(x.CredsOK), num(x.CredsFail), num(x.CredsUnclear))
		}
		fmt.Fprintf(w, "\nboundary           L%d of L3; %s\n", min(max(x.Level, 0), 3), audit)
		for lvl := 1; lvl <= 3; lvl++ {
			n := map[string]int{}
			for _, c := range x.Checks {
				if c.Level == lvl {
					n[c.Status]++
				}
			}
			fmt.Fprintf(w, "  L%d checks        ok %d, attested %d, failed %d, not verified %d\n", lvl, n["ok"], n["attested"], n["FAIL"], n["not verified"])
		}
	}
}
