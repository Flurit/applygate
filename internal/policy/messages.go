package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/preflight"
)

func first(ss []string, n int) []string {
	if len(ss) > n {
		return append(ss[:n:n], fmt.Sprintf("and %d more", len(ss)-n))
	}
	return ss
}

func nextStep(c classify.Class, engine string) string {
	tf := engine
	if tf == "" || tf == "terragrunt" {
		tf = "terraform"
	}
	switch c {
	case classify.UnreviewedApply:
		return fmt.Sprintf("Run `%s plan -out=tfplan`, show the plan to the user, then apply the saved plan with `%s apply tfplan`.", tf, tf)
	case classify.Destroy:
		return "Do not retry or rephrase this. Destroying resources here needs a human: tell the user what you intended and let them run it outside the agent."
	case classify.RoutineReplace:
		return "Do not retry or rephrase this. Replacing resources in a protected environment needs a human, whatever their type: tell the user what you intended and let them run it outside the agent."
	case classify.StateSurgery:
		return "State surgery must be done by a human. Tell the user what you intended and why."
	case classify.CloudDestructive:
		return "Deleting cloud resources directly needs a human. Tell the user which resource and why; prefer changing the Terraform configuration and planning."
	case classify.Tampering:
		return "The agent may not change its own guardrails, hook configuration or applygate's config and log. Ask the user to make this change themselves."
	case classify.HookRewrite:
		return "This rewrites the work tree of the repository or session directory where the agent's hook settings are loaded from, and could bring in changed hook files. Confirm with the user first."
	case classify.Dynamic:
		return "Write the command out literally, without eval, variables for subcommands, encoded text, or piping generated or fetched text into a shell, so it can be checked."
	case classify.UnknownWrapper:
		return "Run the underlying commands directly so they can be checked, or ask the user to run this wrapper."
	case classify.ComplexShape:
		return "In a protected environment only plain commands run without asking: a list or pipeline of known programs, without functions, loops, substitutions or other shells. Split the command into plain steps, or ask the user."
	case classify.CredentialAccess:
		return "Do not read credentials. Use the configured profile through the CLI instead, and ask the user if access is really needed."
	case classify.Mutating, classify.CloudWrite:
		return "This changes a protected environment. Confirm with the user first."
	}
	return ""
}

func message(d Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "applygate: %s.", strings.ToUpper(string(d.Enforced)))
	if d.Enforced != d.Verdict {
		fmt.Fprintf(&b, " (policy verdict: %s)", d.Verdict)
	}
	var rs []ActionResult
	for _, a := range d.Actions {
		if a.Verdict != Allow {
			rs = append(rs, a)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Verdict.rank() > rs[j].Verdict.rank() })
	steps := map[string]bool{}
	for _, a := range rs {
		fmt.Fprintf(&b, "\n- [%s] %s: %s", a.Verdict, a.Class, a.Why)
		if a.Tier != "" {
			fmt.Fprintf(&b, "\n  environment: %s (tier %s; %s)", a.Env, a.Tier, strings.Join(a.Matched, "; "))
		}
		if a.Command != "" && !strings.Contains(a.Why, a.Command) {
			fmt.Fprintf(&b, "\n  command: %s", a.Command)
		}
		if len(a.Via) > 0 {
			fmt.Fprintf(&b, "\n  reached via: %s", strings.Join(a.Via, " > "))
		}
		for _, f := range a.Findings {
			if f.Severity == preflight.Info {
				continue
			}
			fmt.Fprintf(&b, "\n  finding (%s, %s): %s", f.Severity, f.Rule, f.Message)
			for _, e := range first(f.Evidence, 5) {
				fmt.Fprintf(&b, "\n    - %s", e)
			}
		}
		if a.PlanSHA256 != "" {
			fmt.Fprintf(&b, "\n  plan sha256: %s", a.PlanSHA256)
		}
	}
	// An enforced "ask" is shown to a human as a permission prompt, so the
	// closing guidance is human-facing. A block is read by the agent (including
	// when an ask was converted to a block because the agent cannot prompt), so
	// it keeps the agent-facing "Next step" instructions. The verdict itself is
	// unchanged either way; only the wording differs by audience.
	if d.Enforced == Ask {
		b.WriteString("\nThis needs your approval. Approve only if you asked for this and the effect above is what you intend; otherwise deny.")
	} else {
		for _, a := range rs {
			if a.NextStep != "" && !steps[a.NextStep] {
				steps[a.NextStep] = true
				fmt.Fprintf(&b, "\nNext step: %s", a.NextStep)
			}
		}
	}
	for _, n := range d.Notes {
		fmt.Fprintf(&b, "\nNote: %s", n)
	}
	return b.String()
}
