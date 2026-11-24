package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
)

// SavedPlanVerdict is the verdict applying a saved plan with this plan-gate
// result gets in tier t, as planGate and the decision table judge it: a
// replace counts as a destroy.
func SavedPlanVerdict(res *plangate.Result, t config.Tier) Verdict {
	class := classify.ApplySavedPlan
	if len(res.Deletes)+len(res.Replaces) > 0 {
		class = classify.Destroy
	}
	v := Table[class][t]
	for _, f := range res.Findings {
		v = Max(v, FindingVerdict(f.Severity, t))
	}
	return v
}

// planGate runs the saved-plan checks and returns the effective class
// (Destroy when the plan deletes resources).
func planGate(r *ActionResult, a classify.Action, cfg *config.Config, deps Deps, recorded, declared *preflight.Backend) classify.Class {
	if a.PlanWritten {
		// The plan on disk now is not the one that will be applied: an
		// earlier step of this command writes it (plan -out, cp, a download).
		// It was made where its plan -out ran; written by anything else, it
		// could have been made anywhere.
		if a.PlanOrigin == "" {
			r.Tier, r.Env = config.Protected, "unknown"
			r.Matched = append(r.Matched, "an earlier step writes the saved plan "+a.PlanFile+" by a means other than plan -out, so where it was made is not known; judged as protected")
		} else if filepath.Clean(a.PlanOrigin) != filepath.Clean(a.Dir) {
			sig, _ := DirSignals(a.PlanOrigin, deps.Env)
			if alt := cfg.Resolve(sig); alt.Tier.Rank() > r.Tier.Rank() {
				r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is made in "+a.PlanOrigin)
			}
		}
		for _, d := range a.PlanStateDirs {
			// plan -state=FILE -out=p: p changes the resources in FILE.
			if alt := cfg.Resolve(config.Signals{Dir: d, StateDirs: []string{d}}); alt.Unknown || alt.Tier.Rank() > r.Tier.Rank() {
				t, e := alt.Tier, alt.Env
				if alt.Unknown && t.Rank() < r.Tier.Rank() {
					t, e = r.Tier, r.Env
				}
				r.Tier, r.Env, r.Matched = t, e, append(r.Matched, "the saved plan is made from the state in "+d)
			}
		}
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unverifiable", Severity: preflight.Critical,
			Message: "an earlier step of this command writes the saved plan " + a.PlanFile + ", so the plan that would be applied cannot be checked; run the steps separately"})
		return classify.ApplySavedPlan
	}
	if a.Dir == "" && a.PlanFile != "" && !filepath.IsAbs(a.PlanFile) && a.PlanFile != "-" {
		// A relative plan file from a directory that is not known: which file
		// this opens, and what is in it, cannot be told.
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-ambiguous", Severity: preflight.Critical,
			Message: "the directory this command runs in is not known, so the saved plan file " + a.PlanFile + " cannot be identified and read"})
		return classify.ApplySavedPlan
	}
	planPath := a.PlanFile
	if !filepath.IsAbs(planPath) && a.Dir != "" {
		// Physically, as Terraform opens it: m/../tfplan through a link m
		// is in the directory the link's parent is.
		planPath = shell.PhysicalJoin(a.Dir, planPath)
	}
	if streamPath(planPath) {
		// A plan read from stdin or a descriptor (apply /dev/stdin <
		// ../prod/tfplan) has no directory.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "the saved plan "+a.PlanFile+" is read from a stream, so where it was made is not known; judged as protected")
	}
	if b, err := deps.ReadFile(planPath); err == nil {
		sum := sha256.Sum256(b)
		r.PlanSHA256 = hex.EncodeToString(sum[:])
	} else if fi, serr := os.Stat(planPath); serr == nil && fi.Size() > 0 {
		// Larger than the read cap: hash by streaming.
		if f, err := os.Open(planPath); err == nil {
			h := sha256.New()
			_, _ = io.Copy(h, f)
			f.Close()
			r.PlanSHA256 = hex.EncodeToString(h.Sum(nil))
		}
	}
	if ws, ok := preflight.PlanWorkspace(planPath); ok && r.Workspace != "" && ws != r.Workspace {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "workspace-mismatch", Severity: preflight.Critical,
			Message:  fmt.Sprintf("the plan was made in workspace %q but workspace %q is selected; applying it would change the wrong environment", ws, r.Workspace),
			Evidence: []string{"plan workspace: " + ws, "selected workspace: " + r.Workspace}})
		// The plan's own workspace may be more protected than the selected one.
		alt := cfg.Resolve(config.Signals{Dir: a.Dir, Workspace: ws, Backend: r.Backend, AWSProfile: r.Profile})
		if alt.Tier.Rank() > r.Tier.Rank() {
			r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "plan workspace "+ws)
		}
	}
	// A plan saved in another directory was made against that directory's
	// state: its tier joins the command's. A plan reached through a
	// symlink is in the directory the link leads to.
	// Only a Terraform working directory says where a plan was made: a plan
	// file kept in /tmp says nothing.
	planDirs := []string{filepath.Dir(planPath)}
	if real, err := filepath.EvalSymlinks(planPath); err == nil {
		planDirs = append(planDirs, filepath.Dir(real))
	}
	for _, pd := range planDirs {
		if a.Dir == "" || !filepath.IsAbs(pd) || filepath.Clean(pd) == filepath.Clean(a.Dir) {
			continue
		}
		if terraformDir(pd) {
			sig, _ := DirSignals(pd, deps.Env)
			if alt := cfg.Resolve(sig); alt.Tier.Rank() > r.Tier.Rank() {
				r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is in "+pd)
			}
			continue
		}
		// Elsewhere only a configured environment's path counts (a plan in
		// envs/prod/out is prod's); an unmatched place such as /tmp says
		// nothing.
		if alt := cfg.Resolve(config.Signals{Dir: pd}); !alt.Unknown && alt.Tier.Rank() > r.Tier.Rank() {
			r.Tier, r.Env, r.Matched = alt.Tier, alt.Env, append(alt.Matched, "the saved plan is in "+pd)
		}
	}
	if fi, err := os.Stat(planPath); err == nil && hardLinked(fi) && r.Tier.Rank() < config.Protected.Rank() {
		// A hard link is the same file under another name, in a directory
		// that cannot be found from here.
		r.Tier, r.Env = config.Protected, "unknown"
		r.Matched = append(r.Matched, "the saved plan "+a.PlanFile+" is a hard link, so the directory it was made in is not known; judged as protected")
	}
	for _, f := range r.Findings {
		if f.Rule == "plan-ambiguous" {
			// Several candidate planfiles: nothing to show, and reading one
			// of them would check the wrong plan.
			return classify.ApplySavedPlan
		}
	}
	if deps.PlanJSON == nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: "reading saved plans is disabled (plan_gate.run_show: false), so the plan cannot be checked"})
		return classify.ApplySavedPlan
	}
	js, err := deps.PlanJSON(a.Engine, a.Dir, a.PlanFile)
	if err != nil {
		// F10: distinguish a plan file that simply does not exist from one that
		// exists but cannot be read. A missing file means there is nothing to
		// apply, so it is High (protected tier asks) rather than Critical
		// (block). An existing-but-unreadable plan stays Critical: applygate
		// cannot verify a real plan, so it must fail closed.
		if _, serr := os.Stat(planPath); errors.Is(serr, os.ErrNotExist) {
			r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-missing", Severity: preflight.High,
				Message: "the saved plan file " + a.PlanFile + " does not exist, so there is nothing to apply; check the path"})
			return classify.ApplySavedPlan
		}
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical,
			Message: "could not read the saved plan with show -json: " + err.Error()})
		return classify.ApplySavedPlan
	}
	be := recorded
	if be == nil {
		be = declared
	}
	gres, err := plangate.Evaluate(plangate.Input{PlanJSON: js, MaxDestroy: cfg.MaxDestroy(r.Tier), Scope: cfg.PlanGate.Scope, Protected: cfg.ProtectedResources, Backend: be}, deps.Rules)
	if err != nil {
		r.Findings = append(r.Findings, preflight.Finding{Rule: "plan-unreadable", Severity: preflight.Critical, Message: err.Error()})
		return classify.ApplySavedPlan
	}
	if r.PlanSHA256 == "" {
		sum := sha256.Sum256(js)
		r.PlanSHA256 = "json:" + hex.EncodeToString(sum[:])
	}
	r.Findings = append(r.Findings, gres.Findings...)
	// Replacing a resource destroys it first (or after its successor is
	// created): it is judged like deleting it.
	if gone := append(append([]string(nil), gres.Deletes...), gres.Replaces...); len(gone) > 0 {
		verb := "destroys"
		switch {
		case len(gres.Deletes) == 0:
			verb = "replaces"
		case len(gres.Replaces) > 0:
			verb = "destroys or replaces"
		}
		r.Why = fmt.Sprintf("applies saved plan %s, which %s %d resource(s): %s", a.PlanFile, verb, len(gone), strings.Join(first(gone, 5), ", "))
		return classify.Destroy
	}
	r.Why = fmt.Sprintf("applies saved plan %s (%d change(s))", a.PlanFile, gres.Changes)
	return classify.ApplySavedPlan
}

func orHost(agent string) string {
	if agent == "" {
		return "the host"
	}
	return agent
}

// Limits of the planfile search under the session root.
const (
	planSearchMaxDepth   = 8
	planSearchMaxEntries = 20000
	planSearchMaxMatches = 5
)

// findPlanfile looks for rel (a relative planfile path) in every directory
// under root, bounded by depth and by the number of directory entries
// visited; .git and .terraform are skipped and symbolic links are not
// followed. truncated is true when a limit stopped the walk before it
// finished, so the matches may be incomplete.
func findPlanfile(root, rel string) (matches []string, truncated bool) {
	entries := 0
	stop := errors.New("stop")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if d.Type()&os.ModeSymlink != 0 {
				// A link to a directory leads somewhere the search does not
				// go: a copy of the plan there would be missed.
				if fi, err := os.Stat(p); err != nil || fi.IsDir() {
					truncated = true
				}
			}
			return nil
		}
		if p != root {
			switch d.Name() {
			case ".git", ".terraform":
				return filepath.SkipDir
			}
			if r, err := filepath.Rel(root, p); err == nil && strings.Count(r, string(filepath.Separator)) >= planSearchMaxDepth {
				// Deeper directories are not searched, so a copy there would
				// be missed.
				truncated = true
				return filepath.SkipDir
			}
		}
		entries++
		if entries > planSearchMaxEntries {
			truncated = true
			return stop
		}
		if p == root {
			return nil
		}
		if fi, err := os.Stat(filepath.Join(p, rel)); err == nil && fi.Mode().IsRegular() {
			matches = append(matches, filepath.Join(p, rel))
			if len(matches) >= planSearchMaxMatches {
				truncated = true
				return stop
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		truncated = true
	}
	return matches, truncated
}

// rootOf is the directory a command whose directory is not known is
// assumed to run under: the repository config's directory, else the
// event's.
func rootOf(cfg *config.Config, ev Event) string {
	if cfg.Root != "" {
		return cfg.Root
	}
	return ev.Cwd
}
