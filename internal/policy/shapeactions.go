package policy

import (
	"context"
	"sort"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
)

func isTerraform(engine string) bool {
	return engine == "terraform" || engine == "tofu" || engine == "terragrunt"
}

// shapeActions are the strict-shapes actions of a shell command that is not
// plain: one per directory its programs are known to run in, each judged at
// that directory's tier: ask in protected, allow elsewhere. A part the
// analysis lost is judged by the command's own actions.
func shapeActions(ev Event, res *shell.Result, deps Deps, acts []classify.Action) []classify.Action {
	ok, why, unseen := shell.PlainShapeUnseen(ev.Command, res)
	if ok {
		// The provider, lock-file and data-source checks read the disk
		// before the command runs; a step that rewrites what they read
		// comes first.
		for _, a := range acts {
			if isTerraform(a.Engine) && (a.InstalledEarlier || a.InitEarlier && !preflight.InitSafe(ctxOf(deps), a.Dir)) && startsProviders(a.Sub, nil) {
				why = "an earlier step installs providers or modules in " + a.Dir + " that " + a.Engine + " then runs, from somewhere the committed lock file does not vouch for"
				ok, unseen = false, why
				break
			}
			if isTerraform(a.Engine) && (a.ConfigWritten || a.DataDirWritten) && startsProviders(a.Sub, nil) {
				why = "an earlier step writes the configuration or .terraform in " + a.Dir + " that " + a.Engine + " then reads"
				ok, unseen = false, why
				break
			}
			if isTerraform(a.Engine) && ev.Persistent && startsProviders(a.Sub, nil) {
				// The provider check needs the directory, which a shell that
				// keeps running between calls may have left.
				why = a.Engine + " typed into a shell that keeps running between calls, whose directory the hook cannot follow"
				ok, unseen = false, why
				break
			}
		}
	}
	if ok {
		ctx := deps.Ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if why = engineState(ctx, res, deps.Env); why == "" {
			return nil
		}
		unseen = why
	}
	dirs := map[string]bool{ev.Cwd: true}
	for _, inv := range res.Invocations {
		if inv.Dir != "" {
			dirs[inv.Dir] = true
		}
	}
	var out []classify.Action
	for d := range dirs {
		out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, Dir: d,
			Why: "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	// A command that can run code the analysis does not see (a program with
	// no shape, python3, perl -e, awk, a name or part it could not resolve)
	// can reach any directory, a cd or -chdir to a protected sibling
	// included: it is judged at the most protected tier under the root too.
	if unseen != "" {
		out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, AnyDir: true,
			AnyDirWhy: "the command is not plain and can run code the analysis does not follow (" + unseen + "), which can reach any directory under the root",
			Why:       "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
	}
	// A command run over every unit under a directory (terragrunt
	// --all) runs what each unit's configuration names: the shape is
	// judged at the most protected unit's tier too.
	for _, a := range acts {
		if a.Subtree && a.Dir != "" {
			out = append(out, classify.Action{Class: classify.ComplexShape, Engine: "shell", Command: ev.Command, Dir: a.Dir,
				Subtree: true, UnitsUnknown: a.UnitsUnknown,
				Why: "strict shapes: the command is not a plain list or pipeline of known programs (" + why + ")"})
		}
	}
	return out
}
