package policy

import (
	"context"
	"strings"
	"sync"

	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
)

// tfStarts are the terraform and tofu subcommands that start the provider
// binaries in .terraform/providers, and with plan the data sources that run
// programs. A plain one is checked like the plan gate's show: providers
// that match the committed lock file, a lock file the upstream branch
// agrees with, and no data source that runs a program.
var tfStarts = map[string]bool{"plan": true, "validate": true, "console": true, "show": true, "refresh": true, "import": true,
	"test": true, "providers schema": true, "state show": true, "apply": true, "destroy": true}

// engineCache holds the verdict per directory for the process.
var engineCache sync.Map

// engineState reports why a plain command's terraform or tofu calls are
// not plain after all ("" when they are).
func engineState(ctx context.Context, res *shell.Result, env map[string]string) string {
	for _, inv := range res.Invocations {
		if len(inv.Args) == 0 || !inv.Args[0].Resolved {
			continue
		}
		if n := shell.ProgName(inv.Args[0].Text); n != "terraform" && n != "tofu" {
			continue
		}
		dir, args := inv.Dir, inv.Args[1:]
		for len(args) > 0 && strings.HasPrefix(args[0].Text, "-") {
			if v, ok := strings.CutPrefix(args[0].Text, "-chdir="); ok && dir != "" {
				dir = shell.PhysicalJoin(dir, v)
			}
			args = args[1:]
		}
		if len(args) == 0 {
			continue
		}
		sub := args[0].Text
		if (sub == "state" || sub == "providers") && len(args) > 1 {
			sub += " " + args[1].Text
		}
		if !tfStarts[sub] {
			continue
		}
		if dir == "" {
			return "terraform " + sub + " in a directory that cannot be followed"
		}
		e := map[string]string{}
		for k, v := range env {
			e[k] = v
		}
		for k, v := range inv.Env {
			e[k] = v
		}
		dataDir := preflight.DataDir(dir, e)
		key := dir + "\x00" + dataDir
		if v, ok := engineCache.Load(key); ok {
			if s := v.(string); s != "" {
				return s
			}
			continue
		}
		why := ""
		if err := preflight.VerifyProviders(ctx, dir, dataDir); err != nil {
			why = "terraform " + sub + " starts providers that cannot be verified: " + err.Error()
		} else if err := preflight.UpstreamLock(ctx, dir); err != nil {
			why = "terraform " + sub + ": " + err.Error()
		} else if r := preflight.RunsPrograms(dir, dataDir); r != "" {
			why = "terraform " + sub + ": " + r
		}
		engineCache.Store(key, why)
		if why != "" {
			return why
		}
	}
	return ""
}

// startsProviders reports whether terraform subcommand sub starts the
// provider binaries.
func startsProviders(sub string) bool { return tfStarts[sub] }
