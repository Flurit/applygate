package policy

import (
	"context"
	"strings"
	"sync"

	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/shell"
)

// tfNoStart are the terraform and tofu subcommands known not to start the
// provider binaries in .terraform/providers or to run what the
// configuration names. Every other one (plan, validate, console, show,
// graph, query, test, import, refresh, apply, destroy, state show,
// providers schema, and any subcommand applygate does not know) is checked
// like the plan gate's show: providers that match the committed lock
// file, a lock file the upstream branch agrees with, and no configuration
// that runs a program.
var tfNoStart = map[string]bool{"fmt": true, "version": true, "output": true, "init": true, "get": true, "login": true,
	"logout": true, "modules": true, "providers": true, "providers lock": true, "providers mirror": true, "state list": true,
	"state pull": true, "workspace list": true, "workspace show": true, "workspace select": true, "workspace new": true,
	"workspace delete": true, "force-unlock": true, "taint": true, "untaint": true, "metadata functions": true, "-version": true,
	"-help": true, "help": true}

// startsProviders reports whether terraform subcommand sub (with its
// arguments after the subcommand word) may start the provider binaries.
func startsProviders(sub string, args []string) bool {
	// graph starts the providers whatever its -type (terraform 1.14 started
	// one for -type=plan).
	return !tfNoStart[sub]
}

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
		if !args[0].Resolved {
			return "a terraform subcommand that cannot be resolved"
		}
		sub := args[0].Text
		if (sub == "state" || sub == "providers" || sub == "workspace" || sub == "metadata") && len(args) > 1 {
			sub += " " + args[1].Text
		}
		var rest []string
		for _, w := range args[1:] {
			rest = append(rest, w.Text)
		}
		if !startsProviders(sub, rest) {
			// These do not start providers, but all but a few configure the
			// backend, and a backend that names a credentials file runs
			// the program in it.
			if tfNoBackend[sub] {
				continue
			}
			if dir == "" {
				return "terraform " + sub + " in a directory that cannot be followed"
			}
			bkey := dir + "\x00backend\x00" + strings.Join(backendConfigs(rest), "\x00")
			if v, ok := engineCache.Load(bkey); ok {
				if w := v.(string); w != "" {
					return w
				}
				continue
			}
			why := ""
			if r := preflight.RunsBackendPrograms(dir); r != "" {
				why = "terraform " + sub + ": " + r
			} else if r := preflight.RunsRecordedBackend(preflight.DataDir(dir, mergeEnv(env, inv.Env))); r != "" {
				why = "terraform " + sub + ": " + r
			} else if sub == "init" {
				if r := preflight.RunsBackendConfig(dir, backendConfigs(rest)); r != "" {
					why = "terraform init: " + r
				}
			}
			engineCache.Store(bkey, why)
			if why != "" {
				return why
			}
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

// backendConfigs are the -backend-config values in an init's arguments.
func backendConfigs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := strings.TrimLeft(args[i], "-")
		if v, ok := strings.CutPrefix(a, "backend-config="); ok {
			out = append(out, v)
		} else if a == "backend-config" && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return out
}

// tfNoBackend are the subcommands that neither start providers nor
// configure the backend.
var tfNoBackend = map[string]bool{"fmt": true, "version": true, "-version": true, "-help": true, "help": true, "login": true,
	"logout": true, "metadata functions": true, "providers lock": true, "providers mirror": true, "validate": false}
