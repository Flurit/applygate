package classify

import (
	"strings"

	"github.com/Flurit/seatbelt/internal/shell"
)

// Terraform/OpenTofu flags that take a separate value ("-var a=b").
var tfValueFlags = map[string]bool{
	"var": true, "var-file": true, "target": true, "replace": true, "lock-timeout": true, "parallelism": true,
	"state": true, "state-out": true, "backup": true, "out": true, "generate-config-out": true, "exclude": true,
	"config": true, "backend-config": true, "from-module": true, "plugin-dir": true, "provider": true, "chdir": true,
	"filter": true, "test-directory": true, "id": true, "lock-file": true,
}

type tfFlag struct {
	name  string
	value string
	has   bool // value given with "="
}

// splitTF separates flags and positionals the way Go's flag package does for
// terraform: options end at the first positional or "--".
func splitTF(args []shell.Word) (flags []tfFlag, pos []shell.Word, unresolved bool) {
	i := 0
	for i < len(args) {
		w := args[i]
		if !w.Resolved {
			// A flag with a dynamic value is fine ("-var=region=$R"); a whole
			// dynamic word could be any flag, including -destroy.
			if strings.HasPrefix(w.Prefix, "-") && strings.Contains(w.Prefix, "=") {
				name, _, _ := strings.Cut(strings.TrimLeft(w.Prefix, "-"), "=")
				flags = append(flags, tfFlag{name: name, has: true})
				i++
				continue
			}
			unresolved = true
			pos = append(pos, w)
			i++
			continue
		}
		t := w.Text
		if t == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			name, val, has := strings.Cut(strings.TrimLeft(t, "-"), "=")
			f := tfFlag{name: name, value: val, has: has}
			if !has && tfValueFlags[name] && i+1 < len(args) {
				f.value = args[i+1].Text
				if !args[i+1].Resolved {
					f.value = "<?>"
				}
				i++
			}
			flags = append(flags, f)
			i++
			continue
		}
		pos = append(pos, w)
		i++
	}
	return
}

func flagOn(flags []tfFlag, name string) bool {
	for _, f := range flags {
		if f.name == name {
			if !f.has {
				return true
			}
			return f.value != "false" && f.value != "0"
		}
	}
	return false
}

func flagVal(flags []tfFlag, name string) (string, bool) {
	for _, f := range flags {
		if f.name == name {
			return f.value, true
		}
	}
	return "", false
}

// terraformArgs classifies terraform, tofu and terragrunt invocations.
func terraformArgs(a *Action, args []shell.Word) {
	// Global options before the subcommand.
	for len(args) > 0 && args[0].Resolved && strings.HasPrefix(args[0].Text, "-") {
		t := args[0].Text
		if v, ok := strings.CutPrefix(strings.TrimLeft(t, "-"), "chdir="); ok {
			a.Dir = absPath(a.Dir, v, "")
		} else if strings.TrimLeft(t, "-") == "chdir" && len(args) > 1 {
			a.Dir = absPath(a.Dir, args[1].Text, "")
			args = args[1:]
		}
		if t == "-version" || t == "--version" || t == "-help" || t == "--help" || t == "-h" {
			a.Class, a.Why = ReadOnly, "version or help"
			return
		}
		args = args[1:]
	}
	if len(args) == 0 {
		a.Class, a.Why = ReadOnly, "no subcommand"
		return
	}
	if !args[0].Resolved {
		a.Class, a.Why = Dynamic, "subcommand cannot be resolved statically"
		return
	}
	sub := args[0].Text
	rest := args[1:]
	if a.Engine == "terragrunt" {
		switch sub {
		case "run-all", "run":
			// terragrunt run-all <cmd>, terragrunt run [--all] -- <cmd>
			r := rest
			for len(r) > 0 && r[0].Resolved && strings.HasPrefix(r[0].Text, "-") {
				r = r[1:]
			}
			a.Via = append(a.Via, "terragrunt "+sub)
			terraformArgs(a, r)
			return
		case "plan-all", "validate-all", "output-all", "render-json", "graph-dependencies", "hclfmt", "hcl", "info", "find", "list", "dag", "catalog", "scaffold", "render":
			a.Class, a.Sub, a.Why = ReadOnly, sub, "terragrunt read-only command"
			return
		case "apply-all":
			a.Class, a.Sub, a.Why = UnreviewedApply, sub, "terragrunt apply-all applies without a saved plan"
			return
		case "destroy-all":
			a.Class, a.Sub, a.Why = Destroy, sub, "terragrunt destroy-all"
			return
		}
	}
	a.Sub = sub
	flags, pos, unresolved := splitTF(rest)
	set := func(c Class, why string) {
		a.Class, a.Why = c, why
		if unresolved && severityRank(c) < severityRank(Destroy) {
			a.Class, a.Why = Dynamic, a.Engine+" "+sub+" has arguments that cannot be resolved statically"
		}
	}
	switch sub {
	case "plan":
		a.TouchesState = true
		set(ReadOnly, "plan does not change infrastructure")
	case "show", "output", "validate", "fmt", "graph", "providers", "version", "get", "console", "modules", "metadata", "query", "login", "logout", "stacks":
		a.TouchesState = sub == "show" || sub == "output" || sub == "console"
		if sub == "providers" && len(pos) > 0 && pos[0].Text == "lock" {
			set(ReadOnly, "providers lock updates the lock file only")
			return
		}
		set(ReadOnly, sub+" is read-only")
	case "init":
		a.TouchesState = true
		switch {
		case flagOn(flags, "reconfigure"):
			set(StateSurgery, "init -reconfigure discards the configured backend")
		case flagOn(flags, "migrate-state") || flagOn(flags, "force-copy"):
			set(StateSurgery, "init -migrate-state moves state between backends")
		default:
			set(ReadOnly, "init prepares the working directory")
		}
	case "apply":
		a.TouchesState = true
		if v, ok := flagVal(flags, "replace"); ok {
			a.Class, a.Why = Destroy, "apply -replace="+v+" destroys and recreates a resource"
			return
		}
		if flagOn(flags, "destroy") {
			a.Class, a.Why = Destroy, "apply -destroy destroys every resource in the state"
			return
		}
		if unresolved {
			set(UnreviewedApply, "")
			return
		}
		if len(pos) > 0 {
			a.PlanFile = pos[0].Text
			a.Class, a.Why = ApplySavedPlan, "applies saved plan "+pos[0].Text
			return
		}
		why := "apply without a saved plan"
		if flagOn(flags, "auto-approve") {
			why = "apply -auto-approve without a saved plan"
		}
		if flagOn(flags, "refresh-only") {
			why = "apply -refresh-only without a saved plan"
		}
		a.Class, a.Why = UnreviewedApply, why
	case "destroy":
		a.TouchesState = true
		a.Class, a.Why = Destroy, a.Engine+" destroy"
	case "import", "refresh":
		a.TouchesState = true
		set(Mutating, sub+" writes to state")
	case "test":
		set(Mutating, "test creates and destroys real resources")
	case "taint", "untaint", "force-unlock":
		a.TouchesState = true
		set(StateSurgery, sub+" edits state directly")
	case "state":
		a.TouchesState = true
		op := ""
		if len(pos) > 0 {
			op = pos[0].Text
			if !pos[0].Resolved {
				a.Class, a.Why = Dynamic, "state subcommand cannot be resolved"
				return
			}
		}
		a.Sub = "state " + op
		switch op {
		case "list", "show", "pull", "identities", "":
			set(ReadOnly, "state "+op+" is read-only")
		default:
			a.Class, a.Why = StateSurgery, "state "+op+" edits state directly"
		}
	case "workspace", "env":
		op := ""
		if len(pos) > 0 {
			op = pos[0].Text
		}
		a.Sub = "workspace " + op
		if (op == "select" || op == "new") && len(pos) > 1 && pos[1].Resolved {
			a.SelectWorkspace = pos[1].Text
		}
		if op == "delete" {
			a.TouchesState = true
			a.Class, a.Why = StateSurgery, "workspace delete removes a workspace's state"
			return
		}
		set(ReadOnly, "workspace "+op)
	default:
		a.Class, a.Why = UnknownWrapper, "unrecognized "+a.Engine+" subcommand "+sub
	}
}

// severityRank orders classes by how much damage they can do, for choosing
// between a resolved class and Dynamic.
func severityRank(c Class) int {
	switch c {
	case ReadOnly:
		return 0
	case Mutating, CloudWrite:
		return 1
	case ApplySavedPlan, UnreviewedApply, UnknownWrapper, Dynamic, CredentialAccess:
		return 2
	case Destroy, StateSurgery, CloudDestructive:
		return 3
	case Tampering:
		return 4
	}
	return 0
}

var awsValueOpts = map[string]bool{
	"--profile": true, "--region": true, "--output": true, "--endpoint-url": true, "--query": true,
	"--cli-read-timeout": true, "--cli-connect-timeout": true, "--ca-bundle": true, "--color": true, "--cli-binary-format": true,
}

// Flags that remove protection when present in any AWS call.
var awsProtectionRemoval = []string{
	"--no-deletion-protection", "--skip-final-snapshot", "--no-deletion-protection-enabled",
	"--no-disable-api-termination", "--delete-automated-backups", "--force-delete-without-recovery",
	"--bypass-governance-retention",
}

func awsArgs(base Action, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = "aws"
	var pos []string
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		if t == "--profile" && i+1 < len(args) {
			a.Profile = args[i+1].Text
		}
		if strings.HasPrefix(t, "--profile=") {
			a.Profile = strings.TrimPrefix(t, "--profile=")
		}
		if strings.HasPrefix(t, "--") {
			if awsValueOpts[t] && len(pos) < 2 {
				i++
			}
			continue
		}
		if !args[i].Resolved && len(pos) < 2 {
			a.Class, a.Why = Dynamic, "aws service or operation cannot be resolved statically"
			return a, true
		}
		pos = append(pos, t)
	}
	if a.Profile == "" {
		a.Profile = a.Env["AWS_PROFILE"]
	}
	if len(pos) < 2 {
		a.Class, a.Why = ReadOnly, "aws help or configuration"
		return a, true
	}
	svc, op := pos[0], pos[1]
	a.Sub = svc + " " + op
	all := strings.Join(texts(args), " ")
	for _, f := range awsProtectionRemoval {
		if strings.Contains(" "+all+" ", " "+f+" ") || strings.Contains(all, f+"=") {
			a.Class, a.Why = CloudDestructive, "aws "+svc+" "+op+" "+f+" removes a safeguard"
			return a, true
		}
	}
	switch {
	case svc == "configure" && (op == "get" && len(pos) > 2 && isSecretEnv(strings.ToUpper(pos[2])) || op == "export-credentials"):
		a.Class, a.Why = CredentialAccess, "aws configure "+op+" prints credentials"
	case svc == "configure" || svc == "sts" && op != "get-session-token":
		a.Class, a.Why = ReadOnly, "aws "+svc+" "+op
	case svc == "s3" && (op == "rb" || op == "rm"):
		a.Class, a.Why = CloudDestructive, "aws s3 "+op+" deletes buckets or objects"
	case svc == "s3" && op == "sync" && strings.Contains(all, "--delete"):
		a.Class, a.Why = CloudDestructive, "aws s3 sync --delete removes objects"
	case svc == "s3" && op == "mv":
		a.Class, a.Why = CloudWrite, "aws s3 mv moves objects"
	case svc == "s3" && op == "cp":
		if len(pos) > 3 && strings.HasPrefix(pos[3], "s3://") {
			a.Class, a.Why = CloudWrite, "aws s3 cp uploads objects"
		} else {
			a.Class, a.Why = ReadOnly, "aws s3 cp downloads objects"
		}
	case svc == "s3" && (op == "ls" || op == "presign"):
		a.Class, a.Why = ReadOnly, "aws s3 "+op
	case svc == "s3api" && op == "put-bucket-versioning" && strings.Contains(all, "Suspended"):
		a.Class, a.Why = CloudDestructive, "suspends bucket versioning"
	case strings.Contains(op, "delete") || hasAnyPrefix(op, "terminate", "remove-", "deregister", "purge", "schedule-key-deletion", "disable-key", "release-", "revoke-"):
		a.Class, a.Why = CloudDestructive, "aws "+svc+" "+op+" deletes or terminates resources"
	case op == "update-kubeconfig" || op == "login" || svc == "ecr" && op == "get-login-password":
		// Write only local client configuration (kubeconfig, SSO token cache).
		a.Class, a.Why = ReadOnly, "aws "+svc+" "+op+" only updates local client configuration"
	case hasAnyPrefix(op, "describe", "list", "get", "head", "lookup", "search", "scan", "query", "batch-get", "select", "validate", "estimate", "wait", "help", "filter-", "test-", "simulate-", "decode-", "preview-"):
		a.Class, a.Why = ReadOnly, "aws "+svc+" "+op+" is read-only"
	default:
		a.Class, a.Why = CloudWrite, "aws "+svc+" "+op+" changes resources"
	}
	return a, true
}

func kubectlArgs(base Action, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = "kubectl"
	var pos []string
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		if strings.HasPrefix(t, "-") {
			if (t == "-n" || t == "--namespace" || t == "--context" || t == "-l" || t == "--selector" || t == "-f" || t == "-o" || t == "--kubeconfig") && i+1 < len(args) {
				i++
			}
			continue
		}
		if !args[i].Resolved && len(pos) == 0 {
			a.Class, a.Why = Dynamic, "kubectl verb cannot be resolved"
			return a, true
		}
		pos = append(pos, t)
	}
	if len(pos) == 0 {
		return a, false
	}
	a.Sub = pos[0]
	switch pos[0] {
	case "delete", "drain":
		a.Class, a.Why = CloudDestructive, "kubectl "+strings.Join(pos, " ")
	case "get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version", "config", "auth", "diff", "events", "wait", "cluster-info",
		"port-forward", "proxy", "relay", "completion", "kustomize", "options":
		// port-forward, proxy and the relay plugin open local tunnels;
		// kustomize renders manifests locally. None change cluster state.
		a.Class, a.Why = ReadOnly, "kubectl "+pos[0]+" is read-only"
	default:
		a.Class, a.Why = CloudWrite, "kubectl "+pos[0]+" changes resources"
	}
	return a, true
}

func agentFlags(base Action, name string, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = "agent"
	for i, w := range args {
		t := w.Text
		bypass := t == "--dangerously-skip-permissions" || t == "--dangerously-bypass-approvals-and-sandbox" ||
			t == "--yolo" || t == "--dangerously-bypass-hook-trust" || t == "--allow-dangerously-skip-permissions" ||
			(t == "--permission-mode" && i+1 < len(args) && args[i+1].Text == "bypassPermissions") ||
			t == "--permission-mode=bypassPermissions" || (name == "cursor-agent" && (t == "--force" || t == "-f"))
		if bypass {
			a.Class, a.Why = Tampering, name+" "+t+" turns off the agent's permission checks"
			return a, true
		}
	}
	return a, false
}

func hasAnyPrefix(s string, ps ...string) bool {
	for _, p := range ps {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func texts(ws []shell.Word) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Text
	}
	return out
}
