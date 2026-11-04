package classify

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

// Terraform/OpenTofu flags that take a separate value ("-var a=b").
var tfValueFlags = map[string]bool{
	"var": true, "var-file": true, "target": true, "replace": true, "lock-timeout": true, "parallelism": true,
	"state": true, "state-out": true, "backup": true, "out": true, "generate-config-out": true, "exclude": true,
	"config": true, "backend-config": true, "from-module": true, "plugin-dir": true, "provider": true, "chdir": true,
	"filter": true, "test-directory": true, "id": true, "lock-file": true, "invoke": true,
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
				flags = append(flags, tfFlag{name: name, value: "<?>", has: true})
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
	if a.Engine == "terragrunt" {
		args = terragruntDir(a, args)
	}
	// Global options before the subcommand. A -chdir whose directory cannot
	// be resolved leaves the directory unknown.
	for len(args) > 0 && (args[0].Resolved && strings.HasPrefix(args[0].Text, "-") || !args[0].Resolved && strings.HasPrefix(args[0].Prefix, "-")) {
		t := args[0].Text
		if !args[0].Resolved {
			if strings.HasPrefix(strings.TrimLeft(args[0].Prefix, "-"), "chdir") {
				a.Dir, a.AnyDir = "", true
			}
			args = args[1:]
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimLeft(t, "-"), "chdir="); ok {
			a.Dir = absPath(a.Dir, v, "")
		} else if strings.TrimLeft(t, "-") == "chdir" && len(args) > 1 {
			if args[1].Resolved {
				a.Dir = absPath(a.Dir, args[1].Text, "")
			} else {
				a.Dir, a.AnyDir = "", true
			}
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
		if strings.HasSuffix(sub, "-all") {
			a.Subtree = true
		}
		for _, w := range rest {
			if w.Text == "--all" || w.Text == "-all" || w.Text == "--terragrunt-all" || !w.Resolved && strings.HasPrefix(w.Prefix, "-") {
				a.Subtree = true
			}
		}
		switch sub {
		case "stack":
			// terragrunt stack run CMD runs CMD in units generated from
			// terragrunt.stack.hcl at run time, which the hook cannot list.
			if len(rest) > 0 && rest[0].Text == "run" {
				a.Subtree, a.UnitsUnknown = true, true
				a.Via = append(a.Via, "terragrunt stack run")
				terraformArgs(a, rest[1:])
				return
			}
			a.Class, a.Sub, a.Why = ReadOnly, "stack "+firstText(rest), "terragrunt stack "+firstText(rest)
			if len(rest) > 0 && rest[0].Text != "generate" && rest[0].Text != "output" && rest[0].Text != "clean" {
				a.Class, a.Why = UnknownWrapper, "unrecognized terragrunt stack subcommand "+firstText(rest)
			}
			return
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
	if a.Engine != "terragrunt" {
		rest = append(cliArgs(a.Env, sub), rest...)
	}
	flags, pos, unresolved := splitTF(rest)
	for _, f := range flags {
		switch {
		case (f.name == "var" || f.name == "var-file") && strings.Contains(f.value, "<?>"):
			a.VarsUnknown = "a -" + f.name + " cannot be resolved statically"
		case f.name == "var":
			if k, v, ok := strings.Cut(f.value, "="); ok {
				if a.Vars == nil {
					a.Vars = map[string]string{}
				}
				a.Vars[k] = v
			}
		case f.name == "var-file" && a.Dir != "":
			a.VarFiles = append(a.VarFiles, absPath(a.Dir, f.value, ""))
		}
		if (f.name == "state" || f.name == "state-out" || f.name == "backup") && f.value != "" && f.value != "-" && a.Dir != "" {
			if strings.Contains(f.value, "<?>") {
				a.StateUnknown = true
			} else {
				a.StateFiles = append(a.StateFiles, absPath(a.Dir, f.value, ""))
			}
		}
	}
	defer func() {
		// destroy, state surgery and the other calls that do not go
		// through set: unresolved arguments may retarget them too.
		if unresolved && a.TargetUnknown == "" && a.Class != ReadOnly && a.Class != Dynamic {
			a.TargetUnknown = a.Engine + " " + sub + " has arguments that cannot be resolved statically, which may name another state, plan or directory"
		}
	}()
	set := func(c Class, why string) {
		a.Class, a.Why = c, why
		if unresolved && c != ReadOnly {
			a.TargetUnknown = a.Engine + " " + sub + " has arguments that cannot be resolved statically, which may name another state, plan or directory"
		}
		if unresolved && severityRank(c) < severityRank(Destroy) {
			a.Class, a.Why = Dynamic, a.Engine+" "+sub+" has arguments that cannot be resolved statically"
		}
	}
	switch sub {
	case "plan":
		a.TouchesState = true
		set(ReadOnly, "plan does not change infrastructure")
	case "stacks":
		// stacks manages HCP Terraform stack operations: approving a
		// deployment's plans applies or destroys infrastructure there.
		class, why := Mutating, "terraform stacks changes HCP Terraform stack objects"
		var words []string
		for _, w := range pos {
			words = append(words, w.Text)
		}
		for _, w := range words {
			switch {
			case strings.Contains(w, "approve") || strings.Contains(w, "apply") || strings.Contains(w, "destroy"):
				class, why = UnreviewedApply, "terraform stacks "+strings.Join(words, " ")+" approves or applies a deployment's plans"
			case strings.Contains(w, "delete") || strings.Contains(w, "cancel") || strings.Contains(w, "discard"):
				if class != UnreviewedApply {
					class, why = Destroy, "terraform stacks "+strings.Join(words, " ")+" deletes or cancels HCP Terraform objects"
				}
			}
		}
		if class == Mutating && len(words) > 0 {
			if last := words[len(words)-1]; last == "list" || last == "read" || last == "show" || last == "fetch" || last == "get" || last == "help" {
				class, why = ReadOnly, "terraform stacks "+strings.Join(words, " ")+" reads"
			}
		}
		a.TouchesState = true
		set(class, why)
	case "show", "output", "validate", "fmt", "graph", "providers", "version", "get", "console", "modules", "metadata", "query", "login", "logout":
		a.TouchesState = sub == "show" || sub == "output" || sub == "console"
		if sub == "providers" && len(pos) > 0 && pos[0].Text == "lock" {
			set(ReadOnly, "providers lock updates the lock file only")
			return
		}
		set(ReadOnly, sub+" is read-only")
	case "init":
		a.TouchesState = true
		var backendCfg []string
		resolved := true
		for _, f := range flags {
			if f.name == "backend-config" {
				backendCfg = append(backendCfg, f.value)
				resolved = resolved && f.value != "" && !strings.Contains(f.value, "<?>")
			}
		}
		if resolved {
			a.BackendConfig = backendCfg
		} else {
			a.BackendConfigUnknown = true
		}
		switch {
		case flagOn(flags, "migrate-state") || flagOn(flags, "force-copy"):
			set(StateSurgery, "init -migrate-state moves state between backends")
		case flagOn(flags, "reconfigure") && len(backendCfg) > 0 && resolved:
			// Switching a working directory between per-environment backends
			// (init -backend-config prod.backend -reconfigure) changes no
			// state. Later commands are judged against the new backend.
			set(ReadOnly, "init -reconfigure -backend-config points the working directory at another backend without changing state")
		case flagOn(flags, "reconfigure"):
			set(StateSurgery, "init -reconfigure discards the configured backend")
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
		if (op == "select" || op == "new") && len(pos) > 1 {
			a.SelectWorkspace = pos[1].Text
			if !pos[1].Resolved {
				a.SelectWorkspace = UnknownWorkspace
			}
		}
		if op == "delete" {
			a.TouchesState = true
			a.Class, a.Why = StateSurgery, "workspace delete removes a workspace's state"
			return
		}
		if op == "new" && len(a.StateFiles) > 0 {
			// The new workspace starts from a copy of that state, so later
			// calls here act on its resources: judged at its tier.
			a.TouchesState = true
			a.Class, a.Why = StateSurgery, "workspace new -state copies another state into this directory"
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

// awsBoolOpts are the aws CLI's global options that take no value.
var awsBoolOpts = map[string]bool{"--debug": true, "--no-verify-ssl": true, "--no-paginate": true, "--no-sign-request": true,
	"--no-cli-pager": true, "--cli-auto-prompt": true, "--no-cli-auto-prompt": true}

// helmBoolOpts are helm's global options that take no value.
var helmBoolOpts = map[string]bool{"--debug": true, "-h": true, "--help": true}

// bothWays classifies a command whose path (service and operation, or
// subcommand) may be shifted by an option applygate does not know: an
// unknown option before the first n positionals may or may not take the
// next word as its value. Both readings are classified, and the stricter
// one is kept.
func bothWays(classify func(Action, []shell.Word) (Action, bool), base Action, args []shell.Word, valued, booleans map[string]bool, n int) (Action, bool) {
	return bothWaysDepth(classify, base, args, valued, booleans, n, 0)
}

func bothWaysDepth(classify func(Action, []shell.Word) (Action, bool), base Action, args []shell.Word, valued, booleans map[string]bool, n, depth int) (Action, bool) {
	pos := 0
	for i := 0; i < len(args) && pos < n; i++ {
		t := args[i].Text
		if !strings.HasPrefix(t, "-") || t == "-" {
			pos++
			continue
		}
		if strings.Contains(t, "=") || booleans[t] {
			continue
		}
		if valued[t] {
			i++
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1].Text, "-") {
			continue
		}
		if depth >= 3 {
			a := base
			a.Class, a.Why = Dynamic, "too many options applygate does not know before the command"
			return a, true
		}
		// i is unknown and followed by a word: boolean, or valued.
		boolA, okA := bothWaysDepth(classify, base, args, valued, mergeSet(booleans, t), n, depth+1)
		rest := append(append([]shell.Word(nil), args[:i+1]...), args[i+2:]...)
		valB, okB := bothWaysDepth(classify, base, rest, valued, booleans, n, depth+1)
		switch {
		case !okB:
			return boolA, okA
		case !okA || severityRank(valB.Class) > severityRank(boolA.Class):
			return valB, true
		}
		return boolA, okA
	}
	return classify(base, args)
}

func mergeSet(m map[string]bool, k string) map[string]bool {
	out := make(map[string]bool, len(m)+1)
	for x, v := range m {
		out[x] = v
	}
	out[k] = true
	return out
}

func awsArgs(base Action, args []shell.Word) (Action, bool) {
	a, ok := bothWays(awsArgsOne, base, args, awsValueOpts, awsBoolOpts, 2)
	if f := flagUnresolved(args, "--profile", "--endpoint-url"); f != "" && ok {
		a.TargetUnknown = "aws " + f + " cannot be resolved statically, so the account it acts on is unknown"
	}
	return a, ok
}

func awsArgsOne(base Action, args []shell.Word) (Action, bool) {
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
		// The destination is the last path, but an option's value may sit
		// among the paths, so any s3:// word after the source counts.
		if slices.ContainsFunc(pos[min(3, len(pos)):], func(p string) bool { return strings.HasPrefix(p, "s3://") }) {
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
	// The cluster: --context, else --cluster, else the API server URL.
	for _, f := range []string{"--context", "--cluster", "--server", "-s"} {
		if a.Target = flagValue(args, f); a.Target != "" {
			break
		}
	}
	kubeconfigFlag(&a, args)
	if f := flagUnresolved(args, "--context", "--cluster", "--server", "--kubeconfig", "--user"); f != "" && a.TargetUnknown == "" {
		a.TargetUnknown = "kubectl " + f + " cannot be resolved statically, so the cluster it acts on is unknown"
	}
	if flagValue(args, "--context") != "" {
		// --cluster, --server and --user replace what the context names,
		// so the cluster and credentials the call uses are not the
		// context's.
		for _, f := range []string{"--cluster", "--server", "-s", "--user", "--token", "--as"} {
			if flagValue(args, f) != "" {
				a.TargetUnknown = "kubectl " + f + " replaces the cluster or credentials the context names, so the cluster it acts on is not the context's"
				break
			}
		}
	}
	var pos []string
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		if strings.HasPrefix(t, "-") {
			// Before the verb, a long flag takes the next word unless it is
			// a known boolean: --cluster prod delete must not read "prod"
			// as the verb.
			valued := t == "-n" || t == "--namespace" || t == "--context" || t == "-l" || t == "--selector" || t == "-f" || t == "-o" ||
				t == "--kubeconfig" || t == "-s" || t == "-v" || t == "-c" || t == "--container"
			if len(pos) == 0 && strings.HasPrefix(t, "--") && !strings.Contains(t, "=") && !kubectlBool[t] {
				valued = true
			}
			if valued && !strings.Contains(t, "=") && i+1 < len(args) {
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
	switch {
	case pos[0] == "auth" && len(pos) > 1 && pos[1] == "reconcile":
		// reconcile writes RBAC objects, and --remove-extra-* deletes
		// subjects and permissions.
		if hasArg(args, "--remove-extra-subjects") || hasArg(args, "--remove-extra-permissions") {
			a.Class, a.Why = CloudDestructive, "kubectl auth reconcile --remove-extra-* removes RBAC subjects or permissions"
		} else {
			a.Class, a.Why = CloudWrite, "kubectl auth reconcile changes RBAC objects"
		}
		return a, true
	}
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

// kubectlBool are kubectl's global flags that take no value.
var kubectlBool = toSet("--insecure-skip-tls-verify", "--all-namespaces", "--warnings-as-errors", "--match-server-version",
	"--disable-compression", "--help", "--version")

// helmArgs classifies a helm command by its subcommand: uninstall deletes a
// release and everything it created, install, upgrade and rollback change the
// cluster, and the rest only read or work locally.
var helmValueOpts = map[string]bool{"-n": true, "--namespace": true, "--kube-context": true, "--kubeconfig": true, "--kube-apiserver": true, "--kube-token": true, "--kube-as-user": true,
	"-f": true, "--values": true, "--set": true, "--set-string": true, "--version": true, "-o": true, "--output": true, "--repo": true,
	"--kube-as-group": true, "--kube-ca-file": true, "--kube-tls-server-name": true, "--burst-limit": true, "--qps": true,
	"--registry-config": true, "--repository-cache": true, "--repository-config": true}

func helmArgs(base Action, args []shell.Word) (Action, bool) {
	return bothWays(helmArgsOne, base, args, helmValueOpts, helmBoolOpts, 1)
}

func helmArgsOne(base Action, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = "helm"
	if a.Target = flagValue(args, "--kube-context"); a.Target == "" {
		a.Target = flagValue(args, "--kube-apiserver")
	}
	kubeconfigFlag(&a, args)
	if f := flagUnresolved(args, "--kube-context", "--kube-apiserver", "--kubeconfig"); f != "" && a.TargetUnknown == "" {
		a.TargetUnknown = "helm " + f + " cannot be resolved statically, so the cluster it acts on is unknown"
	}
	if flagValue(args, "--kube-context") != "" {
		for _, f := range []string{"--kube-apiserver", "--kube-token", "--kube-as-user", "--kube-ca-file"} {
			if flagValue(args, f) != "" {
				a.TargetUnknown = "helm " + f + " replaces the cluster or credentials the context names, so the cluster it acts on is not the context's"
				break
			}
		}
	}
	pos, dynamic := positionals(args, helmValueOpts)
	if dynamic {
		a.Class, a.Why = Dynamic, "helm subcommand cannot be resolved"
		return a, true
	}
	if len(pos) == 0 {
		return a, false
	}
	a.Sub = pos[0]
	switch pos[0] {
	case "uninstall", "delete", "del", "un":
		a.Class, a.Why = CloudDestructive, "helm "+strings.Join(pos, " ")+" deletes a release and its resources"
	case "list", "ls", "status", "get", "history", "hist", "show", "inspect", "template", "search", "repo", "version", "lint",
		"env", "dependency", "dep", "pull", "fetch", "verify", "help", "completion", "create", "package", "plugin", "registry":
		a.Class, a.Why = ReadOnly, "helm "+pos[0]+" does not change the cluster"
	default:
		a.Class, a.Why = CloudWrite, "helm "+pos[0]+" changes the cluster"
	}
	return a, true
}

// cloudCLIArgs classifies az, gcloud and gsutil commands by their verb: the
// first word of the command path that is a known verb decides, except that
// a destructive word anywhere in the path (delete, purge, rm, delete-batch)
// always counts. A read word can never turn a write into a read. Flags take
// the next word as their value unless they are known booleans.
func cloudCLIArgs(base Action, name string, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = name
	switch name {
	case "gcloud":
		a.Target = flagValue(args, "--project")
		if c := flagValue(args, "--configuration"); c != "" {
			a.TargetEnv = map[string]string{"CLOUDSDK_ACTIVE_CONFIG_NAME": c}
		}
	case "gsutil":
		a.Engine, a.Target = "gcloud", flagValue(args, "-p")
	default:
		a.Target = flagValue(args, "--subscription")
	}
	if f := flagUnresolved(args, "--project", "--configuration", "--subscription", "--account"); f != "" {
		a.TargetUnknown = name + " " + f + " cannot be resolved statically, so the project or subscription it acts on is unknown"
	}
	pos, dynamic := cloudPositionals(args)
	if dynamic {
		a.Class, a.Why = Dynamic, name+" command cannot be resolved"
		return a, true
	}
	if len(pos) == 0 {
		return a, false
	}
	a.Sub = strings.Join(pos, " ")
	cmd := name + " " + strings.Join(pos, " ")
	// Access tokens printed are credentials, as aws configure
	// export-credentials is.
	if name == "gcloud" && (slices.Contains(pos, "print-access-token") || slices.Contains(pos, "print-identity-token") || slices.Contains(pos, "print-refresh-token")) ||
		name == "az" && slices.Contains(pos, "get-access-token") {
		a.Class, a.Why = CredentialAccess, cmd+" prints an access token"
		return a, true
	}
	// az rest sends any request: its method decides.
	if name == "az" && pos[0] == "rest" {
		m := strings.ToLower(flagValue(args, "--method"))
		if m == "" {
			m = strings.ToLower(flagValue(args, "-m"))
		}
		switch m {
		case "delete":
			a.Class, a.Why = CloudDestructive, cmd+" --method delete deletes the resource it names"
		case "get", "head", "":
			a.Class, a.Why = ReadOnly, cmd+" reads"
			if m == "" && (flagValue(args, "--body") != "" || flagValue(args, "-b") != "") {
				a.Class, a.Why = CloudWrite, cmd+" with a body posts it"
			}
		default:
			a.Class, a.Why = CloudWrite, cmd+" --method "+m+" changes resources"
		}
		return a, true
	}
	verb := ""
	for _, p := range pos {
		if cloudDestructive(p) {
			a.Class, a.Why = CloudDestructive, cmd+" deletes resources"
			return a, true
		}
		if verb == "" && (cloudRead[p] || cloudWrite[p] || strings.HasPrefix(p, "list-") || strings.HasPrefix(p, "get-") ||
			strings.HasPrefix(p, "describe-") || strings.HasPrefix(p, "show-")) {
			verb = p
		}
	}
	if name == "gsutil" && pos[0] == "rsync" && hasArg(args, "-d") {
		a.Class, a.Why = CloudDestructive, cmd+" -d deletes objects missing from the source"
		return a, true
	}
	if name == "az" && slices.Contains(pos, "deployment") && strings.EqualFold(flagValue(args, "--mode"), "complete") {
		a.Class, a.Why = CloudDestructive, cmd+" --mode Complete deletes the resources the template leaves out"
		return a, true
	}
	read := verb != "" && !cloudWrite[verb]
	if read || verb == "" && (pos[0] == "config" || pos[0] == "account" || pos[0] == "auth" || pos[0] == "version" || pos[0] == "help") {
		a.Class, a.Why = ReadOnly, cmd+" does not change resources"
		return a, true
	}
	a.Class, a.Why = CloudWrite, cmd+" changes resources"
	return a, true
}

var cloudRead = toSet("list", "show", "describe", "get", "version", "help", "login", "info", "ls", "cat", "stat", "du", "hash",
	"logs", "read", "tail", "wait", "check", "validate", "export", "search", "query", "browse", "print-access-token", "print-identity-token")

var cloudWrite = toSet("create", "update", "set", "add", "cp", "mv", "rsync", "copy", "move", "deploy", "apply", "start", "stop",
	"restart", "resize", "import", "attach", "detach", "enable", "disable", "patch", "replace", "upload", "run", "exec", "ssh", "scp",
	"assign", "grant", "revoke", "rotate", "reset", "scale", "upgrade", "install", "push", "tag", "publish", "submit", "invoke",
	"call", "execute", "write", "put", "modify", "register", "unregister", "mb", "acl", "setmeta", "lifecycle", "iam", "compose",
	"rewrite", "retention", "suspend", "resume", "failover", "swap", "restore", "regenerate", "renew", "generate", "lock", "unlock")

// cloudDestructive reports whether a command word removes resources.
func cloudDestructive(p string) bool {
	switch p {
	case "delete", "purge", "rm", "rb", "remove", "destroy", "terminate", "uninstall", "wipe", "abandon":
		return true
	}
	return strings.HasPrefix(p, "delete-") || strings.HasSuffix(p, "-delete") || strings.HasPrefix(p, "remove-") || strings.HasPrefix(p, "purge-")
}

// cloudBool are the flags of az, gcloud and gsutil that take no value.
var cloudBool = toSet("--quiet", "--async", "--recursive", "--all", "--force", "--log-http", "--no-user-output-enabled",
	"--user-output-enabled", "--help", "--dry-run", "--dryrun", "--continue-on-error", "--yes", "--no-wait", "--verbose",
	"--debug", "--only-show-errors", "--no-progress", "--overwrite", "--no-clobber", "--preserve-posix", "--include-managed-folders",
	"--skip-if-missing", "--no-async", "--no-prompt", "--disable-prompts", "--allow-missing", "--keep-deleted", "--uri", "--json")

// cloudPositionals returns the words of a cloud CLI command that are not
// flags or flag values. A long flag takes the next word as its value unless
// it is a known boolean; short flags take none, except the az ones that
// name things (-n, -g, -o, -l, -s, -p).
func cloudPositionals(args []shell.Word) (pos []string, dynamic bool) {
	shortValued := toSet("-n", "-g", "-o", "-l", "-s", "-p", "-h", "-u", "-c", "-z", "-f", "-e")
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := w.Text
		if !w.Resolved {
			t = w.Prefix
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			next := i+1 < len(args) && !strings.HasPrefix(args[i+1].Text, "-")
			switch {
			case strings.Contains(t, "="):
			case strings.HasPrefix(t, "--") && !cloudBool[t] && !strings.HasPrefix(t, "--no-") && next:
				i++
			case !strings.HasPrefix(t, "--") && shortValued[t] && next:
				i++
			}
			continue
		}
		if !w.Resolved && len(pos) == 0 {
			return nil, true
		}
		pos = append(pos, t)
	}
	return pos, false
}

func hasArg(args []shell.Word, name string) bool {
	for _, w := range args {
		if w.Text == name {
			return true
		}
	}
	return false
}

// hasOpt reports whether args carry the option name, bare or with =value,
// with one or two leading dashes (Terraform accepts both).
func hasOpt(args []shell.Word, name string) bool {
	for _, w := range args {
		t := strings.TrimLeft(w.Text, "-")
		if len(w.Text)-len(t) == 0 || len(w.Text)-len(t) > 2 {
			continue
		}
		if t == name || strings.HasPrefix(t, name+"=") {
			return true
		}
	}
	return false
}

func toSet(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// flagValue returns the value of a flag given as "--name value" or
// "--name=value"; the last one wins, as in the CLIs.
// flagUnresolved reports a flag whose value cannot be resolved
// (--context "$(cat f)", --profile=$P): the target it selects is unknown.
func flagUnresolved(args []shell.Word, names ...string) string {
	for i, w := range args {
		for _, n := range names {
			switch {
			case w.Text == n && w.Resolved && i+1 < len(args) && !args[i+1].Resolved:
				return n
			case !w.Resolved && strings.HasPrefix(w.Text, n+"="):
				return n
			}
		}
	}
	return ""
}

func flagValue(args []shell.Word, name string) string {
	v := ""
	for i, w := range args {
		switch {
		case w.Text == name && i+1 < len(args):
			v = args[i+1].Text
		case strings.HasPrefix(w.Text, name+"="):
			v = strings.TrimPrefix(w.Text, name+"=")
		}
	}
	return v
}

// positionals returns the non-flag words; flags in valued take the next word.
// dynamic is true when the first positional cannot be resolved.
func positionals(args []shell.Word, valued map[string]bool) (pos []string, dynamic bool) {
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		if strings.HasPrefix(t, "-") {
			if valued[t] && !strings.Contains(t, "=") && i+1 < len(args) {
				i++
			}
			continue
		}
		if !args[i].Resolved && len(pos) == 0 {
			return nil, true
		}
		pos = append(pos, t)
	}
	return pos, false
}

func agentFlags(base Action, name string, args []shell.Word) (Action, bool) {
	a := base
	a.Engine = "agent"
	// A nested session that skips hooks, or reads its settings from
	// somewhere else, runs without the hook.
	for k := range base.Env {
		switch {
		case k == "CLAUDE_CODE_SIMPLE" && name == "claude", k == "CLAUDE_CONFIG_DIR" && name == "claude",
			k == "CODEX_HOME" && name == "codex", k == "HOME", k == "XDG_CONFIG_HOME", k == "COPILOT_HOME" && name == "copilot",
			k == "GEMINI_CLI_HOME" && name == "gemini",
			// What the hook and the Claude Code plugin's launcher read:
			// where applygate's state and pinned binary live, and which
			// binary runs as the hook.
			k == "XDG_STATE_HOME", k == "XDG_CACHE_HOME", k == "CLAUDE_PLUGIN_DATA", k == "CLAUDE_PLUGIN_ROOT",
			strings.HasPrefix(k, "APPLYGATE_"):
			a.Class, a.Why = Tampering, name+" started with "+k+" set, so it may run without the hook"
			return a, true
		}
	}
	for i, w := range args {
		t := w.Text
		off := name == "claude" && t == "--bare" ||
			name == "codex" && (t == "--disable" && i+1 < len(args) && strings.Contains(args[i+1].Text, "hook") || strings.HasPrefix(t, "--disable=") && strings.Contains(t, "hook")) ||
			name == "gemini" && (t == "-y" || t == "--yolo" || t == "--approval-mode=yolo" || t == "--approval-mode" && i+1 < len(args) && args[i+1].Text == "yolo") ||
			name == "copilot" && (t == "--allow-all-tools" || t == "--allow-all" || t == "--allow-all-paths") ||
			// A Codex profile can set features.hooks = false.
			name == "codex" && (t == "-p" || t == "--profile" || strings.HasPrefix(t, "--profile="))
		if off {
			a.Class, a.Why = Tampering, name+" "+t+" starts a session without the hook or its checks"
			return a, true
		}
	}
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
		// A nested session with other settings, or settings sources that
		// leave out the user's, can run without the hook.
		// An inline MCP server, plugin directory or subagent definition
		// starts programs of its own when the session starts, and no hook
		// judges a server's start-up command.
		if flag, _, _ := strings.Cut(t, "="); (name == "claude" && (flag == "--mcp-config" || flag == "--strict-mcp-config" || flag == "--plugin-dir" || flag == "--agents")) ||
			(name == "copilot" && (flag == "--additional-mcp-config" || flag == "--mcp-config")) ||
			(name == "gemini" && (flag == "--extensions" || flag == "-e")) {
			a.Class, a.Why = Tampering, name+" "+flag+" starts a session with MCP servers, plugins or agents of its own, whose commands no hook judges"
			return a, true
		}
		if t == "--settings" || strings.HasPrefix(t, "--settings=") || t == "--setting-sources" || strings.HasPrefix(t, "--setting-sources=") ||
			(name == "codex" && (t == "-c" || t == "--config" || strings.HasPrefix(t, "--config=")) && i+1 < len(args) && codexHookKey(args[i+1].Text)) ||
			(name == "codex" && strings.HasPrefix(t, "--config=") && codexHookKey(strings.TrimPrefix(t, "--config="))) {
			a.Class, a.Why = Tampering, name+" "+t+" starts a session whose settings may leave out the hook"
			return a, true
		}
	}
	// The agent CLI changing its own plugins or settings: claude plugin
	// disable|uninstall|remove, claude config set (hooks, permissions).
	if pos := positional(args); len(pos) >= 2 {
		switch {
		case pos[0] == "plugin" || pos[0] == "plugins" || pos[0] == "extensions" || pos[0] == "extension":
			// A plugin or extension installed or turned on brings hooks and
			// MCP servers of its own; one turned off may be the hook.
			switch pos[1] {
			case "list", "ls", "help":
			default:
				a.Class, a.Why = Tampering, name+" "+pos[0]+" "+pos[1]+" changes the agent's plugins, which may remove the hook or add one"
				return a, true
			}
		case pos[0] == "mcp" && pos[1] != "list" && pos[1] != "get" && pos[1] != "help":
			a.Class, a.Why = Tampering, name+" mcp "+pos[1]+" changes the agent's MCP servers, whose tools run outside the shell hook"
			return a, true
		case pos[0] == "features" && pos[1] != "list" && pos[1] != "help":
			a.Class, a.Why = Tampering, name+" features "+pos[1]+" changes the agent's features, hooks among them"
			return a, true
		case pos[0] == "config" && (pos[1] == "set" || pos[1] == "add" || pos[1] == "remove" || pos[1] == "unset"):
			a.Class, a.Why = Tampering, name+" config "+pos[1]+" changes the agent's settings, which hold the hook"
			return a, true
		}
	}
	return a, false
}

// codexHookKey reports whether a codex -c override touches hooks, the
// sandbox, approvals or a command Codex starts itself.
func codexHookKey(kv string) bool {
	k, _, _ := strings.Cut(kv, "=")
	k = strings.ToLower(k)
	return strings.Contains(k, "hook") || strings.Contains(k, "sandbox") || strings.Contains(k, "approval") ||
		// MCP servers and the notify program are commands Codex starts
		// itself, outside any hook.
		strings.Contains(k, "mcp_servers") || k == "notify" || strings.HasPrefix(k, "profiles")
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

// terragruntDir applies Terragrunt's working-directory options, which may
// appear anywhere in the arguments (--working-dir, --terragrunt-working-dir)
// or in the environment (TG_WORKING_DIR, TERRAGRUNT_WORKING_DIR), and
// returns the arguments without them.
func terragruntDir(a *Action, args []shell.Word) []shell.Word {
	setDir := func(w shell.Word) {
		if w.Resolved && w.Text != "" {
			a.Dir = absPath(a.Dir, w.Text, "")
		} else {
			a.Dir, a.AnyDir = "", true
		}
	}
	// --config names the terragrunt.hcl to run. Terraform still runs in the
	// working directory, so the call is judged in both: a config in prod is
	// prod's, and a dev config does not make a prod directory dev (4H26).
	var config *shell.Word
	setConfig := func(w shell.Word) { config = &w }
	for _, k := range []string{"TERRAGRUNT_WORKING_DIR", "TG_WORKING_DIR"} {
		if v, ok := a.Env[k]; ok {
			setDir(shell.Word{Text: v, Resolved: v != "", Prefix: v})
		}
	}
	for _, k := range []string{"TERRAGRUNT_CONFIG", "TG_CONFIG"} {
		if v, ok := a.Env[k]; ok {
			setConfig(shell.Word{Text: v, Resolved: v != "", Prefix: v})
		}
	}
	// --source replaces the unit's terraform.source: the configuration
	// that runs, and its backend block, come from there (4H12).
	setSource := func(w shell.Word) {
		if !w.Resolved || w.Text == "" {
			a.SourceUnknown = true
		} else {
			a.Source = w.Text
		}
	}
	for _, k := range []string{"TERRAGRUNT_SOURCE", "TG_SOURCE"} {
		if v, ok := a.Env[k]; ok {
			setSource(shell.Word{Text: v, Resolved: v != "", Prefix: v})
		}
	}
	defer func() {
		if config == nil {
			return
		}
		if !config.Resolved || config.Text == "" {
			a.Dir, a.AnyDir = "", true
			return
		}
		if a.Dir != "" || filepath.IsAbs(config.Text) {
			a.ConfigDir = filepath.Dir(absPath(a.Dir, config.Text, ""))
		}
	}()
	out := make([]shell.Word, 0, len(args))
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := w.Text
		if !w.Resolved {
			t = w.Prefix
		}
		name, val, eq := strings.Cut(t, "=")
		set := setDir
		switch name {
		case "--working-dir", "--terragrunt-working-dir":
		case "--config", "--terragrunt-config":
			set = setConfig
		case "--source", "--terragrunt-source":
			set = setSource
		default:
			out = append(out, w)
			continue
		}
		switch {
		case eq:
			set(shell.Word{Text: val, Resolved: w.Resolved, Prefix: val})
		case i+1 < len(args):
			set(args[i+1])
			i++
		}
	}
	return out
}

// cliArgs returns the arguments Terraform takes from TF_CLI_ARGS and
// TF_CLI_ARGS_<subcommand>, which it inserts after the subcommand. An
// exported value that cannot be resolved (empty in the environment map) is
// one unresolved word.
func cliArgs(env map[string]string, sub string) []shell.Word {
	var out []shell.Word
	for _, k := range []string{"TF_CLI_ARGS", "TF_CLI_ARGS_" + strings.ReplaceAll(sub, "-", "_")} {
		v, ok := env[k]
		if !ok {
			continue
		}
		if v == "" || strings.ContainsAny(v, `"'\$`) {
			out = append(out, shell.Word{Text: v})
			continue
		}
		for _, f := range strings.Fields(v) {
			out = append(out, shell.Word{Text: f, Resolved: true, Prefix: f})
		}
	}
	return out
}

// kubeconfigFlag records kubectl's and helm's --kubeconfig, which selects
// the kubeconfig whose current context is the target.
func kubeconfigFlag(a *Action, args []shell.Word) {
	if v := flagValue(args, "--kubeconfig"); v != "" {
		a.TargetEnv = map[string]string{"KUBECONFIG": absPath(a.Dir, v, "")}
	}
}

// agentPackages are the npm packages of the agent CLIs, run through npx,
// bunx and similar.
var agentPackages = map[string]string{"@anthropic-ai/claude-code": "claude", "@openai/codex": "codex",
	"@google/gemini-cli": "gemini", "@github/copilot": "copilot", "opencode-ai": "opencode",
	// the unscoped names npm also serves
	"claude-code": "claude", "codex": "codex", "gemini-cli": "gemini", "copilot-cli": "copilot", "opencode": "opencode",
	"claude": "claude", "cursor-agent": "cursor-agent"}

// packageAgent returns the agent CLI a package runner starts and its
// arguments: npx @anthropic-ai/claude-code --bare, bunx @openai/codex.
func packageAgent(name string, args []shell.Word) (string, []shell.Word, bool) {
	r := args
	switch name {
	case "npx", "bunx", "pnpx":
	case "pnpm", "yarn", "bun":
		if len(r) == 0 || r[0].Text != "dlx" && r[0].Text != "x" {
			return "", nil, false
		}
		r = r[1:]
	case "npm":
		if len(r) == 0 || r[0].Text != "exec" && r[0].Text != "x" {
			return "", nil, false
		}
		r = r[1:]
	default:
		return "", nil, false
	}
	for i, w := range r {
		if strings.HasPrefix(w.Text, "-") {
			continue
		}
		pkg := w.Text
		if j := strings.LastIndex(pkg, "@"); j > 0 {
			pkg = pkg[:j]
		}
		if agent, ok := agentPackages[pkg]; ok {
			return agent, r[i+1:], true
		}
		return "", nil, false
	}
	return "", nil, false
}

func firstText(ws []shell.Word) string {
	if len(ws) == 0 {
		return ""
	}
	return ws[0].Text
}
