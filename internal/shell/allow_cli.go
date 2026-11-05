package shell

import "strings"

// Stage 4 of the allow-list: the command-line tools whose calls have a
// subcommand, by a list of the subcommands and options that are understood.
// Subcommands that change a cluster, an account or a state are not plain here
// whatever their options: the classifier gives them their class, and in a
// protected tier they ask or block on that class as well.

// cmdTree reads the global options, takes the first word that is not an option
// as the subcommand, and checks the rest against that subcommand's table.
func cmdTree(name string, global *prog, subs map[string]*prog) shape {
	return func(args []Word, _ Invocation) string {
		i := 0
		for i < len(args) {
			t := optText(args[i])
			if !strings.HasPrefix(t, "-") || t == "-" {
				break
			}
			if !args[i].Resolved {
				return "a " + name + " option that cannot be resolved"
			}
			if global.vals[t] {
				i++
			}
			i++
		}
		if why := global.check(name, args[:min(i, len(args))]); why != "" {
			return why
		}
		if i >= len(args) {
			return ""
		}
		if !args[i].Resolved {
			return "a " + name + " subcommand that cannot be resolved"
		}
		sub := args[i].Text
		p := subs[sub]
		if p == nil {
			return "the " + name + " subcommand " + sub
		}
		return p.check(name+" "+sub, args[i+1:])
	}
}

// firstOp makes a prog that needs its first operand to be one of ops.
func firstOp(p *prog, name string, ops ...string) *prog {
	okOps := toSet(ops...)
	p.ops = func(o []Word) string {
		if len(o) == 0 {
			if okOps[""] {
				return ""
			}
			return name + " without a subcommand"
		}
		if !o[0].Resolved || !okOps[o[0].Text] {
			return "the " + name + " " + optText(o[0])
		}
		return ""
	}
	return p
}

func init() {
	// terraform and tofu. -state, -state-out, -backup (local state files),
	// -generate-config-out and -plugin-dir are absent; so are import, taint,
	// untaint, force-unlock, refresh, test, console, login, metadata, state
	// edits, `providers lock` and `providers mirror`.
	common := "-no-color -json -compact-warnings -detailed-exitcode -auto-approve -show-sensitive -concise -upgrade -reconfigure -migrate-state " +
		"-get -update -backend -lock -input -refresh -force-copy -check -diff -list -write -recursive -draw-cycles -raw -destroy -refresh-only " +
		"-or-create -readonly -lockfile -ignore-remote-version -no-tests -verbose"
	planVals := "-var -var-file -target -replace -parallelism -lock-timeout -out -backend-config -from-module -test-directory -id -lockfile -chdir -filter"
	tfProg := func() *prog { return newProg(common, planVals) }
	// -state names a local state file: read by plan, show, output and state
	// list/show/pull; apply and destroy write it, which is state surgery in
	// that file's directory and stays absent here.
	tfRead := func() *prog { return newProg(common, planVals+" -state") }
	tfSubs := func() map[string]*prog {
		return map[string]*prog{
			"plan": tfRead(), "apply": tfProg(), "destroy": tfProg(), "init": tfProg(), "validate": tfProg().withLoose(), "fmt": tfProg().withLoose(),
			"show": tfRead(), "output": tfRead(), "import": newProg(common, planVals+" -config -allow-missing-config"), "version": tfProg(), "get": tfProg(),
			"stacks":    firstOp(tfProg(), "stacks", "configuration", "version"),
			"graph":     newProg("-draw-cycles -no-color", "-plan -module-depth").withLoose(),
			"providers": firstOp(newProg(common, planVals+" -platform"), "providers", "", "schema", "lock"),
			"state":     firstOp(tfRead(), "state", "list", "show", "pull"),
			"workspace": firstOp(tfProg(), "workspace", "list", "show", "select"),
		}
	}
	tfGlobal := func() *prog { return newProg("-version -help -h --version --help", "-chdir").withLoose() }
	allow2 := func(name string) { shapes[name] = cmdTree(name, tfGlobal(), tfSubs()) }
	allow2("terraform")
	allow2("tofu")

	// aws: the read verbs of every service, and the services' own help and
	// waiters. A verb that is not a read (start-session and ecs
	// execute-command run a plugin, emr ssh runs ssh, s3 cp writes files) is
	// not plain.
	shapes["aws"] = func(args []Word, _ Invocation) string {
		pos := positional(args, 2, cloudValued)
		if len(pos) == 0 {
			return ""
		}
		for _, p := range pos {
			if p == "" {
				return "an aws word that cannot be resolved"
			}
		}
		if pos[0] == "configure" {
			if len(pos) == 2 && (pos[1] == "get" || pos[1] == "list" || pos[1] == "list-profiles" || pos[1] == "export-credentials") {
				return ""
			}
			return "aws configure " + strings.Join(pos[1:], " ")
		}
		if len(pos) < 2 {
			if pos[0] == "help" || pos[0] == "s3" {
				return ""
			}
			return "aws " + pos[0] + " without an operation"
		}
		// update-kubeconfig writes the kubeconfig's aws eks get-token entry.
		if pos[0] == "eks" && pos[1] == "update-kubeconfig" && !hasOpt(args, "--kubeconfig") {
			return ""
		}
		if pos[0] == "s3" {
			if pos[1] == "ls" {
				return ""
			}
			return "aws s3 " + pos[1]
		}
		if readVerb(pos[1], "describe-", "list-", "get-", "batch-get-", "head-", "lookup-", "search-", "validate-", "filter-", "estimate-", "test-") ||
			pos[1] == "help" || pos[1] == "wait" || pos[1] == "tail" || pos[1] == "query" || pos[1] == "scan" || pos[1] == "ls" {
			return ""
		}
		return "the aws operation " + pos[0] + " " + pos[1]
	}
	// az and gcloud have thousands of commands: read verbs only.
	shapes["az"] = leadingVerbShape("az", []string{"list", "show", "get", "exists", "query", "version"}, []string{"list-", "show-", "get-"})
	shapes["gcloud"] = leadingVerbShape("gcloud", []string{"list", "describe", "get-value", "read", "version", "info", "help", "topic", "print-access-token", "print-identity-token"},
		[]string{"list-", "describe-", "get-"})

	// kubectl: reads, rollout status and history, auth can-i, and the config
	// subcommands that name a context; another kubeconfig, a plugin and the
	// kustomize plugin options are not plain.
	kubectlReads := toSet("get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version", "cluster-info", "events", "wait", "completion", "port-forward")
	shapes["kubectl"] = func(args []Word, inv Invocation) string {
		if hasOpt(args, "--kubeconfig") {
			return "the option --kubeconfig"
		}
		pos := positional(args, 2, kubeValued)
		if len(pos) == 0 {
			return ""
		}
		switch {
		case kubectlReads[pos[0]]:
			return ""
		case pos[0] == "rollout" && len(pos) == 2 && (pos[1] == "status" || pos[1] == "history"):
			return ""
		case pos[0] == "auth" && len(pos) == 2 && (pos[1] == "can-i" || pos[1] == "whoami"):
			return ""
		case pos[0] == "config" && len(pos) == 2 && (pos[1] == "view" || pos[1] == "get-contexts" || pos[1] == "current-context" || pos[1] == "get-clusters" || pos[1] == "use-context"):
			return ""
		}
		return "the kubectl subcommand " + strings.Join(pos, " ")
	}
	helmReads := toSet("list", "ls", "get", "status", "history", "show", "search", "template", "lint", "version", "env", "verify", "completion", "help")
	shapes["helm"] = func(args []Word, _ Invocation) string {
		if hasOpt(args, "--post-renderer") {
			return "the option --post-renderer"
		}
		if hasOpt(args, "--kubeconfig") {
			return "the option --kubeconfig"
		}
		pos := positional(args, 2, kubeValued)
		if len(pos) == 0 {
			return ""
		}
		switch {
		case helmReads[pos[0]]:
			return ""
		case (pos[0] == "repo" || pos[0] == "dependency" || pos[0] == "dep") && len(pos) == 2 && (pos[1] == "list" || pos[1] == "ls"):
			return ""
		}
		return "the helm subcommand " + strings.Join(pos, " ")
	}
	shapes["vault"] = func(args []Word, _ Invocation) string {
		pos := positional(args, 2, toSet("-address", "-namespace", "-format", "-field"))
		if len(pos) == 0 {
			return ""
		}
		switch pos[0] {
		case "status", "version", "read", "list":
			return ""
		case "kv":
			if len(pos) == 2 && (pos[1] == "get" || pos[1] == "list" || pos[1] == "metadata") {
				return ""
			}
		case "token":
			if len(pos) == 2 && pos[1] == "lookup" {
				return ""
			}
		case "secrets", "auth", "policy":
			if len(pos) == 2 && (pos[1] == "list" || pos[1] == "read") {
				return ""
			}
		}
		return "the vault command " + strings.Join(pos, " ")
	}
}

func readVerb(op string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}

// leadingVerbShape: az and gcloud name a group, perhaps a subgroup, a verb and
// then the resource, before their options. The call is plain when the first
// word that is a read verb comes before any word that changes something.
func leadingVerbShape(name string, verbs, prefixes []string) shape {
	vs := toSet(verbs...)
	changes := toSet("create", "delete", "update", "remove", "add", "set", "start", "stop", "restart", "reboot", "reset", "deallocate", "invoke",
		"run", "ssh", "scp", "apply", "deploy", "import", "attach", "detach", "resize", "move", "patch", "replace", "rotate", "revoke", "grant",
		"login", "logout", "upgrade", "install", "uninstall", "purge", "cancel", "execute", "enable", "disable", "unset", "clear", "swap", "restore")
	return func(args []Word, _ Invocation) string {
		var words []string
		for _, w := range args {
			t := optText(w)
			if strings.HasPrefix(t, "-") {
				break
			}
			if !w.Resolved {
				return "a " + name + " word that cannot be resolved"
			}
			words = append(words, t)
		}
		if len(words) == 0 {
			return ""
		}
		for _, v := range words {
			if changes[v] {
				break
			}
			if vs[v] || readVerb(v, prefixes...) {
				return ""
			}
		}
		return "the " + name + " command " + strings.Join(words, " ")
	}
}

// seenPrograms are the programs whose subcommands the classifier gives a class
// (reads, writes, destroys). A call of one that is not plain only because its
// subcommand is not a read is judged on that class; it can run code the analysis
// does not follow only when it names one of the words that run a local program
// (a session plugin, ssh, an editor, an external diff), an option that names a
// program or another config, or a subcommand nobody lists. terraform and tofu
// are not here: an unlisted subcommand (console, test, import, refresh) starts
// providers and reads configuration, which earlier steps may have written.
var seenPrograms = map[string][]string{
	"vault":   nil,
	"aws":     {"start-session", "execute-command", "ssh", "socks", "put", "get", "send-ssh-public-key", "open-tunnel", "ssh-session"},
	"az":      {"ssh", "extension", "run-command", "interactive", "upgrade", "bastion"},
	"gcloud":  {"ssh", "components", "interactive", "start-iap-tunnel", "scp", "terraform"},
	"kubectl": {"exec", "edit", "diff", "debug", "cp", "attach", "proxy", "run", "plugin", "kustomize"},
	"helm":    {"plugin", "install", "upgrade", "template", "lint", "pull", "push", "package", "registry"},
}

// shapeUnseen reports whether a call that is not plain can run code the analysis
// does not follow.
func shapeUnseen(inv Invocation, why string) bool {
	n := ProgName(inv.Args[0].Text)
	words, ok := seenPrograms[n]
	if !ok {
		return true
	}
	if strings.HasPrefix(why, "the option") || strings.Contains(why, "kubeconfig") || strings.Contains(why, "cannot be resolved") {
		return true
	}
	for _, w := range inv.Args[1:] {
		for _, x := range words {
			if optText(w) == x {
				return true
			}
		}
	}
	return false
}
