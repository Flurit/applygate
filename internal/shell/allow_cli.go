package shell

import (
	"regexp"
	"strings"
)

// Stage 4 of the allow-list: the command-line tools whose calls have a
// subcommand, by a list of the subcommands and options that are understood.
// Subcommands that change a cluster, an account or a state are not plain here
// whatever their options: the classifier gives them their class, and in a
// protected tier they ask or block on that class as well.

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

// boolProg splits a list of boolean options: the long ones also take
// =true or =false (cobra and Go's flag package read --watch=false), the short
// ones do not.
func boolProg(bools, vals string) *prog {
	var short, long []string
	for _, f := range strings.Fields(bools) {
		if strings.HasPrefix(f, "--") {
			long = append(long, f)
		} else {
			short = append(short, f)
		}
	}
	return newProg(strings.Join(short, " "), vals).withOptVal(strings.Join(long, " "))
}

// goFlags builds a prog for a program that reads Go's flag package: every
// option may be spelled with one dash or two.
func goFlags(flags, vals string) *prog {
	dbl := func(s string) string {
		var out []string
		for _, f := range strings.Fields(s) {
			out = append(out, f, "-"+f)
		}
		return strings.Join(out, " ")
	}
	return newProg(dbl(flags), dbl(vals))
}

func init() {
	// terraform and tofu: each subcommand with its own options, as terraform
	// 1.14 and OpenTofu 1.10 document them. -state-out, -backup (local state
	// files written), -generate-config-out, -plugin-dir, a subcommand-level
	// -chdir and graph -type are absent; so are taint, untaint, force-unlock,
	// refresh, test, console, login, logout, metadata, the state edits,
	// `providers mirror`, `workspace new|delete`, `workspace select -or-create` and
	// `stacks configuration` other than list.
	// apply, destroy and import are listed: their class (they change state)
	// is the classifier's, as for every listed subcommand that changes
	// something.
	tfMode := "-no-color -json -concise -compact-warnings -consolidate-warnings -consolidate-errors -show-sensitive -input -lock -refresh"
	tfVars := "-var -var-file -lock-timeout -parallelism -target -replace -exclude -target-file -exclude-file -deprecation"
	// terraform reads -no-color before any subcommand reads its options, so
	// every subcommand takes it.
	tp := func(flags, vals string) *prog { return newProg(flags+" -no-color", vals) }
	tfTree := func() *tree {
		return gtree(tp("-version -help -h --version --help", "-chdir").withLoose(), map[string]node{
			"plan":     leaf(tp(tfMode+" -destroy -refresh-only -detailed-exitcode", tfVars+" -out -state")),
			"apply":    leaf(tp(tfMode+" -destroy -refresh-only -auto-approve", tfVars)),
			"destroy":  leaf(tp(tfMode+" -auto-approve -refresh-only", tfVars)),
			"import":   leaf(tp(tfMode+" -allow-missing-config -ignore-remote-version", tfVars+" -config")),
			"init":     leaf(tp("-no-color -json -input -lock -backend -get -upgrade -reconfigure -migrate-state -force-copy -ignore-remote-version -verify-plugins", "-backend-config -from-module -lock-timeout -lockfile -test-directory -var -var-file")),
			"validate": leaf(tp("-no-color -json -no-tests -query", "-test-directory -var -var-file").withLoose()),
			"fmt":      leaf(tp("-no-color -list -write -diff -check -recursive", "").withLoose()),
			"show":     leaf(tp("-no-color -json -show-sensitive", "").withMaxOps(1)),
			"output":   leaf(tp("-no-color -json -raw -show-sensitive", "-state").withMaxOps(1)),
			"version":  leaf(tp("-json", "").withMaxOps(0)),
			"get":      leaf(tp("-no-color -update", "-test-directory").withMaxOps(0)),
			"graph":    leaf(tp("-draw-cycles -no-color", "-plan -module-depth").withLoose()),
			"providers": group(gtree(tp("", "-test-directory"), map[string]node{
				"schema": leaf(tp("-json", "").withMaxOps(0)),
				"lock":   leaf(tp("-enable-plugin-cache", "-platform")),
			})),
			// -state names a local state file these read.
			"state": group(gtree(tp("", ""), map[string]node{
				"list": leaf(tp("", "-state -id")),
				"show": leaf(tp("-show-sensitive", "-state").withMaxOps(1)),
				"pull": leaf(tp("", "").withMaxOps(0)),
			})),
			"workspace": group(gtree(tp("", ""), map[string]node{
				"list": leaf(tp("", "").withMaxOps(1)),
				"show": leaf(tp("", "").withMaxOps(0)),
				// -or-create makes a new workspace (and its state).
				"select": leaf(tp("", "").withMaxOps(1)),
			})),
			"stacks": group(gtree(tp("", ""), map[string]node{
				"version":       leaf(tp("", "").withMaxOps(0)),
				"configuration": group(gtree(tp("", ""), map[string]node{"list": leaf(tp("", "").withMaxOps(0))})),
			})),
		})
	}
	registerTree("terraform", tfTree())
	registerTree("tofu", tfTree())
	// The options by which a plan or a state is written to a file.
	regOutputs("terraform", "-out --out -generate-config-out -state-out -backup")
	regOutputs("tofu", "-out --out -generate-config-out -state-out -backup")

	// aws: the read verbs of every service, and the services' own help and
	// waiters. A verb that is not a read (start-session and ecs
	// execute-command run a plugin, emr ssh runs ssh, s3 cp writes files) is
	// not plain. The global options are listed; the operations' own options
	// (some 15,000 operations, from the service models) are read by their
	// form: a lower-case --name, its value in the next word or after =.
	// --cli-auto-prompt (an interactive prompt that builds another command)
	// and --generate-cli-skeleton are absent.
	awsGlobal := newProg("--debug --no-verify-ssl --no-paginate --no-sign-request --no-cli-pager --no-cli-auto-prompt --version --help",
		"--region --profile --output --query --endpoint-url --page-size --max-items --starting-token --color --ca-bundle --cli-read-timeout "+
			"--cli-connect-timeout --cli-binary-format --cli-input-json --cli-input-yaml")
	awsKnownGlobal := toSet("--cli-auto-prompt", "--generate-cli-skeleton")
	shapes["aws"] = func(args []Word, _ Invocation) string {
		if why := cloudOptions("aws", args, awsGlobal, awsKnownGlobal, false); why != "" {
			return why
		}
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
	// az and gcloud have thousands of commands: read verbs only, and options
	// by their form (az also takes -g, -n and the like). gcloud --flags-file
	// reads more options from a file the analysis does not read.
	azGlobal := newProg("--debug --verbose --only-show-errors --help -h", "--output -o --query --subscription")
	azVerbs := leadingVerbShape("az", []string{"list", "show", "get", "exists", "query", "version"}, []string{"list-", "show-", "get-"})
	shapes["az"] = func(args []Word, inv Invocation) string {
		if why := cloudOptions("az", args, azGlobal, nil, true); why != "" {
			return why
		}
		return azVerbs(args, inv)
	}
	gcloudGlobal := newProg("--quiet -q --log-http --user-output-enabled --help -h --no-user-output-enabled",
		"--project --account --billing-project --configuration --format --flatten --verbosity --trace-token --impersonate-service-account "+
			"--filter --limit --page-size --sort-by --uri --region --zone")
	gcloudKnownGlobal := toSet("--flags-file", "--access-token-file")
	gcloudVerbs := leadingVerbShape("gcloud", []string{"list", "describe", "get-value", "read", "version", "info", "help", "topic", "print-access-token", "print-identity-token"},
		[]string{"list-", "describe-", "get-"})
	shapes["gcloud"] = func(args []Word, inv Invocation) string {
		if why := cloudOptions("gcloud", args, gcloudGlobal, gcloudKnownGlobal, false); why != "" {
			return why
		}
		return gcloudVerbs(args, inv)
	}

	// kubectl: reads, rollout status and history, auth can-i and whoami, and
	// the config subcommands that name a context, each with its options. The
	// global options that send the call to another cluster, server or
	// identity than the context names (--kubeconfig, --server, --cluster,
	// --user, --token, --as and the certificate options), and the ones that
	// write files (--profile-output, --cache-dir, --log-file), are absent;
	// so are -k (kustomize) and every subcommand that changes something.
	kubeG := "--warnings-as-errors --match-server-version --disable-compression --help -h"
	kubeGV := "--context -n --namespace --request-timeout -v --v --vmodule"
	kp := func(bools, vals string) *prog { return boolProg(bools+" "+kubeG, vals+" "+kubeGV) }
	top := func(bools, vals string) node { return leaf(kp(bools, vals)) }
	topNode := top("--no-headers --use-protocol-buffers --show-capacity", "-l --selector --sort-by")
	topPod := top("-A --all-namespaces --containers --no-headers --use-protocol-buffers --sum", "-l --selector --sort-by --field-selector")
	registerTree("kubectl", gtree(kp("", ""), map[string]node{
		"get": leaf(kp("-A --all-namespaces -w --watch --watch-only --show-labels --no-headers --ignore-not-found --show-kind --server-print --show-managed-fields --output-watch-events --allow-missing-template-keys -R --recursive",
			"-o --output -l --selector -L --label-columns --field-selector --sort-by --chunk-size --raw --template -f --filename --subresource")),
		"describe": leaf(kp("-A --all-namespaces --show-events -R --recursive", "-l --selector -f --filename --chunk-size")),
		"logs": leaf(kp("-f --follow -p --previous --timestamps --all-containers --prefix --ignore-errors --all-pods",
			"-c --container --tail --since --since-time -l --selector --max-log-requests --limit-bytes --pod-running-timeout")),
		"top":           group(gtree(kp("", ""), map[string]node{"node": topNode, "nodes": topNode, "no": topNode, "pod": topPod, "pods": topPod, "po": topPod})),
		"explain":       leaf(kp("--recursive", "--api-version -o --output")),
		"api-resources": leaf(kp("--namespaced --no-headers --cached", "--verbs --api-group -o --output --sort-by --categories").withMaxOps(0)),
		"api-versions":  leaf(kp("", "").withMaxOps(0)),
		"version":       leaf(kp("--client", "-o --output").withMaxOps(0)),
		"cluster-info":  leaf(kp("", "").withMaxOps(0)),
		"events":        leaf(kp("-A --all-namespaces -w --watch --no-headers", "--for --types -o --output --chunk-size")),
		"wait":          leaf(kp("-A --all-namespaces --all -R --recursive", "--for --timeout -l --selector --field-selector -f --filename -o --output")),
		"completion":    leaf(kp("", "").withMaxOps(1)),
		"port-forward":  leaf(kp("", "--address --pod-running-timeout")),
		"rollout": group(gtree(kp("", ""), map[string]node{
			"status":  leaf(kp("-w --watch -R --recursive", "--revision --timeout -l --selector -f --filename")),
			"history": leaf(kp("-R --recursive", "--revision -o --output -l --selector -f --filename")),
		})),
		"auth": group(gtree(kp("", ""), map[string]node{
			"can-i":  leaf(kp("-A --all-namespaces --list --no-headers -q --quiet", "--subresource")),
			"whoami": leaf(kp("", "-o --output").withMaxOps(0)),
		})),
		"config": group(gtree(kp("", ""), map[string]node{
			"view":            leaf(kp("--minify --raw --flatten --merge", "-o --output").withMaxOps(0)),
			"get-contexts":    leaf(kp("--no-headers", "-o --output")),
			"current-context": leaf(kp("", "").withMaxOps(0)),
			"get-clusters":    leaf(kp("", "").withMaxOps(0)),
			"use-context":     leaf(kp("", "").withMaxOps(1)),
		})),
	}))

	// helm: the reads, template and lint, each with its options. The global
	// options that point at another cluster or identity (--kubeconfig,
	// --kube-apiserver, --kube-token, --kube-as-*, the certificate options)
	// or at other configuration files (--registry-config,
	// --repository-config, --repository-cache), --post-renderer, template
	// --output-dir, --dependency-update, --verify, --keyring (outside
	// verify) and the credential options are absent.
	helmG := "--debug --help -h"
	helmGV := "--kube-context -n --namespace --burst-limit --qps"
	hp := func(bools, vals string) *prog { return boolProg(bools+" "+helmG, vals+" "+helmGV) }
	getLeaf := func() node { return leaf(hp("-a --all", "--revision -o --output --template")) }
	showLeaf := func() node {
		return leaf(hp("--devel --insecure-skip-tls-verify --plain-http --pass-credentials", "--version --repo --jsonpath --ca-file"))
	}
	showTree := func() node {
		return group(gtree(hp("", ""), map[string]node{"all": showLeaf(), "chart": showLeaf(), "readme": showLeaf(), "values": showLeaf(), "crds": showLeaf()}))
	}
	list := leaf(hp("-a --all -A --all-namespaces -d --date -r --reverse -q --short --deployed --failed --pending --superseded --uninstalled --uninstalling --no-headers",
		"-o --output -f --filter -m --max --offset --time-format -l --selector").withMaxOps(0))
	hist := leaf(hp("", "--max -o --output").withMaxOps(1))
	setVals := "-f --values --set --set-string --set-file --set-json --set-literal --kube-version"
	repoList := leaf(hp("", "-o --output").withMaxOps(0))
	depList := leaf(hp("", "--max-col-width"))
	registerTree("helm", gtree(hp("", ""), map[string]node{
		"list": list, "ls": list,
		"get":     group(gtree(hp("", ""), map[string]node{"all": getLeaf(), "values": getLeaf(), "manifest": getLeaf(), "notes": getLeaf(), "hooks": getLeaf(), "metadata": getLeaf()})),
		"status":  leaf(hp("--show-desc --show-resources", "--revision -o --output").withMaxOps(1)),
		"history": hist, "hist": hist,
		"show": showTree(), "inspect": showTree(),
		"search": group(gtree(hp("", ""), map[string]node{
			"hub":  leaf(hp("--list-repo-url --fail-on-no-result", "--endpoint -o --output --max-col-width")),
			"repo": leaf(hp("-r --regexp --devel -l --versions --fail-on-no-result", "--version -o --output --max-col-width")),
		})),
		"template": leaf(hp("--include-crds --skip-crds --skip-tests --is-upgrade -g --generate-name --no-hooks --devel --disable-openapi-validation --skip-schema-validation",
			setVals+" --version --repo -a --api-versions -s --show-only --release-name --name-template --description")),
		"lint":       leaf(hp("--strict --with-subcharts --quiet --skip-schema-validation", setVals)),
		"version":    leaf(hp("--short -c --client", "--template").withMaxOps(0)),
		"env":        leaf(hp("", "").withMaxOps(1)),
		"verify":     leaf(hp("", "--keyring").withMaxOps(1)),
		"completion": leaf(hp("--no-descriptions", "").withMaxOps(1)),
		"help":       leaf(hp("", "")),
		"repo":       group(gtree(hp("", ""), map[string]node{"list": repoList, "ls": repoList})),
		"dependency": group(gtree(hp("", ""), map[string]node{"list": depList, "ls": depList})),
		"dep":        group(gtree(hp("", ""), map[string]node{"list": depList, "ls": depList})),
	}))

	// vault: the reads, with the options Go's flag package takes after the
	// subcommand (-address, -format and the like). -header, -wrap-ttl (a
	// response wrapped in a new token), -output-curl-string, -output-policy,
	// the client certificate options and every write are absent; so is kv
	// metadata other than get (kv metadata delete destroys every version).
	vG, vGV := "-tls-skip-verify -non-interactive", "-address -namespace -format -ca-cert -ca-path -tls-server-name -mfa"
	vp := func(flags, vals string) *prog { return goFlags(flags+" "+vG, vals+" "+vGV) }
	vlist := func() *tree {
		return gtree(vp("", ""), map[string]node{"list": leaf(vp("-detailed", "").withMaxOps(0))})
	}
	registerTree("vault", gtree(goFlags("-v -version -h -help", ""), map[string]node{
		"status":  leaf(vp("", "").withMaxOps(0)),
		"version": leaf(vp("", "").withMaxOps(0)),
		"read":    leaf(vp("", "-field")),
		"list":    leaf(vp("-detailed", "").withMaxOps(1)),
		"kv": group(gtree(vp("", ""), map[string]node{
			"get":      leaf(vp("", "-version -mount -field").withMaxOps(1)),
			"list":     leaf(vp("", "-mount").withMaxOps(1)),
			"metadata": group(gtree(vp("", ""), map[string]node{"get": leaf(vp("", "-mount").withMaxOps(1))})),
		})),
		"token":   group(gtree(vp("", ""), map[string]node{"lookup": leaf(vp("-accessor", "").withMaxOps(1))})),
		"secrets": group(vlist()),
		"auth":    group(vlist()),
		"policy":  group(gtree(vp("", ""), map[string]node{"list": leaf(vp("", "").withMaxOps(0)), "read": leaf(vp("", "").withMaxOps(1))})),
	}))
}

// cloudOptions checks the options of an aws, az or gcloud call: a global
// option must be listed in global, and any other must have the form of an
// operation's option (a lower-case --name, or with shortOK a -x) and not be
// one of the known global options left out. A word that starts with one dash
// is a value when it follows an option without =; a word that cannot be
// resolved may be an option unless it does.
func cloudOptions(name string, args []Word, global *prog, known map[string]bool, shortOK bool) string {
	afterOpt := false
	for _, w := range args {
		t := optText(w)
		if t == "--" && w.Resolved {
			return ""
		}
		isOpt := strings.HasPrefix(t, "-") && t != "-" && !(afterOpt && !strings.HasPrefix(t, "--"))
		if !w.Resolved && !afterOpt && (t == "" || strings.HasPrefix(t, "-") && !strings.Contains(t, "=")) {
			return "a " + name + " word that cannot be resolved may be an option"
		}
		if !isOpt {
			afterOpt = false
			continue
		}
		k, _, eq := strings.Cut(t, "=")
		switch {
		case global.flags[k] || global.optVal[k]:
			afterOpt = false
			continue
		case global.vals[k]:
			afterOpt = !eq
			continue
		case known[k]:
			return "the " + name + " option " + k
		case cloudOptRE.MatchString(k), shortOK && shortOptRE.MatchString(k):
			// An operation's option: its value, if it has one, is the next
			// word unless = gave it.
			afterOpt = !eq
		default:
			return "the " + name + " option " + k
		}
	}
	return ""
}

var cloudOptRE = regexp.MustCompile(`^--[a-z0-9]+(-[a-z0-9]+)*$`)
var shortOptRE = regexp.MustCompile(`^-[a-zA-Z]$`)

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
