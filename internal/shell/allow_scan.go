package shell

import (
	"os"
	"path/filepath"
	"strings"
)

// Stage 6b: the container, forge and policy-scanner CLIs by subcommand and
// option list. Each leaf names the options it understands; what is left out
// either runs a program (docker -H ssh://, gh --web and --editor, an external
// checks directory, a plugin), reads options from a file (trivy --config,
// checkov --config-file, terraform-docs -c), or writes a file the analysis
// does not follow (every output option: they are listed in OutputOpts only).

func pr(flags, vals string) *prog { return newProg(flags, vals) }

func init() {
	// docker. -H/--host ssh://... starts the ssh program; --config names a
	// directory whose config file holds a credential helper.
	dockerHost := func(opt string, v Word) string {
		if opt == "-H" || opt == "--host" {
			if !v.Resolved || !(strings.HasPrefix(v.Text, "unix://") || strings.HasPrefix(v.Text, "tcp://") || strings.HasPrefix(v.Text, "npipe://")) {
				return "a docker host that is not unix://, tcp:// or npipe://"
			}
		}
		return ""
	}
	psProg := func() *prog {
		return pr("-a --all -q --quiet --no-trunc -s --size -l --latest", "-n --last -f --filter --format")
	}
	imagesProg := func() *prog {
		return pr("-a --all -q --quiet --digests --no-trunc --tree", "-f --filter --format")
	}
	readLeaves := func() map[string]node {
		return map[string]node{
			"ps":        leaf(psProg()),
			"images":    leaf(imagesProg()),
			"image":     group(gtree(pr("", ""), map[string]node{"ls": leaf(imagesProg()), "inspect": leaf(pr("", "-f --format"))})),
			"inspect":   leaf(pr("-s --size", "-f --format --type")),
			"logs":      leaf(pr("-f --follow -t --timestamps --details", "--since --until -n --tail")),
			"version":   leaf(pr("", "-f --format")),
			"info":      leaf(pr("", "-f --format")),
			"container": group(gtree(pr("", ""), map[string]node{"ls": leaf(psProg()), "inspect": leaf(pr("-s --size", "-f --format")), "logs": leaf(pr("-f --follow -t --timestamps --details", "--since --until -n --tail"))})),
			"system":    group(gtree(pr("", ""), map[string]node{"info": leaf(pr("", "-f --format"))})),
			"network":   group(gtree(pr("", ""), map[string]node{"ls": leaf(pr("-q --quiet --no-trunc", "-f --filter --format")), "inspect": leaf(pr("-v --verbose", "-f --format"))})),
			"volume":    group(gtree(pr("", ""), map[string]node{"ls": leaf(pr("-q --quiet", "-f --filter --format")), "inspect": leaf(pr("", "-f --format"))})),
		}
	}
	dockerSubs := readLeaves()
	dockerSubs["context"] = group(gtree(pr("", ""), map[string]node{"ls": leaf(pr("-q --quiet", "--format")), "show": leaf(pr("", ""))}))
	composeGlobal := pr("--dry-run --compatibility --all-resources", "-f --file --env-file -p --project-name --profile --project-directory --ansi --progress --parallel")
	dockerSubs["compose"] = group(gtree(composeGlobal, map[string]node{
		"ps":      leaf(pr("-a --all -q --quiet --services --no-trunc", "--format --filter --status")),
		"ls":      leaf(pr("-a --all -q --quiet", "--format --filter")),
		"config":  leaf(pr("-q --quiet --services --volumes --profiles --images --no-interpolate --no-normalize --no-consistency --no-path-resolution --resolve-image-digests --environment --variables --lock-image-digests", "--format --hash")),
		"logs":    leaf(pr("-f --follow -t --timestamps --no-color --no-log-prefix", "--since --until -n --tail --index")),
		"version": leaf(pr("--short", "-f --format")),
	}))
	registerTree("docker", gtree(pr("-D --debug --tls --tlsverify --version -v -h --help", "-H --host --context -l --log-level --tlscacert --tlscert --tlskey").withValOK(dockerHost), dockerSubs))
	// podman runs the OCI runtime and conmon its options name, hook
	// directories, a network helper and the ssh program of a remote
	// connection: only the log level is a global option here.
	registerTree("podman", gtree(pr("-h --help -v --version --syslog", "--log-level"), readLeaves()))

	registerGH()
	registerGlab()
	registerScanners()
}

// jsonOut are the options by which gh and glab format what they print.
const jsonOut = "--json -q --jq -t --template"

// ghl is a gh leaf: -R names the repository.
func ghl(flags, vals string) node {
	return leaf(pr(flags, "-R --repo "+vals))
}

func ghg(subs map[string]node) node { return group(gtree(pr("", ""), subs)) }

func registerGH() {
	prList := "-A --author -a --assignee -B --base -H --head -l --label -L --limit -S --search -s --state --app " + jsonOut
	editVals := "-t --title -b --body -F --body-file --add-label --remove-label --add-assignee --remove-assignee --add-reviewer --remove-reviewer -m --milestone --add-project --remove-project -B --base"
	// search: the qualifier options are words of the query.
	// Their values are given with "=" or are a word of their own that is read
	// as an operand: no qualifier takes the next word here.
	searchOpt := "--match --sort --order --owner --language --state --label --author --assignee --created --updated --visibility " +
		"--topic --size --stars --forks --followers --license --filename --extension --committer --hash --parent --tree --author-date --committer-date " +
		"--merge --merged --merged-at --base --head --draft --mentions --milestone --project --reactions --comments --interactions --involves --team-mentions " +
		"--no-assignee --no-label --no-milestone --no-project --review --reviewed-by --review-requested --checks --closed --commenter --app --archived " +
		"--include-forks --good-first-issues --help-wanted-issues --number-topics"
	sr := func() node { return leaf(pr("", "-L --limit -R --repo "+jsonOut).withOptVal(searchOpt)) }
	ghTree := gtree(pr("--version -h --help", ""), map[string]node{
		"auth":   ghg(map[string]node{"status": leaf(pr("-a --active", "--hostname -h "+jsonOut))}),
		"config": ghg(map[string]node{"get": leaf(pr("", "-h --host")), "list": leaf(pr("", "-h --host"))}),
		"status": ghl("", "-e --exclude -o --org"),
		// api: -F and --input read files into the request; a request with a body
		// to a host other than this machine is a write by the classifier.
		"api": leaf(pr("--paginate --slurp -i --include --silent --verbose",
			"-X --method -f --raw-field -F --field -H --header -q --jq -t --template --hostname --cache --input -p --preview")),
		"pr": ghg(map[string]node{
			"list":     ghl("-d --draft", prList),
			"view":     ghl("-c --comments", jsonOut),
			"status":   ghl("-c --conflict-status", jsonOut),
			"diff":     ghl("--name-only --patch", "--color"),
			"checks":   ghl("--fail-fast --required --watch", "-i --interval "+jsonOut),
			"comment":  ghl("--edit-last --create-if-none --delete-last --yes", "-b --body -F --body-file"),
			"create":   ghl("-d --draft -f --fill --fill-first --fill-verbose --no-maintainer-edit --dry-run", "-a --assignee -B --base -b --body -F --body-file -H --head -l --label -m --milestone -p --project -r --reviewer -T --template -t --title --recover"),
			"merge":    ghl("--admin -d --delete-branch -m --merge -r --rebase -s --squash --auto --disable-auto", "-b --body -F --body-file -t --subject --match-head-commit"),
			"checkout": ghl("--detach -f --force --recurse-submodules", "-b --branch"),
			"close":    ghl("-d --delete-branch", "-c --comment"),
			"reopen":   ghl("", "-c --comment"),
			"ready":    ghl("--undo", ""),
			"edit":     ghl("", editVals),
		}),
		"issue": ghg(map[string]node{
			"list":    ghl("", prList+" --mention"),
			"view":    ghl("-c --comments", jsonOut),
			"status":  ghl("", jsonOut),
			"create":  ghl("", "-a --assignee -b --body -F --body-file -l --label -m --milestone -p --project -T --template -t --title --recover"),
			"comment": ghl("--edit-last --create-if-none", "-b --body -F --body-file"),
			"close":   ghl("", "-c --comment -r --reason"),
			"reopen":  ghl("", "-c --comment"),
			"edit":    ghl("", editVals),
		}),
		"repo": ghg(map[string]node{
			"view":  ghl("", "-b --branch "+jsonOut),
			"list":  ghl("--archived --fork --no-archived --source", "-L --limit -l --language --topic --visibility "+jsonOut),
			"clone": leaf(pr("", "-u --upstream-remote-name")),
			"fork":  leaf(pr("--clone --default-branch-only --remote", "--fork-name --org --remote-name -R --repo")),
			"sync":  ghl("--force", "-b --branch --source"),
		}),
		"release": ghg(map[string]node{"list": ghl("--exclude-drafts --exclude-pre-releases", "-L --limit -O --order "+jsonOut), "view": ghl("", jsonOut)}),
		"run": ghg(map[string]node{
			"list":  ghl("", "-b --branch -c --commit -e --event -L --limit -s --status -u --user -w --workflow --created "+jsonOut),
			"view":  ghl("--exit-status --log --log-failed -v --verbose", "-j --job -a --attempt "+jsonOut),
			"watch": ghl("--exit-status", "-i --interval"),
		}),
		"workflow": ghg(map[string]node{"list": ghl("-a --all", "-L --limit "+jsonOut), "view": ghl("-y --yaml", "-r --ref")}),
		"gist":     ghg(map[string]node{"list": leaf(pr("--public --secret", "-L --limit")), "view": leaf(pr("-r --raw --files", "-f --filename"))}),
		"label":    ghg(map[string]node{"list": ghl("", "-L --limit -S --search --sort -O --order "+jsonOut)}),
		"org":      ghg(map[string]node{"list": leaf(pr("", "-L --limit"))}),
		"project": ghg(map[string]node{
			"list":       leaf(pr("--closed", "--owner -L --limit "+jsonOut)),
			"view":       leaf(pr("", "--owner --format "+jsonOut)),
			"field-list": leaf(pr("", "--owner -L --limit "+jsonOut)),
			"item-list":  leaf(pr("", "--owner -L --limit "+jsonOut)),
		}),
		"ruleset":  ghg(map[string]node{"list": ghl("-p --parents", "-L --limit -o --org"), "view": ghl("-p --parents", "-o --org"), "check": ghl("--default", "")}),
		"secret":   ghg(map[string]node{"list": ghl("-a --app", "-e --env -o --org -u --user "+jsonOut)}),
		"variable": ghg(map[string]node{"list": ghl("", "-e --env -o --org "+jsonOut), "get": ghl("", "-e --env -o --org")}),
		"search":   ghg(map[string]node{"code": sr(), "commits": sr(), "issues": sr(), "prs": sr(), "repos": sr()}),
		"cache":    ghg(map[string]node{"list": ghl("", "-L --limit -k --key -r --ref --sort -O --order "+jsonOut)}),
	})
	registerTree("gh", ghTree)
}

func registerGlab() {
	gl := func(flags, vals string) node { return leaf(pr(flags, "-R --repo "+vals)) }
	registerTree("glab", gtree(pr("--version -h --help", ""), map[string]node{
		"api":  leaf(pr("--paginate -i --include --silent", "-X --method -F --field -f --raw-field -H --header --hostname --input --output")),
		"auth": ghg(map[string]node{"status": leaf(pr("-a --all", "-h --hostname"))}),
		"ci": ghg(map[string]node{
			"list":   gl("", "-s --status -P --per-page -p --page -F --output --ref --order-by --sort --source"),
			"status": gl("--live --compact", "-b --branch"),
			"view":   gl("", "-b --branch"),
		}),
		"issue":    ghg(map[string]node{"list": gl("-a --all --closed --confidential", "-A --author -a --assignee -l --label -m --milestone -P --per-page -p --page -F --output --search"), "view": gl("-c --comments", "-F --output")}),
		"label":    ghg(map[string]node{"list": gl("", "-P --per-page -p --page -F --output")}),
		"mr":       ghg(map[string]node{"list": gl("-a --all --closed --merged --draft", "-A --author -l --label -m --milestone -P --per-page -p --page -F --output --reviewer --source-branch --target-branch --search"), "view": gl("-c --comments", "-F --output")}),
		"release":  ghg(map[string]node{"list": gl("", "-P --per-page -p --page -F --output"), "view": gl("", "-F --output")}),
		"repo":     ghg(map[string]node{"view": gl("", "-b --branch -F --output")}),
		"variable": ghg(map[string]node{"list": gl("", "-P --per-page -p --page -F --output -g --group"), "get": gl("", "-g --group")}),
		"config":   ghg(map[string]node{"get": leaf(pr("-g --global", "-h --host"))}),
	}))
}

// trivyOpts are the options of trivy's scans that read files or the network or
// print; --config (a file of options), --kubeconfig and --output are absent.
const (
	trivyFlags = "-h --help -q --quiet -d --debug --no-progress --skip-db-update --skip-java-db-update --skip-check-update --skip-policy-update " +
		"--download-db-only --download-java-db-only --ignore-unfixed --list-all-pkgs --dependency-tree --include-dev-deps --show-suppressed --offline-scan " +
		"--insecure --include-non-failures --skip-version-check --reset --clear-cache --tf-exclude-downloaded-modules --disable-telemetry " +
		"--no-color --version"
	trivyVals = "-f --format -s --severity --scanners --security-checks --exit-code --skip-dirs --skip-files --ignorefile --ignore-policy --template --config-check " +
		"--check-namespaces --namespaces --config-data --tf-vars --vuln-type --pkg-types --pkg-relationships --input --image-src --platform --timeout --cache-dir " +
		"--cache-backend --db-repository --java-db-repository --server --token --token-header --custom-headers --compliance --report --secret-config --file-patterns " +
		"--detection-priority --sbom-sources --rekor-url --table-mode --vex --distro --max-image-size --image-config-scanners --parallel --k8s-version --context " +
		"--namespace --components --node-collector-namespace --policy --policy-namespaces"
)

func registerScanners() {
	tv := func() node { return leaf(pr(trivyFlags, trivyVals)) }
	registerTree("trivy", gtree(pr("-h --help -v --version -d --debug -q --quiet --insecure", "--cache-dir --timeout"),
		map[string]node{"config": tv(), "fs": tv(), "filesystem": tv(), "repo": tv(), "repository": tv(), "image": tv(), "sbom": tv(), "k8s": tv(), "version": leaf(pr("", "-f --format --cache-dir"))}))
	regOutputs("trivy", "-o --output")

	// kustomize: build and version. --enable-alpha-plugins, --enable-exec,
	// --enable-helm and --helm-command run plugins and helm.
	registerTree("kustomize", gtree(pr("-h --help", ""), map[string]node{
		"build":   leaf(pr("--enable-managedby-label --stack-trace --network -h --help", "--load-restrictor --reorder --mount --network-name")),
		"version": leaf(pr("--short", "-o --output")),
	}))
	regOutputs("kustomize", "-o --output")

	// opa: build writes a bundle file and fmt -w rewrites in place.
	registerTree("opa", gtree(pr("-h --help", ""), map[string]node{
		"eval": leaf(pr("-I --stdin-input -p --partial --strict --fail --fail-defined --profile --metrics --instrument --strict-builtin-errors --show-builtin-errors "+
			"--v0-compatible --v1-compatible --shallow-inlining", "-d --data -i --input -b --bundle -f --format --explain --count --timeout -s --schema -u --unknown "+
			"--capabilities --ignore --profile-sort --profile-limit --pretty-limit --disable-inlining")),
		"test": leaf(pr("--bench --benchmem -c --coverage -v --verbose --exit-zero-on-skipped --show-failure-line --var-values --stop-on-fail --v0-compatible --v1-compatible",
			"-b --bundle -f --format -r --run --threshold --timeout --count --ignore --explain --capabilities -s --schema")),
		"fmt":     leaf(pr("-d --diff -l --list --fail --v1 --v0-v1 --rego-v1 --v0-compatible --v1-compatible", "--capabilities --ignore")),
		"check":   leaf(pr("--strict --v0-compatible --v1-compatible", "-b --bundle -f --format -s --schema --max-errors --capabilities --ignore")),
		"inspect": leaf(pr("-a --annotations --v1-compatible", "-f --format --capabilities --ignore")),
		"parse":   leaf(pr("--v0-compatible --v1-compatible", "-f --format --json-include")),
		"version": leaf(pr("", "")),
	}))
	regOutputs("opa", "-o --output")

	// conftest: --update downloads policies into a directory, and fmt writes.
	registerTree("conftest", gtree(pr("-h --help --no-color", ""), map[string]node{
		"test": leaf(pr("--all-namespaces --combine --fail-on-warn --no-color --no-fail --strict --trace --show-builtin-errors",
			"-p --policy -d --data -n --namespace -o --output --parser --ignore --capabilities --proto-file-dirs --input")),
		"verify":  leaf(pr("--no-color --trace --show-builtin-errors", "-p --policy -d --data --report -o --output --capabilities")),
		"parse":   leaf(pr("--combine --no-color", "--parser -o --output --ignore --input")),
		"version": leaf(pr("", "")),
	}))

	// infracost: its breakdown and diff run terraform init and plan in the
	// directory; only what reads a result file or prints is plain.
	registerTree("infracost", gtree(pr("--version -v -h --help", ""), map[string]node{
		"version":   leaf(pr("", "")),
		"help":      leaf(pr("", "")),
		"configure": ghg(map[string]node{"get": leaf(pr("", ""))}),
		"output":    leaf(pr("--show-skipped --no-color", "--path --format --fields --project-name --compare-to --log-level")),
	}))
	regOutputs("infracost", "--out-file")

	// terragrunt evaluates terragrunt.hcl, whose run_cmd() and hooks run
	// programs: only formatting, help and the version are plain.
	tgFmt := func() node {
		return leaf(pr("--terragrunt-check --check --terragrunt-diff --diff --terragrunt-no-color --no-color --terragrunt-non-interactive --non-interactive --stdin",
			"--terragrunt-hclfmt-file --file --terragrunt-working-dir --working-dir --terragrunt-log-level --log-level --terragrunt-exclude-dir --exclude-dir --terragrunt-include-dir --include-dir"))
	}
	registerTree("terragrunt", gtree(pr("--version -version -h --help", ""), map[string]node{
		"help": leaf(pr("", "")), "hclfmt": tgFmt(), "hcl": ghg(map[string]node{"fmt": tgFmt()}),
	}))
	regOutputs("terragrunt", "-out --out -generate-config-out -state-out -backup")

	// terraform-docs writes the files its output options and .terraform-docs.yml
	// name (output.file), guard files included: no output option, no -c, and no
	// config file in the directories it reads.
	docs := func() node {
		return leaf(pr("--anchor --default --description --escape --hide-all --html --no-header --no-footer --no-providers --no-requirements --read-comments --recursive "+
			"--recursive-include-main --reverse-sort --show-all --sensitive --required --type --sort --sort-by-required --sort-by-type --use-signature --color --lockfile -h --help",
			"--header-from --footer-from --hide --show --sort-by --indent --output-values-from --recursive-path"))
	}
	docsSubs := map[string]node{}
	for _, f := range []string{"asciidoc", "json", "markdown", "pretty", "table", "tfvars", "toml", "xml", "yaml"} {
		docsSubs[f] = docs()
	}
	docsSubs["version"] = leaf(pr("", ""))
	docsTree := gtree(pr("-h --help -v --version", ""), docsSubs)
	registerTree("terraform-docs", docsTree)
	regOutputs("terraform-docs", "--output-file")
	base := shapes["terraform-docs"]
	shapes["terraform-docs"] = func(args []Word, inv Invocation) string {
		if why := base(args, inv); why != "" {
			return why
		}
		dirs := []string{inv.Dir}
		for _, w := range args {
			if t := optText(w); !strings.HasPrefix(t, "-") && t != "" && inv.Dir != "" {
				dirs = append(dirs, PhysicalJoin(inv.Dir, t))
			}
		}
		for _, d := range dirs {
			for _, n := range []string{".terraform-docs.yml", ".terraform-docs.yaml"} {
				if _, err := os.Stat(filepath.Join(d, n)); d == "" || err == nil {
					return "terraform-docs with a " + n + " config in " + d
				}
			}
		}
		return ""
	}

	// checkov loads Python checks from a directory its options or a
	// .checkov.yaml in the directory name: neither --external-checks-dir,
	// --external-checks-git nor --config-file is listed.
	ck := newProg("--compact --quiet --soft-fail --no-guide --output-bc-ids --skip-download --deep-analysis --enable-secret-scan-all-files -l --list --version -h --help "+
		"--skip-resources-without-violations",
		"-d --directory -f --file --framework -c --check --skip-check --evaluate-variables --repo-root-for-plan-enrichment --var-file -o --output --skip-path "+
			"--skip-framework --summary-position --baseline --repo-id --branch --download-external-modules --block-list-secret-scan "+
			"--policy-metadata-filter --severity --min-cve-severity --docker-image --dockerfile-path --image-id --secrets-scan-file-type --mask")
	ck.outputs = []string{"--output-file-path"}
	regOutputs("checkov", "--output-file-path")
	allowProgs["checkov"] = ck
	shapes["checkov"] = func(args []Word, inv Invocation) string {
		if why := ck.check("checkov", args); why != "" {
			return why
		}
		// Its config is read from the working directory, the home
		// directory and each directory it scans (-d).
		dirs := []string{inv.Dir, os.Getenv("HOME")}
		for i, w := range args {
			t := optText(w)
			switch {
			case (t == "-d" || t == "--directory") && i+1 < len(args):
				if !args[i+1].Resolved {
					return "a checkov directory that cannot be resolved"
				}
				dirs = append(dirs, PhysicalJoin(inv.Dir, args[i+1].Text))
			case strings.HasPrefix(t, "--directory="):
				dirs = append(dirs, PhysicalJoin(inv.Dir, strings.TrimPrefix(t, "--directory=")))
			}
		}
		for _, d := range dirs {
			for _, n := range []string{".checkov.yaml", ".checkov.yml"} {
				if _, err := os.Stat(filepath.Join(d, n)); d == "" || err == nil {
					return "checkov with a " + n + " config in " + d
				}
			}
		}
		return ""
	}
}
