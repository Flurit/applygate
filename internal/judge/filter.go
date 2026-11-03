package judge

import (
	"path"
	"regexp"
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

// Relevant reports whether a residual call should go to the judge. It is the
// inverse of a word list: everything goes, except calls made only of
// programs known to act on the working tree alone (reading, building,
// testing, local git), so the judge does not pay for ordinary development
// and does not depend on guessing which words signal danger.
//
//   - MCP calls always go: a tool the table does not know is what the judge
//     is for.
//   - File writes and edits always go: what a write sets up (a hook, a
//     config, a script, instructions for later agents) cannot be told from
//     its path. File reads never go.
//   - Shell commands go unless every program the shell would start is known
//     safe and nothing in the command is unresolved.
func Relevant(in Input) bool {
	if strings.HasPrefix(in.Tool, "mcp__") {
		return true
	}
	if in.Command == "" {
		return in.Write || writeTools[in.Tool]
	}
	if bareEnv.MatchString(in.Command) {
		return true // prints every variable, secrets included
	}
	res := shell.Analyze(in.Command, shell.Options{Dir: in.Cwd, ReadFile: noFiles})
	if len(res.Problems) > 0 || len(res.Invocations) == 0 {
		return true
	}
	for _, inv := range res.Invocations {
		if !safeInvocation(inv, in.Cwd) {
			return true
		}
	}
	return false
}

// noFiles keeps the filter from reading scripts and Makefiles: a program it
// cannot see into is not known safe, so it goes to the judge anyway.
func noFiles(string) ([]byte, error) { return nil, errNoFiles }

type filterErr string

func (e filterErr) Error() string { return string(e) }

const errNoFiles = filterErr("the filter reads no files")

// writeTools are Claude Code's and Codex's file-writing tools, for inputs
// that do not carry the hook's classification.
var writeTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "apply_patch": true}

// bareEnv matches env run without a command, which prints the environment;
// the analyzer drops it as a wrapper with nothing to run.
var bareEnv = regexp.MustCompile(`(^|[|;&(]\s*)env\s*($|[|;&)>])`)

// secretFile matches file names that usually hold credentials, so reading
// one goes to the judge even with a local-only program.
var secretFile = regexp.MustCompile(`(?i)(^|/)(\.env(\.[^/]*)?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|[^/]*credentials[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore)|id_(rsa|dsa|ecdsa|ed25519)|kubeconfig|` +
	// Terraform state and variable files hold secrets in plain text, and
	// these are the dotfiles of Vault, MySQL, s3cmd, boto and Terraform.
	`[^/]*\.tfstate(\.[^/]*)?|[^/]*\.tfvars(\.json)?|\.vault-token|\.my\.cnf|\.s3cfg|\.boto|\.terraformrc|terraform\.rc)$`)

// credentialDir matches paths inside the directories where CLIs keep
// credentials and session tokens.
var credentialDir = regexp.MustCompile(`(^|/)(\.aws|\.ssh|\.kube|\.docker|\.azure|\.gnupg|\.terraform\.d|\.oci|\.vault|\.config/(gcloud|gh|op|doctl|hcloud|rclone|flyctl|linode-cli|scw|exoscale|vultr-cli|helm|kube|sops|age))(/|$)`)

// fileWriters are local-only programs that change files.
var fileWriters = map[string]bool{"rm": true, "cp": true, "mv": true, "ln": true, "tee": true, "chmod": true, "touch": true, "mkdir": true, "tar": true, "unzip": true, "sed": true, "gzip": true, "gunzip": true, "zip": true}

// textArgs are programs whose arguments are text, not paths.
var textArgs = map[string]bool{"echo": true, "printf": true, "test": true, "[": true, "sleep": true, "date": true, "true": true, "false": true, "which": true, "type": true}

// localOnly are programs that read, transform or write files in the working
// tree and start nothing else.
var localOnly = map[string]bool{
	"ls": true, "rm": true, "cat": true, "head": true, "tail": true, "less": true, "more": true, "wc": true, "grep": true, "egrep": true, "fgrep": true,
	"rg": true, "ag": true, "fd": true, "tree": true, "pwd": true, "echo": true, "printf": true, "true": true, "false": true, "test": true,
	"[": true, "which": true, "type": true, "file": true, "stat": true, "du": true, "df": true, "date": true, "jq": true, "yq": true,
	"sort": true, "uniq": true, "cut": true, "tr": true, "diff": true, "cmp": true, "basename": true, "dirname": true, "realpath": true,
	"readlink": true, "mkdir": true, "touch": true, "cp": true, "mv": true, "ln": true, "tee": true, "column": true, "nl": true,
	"sed": true, "comm": true, "paste": true, "sleep": true, "cd": true, "tar": true, "zip": true, "unzip": true, "gzip": true,
	"gunzip": true, "sha256sum": true, "shasum": true, "md5sum": true, "chmod": true, "go": true, "gofmt": true, "cargo": true,
	"rustc": true, "tsc": true, "eslint": true, "prettier": true, "ruff": true, "black": true, "isort": true, "flake8": true,
	"mypy": true, "pylint": true, "pytest": true, "jest": true, "vitest": true, "mocha": true, "rspec": true, "rubocop": true,
	"shellcheck": true, "shfmt": true, "tflint": true, "golangci-lint": true, "staticcheck": true, "javac": true,
	"tox": true, "nox": true, "pre-commit": true,
	// mvn, gradle and dotnet are not here: their plugins and tasks run any
	// program (mvn exec:exec, dotnet run).
}

// subcommands lists programs that are safe only with these first arguments.
var subcommands = map[string]map[string]bool{
	"npm":    set("install", "i", "ci", "uninstall", "remove", "rm", "add", "test", "t", "ls", "list", "outdated", "audit", "view", "pack"),
	"pnpm":   set("install", "i", "add", "remove", "rm", "test", "list", "ls", "outdated", "audit"),
	"yarn":   set("install", "add", "remove", "test", "list", "outdated", "audit"),
	"bun":    set("install", "add", "remove", "test"),
	"pip":    set("install", "uninstall", "list", "show", "freeze", "download"),
	"pip3":   set("install", "uninstall", "list", "show", "freeze", "download"),
	"uv":     set("pip", "sync", "add", "remove", "lock", "venv"),
	"poetry": set("install", "add", "remove", "lock", "show", "check"),
	"bundle": set("install", "add", "list"),
	"docker": set("build", "images", "ps", "logs", "inspect", "pull", "version", "info", "buildx"),
	"git": set("status", "log", "diff", "show", "branch", "add", "commit", "checkout", "switch", "restore", "stash", "fetch", "pull",
		"rev-parse", "ls-files", "blame", "grep", "remote", "tag", "merge", "rebase", "cherry-pick", "reset", "describe", "shortlog",
		"worktree", "mv", "rm", "config", "init", "clone", "submodule", "apply", "am", "format-patch", "reflog", "bisect", "clean", "push"),
}

// runScripts are package-manager scripts that build, test or lint.
var runScripts = regexp.MustCompile(`^(test|tests|build|lint|format|fmt|typecheck|type-check|check|compile)(:|$)`)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// outside reports whether a path argument, resolved against the
// directory its program runs in (after any cd), may lie outside the working
// tree the agent was started in. Scratch locations are not counted.
func outside(p, dir, root string) bool {
	switch {
	case p == "/dev/null" || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/dev/std"):
		return false
	case strings.HasPrefix(p, "~"):
		return true
	case !strings.HasPrefix(p, "/"):
		if dir == "" {
			return true
		}
		p = path.Join(dir, p)
	}
	if strings.HasPrefix(p, "/tmp/") {
		return false
	}
	return root == "" || !strings.HasPrefix(path.Clean(p)+"/", path.Clean(root)+"/")
}

// execFlags are the options of otherwise local programs that run another
// program: a command, a compressor, a preprocessor or a test runner.
var execFlags = map[string][]string{
	"tar":  {"--checkpoint-action", "--to-command", "--use-compress-program", "--rsh-command", "--info-script", "--new-volume-script", "--rmt-command", "-I", "-F"},
	"sort": {"--compress-program"},
	"zip":  {"-TT", "--unzip-command"},
	"rg":   {"--pre"},
	"go":   {"-exec", "-toolexec", "--toolexec", "-vettool", "--exec"},
	"git":  {"--upload-pack", "--receive-pack", "--exec", "--ext-diff", "--template", "-c", "--config", "-x", "--extcmd", "--tool"},
}

// runsProgram reports whether an argument of a local program makes it run
// another program (tar --to-command, rg --pre, go test -exec, a tar
// cluster holding -I or -F).
func runsProgram(name string, rest []string) bool {
	flags := execFlags[name]
	for i, a := range rest {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") || len(f) > 2 && strings.HasPrefix(f, "--") && strings.HasPrefix(a, f) {
				return true
			}
		}
		// tar's short options cluster (-xIf, or the old style xIf first).
		if name == "tar" && (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") || i == 0) && strings.ContainsAny(strings.TrimPrefix(a, "-"), "IF") {
			return true
		}
		if name == "git" && strings.HasPrefix(a, "-u") && !strings.HasPrefix(a, "--") && i > 0 && (rest[0] == "clone" || rest[0] == "fetch" || rest[0] == "pull" || rest[0] == "ls-remote" || rest[0] == "archive") {
			return true // -u <upload-pack>
		}
	}
	if name == "go" && len(rest) >= 2 && rest[0] == "env" && rest[1] == "-w" {
		return true // go env -w GOFLAGS=-toolexec=... changes later builds
	}
	return false
}

// shortFlags expands clustered short options: -uf is -u -f.
func shortFlags(a string) []string {
	if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") || len(a) < 3 {
		return []string{a}
	}
	var out []string
	for _, c := range a[1:] {
		out = append(out, "-"+string(c))
	}
	return out
}

func safeInvocation(inv shell.Invocation, root string) bool {
	var args []string
	for _, w := range inv.Args {
		if !w.Resolved {
			return false
		}
		args = append(args, w.Text)
	}
	if len(args) == 0 {
		return false
	}
	for _, r := range inv.Redirs {
		t := r.Target.Text
		// A file the shell writes goes to the judge, as a Write call does:
		// a test file or a package script written here runs in the next
		// step (printf '…' > zz_test.go && go test).
		if !r.Target.Resolved || secretFile.MatchString(t) || credentialDir.MatchString(t) ||
			r.Write && t != "/dev/null" && !strings.HasPrefix(t, "/dev/std") && !strings.HasPrefix(t, "/tmp/") {
			return false
		}
	}
	name := shell.ProgName(args[0])
	rest := args[1:]
	if runsProgram(name, rest) {
		return false
	}
	if inv.Env["GOFLAGS"] != "" && name == "go" {
		return false
	}
	switch name {
	case "tee":
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") && a != "/dev/null" && !strings.HasPrefix(a, "/tmp/") {
				return false
			}
		}
	case "sed", "gsed", "perl":
		for _, a := range rest {
			if strings.HasPrefix(a, "-i") || a == "--in-place" || strings.HasPrefix(a, "--in-place=") {
				return false // edits a file in place
			}
		}
	}
	if localOnly[name] && !textArgs[name] {
		// A file that usually holds credentials goes to the judge whoever
		// reads it; a program that changes files goes when a path lies
		// outside the working tree. Reading elsewhere (an agent's own skill
		// files, a sibling module) stays local.
		for _, a := range rest {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if secretFile.MatchString(a) || credentialDir.MatchString(a) || (fileWriters[name] && outside(a, inv.Dir, root)) {
				return false
			}
		}
	}
	if len(rest) == 1 && (rest[0] == "--version" || rest[0] == "--help" || rest[0] == "-h" || rest[0] == "version") {
		return true
	}
	switch name {
	case "find":
		for _, a := range rest {
			if a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
				return false
			}
		}
		return true
	case "go":
		return len(rest) > 0 && rest[0] != "run" && rest[0] != "generate"
	case "cargo":
		return len(rest) > 0 && rest[0] != "run"
	case "python", "python3":
		return len(rest) >= 2 && rest[0] == "-m" && (rest[1] == "pytest" || rest[1] == "unittest" || rest[1] == "pip" || rest[1] == "mypy" || rest[1] == "black" || rest[1] == "ruff")
	case "npm", "pnpm", "yarn", "bun":
		if len(rest) >= 2 && rest[0] == "run" {
			return runScripts.MatchString(rest[1])
		}
		if name == "yarn" && len(rest) == 1 && runScripts.MatchString(rest[0]) {
			return true
		}
	case "git":
		if len(rest) > 0 && rest[0] == "push" {
			// A push that rewrites or deletes remote history goes to the
			// judge, which looks at the branch.
			for _, arg := range rest[1:] {
				for _, a := range shortFlags(arg) {
					if a == "-f" || a == "-d" || a == "--delete" || a == "--mirror" || a == "--prune" || strings.HasPrefix(a, "--force") || strings.HasPrefix(a, "+") || strings.HasPrefix(a, ":") {
						return false
					}
				}
			}
			return true
		}
		if len(rest) > 0 && rest[0] == "config" {
			// Reading a value is local; setting one (an alias, a pager,
			// core.fsmonitor, a hook path) makes later git commands run it.
			var pos []string
			read := false
			for _, a := range rest[1:] {
				switch {
				case a == "--get" || a == "--get-all" || a == "--get-regexp" || a == "--list" || a == "-l" || a == "--show-origin" || a == "--show-scope" || a == "--name-only":
					read = true
				case !strings.HasPrefix(a, "-"):
					pos = append(pos, a)
				}
			}
			return read || len(pos) <= 1
		}
	}
	if localOnly[name] {
		return true
	}
	if subs, ok := subcommands[name]; ok {
		return len(rest) > 0 && subs[rest[0]]
	}
	return false
}
