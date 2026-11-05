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
	if strings.HasPrefix(in.Tool, "mcp__") || in.Command == "" && len(in.Args) > 0 {
		// A tool of an MCP server, or one no table knows whose arguments the
		// hook passes on (use_mcp_tool, Gemini's mcp_ names).
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

// HiddenByRedaction reports whether redacting a command removed programs it
// starts (API_TOKEN=`{pulumi,destroy,--yes}` true): the judge would not see
// what the call runs. A redaction that breaks the parse hides nothing the
// judge cannot see is broken.
func HiddenByRedaction(raw, redacted, cwd string) bool {
	if raw == redacted {
		return false
	}
	red := shell.Analyze(redacted, shell.Options{Dir: cwd, ReadFile: noFiles})
	if len(red.Problems) > 0 {
		// A redacted copy that does not parse shows the judge less than the
		// command runs, when the command itself parses.
		whole := shell.Analyze(raw, shell.Options{Dir: cwd, ReadFile: noFiles})
		if len(whole.Problems) > 0 {
			return false
		}
		for _, inv := range whole.Invocations {
			if len(inv.Args) > 0 && !strings.Contains(redacted, inv.Args[0].Text) {
				return true
			}
		}
		return false
	}
	have := map[string]int{}
	for _, inv := range red.Invocations {
		if len(inv.Args) > 0 {
			have[inv.Args[0].Text]++
		}
	}
	for _, inv := range shell.Analyze(raw, shell.Options{Dir: cwd, ReadFile: noFiles}).Invocations {
		if len(inv.Args) == 0 {
			continue
		}
		if have[inv.Args[0].Text] == 0 {
			return true
		}
		have[inv.Args[0].Text]--
	}
	return false
}

// Dirs lists the directories a command's programs run in ("" when one is
// unknown).
func Dirs(cmd, cwd string) []string {
	seen := map[string]bool{}
	var out []string
	res := shell.Analyze(cmd, shell.Options{Dir: cwd, ReadFile: noFiles})
	for _, inv := range res.Invocations {
		if !seen[inv.Dir] {
			seen[inv.Dir] = true
			out = append(out, inv.Dir)
		}
	}
	for _, p := range res.Problems {
		if p.AnyDir && !seen[""] {
			seen[""] = true
			out = append(out, "")
		}
	}
	return out
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
var bareEnv = regexp.MustCompile(`(^|[|;&(]\s*)(?:\S*/)?env\s*($|[|;&)>])`)

// pushLongAbbrev reports an abbreviation (three characters or more) of a
// git push long option that rewrites or deletes remote history: git takes
// any unambiguous prefix, so --mirr is --mirror.
func pushLongAbbrev(a string) bool {
	k, _, _ := strings.Cut(a, "=")
	if len(k) < 3 || !strings.HasPrefix(k, "--") {
		return false
	}
	for _, o := range []string{"--mirror", "--prune", "--delete", "--force", "--force-with-lease", "--force-if-includes"} {
		if strings.HasPrefix(o, k) {
			return true
		}
	}
	return false
}

// secretFile matches file names that usually hold credentials, so reading
// one goes to the judge even with a local-only program.
var secretFile = regexp.MustCompile(`(?i)(^|/)(\.env(\.[^/]*)?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|[^/]*credentials[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore)|id_(rsa|dsa|ecdsa|ed25519)|kubeconfig|` +
	// Terraform state and variable files hold secrets in plain text, and
	// these are the dotfiles of Vault, MySQL, s3cmd, boto and Terraform.
	`[^/]*\.tfstate(\.[^/]*)?|[^/]*\.tfvars(\.json)?|\.vault-token|\.my\.cnf|\.s3cfg|\.boto|\.terraformrc|terraform\.rc|` +
	// Maven repository passwords and shell history, which holds typed
	// secrets.
	// Service-account and client keys, kubeconfigs under other names, secret
	// stores, saved plans (they hold values in the clear) and the process
	// environment, which is `env` by another path.
	`[^/]*(service[-_]?account|sa[-_]key|client[-_]secret|apikey|api[-_]key)[^/]*\.(json|ya?ml|txt)|kubeconfig[^/]*|admin\.conf|[^/]*secrets?[^/]*\.(ya?ml|json|txt|env)|secrets?\.txt|[^/]*\.secrets?|[^/]*\.tfplan|plan\.out|` +
	`\.dockercfg|\.mylogin\.cnf|\.htpasswd|\.pip/pip\.conf|\.databrickscfg|\.snowsql/config|\.sentryclirc|\.ngrok2/ngrok\.yml|\.claude\.json|\.codex/auth\.json|` +
	`\.gemini/oauth_creds\.json|\.config/github-copilot/hosts\.json|\.local/share/opencode/auth\.json|\.config/vercel/auth\.json|\.config/netlify/config\.json|\.config/stripe/config\.toml|wp-config\.php|config/database\.yml|proc/[^/]+/environ|` +
	`\.git/config|settings-security\.xml|\.m2/settings\.xml|\.gradle/gradle\.properties|\.(zsh|bash|python|psql|mysql|node_repl|sqlite|rediscli)_history|\.zhistory|\.dbt/profiles\.yml|profiles\.yml)$`)

// credentialDir matches paths inside the directories where CLIs keep
// credentials and session tokens.
var credentialDir = regexp.MustCompile(`(^|/)(\.aws|\.ssh|\.kube|\.docker|\.azure|\.gnupg|\.terraform\.d|\.oci|\.vault|\.fly|\.config/(gcloud|gh|op|doctl|hcloud|rclone|flyctl|fly|linode-cli|scw|exoscale|vultr-cli|helm|kube|sops|age))(/|$)`)

// fileWriters are local-only programs that change files.
var fileWriters = map[string]bool{"rm": true, "cp": true, "mv": true, "ln": true, "tee": true, "chmod": true, "touch": true, "mkdir": true, "tar": true, "unzip": true, "sed": true, "gzip": true, "gunzip": true, "zip": true}

func init() {
	// Every local program that is not a plain reader may write a file through
	// an option or a second operand (uniq IN OUT, sort -o, gofmt -w, go build
	// -o, cargo --target-dir, black, prettier --write): a path outside the
	// working tree makes the call one the judge sees.
	readOnly := set("ls", "cat", "head", "tail", "less", "more", "wc", "grep", "egrep", "fgrep", "rg", "ag", "fd", "tree", "pwd", "echo",
		"printf", "true", "false", "test", "[", "which", "type", "file", "stat", "du", "df", "date", "jq", "cut", "tr", "diff", "cmp",
		"basename", "dirname", "realpath", "readlink", "column", "nl", "comm", "paste", "sleep", "cd", "sha256sum", "shasum", "md5sum")
	for n := range localOnly {
		if !readOnly[n] {
			fileWriters[n] = true
		}
	}
}

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
	if strings.HasPrefix(p, "/") {
		p = path.Clean(p) // /tmp/../Users/x is not in /tmp
	}
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
	"tar":        {"--checkpoint-action", "--to-command", "--use-compress-program", "--rsh-command", "--info-script", "--new-volume-script", "--rmt-command", "-I", "-F"},
	"sort":       {"--compress-program"},
	"zip":        {"-TT", "--unzip-command"},
	"rg":         {"--pre", "--pre-glob", "--hostname-bin"},
	"actionlint": {"-shellcheck", "-pyflakes"},
	"go":         {"-exec", "-toolexec", "--toolexec", "-vettool", "--exec"},
	"git":        {"--upload-pack", "--receive-pack", "--exec", "--ext-diff", "--template", "-c", "--config", "-x", "--extcmd", "--tool", "--open-files-in-pager", "--tree-filter", "--index-filter", "--msg-filter", "--env-filter", "--commit-filter", "--tag-name-filter", "--parent-filter"},
	"yq":         {"--security-enable-system-operator"},
	"docker":     {"--output", "-o", "--push"},
	"ag":         {"--pager"},
	"pylint":     {"--init-hook", "--load-plugins"},
	// cargo --config can set a runner or rustc wrapper; -Z unstable flags
	// and the package managers' script shells run other programs.
	"cargo": {"--config", "-Z"},
	"npm":   {"--script-shell", "--node-options"},
	"pnpm":  {"--script-shell", "--node-options"},
	"yarn":  {"--script-shell"},
}

// execEnv are environment variables that make an otherwise local program
// start another one or load code: compilers, wrappers, preloads and
// interpreter options.
var execEnv = map[string]bool{"CC": true, "CXX": true, "LD": true, "AR": true, "CPP": true, "RUSTC": true, "RUSTC_WRAPPER": true,
	"RUSTC_WORKSPACE_WRAPPER": true, "RUSTDOCFLAGS": true, "RUSTFLAGS": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"PYTHONHOME": true, "NODE_OPTIONS": true, "NODE_PATH": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "BASH_ENV": true, "ENV": true, "PERL5OPT": true,
	"PERL5LIB": true, "RUBYOPT": true, "RUBYLIB": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "CGO_CFLAGS": true,
	"CGO_LDFLAGS": true, "EDITOR": true, "VISUAL": true, "PAGER": true, "SHELL": true, "PATH": true}

// harmlessEnv reports a variable that changes how a program prints or how
// much it logs, and nothing it runs.
func harmlessEnv(k string) bool {
	switch k {
	case "LANG", "LANGUAGE", "TZ", "TERM", "NO_COLOR", "FORCE_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "COLUMNS", "LINES", "CI",
		"DEBUG", "VERBOSE", "NODE_ENV", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "GOOS", "GOARCH", "CGO_ENABLED",
		"GOMAXPROCS", "CARGO_TERM_COLOR", "RUST_BACKTRACE", "RUST_LOG", "LOG_LEVEL", "TF_LOG", "TF_IN_AUTOMATION", "TF_INPUT",
		"PYTHONHASHSEED", "FORCE", "DRY_RUN", "DOCKER_BUILDKIT", "COMPOSE_DOCKER_CLI_BUILD", "PAGER_OFF", "GIT_PAGER_IN_USE":
		return true
	}
	return strings.HasPrefix(k, "LC_") || strings.HasPrefix(k, "PYTEST_") || strings.HasPrefix(k, "TF_VAR_")
}

// sedRuns reports whether a sed script runs a command (GNU sed's e
// command and the s///e flag) or writes a file (w, W, s///w).
func sedRuns(rest []string) bool {
	var scripts []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "-e" || a == "--expression":
			if i+1 < len(rest) {
				scripts = append(scripts, rest[i+1])
				i++
			}
		case strings.HasPrefix(a, "--expression="):
			scripts = append(scripts, strings.TrimPrefix(a, "--expression="))
		case a == "-f" || a == "--file" || strings.HasPrefix(a, "--file="):
			return true // a script file it does not read
		case strings.HasPrefix(a, "-"):
		case len(scripts) == 0:
			scripts = append(scripts, a)
		}
	}
	for _, sc := range scripts {
		if sedExec.MatchString(sc) || sedSubstRuns(sc) {
			return true
		}
	}
	return false
}

var sedExec = regexp.MustCompile(`(^|[;{}\n])\s*(\d+|\$|/[^/]*/)?(,\s*(\d+|\$|/[^/]*/))?\s*!?\s*[ewWrR](\s|$|;)`)

// sedSubstRuns reports whether a substitution in a sed script has the e
// (run) or w (write) flag: s/x/y/e.
func sedSubstRuns(sc string) bool {
	for i := 0; i+1 < len(sc); i++ {
		if sc[i] != 's' || (i > 0 && !strings.ContainsRune(" \t;{}\n0123456789$/!,", rune(sc[i-1]))) {
			continue
		}
		delim := sc[i+1]
		if delim == '\\' || delim == '\n' || delim == ' ' {
			continue
		}
		j, fields := i+2, 0
		for j < len(sc) && fields < 2 {
			switch sc[j] {
			case '\\':
				j++
			case delim:
				fields++
			}
			j++
		}
		if fields < 2 {
			continue
		}
		for j < len(sc) && strings.ContainsRune("gpiImMew0123456789", rune(sc[j])) {
			if sc[j] == 'e' || sc[j] == 'w' {
				return true
			}
			j++
		}
		i = j - 1
	}
	return false
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
			// A single-dash option with several letters takes its value glued
			// (zip -TTprog), and a program that parses options with Go's flag
			// package takes --toolexec as -toolexec.
			if len(f) > 2 && f[0] == '-' && f[1] != '-' && (strings.HasPrefix(a, f) || a == "-"+f || strings.HasPrefix(a, "-"+f+"=")) {
				return true
			}
			// git, GNU tar and the like take any unique prefix of a long
			// option: --recei is --receive-pack.
			if k, _, _ := strings.Cut(a, "="); len(k) >= 4 && strings.HasPrefix(k, "--") && strings.HasPrefix(f, "--") && strings.HasPrefix(f, k) {
				return true
			}
		}
		// tar's short options cluster (-xIf, or the old style xIf first).
		if name == "tar" && (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") || i == 0) && strings.ContainsAny(strings.TrimPrefix(a, "-"), "IF") {
			return true
		}
		if name == "git" && len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], "xO") && i > 0 && (rest[0] == "rebase" || rest[0] == "difftool" || rest[0] == "mergetool" || rest[0] == "grep") {
			return true // -qx <cmd>, -yx <cmd>: the short option inside a cluster
		}
		if name == "git" && strings.HasPrefix(a, "-u") && !strings.HasPrefix(a, "--") && i > 0 && (rest[0] == "clone" || rest[0] == "fetch" || rest[0] == "pull" || rest[0] == "ls-remote" || rest[0] == "archive") {
			return true // -u <upload-pack>
		}
	}
	if name == "go" && len(rest) >= 2 && rest[0] == "env" && (rest[1] == "-w" || rest[1] == "--w" || rest[1] == "-u" || rest[1] == "--u") {
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
		if strings.HasPrefix(t, "/") {
			t = path.Clean(t) // /tmp/../etc/cron.d/y is not in /tmp
		}
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
	for k := range inv.Env {
		// A positive list: a variable not known to be harmless can make the
		// program start another (HOME or XDG_CONFIG_HOME for git, GOCACHEPROG,
		// GOAUTH, LESSOPEN, JAVA_TOOL_OPTIONS), and the list of those is open.
		if execEnv[k] || !harmlessEnv(k) {
			return false
		}
	}
	if (name == "sed" || name == "gsed") && sedRuns(rest) {
		return false
	}
	switch name {
	case "tee":
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") && a != "/dev/null" && !strings.HasPrefix(path.Clean(a), "/tmp/") {
				return false
			}
		}
	case "sed", "gsed", "perl", "ruby", "yq":
		if shell.InPlaceEdit(inv.Args[1:]) {
			return false // edits a file in place (-i, -Ei, -ni, --in-pl…)
		}
	case "cp", "mv", "ln", "install", "rsync", "ditto", "tar", "bsdtar", "gtar", "unzip", "7z", "patch":
		// These write the files they name or carry: a CI workflow, a
		// Makefile or an AGENTS.md copied in from a scratch file acts later,
		// as a Write of it would. Only /tmp is scratch.
		if name != "tar" && name != "bsdtar" && name != "gtar" || shell.TarWrites(inv.Args[1:]) {
			scratch := true
			for _, a := range rest {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if p := path.Clean(a); !strings.HasPrefix(a, "/") || !strings.HasPrefix(p, "/tmp/") {
					if name == "tar" || name == "bsdtar" || name == "gtar" || name == "unzip" || name == "7z" {
						scratch = false
					} else if !strings.HasPrefix(p, "/tmp/") && len(rest) > 0 && a == rest[len(rest)-1] {
						scratch = false // the destination
					}
				}
			}
			if !scratch {
				return false
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
				// A path attached to an option (--output=/etc/x, -o/etc/x)
				// is a path all the same.
				if _, v, ok := strings.Cut(a, "="); ok {
					a = v
				} else if len(a) > 2 && !strings.HasPrefix(a, "--") && strings.ContainsAny(a[2:], "/~") {
					a = a[2:]
				} else {
					continue
				}
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
			if a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" || a == "-fprint" || a == "-fprint0" || a == "-fprintf" || a == "-fls" {
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
		if len(rest) > 0 && rest[0] == "apply" {
			// --directory and --unsafe-paths write the patch's files
			// wherever it says, outside the working tree included.
			for _, a := range rest[1:] {
				if a == "--unsafe-paths" || strings.HasPrefix(a, "--directory") {
					return false
				}
			}
		}
		if len(rest) > 0 && rest[0] == "push" {
			// A push that rewrites or deletes remote history goes to the
			// judge, which looks at the branch.
			for _, arg := range rest[1:] {
				for _, a := range shortFlags(arg) {
					if a == "-f" || a == "-d" || a == "--delete" || a == "--mirror" || a == "--prune" || strings.HasPrefix(a, "--force") || strings.HasPrefix(a, "+") || strings.HasPrefix(a, ":") || pushLongAbbrev(a) {
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
				case a == "--get" || a == "--get-all" || a == "--get-regexp" || a == "--list" || a == "-l" || a == "--get-urlmatch":
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
