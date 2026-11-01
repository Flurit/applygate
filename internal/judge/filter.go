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
//   - File writes go only when the path is one that acts later without the
//     agent: CI and scheduled jobs, deployment configuration, and
//     instructions for agents and reviewers.
//   - Shell commands go unless every program the shell would start is known
//     safe and nothing in the command is unresolved.
func Relevant(in Input) bool {
	if strings.HasPrefix(in.Tool, "mcp__") {
		return true
	}
	if in.Command == "" {
		for _, p := range in.Paths {
			if stagedPath.MatchString(path.Clean("/" + p)) {
				return true
			}
		}
		return false
	}
	res := shell.Analyze(in.Command, shell.Options{Dir: in.Cwd, ReadFile: noFiles})
	if len(res.Problems) > 0 || len(res.Invocations) == 0 {
		return true
	}
	for _, inv := range res.Invocations {
		if !safeInvocation(inv) {
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

// stagedPath matches files whose content runs or deploys later: CI
// pipelines, scheduled jobs, deployment manifests and values, and the
// instruction files agents and reviewers read.
var stagedPath = regexp.MustCompile(`(?i)(/\.github/workflows/|/\.gitlab-ci\.ya?ml$|/\.circleci/|/jenkinsfile$|/azure-pipelines\.ya?ml$|/bitbucket-pipelines\.ya?ml$|/\.buildkite/|/\.drone\.ya?ml$|/crontab$|/cron\.d/|` +
	`/(deploy|deployment|deployments|k8s|kube|kubernetes|manifests|charts|helm|argocd|flux|gitops|kustomize|overlays)/|/values[^/]*\.ya?ml$|/kustomization\.ya?ml$|/(fly|app|render|vercel|netlify|railway|heroku|serverless|skaffold|tilt)\.(toml|ya?ml|json)$|/procfile$|` +
	`/agents\.md$|/claude\.md$|/gemini\.md$|/\.cursorrules$|/\.cursor/rules/|/\.windsurfrules$|/copilot-instructions\.md$|/\.clinerules)`)

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
	"shellcheck": true, "shfmt": true, "tflint": true, "golangci-lint": true, "staticcheck": true, "javac": true, "mvn": true,
	"gradle": true, "dotnet": true, "tox": true, "nox": true, "pre-commit": true,
}

// subcommands lists programs that are safe only with these first arguments.
var subcommands = map[string]map[string]bool{
	"npm":    set("install", "i", "ci", "uninstall", "remove", "rm", "add", "test", "t", "ls", "list", "outdated", "audit", "view", "pack", "init"),
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

// outside reports whether a path argument may lie outside the working tree.
// Scratch locations are not counted.
func outside(p, dir string) bool {
	switch {
	case p == "/dev/null" || strings.HasPrefix(p, "/tmp/") || strings.HasPrefix(p, "/dev/std"):
		return false
	case strings.HasPrefix(p, "~") || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../"):
		return true
	case strings.HasPrefix(p, "/"):
		return dir == "" || !strings.HasPrefix(path.Clean(p)+"/", path.Clean(dir)+"/")
	}
	return false
}

func safeInvocation(inv shell.Invocation) bool {
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
		if r.Write && (!r.Target.Resolved || outside(r.Target.Text, inv.Dir)) {
			return false
		}
	}
	name := path.Base(args[0])
	rest := args[1:]
	if len(rest) == 1 && (rest[0] == "--version" || rest[0] == "--help" || rest[0] == "-h" || rest[0] == "version") {
		return true
	}
	switch name {
	case "rm", "cp", "mv", "ln", "tee", "chmod", "touch", "mkdir", "tar", "unzip", "sed":
		// Changing files in the working tree is local; a path outside it is
		// not known to be.
		for _, a := range rest {
			if !strings.HasPrefix(a, "-") && outside(a, inv.Dir) {
				return false
			}
		}
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
			for _, a := range rest[1:] {
				if a == "-f" || a == "-d" || a == "--delete" || a == "--mirror" || a == "--prune" || strings.HasPrefix(a, "--force") || strings.HasPrefix(a, "+") || strings.HasPrefix(a, ":") {
					return false
				}
			}
			return true
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
