package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/shell"
)

// IsProtectedPath reports whether p is a guard file by pattern alone, with
// symlinks and case resolved as the guard package does.
func IsProtectedPath(p string, patterns []string) bool {
	return guard.New(patterns, nil).Protected(p) || matchAny(filepath.ToSlash(filepath.Clean(p)), patterns)
}

func matchAny(p string, patterns []string) bool {
	for _, pat := range patterns {
		if guard.MatchGlob(pat, p) {
			return true
		}
	}
	return false
}

// selfTamper returns why an applygate command changes applygate itself, or
// "". Only a person approves a call, applies a plan through applygate,
// installs or removes the hook, or turns telemetry on or off. loose is false
// for a program that may not be applygate at all: only argument shapes no
// other tool uses count then.
func selfTamper(args []shell.Word, loose bool) string {
	pos := positional(args)
	if len(pos) == 0 {
		return ""
	}
	has := func(flag string) bool {
		for _, w := range args {
			if w.Text == flag || strings.HasPrefix(w.Text, flag+"=") {
				return true
			}
		}
		return false
	}
	switch pos[0] {
	case "approve":
		if loose || (len(pos) == 2 && hexID.MatchString(pos[1])) {
			return "approves a call applygate stopped, which only a person may do"
		}
	case "apply":
		if loose || has("--plan-json") || has("--engine") {
			return "applies a plan through applygate, whose confirmation only a person may give"
		}
	case "hook":
		if len(pos) >= 2 && (pos[1] == "install" || pos[1] == "remove" || pos[1] == "uninstall") && (loose || has("--agent") || has("--scope")) {
			return "changes applygate's hook installation, which only a person may do"
		}
	case "doctor":
		if has("--creds") {
			return "audits the credentials on this machine, which runs their credential helpers and calls the cloud: only a person may run it"
		}
	case "telemetry":
		if len(pos) >= 2 && (pos[1] == "on" || pos[1] == "off") {
			return "changes applygate's telemetry setting, which only a person may do"
		}
	case "trust":
		if loose || len(pos) == 1 || has("--cwd") {
			return "trusts a repository config, which only a person who reviewed it may do"
		}
	case "install", "uninstall":
		if loose || has("--managed") {
			return "changes applygate's own installation"
		}
	case "init", "disable":
		// --no-hooks and --scope are applygate's own flags.
		if loose || has("--no-hooks") || has("--scope") {
			return "changes applygate's own installation"
		}
	}
	return ""
}

var hexID = regexp.MustCompile(`^[0-9a-f]{8}$`)

// plantsCommand reports a program's own command that writes, into a config
// file outside the repository, a command the program runs later: a global
// git config key that runs a command, a gh or glab shell alias or pager,
// a kubeconfig exec credential plugin, an aws credential_process or pager.
// Plain calls of these programs in a protected tier would then run it.
func plantsCommand(inv shell.Invocation) string {
	if len(inv.Args) < 2 || !inv.Args[0].Resolved {
		return ""
	}
	var ws []string
	for _, w := range inv.Args[1:] {
		ws = append(ws, w.Text)
	}
	has := func(s ...string) bool {
		for _, w := range ws {
			for _, x := range s {
				if w == x || strings.HasPrefix(w, x+"=") {
					return true
				}
			}
		}
		return false
	}
	n := shell.ProgName(inv.Args[0].Text)
	// pos are the positional words, the values of the program's valued
	// options left out (aws --region X, kubectl --context X, gh -R X).
	valued := map[string]bool{}
	switch n {
	case "aws":
		valued = toSet("--profile", "--region", "--output", "--endpoint-url", "--query", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--color")
	case "kubectl":
		valued = toSet("-n", "--namespace", "--context", "--cluster", "--user", "-s", "--server", "--kubeconfig", "--as", "--as-group", "--token", "--request-timeout", "-v")
	case "gh", "glab":
		valued = toSet("-R", "--repo", "--hostname")
	}
	pos := func() []string {
		var out []string
		for i := 0; i < len(ws); i++ {
			w := ws[i]
			if strings.HasPrefix(w, "-") {
				if valued[w] {
					i++
				}
				continue
			}
			out = append(out, w)
		}
		return out
	}()
	switch {
	case n == "git":
		// git [-C dir] [-c k=v] ... config ...: the global options first.
		args := inv.Args[1:]
		for len(args) > 0 && strings.HasPrefix(args[0].Text, "-") {
			if t := args[0].Text; (t == "-C" || t == "-c" || t == "--git-dir" || t == "--work-tree" || t == "--namespace") && len(args) > 1 {
				args = args[1:]
			}
			args = args[1:]
		}
		if len(args) > 0 && args[0].Text == "replace" {
			for _, w := range args[1:] {
				if w.Text == "-l" || w.Text == "--list" || w.Text == "--format" {
					return ""
				}
			}
			// refs/replace makes git read other content for any object, a
			// lock file included, without changing a commit or a branch.
			return "git replace changes what git reads for an object"
		}
		if len(args) == 0 || args[0].Text != "config" {
			return ""
		}
		op, why := shell.GitConfigOp(args[1:])
		if op.Scope == "" {
			// The repository's own config: a key that runs a command, an
			// alias that is a shell command or a value off the safe list
			// makes the next plain git call run it, from wherever the
			// repository is. That is tampering in every tier, not only
			// where strict shapes asks.
			if op.Write && !shell.GitSafeKey(op.Key, op.Value, true) {
				return "git config " + op.Key + " in the repository sets something git runs later"
			}
			// Which branch is upstream is what the provider lock check trusts.
			if op.Write && strings.HasPrefix(op.Key, "branch.") && (strings.HasSuffix(op.Key, ".remote") || strings.HasSuffix(op.Key, ".merge") || strings.HasSuffix(op.Key, ".pushremote")) {
				return "git config " + op.Key + " re-points the upstream branch the provider lock check trusts"
			}
			return ""
		}
		if why != "" && why != "git config --edit runs an editor" {
			return "git config outside the repository: " + why
		}
		if why != "" || op.Write && !shell.GitSafeKey(op.Key, op.Value, true) {
			return "git config " + op.Key + " outside the repository may set a command git runs later"
		}
	case (n == "gh" || n == "glab") && len(pos) >= 2 && pos[0] == "alias" && pos[1] != "list":
		return n + " alias " + pos[1] + " defines a command " + n + " runs later"
	case (n == "gh" || n == "glab") && len(pos) >= 3 && pos[0] == "config" && pos[1] == "set" &&
		(pos[2] == "pager" || pos[2] == "editor" || pos[2] == "browser"):
		return n + " config set " + pos[2] + " names a program " + n + " runs later"
	case n == "kubectl" && len(pos) >= 2 && pos[0] == "config" && pos[1] == "set-credentials" && (has("--exec-command") || has("--auth-provider")):
		return "kubectl config set-credentials writes an exec credential plugin kubectl runs later"
	case n == "kubectl" && len(pos) >= 3 && pos[0] == "config" && pos[1] == "set" && strings.Contains(pos[2], ".exec"):
		return "kubectl config set writes an exec credential plugin kubectl runs later"
	case n == "aws" && len(pos) >= 3 && pos[0] == "configure" && pos[1] == "set" &&
		(strings.Contains(pos[2], "credential_process") || strings.Contains(pos[2], "cli_pager")):
		return "aws configure set " + pos[2] + " names a program aws runs later"
	}
	return ""
}

// isSelf reports whether p is the running applygate binary or one next to
// it, compared as files so a hard link or a copy's original counts.
func isSelf(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	for _, e := range guard.Executable() {
		if est, err := os.Stat(e); err == nil && os.SameFile(st, est) {
			return true
		}
	}
	// A copy under another name: the same size and the same content as the
	// running binary.
	self := selfDigest()
	return self.size > 0 && st.Size() == self.size && fileDigest(p) == self.sum
}

var selfOnce struct {
	once sync.Once
	size int64
	sum  string
}

func selfDigest() *struct {
	once sync.Once
	size int64
	sum  string
} {
	selfOnce.once.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			return
		}
		if fi, err := os.Stat(exe); err == nil {
			selfOnce.size, selfOnce.sum = fi.Size(), fileDigest(exe)
		}
	})
	return &selfOnce
}

func fileDigest(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// knownProgram reports whether name is a common program whose own
// subcommands share names with applygate's (git apply, npm init, terraform
// apply), so its arguments are never read as applygate's.
func knownProgram(name string) bool {
	switch name {
	case "git", "npm", "pnpm", "yarn", "bun", "npx", "go", "cargo", "terraform", "tofu", "terragrunt", "kubectl", "helm", "oc",
		"aws", "az", "gcloud", "gsutil", "pulumi", "cdk", "make", "gh", "glab", "docker", "podman", "brew", "pip", "pip3", "poetry", "uv",
		"claude", "codex", "pre-commit", "husky", "lefthook", "rails", "rake", "mix", "dotnet", "flux", "argocd", "kustomize":
		return true
	}
	return false
}

// positional returns the arguments that are not flags.
func positional(args []shell.Word) []string {
	var out []string
	for _, w := range args {
		if !strings.HasPrefix(w.Text, "-") {
			out = append(out, w.Text)
		}
	}
	return out
}

// readOnlyUse reports whether a program, as called, only reads the files it
// names, so naming a guard file is fine.
func readOnlyUse(name string, args []shell.Word) bool {
	has := func(flags ...string) bool {
		for _, w := range args {
			for _, f := range flags {
				if w.Text == f || strings.HasPrefix(w.Text, f+"=") {
					return true
				}
			}
		}
		return false
	}
	first := ""
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		if name == "git" && t == "-C" {
			i++ // git -C DIR runs in DIR; the subcommand follows
			continue
		}
		if name == "git" && (t == "-c" || strings.HasPrefix(t, "-c") && len(t) > 2 || strings.HasPrefix(t, "--config-env")) {
			return false // a config value such as core.fsmonitor runs a program
		}
		if !strings.HasPrefix(t, "-") {
			first = t
			break
		}
	}
	switch name {
	case "cat", "head", "tail", "less", "more", "ls", "stat", "file", "wc", "diff", "cmp", "test", "[", "sha256sum",
		"shasum", "md5sum", "sha1sum", "readlink", "realpath", "basename", "dirname", "du", "echo", "printf",
		"bat", "strings", "od", "hexdump", "jq", "grep", "egrep", "fgrep", "ack", "ag", "which", "type", "command":
		return true
	case "rg":
		return !has("--pre", "--pre-glob")
	case "yq":
		return !inPlaceEdit(args)
	case "tree":
		return !has("-o", "--output")
	case "find", "fd":
		return !has("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls", "-x", "-X", "--exec", "--exec-batch")
	case "git":
		switch first {
		case "status", "log", "diff", "show", "blame", "ls-files", "add", "commit", "cat-file", "ls-tree", "check-ignore", "check-attr", "rev-parse":
			// --output=FILE writes it, and git takes any unique prefix.
			for _, w := range args {
				if k, _, _ := strings.Cut(w.Text, "="); len(k) >= 5 && strings.HasPrefix("--output", k) || k == "-o" && first != "add" {
					return false
				}
			}
			return true
		}
	case "applygate", "seatbelt":
		switch first {
		case "check", "explain", "doctor", "report", "hosts", "version", "selftest", "plan-check":
			return true
		case "suggest":
			return !has("--out")
		}
	}
	return false
}

// namesGuard returns the guard path a command names, or "". A path counts
// when it is a guard file or lies in a guarded directory; a directory that
// holds a guard file counts only for a program that writes, removes or
// extracts. Words that cannot be resolved count when their literal text
// names a guard file, or when they are a glob that could match one.
func namesGuard(name string, args []shell.Word, dir string, opt Options) string {
	if opt.Guard == nil || readOnlyUse(name, args) {
		return ""
	}
	changes := writers[name] || removers[name] || copiers[name] || (name == "sed" || name == "gsed" || name == "perl" || name == "ruby" || name == "yq") && inPlaceEdit(args) || name == "tar" || name == "bsdtar" || name == "gtar" ||
		name == "unzip" || name == "7z" || name == "cpio" || name == "pax" || name == "find" || name == "fd" || name == "git" ||
		name == "busybox" || name == "toybox"
	var needles []string
	removes := removalOnly(name, args, dir, opt.Home)
	for _, w := range args {
		if name == "git" && strings.HasPrefix(w.Text, ":") && len(w.Text) > 1 && w.Text[1] != ':' {
			// A pathspec with magic: :(top).claude and :/.claude are from the
			// repository root, :(glob)**/settings.json is a pattern.
			rest, top := gitMagic(w.Text)
			if rest != "" || top {
				base := dir
				if top {
					base = repoRoot(dir)
				}
				p := absPath(base, rest, opt.Home)
				if strings.ContainsAny(rest, "*?[") {
					// A pattern may reach any directory of the repository.
					if opt.Guard.GlobTouches(p) || opt.Guard.GlobTouches(absPath(repoRoot(dir), rest, opt.Home)) {
						return w.Text
					}
				} else if opt.gitTouchesHard(removes, p) {
					return p
				}
			}
			continue
		}
		if w.Resolved {
			// The word, and each part of a list (100644,sha,.applygate.yaml)
			// or an option value (--out=~/.claude/settings.json).
			for _, part := range append([]string{w.Text}, strings.FieldsFunc(w.Text, func(r rune) bool { return r == ',' || r == '=' || r == ':' })...) {
				if part == "" || part == "-" || strings.HasPrefix(part, "-") && part == w.Text {
					continue
				}
				p := absPath(dir, part, opt.Home)
				switch {
				case name == "git":
					// A git root or session directory without a config is
					// judged with git's targets (HookRewrite); a guard file
					// git names, or a config root, is tampering here.
					if part != w.Text {
						if opt.Guard.Protected(p) {
							return p
						}
					} else if opt.gitTouchesHard(removes, p) {
						return p
					}
				case part == w.Text && removes[p]:
					if opt.Guard.RemovalTouches(p) {
						return p
					}
				case opt.Guard.Protected(p) || changes && opt.Guard.Touches(p):
					return p
				}
			}
			continue
		}
		t := w.Text
		if strings.ContainsAny(t, "*?[") {
			if opt.Guard.GlobTouches(absPath(dir, t, opt.Home)) {
				return t
			}
		}
		// A word with a part that is not known (${E:-settings.json}, $(…),
		// $X) after a literal prefix may be any name that starts with it.
		if pre := w.Prefix; changes && pre != "" {
			if i := strings.LastIndex(pre, "="); i >= 0 && (strings.HasPrefix(pre, "-") || strings.HasPrefix(pre, "of=")) {
				pre = pre[i+1:] // --output=~/.claude/${X}, of=~/.claude/${X}
			}
			if pre != "" && opt.Guard.GlobTouches(absPath(dir, pre+"*", opt.Home)) {
				return w.Prefix + "<?>"
			}
		}
		if needles == nil {
			needles = opt.Guard.Needles(opt.Home)
		}
		ft := guard.Fold(t)
		for _, n := range needles {
			if strings.Contains(ft, n) {
				return w.Prefix + "<?>" + strings.TrimPrefix(t, w.Prefix)
			}
		}
		// $XDG_CONFIG_HOME/applygate, ${DIR}/seatbelt: applygate's own
		// directories, named by the variable the hook itself reads.
		if changes && (strings.HasSuffix(ft, "/applygate") || strings.HasSuffix(ft, "/seatbelt")) {
			return t
		}
	}
	return ""
}

// packageTamper reports a package manager that removes, replaces or
// downgrades applygate itself: brew uninstall applygate, go install
// …/cmd/applygate@v0.1.0, pip uninstall applygate. A hook whose binary is
// gone fails open on several hosts.
func packageTamper(name string, args []shell.Word) string {
	mutating := map[string]bool{"uninstall": true, "remove": true, "rm": true, "erase": true, "purge": true, "upgrade": true,
		"reinstall": true, "install": true, "unlink": true, "link": true, "switch": true, "pin": true, "clean": true, "cleanup": true,
		"autoremove": true, "update": true, "add": true, "i": true, "un": true, "r": true}
	switch name {
	case "brew", "go", "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "cargo", "gem", "port", "apt", "apt-get", "dnf", "yum",
		"pacman", "apk", "nix-env", "nix", "uv", "mise", "asdf", "scoop", "choco", "winget", "snap", "launchctl":
	default:
		return ""
	}
	if name == "launchctl" {
		for _, w := range args {
			if w.Text == "setenv" || w.Text == "putenv" || w.Text == "unsetenv" {
				return "launchctl " + w.Text + " changes the environment every later session, and its hook, starts with"
			}
		}
		return ""
	}
	sub := ""
	named := false
	for _, w := range args {
		t := strings.ToLower(w.Text)
		if !w.Resolved {
			t = strings.ToLower(w.Prefix)
		}
		if sub == "" && !strings.HasPrefix(t, "-") {
			sub = t
			continue
		}
		if strings.Contains(t, "applygate") || strings.Contains(t, "seatbelt") {
			named = true
		}
	}
	if named && mutating[sub] {
		return name + " " + sub + " changes the applygate binary the hook runs, which only a person may do"
	}
	return ""
}

// configWritten reports whether an earlier write covers Terraform directory
// dir: the directory or one above it (a tree extracted, copied, checked
// out), or a file under it that Terraform reads (configuration, variables,
// .terraform, the lock file, state) or a path with no extension, which may
// be a directory of modules. A plan -out is left to the plan gate.
func configWritten(written []string, origin map[string]string, dir string) bool {
	d := guard.Fold(filepath.Clean(dir))
	for _, w := range written {
		if w == writtenUnknown {
			continue
		}
		w = guard.Fold(filepath.Clean(w))
		if origin[w] != "" {
			continue // a plan -out: the plan gate follows where it came from
		}
		if w == d || strings.HasPrefix(d, w+string(filepath.Separator)) {
			return true
		}
		rel, ok := strings.CutPrefix(w, d+string(filepath.Separator))
		if !ok {
			continue
		}
		b := filepath.Base(rel)
		if strings.HasPrefix(rel, ".terraform"+string(filepath.Separator)) || rel == ".terraform" || !strings.Contains(b, ".") || tfFile(b) {
			return true
		}
	}
	return false
}

// tfFile reports a file name Terraform or OpenTofu reads in a directory.
func tfFile(b string) bool {
	for _, s := range []string{".tf", ".tofu", ".tf.json", ".tofu.json", ".tfvars", ".tfvars.json", ".tfstate", ".tfstate.backup", ".hcl"} {
		if strings.HasSuffix(b, s) {
			return true
		}
	}
	return b == ".terraformrc" || b == "terraform.rc"
}

// hostPackages are the agent CLIs' packages in npm and Homebrew.
var hostPackages = map[string]bool{"@anthropic-ai/claude-code": true, "@openai/codex": true, "@google/gemini-cli": true,
	"@github/copilot": true, "opencode-ai": true, "claude-code": true, "codex": true, "gemini-cli": true, "copilot-cli": true,
	"opencode": true}

// hostInstall reports a command that installs, updates or replaces an
// agent CLI: the program that reads the hook settings, managed ones
// included. A wrapper or an older release in its place can start sessions
// without the hook.
func hostInstall(name string, args []shell.Word) string {
	pos := positional(args)
	switch name {
	case "claude", "codex", "gemini", "copilot", "opencode", "cursor-agent":
		if len(pos) > 0 {
			switch pos[0] {
			case "install", "update", "upgrade", "migrate-installer":
				return name + " " + pos[0] + " replaces the agent CLI, which reads the hook settings"
			}
		}
		return ""
	case "npm", "pnpm", "yarn", "bun", "brew":
	default:
		return ""
	}
	if len(pos) == 0 {
		return ""
	}
	switch pos[0] {
	case "install", "i", "add", "update", "upgrade", "up", "reinstall", "link", "global":
	default:
		return ""
	}
	for _, p := range pos[1:] {
		pkg := p
		if j := strings.LastIndex(pkg, "@"); j > 0 {
			pkg = pkg[:j]
		}
		if hostPackages[strings.TrimPrefix(pkg, "--cask=")] {
			return name + " " + pos[0] + " " + p + " replaces an agent CLI, which reads the hook settings"
		}
	}
	return ""
}

// patchGuard returns a guard file the patch text fed to patch or git apply
// names (the ---, +++, diff --git, rename and copy lines), at any strip
// level: patch -p0 takes the path as written, -p1 drops a component, and
// the default drops none to all depending on the version. "" when none or
// when the patch text is not known.
func patchGuard(inv shell.Invocation, args []shell.Word, opt Options) string {
	if opt.Guard == nil || inv.Stdin == "" {
		return ""
	}
	for _, line := range strings.Split(inv.Stdin, "\n") {
		var p string
		switch {
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "+++ "):
			p = strings.TrimSpace(line[4:])
		case strings.HasPrefix(line, "rename to "), strings.HasPrefix(line, "rename from "), strings.HasPrefix(line, "copy to "):
			p = strings.TrimSpace(line[strings.LastIndex(line, " ")+1:])
		case strings.HasPrefix(line, "diff --git "):
			for _, f := range strings.Fields(line)[2:] {
				if g := patchPathGuard(f, inv.Dir, opt); g != "" {
					return g
				}
			}
			continue
		default:
			continue
		}
		// A timestamp may follow the name, after a tab.
		if i := strings.IndexByte(p, '\t'); i >= 0 {
			p = p[:i]
		}
		if g := patchPathGuard(p, inv.Dir, opt); g != "" {
			return g
		}
	}
	return ""
}

func patchPathGuard(p, dir string, opt Options) string {
	p = strings.Trim(p, "\"")
	if p == "" || p == "/dev/null" {
		return ""
	}
	for strip := 0; strip <= 6; strip++ {
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		if strip >= len(parts) {
			break
		}
		rest := strings.Join(parts[strip:], "/")
		cand := rest
		if strip == 0 && strings.HasPrefix(p, "/") {
			cand = "/" + rest
		}
		abs := absPath(dir, cand, opt.Home)
		if opt.Guard.Protected(abs) {
			return abs
		}
	}
	return ""
}
