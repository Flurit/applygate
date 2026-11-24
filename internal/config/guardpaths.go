package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/shell"
)

// DefaultProtectedPaths are guard files the agent may never modify.
var DefaultProtectedPaths = []string{
	"**/.claude/settings.json", "**/.claude/settings.local.json", "**/managed-settings.json",
	"**/managed-settings.d/**", "**/.codex/hooks.json", "**/.codex/config.toml",
	"**/.applygate.yaml", "**/.applygate.yml", "**/.config/applygate/**", "**/.local/state/applygate/**",
	// Names from before the rename stay guarded so an agent cannot edit a legacy file.
	"**/.seatbelt.yaml", "**/.seatbelt.yml", "**/.config/seatbelt/**", "**/.local/state/seatbelt/**",
	"**/.cursor/hooks.json",
	// The Claude Code plugin: its installed copy (hooks.json and the launcher
	// script), the marketplace clone it is copied from, its data directory
	// and the fallback cache where the launcher keeps the downloaded binary.
	"**/.claude/plugins/cache/applygate/**", "**/.claude/plugins/marketplaces/applygate/**",
	"**/.claude/plugins/data/applygate-*/**", "**/.cache/applygate/**",
	// The plugin registry, which can turn the plugin off, and the MCP
	// server lists, which can add a server whose tools the hook cannot read.
	"**/.claude/plugins/installed_plugins.json", "**/.claude/plugins/known_marketplaces.json",
	"**/.mcp.json", "**/.claude.json",
	// Hook files of the hosts whose adapters were written from their
	// documentation (docs/hosts.md).
	"**/.gemini/settings.json", "**/.gemini/trustedFolders.json", "**/.github/hooks/**", "**/.github/copilot/settings*.json",
	"**/.copilot/hooks/**", "**/.copilot/settings.json", "**/.windsurf/hooks.json", "**/.codeium/windsurf/hooks.json",
	"**/.codeium/hooks.json", "**/.devin/config.json", "**/.devin/hooks.v1.json", "**/.config/devin/config.json",
	"**/.opencode/plugins/**", "**/.config/opencode/plugins/**", "**/.clinerules/hooks/**", "**/.cline/hooks/**",
	"**/Documents/Cline/Hooks/**",
	// Claude Code's skills, subagents and commands, whose frontmatter can
	// declare hooks Claude Code runs itself, and every plugin's files.
	"**/.claude/skills/**", "**/.claude/agents/**", "**/.claude/commands/**", "**/.claude/plugins/**",
	// The MCP server lists of the other hosts.
	"**/.cursor/mcp.json", "**/.vscode/mcp.json", "**/.copilot/mcp-config.json", "**/.codeium/windsurf/mcp_config.json",
	"**/.gemini/extensions/**", "**/opencode.json", "**/.config/opencode/opencode.json",
	// Config files in which a program the hook trusts names a command to
	// run: a plain git, aws, kubectl, gh, docker or terraform call would run
	// what an earlier call planted there (strict shapes, docs/policy.md).
	"**/.gitconfig", "**/.config/git/**", "**/.aws/config", "**/.aws/cli/**", "**/.kube/config", "**/.config/gh/**",
	"**/.config/glab-cli/**", "**/.docker/config.json", "**/.terraformrc", "**/.terraform.d/**", "**/.tofurc",
	"**/.vault", "**/.wgetrc", "**/.tflint.hcl", "**/.tflint.d/**", "**/.config/helm/**",
	"**/Library/Preferences/helm/**", "**/Library/helm/plugins/**", "**/.local/share/helm/plugins/**",
	// ssh's config names a ProxyCommand or Match exec that a plain git
	// fetch or push runs; Docker runs its CLI plugins for docker compose
	// and the like; curl, the Azure CLI and Claude Code's own shell state
	// likewise run or load what is written there. The ssh entries are a
	// glob so that "config.d" does not become a needle in code.
	"**/.ssh/config", "**/.ssh/config*/**", "**/.docker/cli-plugins/**", "**/.curlrc", "**/.azure/cliextensions/**",
	// Claude Code sources a snapshot of the user's shell, and the session's
	// CLAUDE_ENV_FILE scripts, before every Bash call: a function there
	// replaces any program the hook allows.
	"**/.claude/shell-snapshots/**", "**/.claude/session-env/**",
	// Start-up and login files outside the shell rc files.
	"**/Library/LaunchAgents/**", "**/.config/fish/**", "**/.config/environment.d/*", "**/.config/systemd/user/**",
	"**/.oh-my-zsh/custom/**",
	// A repository's own git config and hooks: a hook, an alias that is a
	// shell command or core.fsmonitor in them runs the next time anything
	// runs git there, from whichever directory that is.
	// Provider binaries and modules init installed are code a later plan
	// runs; an agent must not place its own there.
	"**/.terraform/providers/**", "**/.terraform/modules/**", "**/.terraform.d/plugins/**",
	"**/.git/config", "**/.git/config.worktree", "**/.git/hooks/**", "**/.git/modules/**/config", "**/.git/modules/**/hooks/**",
	// The go environment file sets GOFLAGS (-toolexec) for every later go
	// command.
	"**/Library/Application Support/go/env", "**/.config/go/env",
	// The agent CLIs themselves, which read the hook settings (managed
	// ones included): a wrapper or an older release put in their place
	// starts sessions without the hook. The names on PATH are guarded with
	// the trusted programs below.
	"**/.local/share/claude/**", "**/.claude/local/**", "**/lib/node_modules/@anthropic-ai/claude-code/**",
	"**/lib/node_modules/@openai/codex/**", "**/lib/node_modules/@google/gemini-cli/**", "**/lib/node_modules/@github/copilot/**",
	"**/lib/node_modules/opencode-ai/**", "**/.codex/bin/**",
	// What the programs strict shapes trusts load and run from their own
	// install: Homebrew's Cellar (a symlinked program on PATH ends there,
	// and its libexec holds the interpreter and packages of aws, gcloud
	// and the like), and the files Python runs at start-up, whichever
	// interpreter a trusted program uses.
	"**/Cellar/**", "**/site-packages/*.pth", "**/dist-packages/*.pth", "**/site-packages/sitecustomize.py",
	"**/site-packages/usercustomize.py", "**/site-packages/sitecustomize/**", "**/site-packages/usercustomize/**",
}

// plantOnlyPaths are the default guard patterns whose files matter only for
// what is placed in them: code or settings a later program runs (a provider
// binary, a git hook, an ssh ProxyCommand, an MCP server list, a skill's
// hooks). Placing one is tampering; removing one cannot weaken the guard, so
// removing a directory that holds one is not (guard.Set.RemovalTouches).
// Hook settings, applygate's own files, the agent CLIs and the files that
// pick a cloud account or cluster are not here: removing those can turn the
// hook off or retarget a call.
var plantOnlyPaths = []string{
	"**/.mcp.json", "**/.claude/skills/**", "**/.claude/agents/**", "**/.claude/commands/**",
	"**/.cursor/mcp.json", "**/.vscode/mcp.json", "**/.copilot/mcp-config.json", "**/.codeium/windsurf/mcp_config.json",
	"**/.gemini/extensions/**",
	"**/.gitconfig", "**/.config/git/**", "**/.wgetrc", "**/.tflint.hcl", "**/.tflint.d/**",
	"**/Library/helm/plugins/**", "**/.local/share/helm/plugins/**",
	"**/.ssh/config", "**/.ssh/config*/**", "**/.docker/cli-plugins/**", "**/.curlrc", "**/.azure/cliextensions/**",
	"**/.claude/shell-snapshots/**", "**/.claude/session-env/**",
	"**/Library/LaunchAgents/**", "**/.config/fish/**", "**/.config/environment.d/*", "**/.config/systemd/user/**",
	"**/.oh-my-zsh/custom/**",
	"**/.terraform/providers/**", "**/.terraform/modules/**", "**/.terraform.d/plugins/**",
	"**/.git/config", "**/.git/config.worktree", "**/.git/hooks/**", "**/.git/modules/**/config", "**/.git/modules/**/hooks/**",
	"**/Library/Application Support/go/env", "**/.config/go/env",
	"**/site-packages/*.pth", "**/dist-packages/*.pth", "**/site-packages/sitecustomize.py",
	"**/site-packages/usercustomize.py", "**/site-packages/sitecustomize/**", "**/site-packages/usercustomize/**",
}

// PlantOnlyPaths returns plantOnlyPaths (guard.Set.PlantOnly), less any the
// config lists itself.
func (c *Config) PlantOnlyPaths() []string {
	var out []string
	for _, p := range plantOnlyPaths {
		if !slices.Contains(c.ProtectedPaths, p) {
			out = append(out, p)
		}
	}
	return out
}

// pathPrograms are names an agent may not place in a PATH directory: the
// programs strict shapes trusts by name, the helpers the hook, its plugin
// launcher and its documented commands run, and the engines the plan gate
// runs (a plant could answer show -json with any plan).
var pathPrograms = []string{"applygate", "seatbelt", "terraform", "tofu", "terragrunt", "sh", "bash", "zsh", "dash",
	"claude", "codex", "gemini", "copilot", "opencode", "cursor-agent",
	"env", "sudo", "su", "doas", "awk", "sha256sum", "shasum", "cut", "uname", "tar", "curl", "git", "aws", "gcloud",
	"az", "gsutil", "kubectl", "helm", "kustomize", "gh", "glab", "go", "gofmt", "docker", "podman", "make", "vault",
	"jq", "yq", "sed", "grep", "egrep", "rg", "find", "ls", "cat", "head", "tail", "wc", "sort", "uniq", "tr", "tee",
	"diff", "cmp", "tree", "stat", "file", "du", "df", "basename", "dirname", "realpath", "readlink", "mkdir", "touch",
	"cp", "mv", "rm", "ln", "chmod", "column", "xxd", "od", "base64", "md5sum", "gzip", "gunzip", "unzip", "zip",
	"nl", "fold", "comm", "join", "paste", "seq", "id", "whoami", "hostname", "printenv", "printf", "echo", "date",
	"sleep", "which", "test", "true", "false", "pwd", "wget", "tflint", "tfsec", "terraform-docs", "infracost",
	"shellcheck", "actionlint", "checkov", "trivy", "conftest", "opa", "python3", "python", "node", "perl", "ruby",
	// What a plain git, aws, kubectl, docker or terraform call starts by
	// name from PATH: ssh and its helpers, git's remote helpers, merge
	// drivers and credential helpers, Docker's credential helpers, and the
	// credential plugins of the Kubernetes and AWS clients.
	"ssh", "scp", "sftp", "ssh-agent", "ssh-add", "ssh-keygen", "git-remote-*", "git-merge-*", "git-credential-*", "git-lfs",
	"docker-credential-*", "docker-compose", "gke-gcloud-auth-plugin", "kubelogin", "aws-iam-authenticator", "aws-vault", "granted",
	"saml2aws", "aws-sso", "kubectl-*", "helm-*", "terraform-provider-*", "terraform-credentials-*", "pre-commit", "less", "more", "man"}

// GuardPaths returns all protected path patterns: the defaults, the
// config's own, and applygate's files wherever the environment puts them
// (XDG_CONFIG_HOME, XDG_STATE_HOME, CLAUDE_CONFIG_DIR, CODEX_HOME), plus
// the running binary.
func (c *Config) GuardPaths() []string {
	out := append([]string(nil), DefaultProtectedPaths...)
	out = append(out, c.ProtectedPaths...)
	if c.LogPath != "" {
		out = append(out, c.LogPath)
	}
	for _, d := range appDirs() {
		out = append(out, d, filepath.Join(d, "**"))
	}
	out = append(out, ApprovalsPath(), JudgeCachePath())
	out = append(out, hostDirFiles()...)
	out = append(out, managedGuards()...)
	return append(out, guard.Executable()...)
}

// appDirs are applygate's user config and state directories, and the
// pre-rename ones, as the environment resolves them.
func appDirs() []string {
	out := []string{filepath.Dir(userPathFor("applygate")), filepath.Dir(userPathFor("seatbelt")),
		filepath.Dir(logPathFor("applygate")), filepath.Dir(logPathFor("seatbelt"))}
	// The Claude Code plugin keeps its binary and pin under
	// CLAUDE_PLUGIN_DATA, else ${XDG_CACHE_HOME:-~/.cache}/applygate.
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		out = append(out, filepath.Join(d, "applygate"))
	}
	if d := os.Getenv("CLAUDE_PLUGIN_DATA"); d != "" {
		out = append(out, d)
	}
	return out
}

// hostDirFiles are the hook settings under a relocated host directory.
func hostDirFiles() []string {
	var out []string
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		out = append(out, filepath.Join(d, "settings.json"), filepath.Join(d, "settings.local.json"),
			filepath.Join(d, "plugins", "cache", "applygate", "**"), filepath.Join(d, "plugins", "marketplaces", "applygate", "**"),
			filepath.Join(d, "plugins", "data", "applygate-*", "**"),
			filepath.Join(d, "plugins", "installed_plugins.json"), filepath.Join(d, "plugins", "known_marketplaces.json"),
			filepath.Join(d, ".claude.json"))
	}
	if d := os.Getenv("CODEX_HOME"); d != "" {
		out = append(out, filepath.Join(d, "hooks.json"), filepath.Join(d, "config.toml"))
	}
	// hook install writes Copilot CLI's hook under COPILOT_HOME when set.
	if d := os.Getenv("COPILOT_HOME"); d != "" {
		out = append(out, filepath.Join(d, "hooks"), filepath.Join(d, "hooks", "**"), filepath.Join(d, "settings.json"))
	}
	if d := os.Getenv("GEMINI_CLI_HOME"); d != "" {
		out = append(out, filepath.Join(d, ".gemini", "settings.json"), filepath.Join(d, ".gemini", "trustedFolders.json"))
	}
	return out
}

// gitRoot returns the nearest directory at or above dir that holds a .git
// entry (a directory, or the file a worktree or submodule has), or "". It
// reads the file system only: no git runs.
func gitRoot(dir string) string {
	if !filepath.IsAbs(dir) {
		return ""
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if d == filepath.Dir(d) {
			return ""
		}
	}
}

// GuardTargets returns the concrete places guard files live, for the
// ancestor check: removing, moving or extracting into a directory that holds
// one changes it. A default pattern "**/x/y" stands for x/y under each base
// directory: home (the user's home directory); the repository root, which is
// the config's, the directory of the outermost repository config when it
// was not read (untrusted), and the nearest git root, with or without a
// config; and sessionRoots, the directories the agent's session was started
// in (CLAUDE_PROJECT_DIR and the like), whose hook settings the host loads
// whether or not they are a repository root.
func (c *Config) GuardTargets(home string, sessionRoots ...string) []string {
	out := c.patternTargets(append(append([]string(nil), DefaultProtectedPaths...), c.ProtectedPaths...), home, sessionRoots)
	out = append(out, appDirs()...)
	out = append(out, ApprovalsPath(), JudgeCachePath())
	if c.LogPath != "" {
		out = append(out, c.LogPath)
	}
	for _, f := range hostDirFiles() {
		if lit := literalPrefix(f); lit != "" {
			out = append(out, lit)
		}
	}
	for _, f := range managedGuards() {
		if lit := literalPrefix(f); lit != "" {
			out = append(out, lit)
		}
	}
	out = append(out, launchTargets(home)...)
	for _, p := range c.PlanGate.Engines {
		out = append(out, p)
	}
	return append(out, guard.Executable()...)
}

// guardBases are the directories a default pattern "**/x/y" stands for x/y
// under (GuardTargets).
func (c *Config) guardBases(home string, sessionRoots []string) []string {
	return cleanBases(append([]string{home, c.Root, c.GuardRoot, c.GitRoot}, sessionRoots...))
}

func cleanBases(in []string) []string {
	var bases []string
	for _, b := range in {
		if b != "" && filepath.IsAbs(b) && !slices.Contains(bases, filepath.Clean(b)) {
			bases = append(bases, filepath.Clean(b))
		}
	}
	return bases
}

// SoftTargets are the targets GuardTargets has only from a repository-level
// root (the config's directory, the outermost config's directory, the
// nearest git root, the session roots): a git command that rewrites the work
// tree there without naming a guard file is asked about, not blocked
// (guard.Set.Soft), since checkout, pull and the like are routine and bring
// in hook files only when a commit holds them. A changed .applygate.yaml is
// not read until a person trusts it again. Home's and applygate's own
// targets are not soft.
func (c *Config) SoftTargets(home string, sessionRoots ...string) []string {
	all := DefaultProtectedPaths
	all = append(append([]string(nil), all...), c.ProtectedPaths...)
	hard := map[string]bool{}
	for _, t := range c.targetsUnder(all, cleanBases([]string{home})) {
		hard[t] = true
	}
	var out []string
	for _, t := range c.targetsUnder(all, cleanBases(append([]string{c.Root, c.GuardRoot, c.GitRoot}, sessionRoots...))) {
		if !hard[t] {
			hard[t] = true // once
			out = append(out, t)
		}
	}
	return out
}

// targetsUnder are relative patterns' literal prefixes under bases.
func (c *Config) targetsUnder(patterns, bases []string) []string {
	var out []string
	for _, p := range patterns {
		lit := literalPrefix(p)
		if lit == "" || filepath.IsAbs(lit) {
			continue
		}
		for _, b := range bases {
			out = append(out, filepath.Join(b, lit))
		}
	}
	return out
}

// patternTargets are the concrete places patterns stand for: an absolute
// pattern's literal prefix, and a relative one's under each guard base.
func (c *Config) patternTargets(patterns []string, home string, sessionRoots []string) []string {
	var out []string
	bases := c.guardBases(home, sessionRoots)
	for _, p := range patterns {
		lit := literalPrefix(p)
		if lit == "" {
			continue
		}
		if filepath.IsAbs(lit) {
			out = append(out, lit)
			continue
		}
		for _, base := range bases {
			out = append(out, filepath.Join(base, lit))
		}
	}
	return out
}

// PlantOnlyTargets are the targets GuardTargets has only from plant-only
// patterns (PlantOnlyPaths): a target another pattern also stands for is
// not one.
func (c *Config) PlantOnlyTargets(home string, sessionRoots ...string) []string {
	var others []string
	for _, p := range append(append([]string(nil), DefaultProtectedPaths...), c.ProtectedPaths...) {
		if !slices.Contains(plantOnlyPaths, p) || slices.Contains(c.ProtectedPaths, p) {
			others = append(others, p)
		}
	}
	strict := map[string]bool{}
	for _, t := range c.patternTargets(others, home, sessionRoots) {
		strict[t] = true
	}
	var out []string
	for _, t := range c.patternTargets(plantOnlyPaths, home, sessionRoots) {
		if !strict[t] {
			out = append(out, t)
		}
	}
	return out
}

// PathDirs are the PATH directories, and the usual user bin directories,
// that the agent's user can write: a pathPrograms name placed there runs
// instead of the program a plain command or the hook names
// (guard.Set.Programs).
func PathDirs(home string) []string {
	var out []string
	for _, d := range pathDirs(home) {
		if userWritable(d) {
			out = append(out, d)
		}
	}
	return out
}

// PathPrograms are the names guarded in PathDirs.
func PathPrograms() []string {
	return append(append([]string(nil), pathPrograms...), shell.GitPrograms()...)
}

func pathDirs(home string) []string {
	dirs := filepath.SplitList(os.Getenv("PATH"))
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"), filepath.Join(home, "bin"), filepath.Join(home, "go", "bin"),
			filepath.Join(home, ".cargo", "bin"))
	}
	dirs = append(dirs, "/usr/local/bin", "/opt/homebrew/bin")
	var out []string
	for _, d := range dirs {
		if d != "" && filepath.IsAbs(d) {
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// launchTargets are the places that decide which applygate binary runs and
// with which environment: an applygate or seatbelt (or an engine the plan
// gate runs) in any PATH directory or
// the usual user bin directories (a plant there runs instead of the real
// hook), and the shell start-up files (an export there, such as
// APPLYGATE_BIN or XDG_CONFIG_HOME, reaches the next session's hook).
func launchTargets(home string) []string {
	dirs := filepath.SplitList(os.Getenv("PATH"))
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"), filepath.Join(home, "bin"), filepath.Join(home, "go", "bin"),
			filepath.Join(home, ".cargo", "bin"))
	}
	dirs = append(dirs, "/usr/local/bin", "/opt/homebrew/bin")
	var out []string
	for _, d := range dirs {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		out = append(out, filepath.Join(d, "applygate"), filepath.Join(d, "seatbelt"))
		out = append(out, filepath.Join(d, "terraform"), filepath.Join(d, "tofu"), filepath.Join(d, "terragrunt"))
	}
	if home != "" {
		for _, rc := range []string{".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile",
			".config/fish/config.fish", ".config/fish/conf.d", ".config/environment.d", ".pam_environment", "Library/LaunchAgents"} {
			out = append(out, filepath.Join(home, rc))
		}
	}
	return out
}

// literalPrefix is the part of a guard pattern before its first segment with
// a wildcard, without a leading "**/".
func literalPrefix(p string) string {
	p = filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(p), "**/"))
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if strings.ContainsAny(s, "*?[") {
			break
		}
		segs = append(segs, s)
	}
	out := strings.Join(segs, "/")
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(out, "/") {
		out = "/" + out
	}
	return filepath.FromSlash(out)
}
