// Package config loads applygate configuration and resolves environment tiers.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/guard"
	"github.com/Flurit/applygate/internal/safefile"
	"github.com/Flurit/applygate/internal/shell"
)

// Tier is an environment tier.
type Tier string

const (
	Protected  Tier = "protected"
	Standard   Tier = "standard"
	Disposable Tier = "disposable"
)

// Rank orders tiers from least to most protected.
func (t Tier) Rank() int {
	switch t {
	case Disposable:
		return 0
	case Standard:
		return 1
	}
	return 2
}

// FileName is the per-repository config file.
const FileName = ".applygate.yaml"

// LegacyFileName is the name the file had before the project was renamed from
// seatbelt (2026-10-29). It is still read, with a deprecation note in
// Config.Deprecations, and stays a protected guard file.
const LegacyFileName = ".seatbelt.yaml"

// Values of the unknown_dir setting.
const (
	UnknownDirMostProtected = "most_protected"
	UnknownDirSessionRoot   = "session_root"
)

// Boundary is the user's statement about the controls applygate cannot
// verify, and the assurance level doctor must find (docs/boundary.md).
type Boundary struct {
	// Require is the lowest acceptable level, L0 to L3; `applygate doctor
	// --boundary` exits 1 below it.
	Require string `yaml:"require"`
	// Attest lists controls the person vouches for: ci_apply (applies run
	// in a reviewed pipeline), state_guards (versioned, object-locked state
	// with a deny policy), oidc_pinned (the apply role's trust is pinned to
	// an environment) and branch_protection. applygate reports them as
	// attested, never as verified.
	Attest []string `yaml:"attest"`
}

// Config is the merged configuration.
type Config struct {
	Version     int    `yaml:"version"`
	Mode        string `yaml:"mode"` // enforce | observe
	Strict      *bool  `yaml:"strict"`
	DefaultTier Tier   `yaml:"default_tier"`
	OnError     string `yaml:"on_error"` // auto | block | allow
	LogPath     string `yaml:"log_path"`
	NameHints   *bool  `yaml:"name_hints"`
	// StrictShapes asks, in protected tiers, about any shell command that
	// is not a plain list or pipeline of known programs (default on).
	StrictShapes *bool `yaml:"strict_shapes"`
	// UnknownDir says how to judge a command whose directory the host did
	// not report: "most_protected" (default) takes the most protected tier
	// the command could be in under the session root; "session_root" judges
	// it at the root as if the command ran there. A repository config may
	// tighten this to most_protected but not loosen it.
	UnknownDir string            `yaml:"unknown_dir"`
	Aliases    map[string]string `yaml:"aliases"`
	// Approvals lets a person allow one asked command with `applygate
	// approve` on agents that cannot show an ask prompt. It is off by
	// default: on one machine the agent can reach any terminal the person
	// can, so only the user config may turn it on, knowing that.
	Approvals *bool `yaml:"approvals"`
	// Judge sends calls the rules let through without recognizing anything
	// to a language model, which may make the verdict stricter, never
	// looser. Off by default; only the user config can turn it on or
	// configure it, because the call leaves the machine. A repository config
	// may turn it off.
	Judge Judge `yaml:"judge"`
	// Boundary is what the person says about the controls around applygate
	// and the assurance level `applygate doctor --boundary` must reach. Only
	// the user or system config may set it: an agent must not be able to
	// lower the requirement or attest to a control that is not there.
	Boundary Boundary `yaml:"boundary"`

	Environments   []Environment `yaml:"environments"`
	PlanGate       PlanGate      `yaml:"plan_gate"`
	Preflight      Preflight     `yaml:"preflight"`
	ProtectedPaths []string      `yaml:"protected_paths"`
	// Wrappers are extra programs that run the command in their arguments
	// (a team's own credential or environment runner), so applygate
	// analyzes that command. Built-in wrappers need no entry.
	Wrappers []Wrapper `yaml:"wrappers"`
	// ProtectedResources are resource address globs (for example
	// "aws_db_instance.*" or "module.data.*") whose destroy or replace in a
	// saved plan is a critical finding, whatever their type.
	ProtectedResources []string `yaml:"protected_resources"`

	// Root is the directory of the repository config file ("" if none).
	Root string `yaml:"-"`
	// Sources lists the files that were loaded.
	Sources []string `yaml:"-"`
	// Deprecations notes legacy names still in use (a .seatbelt.yaml config
	// file); doctor and check print them.
	Deprecations []string `yaml:"-"`
	// Untrusted lists the repository configs that were not read because
	// their content was not approved with applygate trust.
	Untrusted []string `yaml:"-"`
	// LoadedFor is the directory whose repository configs Load looked up.
	LoadedFor string `yaml:"-"`
	// GuardRoot is the directory of the outermost repository config Load
	// found, read or not: the repository root whose guard files
	// (GuardTargets) are guarded whether or not the config is trusted. An
	// untrusted config decides nothing, but the files beside it are still
	// the repository's hook settings.
	GuardRoot string `yaml:"-"`
	// GitRoot is the nearest directory at or above the one Load looked up
	// that holds a .git entry: the repository root whether or not it has a
	// config, so a repository without .applygate.yaml still has its hook
	// files guarded (GuardTargets).
	GitRoot string `yaml:"-"`
}

// Wrapper declares a program that runs another command: the command
// follows "--" when present, otherwise it starts after Skip positional
// arguments. ProfileArg (1-based, optional) is the positional that names an
// AWS profile or role, used as a tier signal.
type Wrapper struct {
	Name       string `yaml:"name"`
	Skip       int    `yaml:"skip"`
	ProfileArg int    `yaml:"profile_arg"`
}

// Judge configures the model judge (docs/judge.md).
type Judge struct {
	Enabled *bool `yaml:"enabled"`
	// Backend is openai (any OpenAI-compatible chat completions endpoint,
	// with the user's own key; the default wire format) or command (a
	// program the user names).
	Backend string `yaml:"backend"`
	// BaseURL and Model choose the endpoint and model of the openai
	// backend. There is no default provider or model: the user picks one
	// (docs/judge.md compares them), and until they do the judge is not
	// asked.
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
	// APIKeyEnv names the environment variable holding the API key; with
	// none set, no key is sent (a local server). The key itself never goes
	// in a config.
	APIKeyEnv string `yaml:"api_key_env"`
	// ReasoningEffort is sent as reasoning_effort when set, for providers
	// that accept it.
	ReasoningEffort string `yaml:"reasoning_effort"`
	// Command is the program and arguments of the command backend: it reads
	// one request as JSON on stdin and writes the verdict as JSON on stdout.
	Command []string `yaml:"command"`
	Timeout string   `yaml:"timeout"` // per call (default 10s)
	// SkipMCP lists MCP tool name globs never sent to the judge, for tools
	// the user knows only read (a browser, a docs search).
	SkipMCP []string `yaml:"skip_mcp"`
}

// Judge backends and the per-call timeout.
const (
	JudgeBackendOpenAI  = "openai"
	JudgeBackendCommand = "command"
	DefaultJudgeTimeout = 10 * time.Second
)

// JudgeOn reports whether the model judge is enabled.
func (c *Config) JudgeOn() bool { return on(c.Judge.Enabled, false) }

// JudgeTimeout is the per-call deadline for the judge.
func (c *Config) JudgeTimeout() time.Duration {
	if d, err := time.ParseDuration(c.Judge.Timeout); err == nil && d > 0 {
		return d
	}
	return DefaultJudgeTimeout
}

// JudgeSkips reports whether an MCP tool is excluded from the judge.
func (c *Config) JudgeSkips(tool string) bool {
	for _, g := range c.Judge.SkipMCP {
		if ok, _ := path.Match(g, tool); ok {
			return true
		}
	}
	return false
}

// Environment maps signals to a tier.
type Environment struct {
	Name  string `yaml:"name"`
	Tier  Tier   `yaml:"tier"`
	Match Match  `yaml:"match"`
}

// Match lists the signals that identify an environment. Any one matching is
// enough.
type Match struct {
	Paths       []string `yaml:"paths"`
	Workspaces  []string `yaml:"workspaces"`
	Backends    []string `yaml:"backends"` // "s3://bucket/key-glob"
	AWSProfiles []string `yaml:"aws_profiles"`
	AWSAccounts []string `yaml:"aws_accounts"`
	// The cluster or cloud a kubectl, helm, gcloud or az command targets.
	KubeContexts       []string `yaml:"kube_contexts"`
	GCPProjects        []string `yaml:"gcp_projects"`
	AzureSubscriptions []string `yaml:"azure_subscriptions"` // names or ids
}

// PlanGate configures plan rules.
type PlanGate struct {
	MaxDestroy  map[Tier]int `yaml:"max_destroy"`
	Scope       []string     `yaml:"scope"`
	RunShow     *bool        `yaml:"run_show"`
	ShowTimeout string       `yaml:"show_timeout"`
	// Engines are the terraform, tofu and terragrunt binaries the hook runs
	// (show -json, state pull), and the aws CLI preflight.live_identity
	// runs, by name, as absolute paths. Without one the
	// hook looks the name up on PATH. User or system config only; under a
	// managed install, system config only.
	Engines map[string]string `yaml:"engines"`
}

// Preflight configures preflight checks.
type Preflight struct {
	StaleState *bool `yaml:"stale_state"`
	Lockfile   *bool `yaml:"lockfile"`
	Backend    *bool `yaml:"backend"`
	// LiveIdentity enables a read-only "aws sts get-caller-identity" call.
	// Off by default. User config only.
	LiveIdentity bool `yaml:"live_identity"`
	// LiveState enables a read-only "<engine> state pull" when local state
	// files sit next to a remote backend, to compare lineage and serial.
	// Off by default. User config only.
	LiveState bool `yaml:"live_state"`
}

func on(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func (c *Config) IsStrict() bool { return on(c.Strict, true) }
func (c *Config) UnknownDirMostProtected() bool {
	return c.UnknownDir != UnknownDirSessionRoot
}
func (c *Config) UseNameHints() bool    { return on(c.NameHints, true) }
func (c *Config) StrictShapesOn() bool  { return on(c.StrictShapes, true) }
func (c *Config) ApprovalsOn() bool     { return on(c.Approvals, false) }
func (c *Config) Observe() bool         { return c.Mode == "observe" }
func (c *Config) StaleStateCheck() bool { return on(c.Preflight.StaleState, true) }
func (c *Config) LockfileCheck() bool   { return on(c.Preflight.Lockfile, true) }
func (c *Config) BackendCheck() bool    { return on(c.Preflight.Backend, true) }
func (c *Config) RunShow() bool         { return on(c.PlanGate.RunShow, true) }
func (c *Config) ShowTimeout() time.Duration {
	if d, err := time.ParseDuration(c.PlanGate.ShowTimeout); err == nil && d > 0 {
		return d
	}
	return 20 * time.Second
}

// MaxDestroy returns the destroy/replace budget for a tier; -1 is unlimited.
func (c *Config) MaxDestroy(t Tier) int {
	if v, ok := c.PlanGate.MaxDestroy[t]; ok {
		return v
	}
	if t == Protected {
		return 0
	}
	return -1
}

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

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{Version: 1, Mode: "enforce", OnError: "auto", UnknownDir: UnknownDirMostProtected, Aliases: map[string]string{"tf": "terraform"}}
}

// UserPath returns the user-level config path. A config left at the
// pre-rename location (~/.config/seatbelt/config.yaml) is used when no file
// exists at the new one.
func UserPath() string {
	return preferExisting(userPathFor("applygate"), userPathFor("seatbelt"))
}

// UserDir is the applygate user configuration directory. Unlike UserPath it
// never falls back to the pre-rename seatbelt directory.
func UserDir() string { return filepath.Dir(userPathFor("applygate")) }

// HomeProblem says why the user's own files cannot be placed: without an
// absolute home directory, the user config, trust store and log would be
// read relative to the directory the hook runs in, which a repository can
// fill. "" when there is none.
func HomeProblem() string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "no absolute home directory (HOME is unset or relative), so the user config, trust store and log cannot be found"
	}
	return ""
}

func userPathFor(name string) string {
	// A relative XDG directory is ignored, as the XDG spec says.
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, name, "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", name, "config.yaml")
}

// DefaultLogPath returns the decision log path, outside any repository. A
// log that an older seatbelt install kept writing at
// ~/.local/state/seatbelt/decisions.jsonl is used when no log exists at the
// new location, so "report" keeps seeing one history.
func DefaultLogPath() string {
	return preferExisting(logPathFor("applygate"), logPathFor("seatbelt"))
}

// ApprovalsPath is where pending and granted one-time approvals are kept,
// next to the default decision log. It is a guard path.
func ApprovalsPath() string {
	return filepath.Join(filepath.Dir(logPathFor("applygate")), "approvals.json")
}

// JudgeCachePath is where the model judge keeps recent verdicts, next to
// the decision log. It is a guard path: an agent that edited it could
// suppress the judge's prompts.
func JudgeCachePath() string {
	return filepath.Join(filepath.Dir(logPathFor("applygate")), "judge-cache.json")
}

func logPathFor(name string) string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, name, "decisions.jsonl")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", name, "decisions.jsonl")
}

// preferExisting returns the new path unless only the legacy one exists.
func preferExisting(newPath, legacy string) string {
	if _, err := os.Stat(newPath); err == nil {
		return newPath
	}
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return newPath
}

// FindRepoConfig walks up from dir to find .applygate.yaml, accepting the
// legacy .seatbelt.yaml in a directory that has no .applygate.yaml.
func FindRepoConfig(dir string) string {
	for d := dir; d != "" && d != "/" && d != "."; d = filepath.Dir(d) {
		for _, name := range []string{FileName, LegacyFileName} {
			p := filepath.Join(d, name)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

// RepoConfigs returns every repository config from the outermost ancestor
// of dir down to dir, outermost first. The ancestors are those of where dir
// really is, after symlinks: a directory reached through a link from outside
// the repository still gets the repository's config (4H15). Configs on the
// path as written that are not among those follow, as nested configs that
// may only tighten.
func RepoConfigs(dir string) []string {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || real == dir {
		return repoConfigChain(dir)
	}
	out, written := repoConfigChain(real), repoConfigChain(dir)
	for i, q := range out {
		// One the written path also finds keeps its written name, which
		// environment paths and the session root are compared with.
		if j := slices.IndexFunc(written, func(p string) bool { return sameEntry(p, q) }); j >= 0 {
			out[i] = written[j]
		}
	}
	for _, p := range written {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// sameEntry reports whether two paths name the same directory entry (the
// same file, or the same symlink).
func sameEntry(a, b string) bool {
	if a == b {
		return true
	}
	fa, ea := os.Lstat(a)
	fb, eb := os.Lstat(b)
	return ea == nil && eb == nil && os.SameFile(fa, fb)
}

func repoConfigChain(dir string) []string {
	var out []string
	for d := dir; d != "" && d != "."; d = filepath.Dir(d) {
		for _, name := range []string{FileName, LegacyFileName} {
			// Lstat: a symlink or other non-regular entry is listed too, so
			// that Load can refuse it rather than skip it.
			p := filepath.Join(d, name)
			if _, err := os.Lstat(p); err == nil {
				out = append([]string{p}, out...)
				break
			}
		}
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	return out
}

// Load reads the user config (if userPath is non-empty and exists) and every
// repository config from the outermost ancestor of dir down to dir.
//
// Only the user config may loosen protection. The outermost repository
// config is the repository's: it defines the environments, and may tighten
// the rest. A nested one (a subproject, a cloned tool) may only add
// protected environments and other protection; it never replaces the
// repository's config. Settings a repository config may not make are
// ignored and noted in Deprecations.
// MaxConfig is the largest config file read. A larger repository config is
// untrusted (every directory it covers is protected); a larger user or
// system config is an error.
const MaxConfig = 1 << 20

func Load(userPath, dir string) (*Config, error) {
	cfg := Default()
	// Under a managed install the root-owned system config is read first,
	// and the user config, which the agent's user owns, may then only
	// tighten, like a repository config. One the system config root does
	// not own decides nothing, and every directory is protected until it is
	// fixed.
	userLayer := layerUser
	if sp := SystemPath(); sp != "" {
		if _, err := os.Lstat(sp); err == nil {
			userLayer = layerUserManaged
			if err := CheckSystemFile(sp); err != nil {
				cfg.Untrusted = append(cfg.Untrusted, sp)
				cfg.Deprecations = append(cfg.Deprecations, "system config not used: "+err.Error())
			} else if err := merge(cfg, sp, layerSystem); err != nil {
				return nil, err
			}
		}
	}
	if userPath != "" {
		if err := merge(cfg, userPath, userLayer); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if dir != "" {
		cfg.LoadedFor = dir
		n := 0
		repoConfigs := RepoConfigs(dir)
		if len(repoConfigs) > 0 {
			cfg.GuardRoot = filepath.Dir(repoConfigs[0])
		}
		cfg.GitRoot = gitRoot(dir)
		for _, p := range repoConfigs {
			// Trust is for the file read, so only a regular file counts: a
			// symlink would be checked against its target's approval and
			// read at its own place. A config that cannot be read is
			// untrusted too; it must not reach the error path, where the
			// user config's on_error decides.
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				cfg.Untrusted = append(cfg.Untrusted, p)
				cfg.Deprecations = append(cfg.Deprecations, p+" is not a regular file (a symlink?), so it is not read; replace it with the file itself and trust that")
				continue
			}
			b, err := safefile.ReadFileMax(p, MaxConfig)
			if err != nil {
				cfg.Untrusted = append(cfg.Untrusted, p)
				cfg.Deprecations = append(cfg.Deprecations, p+" cannot be read, so it is not read: "+err.Error())
				continue
			}
			if !Trusted(p, b) {
				// Not read: a config nobody approved, or one changed since,
				// decides nothing. Every directory is then protected.
				cfg.Untrusted = append(cfg.Untrusted, p)
				continue
			}
			l := layerRepo
			if n > 0 {
				l = layerNested
			}
			n++
			// The bytes that were hashed are the ones parsed: reading the
			// path again would parse whatever replaced it since.
			if err := mergeBytes(cfg, p, b, l); err != nil {
				return nil, err
			}
		}
	}
	return cfg, cfg.validate()
}

type layer int

const (
	layerUser        layer = iota
	layerSystem            // the managed install's system config, read first
	layerUserManaged       // the user config under a managed install: tighten only
	layerRepo              // the outermost repository config
	layerNested            // a repository config inside another
)

// LoadFile reads one config file on top of the defaults, as a repository
// config.
func LoadFile(path string) (*Config, error) {
	cfg := Default()
	if err := merge(cfg, path, layerRepo); err != nil {
		return nil, err
	}
	return cfg, cfg.validate()
}

func merge(cfg *Config, path string, l layer) error {
	b, err := safefile.ReadFileMax(path, MaxConfig)
	if err != nil {
		return err
	}
	return mergeBytes(cfg, path, b, l)
}

func mergeBytes(cfg *Config, path string, b []byte, l layer) error {
	// repo: the layer may only tighten. The user config under a managed
	// install is held to the same rule as a repository config.
	repo := l != layerUser && l != layerSystem
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	cfg.Sources = append(cfg.Sources, path)
	if filepath.Base(path) == LegacyFileName {
		cfg.Deprecations = append(cfg.Deprecations, path+" uses the pre-rename file name; rename it to "+FileName+" (the old name keeps working for one release)")
	}
	if l == layerRepo {
		cfg.Root = filepath.Dir(path)
	}
	// ignored notes a setting a repository config may not make: it would
	// loosen protection, which only the user config may do.
	where, owner := "a repository config", "the user config ("+UserPath()+")"
	if l == layerUserManaged {
		where, owner = "the user config under a managed install", "the system config ("+SystemPath()+")"
	}
	ignored := func(field string) {
		cfg.Deprecations = append(cfg.Deprecations, path+": "+field+" would loosen protection and is ignored in "+where+"; only "+owner+" may set it")
	}
	// userOnly notes a setting that is the user's for another reason: it
	// sends data off the machine or moves applygate's own files.
	userOnly := func(field string) {
		cfg.Deprecations = append(cfg.Deprecations, path+": "+field+" is ignored in "+where+"; only "+owner+" may set it")
	}
	if c.Mode != "" {
		switch {
		case !repo || c.Mode == "enforce":
			cfg.Mode = c.Mode
		default:
			ignored("mode: " + c.Mode)
		}
	}
	if c.Strict != nil {
		switch {
		case !repo || *c.Strict:
			cfg.Strict = c.Strict
		default:
			ignored("strict: false")
		}
	}
	if c.DefaultTier != "" {
		switch {
		case !repo || cfg.DefaultTier == "" && c.DefaultTier == Protected || cfg.DefaultTier != "" && c.DefaultTier.Rank() >= cfg.DefaultTier.Rank():
			cfg.DefaultTier = c.DefaultTier
		default:
			ignored("default_tier: " + string(c.DefaultTier))
		}
	}
	if c.OnError != "" {
		switch {
		case !repo || onErrorRank(c.OnError) >= onErrorRank(cfg.OnError):
			cfg.OnError = c.OnError
		default:
			ignored("on_error: " + c.OnError)
		}
	}
	if c.LogPath != "" {
		// A repository cannot redirect the log; only the user config can.
		if repo {
			userOnly("log_path")
		} else {
			cfg.LogPath = c.LogPath
		}
	}
	if c.NameHints != nil {
		switch {
		case !repo || *c.NameHints:
			cfg.NameHints = c.NameHints
		default:
			ignored("name_hints: false")
		}
	}
	if c.Approvals != nil {
		// A repository may turn approvals off, never back on.
		if !repo || !*c.Approvals {
			cfg.Approvals = c.Approvals
		} else {
			ignored("approvals: true")
		}
	}
	if !reflect.DeepEqual(c.Boundary, Boundary{}) {
		switch {
		case l == layerUserManaged:
			ignored("boundary (under a managed install it comes from the system config)")
		case repo:
			userOnly("boundary")
		default:
			cfg.Boundary = c.Boundary
		}
	}
	switch {
	case l == layerUserManaged && !reflect.DeepEqual(c.Judge, Judge{}):
		// Under a managed install the judge is the system config's: the
		// agent's user may neither turn it off (R5-5) nor name a command
		// for it to run.
		ignored("judge (under a managed install it comes from the system config)")
	case repo:
		// The judge sends calls off the machine with the user's key: a
		// repository may turn it off, nothing else.
		if c.Judge.Enabled != nil && !*c.Judge.Enabled {
			cfg.Judge.Enabled = c.Judge.Enabled
		} else if !reflect.DeepEqual(c.Judge, Judge{}) {
			userOnly("judge (a repository config may only turn it off)")
		}
	case l == layerUser || !reflect.DeepEqual(c.Judge, Judge{}):
		cfg.Judge = c.Judge
	}
	switch c.UnknownDir {
	case "":
	case UnknownDirMostProtected, UnknownDirSessionRoot:
		// A repository cannot opt out of fail-closed directory handling;
		// only the user config can. It may switch it back on.
		if !repo || c.UnknownDir == UnknownDirMostProtected {
			cfg.UnknownDir = c.UnknownDir
		} else {
			ignored("unknown_dir: " + c.UnknownDir)
		}
	default:
		return fmt.Errorf("%s: unknown_dir must be %s or %s, not %q", path, UnknownDirMostProtected, UnknownDirSessionRoot, c.UnknownDir)
	}
	// An alias rebinds a program name (terraform: ls would hide every
	// terraform command), so only the user config may set one.
	for k, v := range c.Aliases {
		if repo {
			ignored("aliases: " + k)
			continue
		}
		cfg.Aliases[k] = v
	}
	base := filepath.Dir(path)
	for _, e := range c.Environments {
		// A nested config may only add protection, so only its protected
		// environments count: a disposable one would lower the tier of the
		// directories it matches.
		if l == layerNested && e.Tier != Protected {
			ignored("environment " + e.Name + " (tier " + string(e.Tier) + ", in a config nested inside the repository's)")
			continue
		}
		if l == layerUserManaged && e.Tier != Protected {
			ignored("environment " + e.Name + " (tier " + string(e.Tier) + ")")
			continue
		}
		// A repository's patterns, "**" ones included, are rooted at its
		// config's directory, so another repository's "**" cannot claim
		// this one's directories. The user config's "**" patterns match
		// anywhere.
		for i, p := range e.Match.Paths {
			if !filepath.IsAbs(p) && (l == layerRepo || l == layerNested || !strings.HasPrefix(p, "**")) {
				e.Match.Paths[i] = filepath.ToSlash(filepath.Join(base, p))
			}
		}
		cfg.Environments = append(cfg.Environments, e)
	}
	if c.PlanGate.MaxDestroy != nil {
		if cfg.PlanGate.MaxDestroy == nil {
			cfg.PlanGate.MaxDestroy = map[Tier]int{}
		}
		for k, v := range c.PlanGate.MaxDestroy {
			if cur := cfg.MaxDestroy(k); repo && v != cur && (v < 0 || (cur >= 0 && v > cur)) {
				ignored(fmt.Sprintf("plan_gate.max_destroy.%s: %d", k, v))
				continue
			}
			cfg.PlanGate.MaxDestroy[k] = v
		}
	}
	if len(c.PlanGate.Scope) > 0 {
		if repo {
			ignored("plan_gate.scope")
		} else {
			cfg.PlanGate.Scope = c.PlanGate.Scope
		}
	}
	tighten := func(field string, dst **bool, v *bool) {
		switch {
		case v == nil:
		case !repo || *v:
			*dst = v
		default:
			ignored(field + ": false")
		}
	}
	tighten("plan_gate.run_show", &cfg.PlanGate.RunShow, c.PlanGate.RunShow)
	tighten("strict_shapes", &cfg.StrictShapes, c.StrictShapes)
	if c.PlanGate.ShowTimeout != "" {
		cfg.PlanGate.ShowTimeout = c.PlanGate.ShowTimeout
	}
	for name, p := range c.PlanGate.Engines {
		switch {
		case repo && l != layerUserManaged:
			userOnly("plan_gate.engines")
		case repo:
			ignored("plan_gate.engines (under a managed install it comes from the system config)")
		case !filepath.IsAbs(p) || (name != "terraform" && name != "tofu" && name != "terragrunt" && name != "aws"):
			ignored("plan_gate.engines." + name + ": an absolute path for terraform, tofu, terragrunt or aws")
		default:
			if cfg.PlanGate.Engines == nil {
				cfg.PlanGate.Engines = map[string]string{}
			}
			cfg.PlanGate.Engines[name] = p
		}
	}
	tighten("preflight.stale_state", &cfg.Preflight.StaleState, c.Preflight.StaleState)
	tighten("preflight.lockfile", &cfg.Preflight.Lockfile, c.Preflight.Lockfile)
	tighten("preflight.backend", &cfg.Preflight.Backend, c.Preflight.Backend)
	// Network access is a user decision.
	for _, x := range []struct {
		on   bool
		dst  *bool
		name string
	}{{c.Preflight.LiveIdentity, &cfg.Preflight.LiveIdentity, "preflight.live_identity"}, {c.Preflight.LiveState, &cfg.Preflight.LiveState, "preflight.live_state"}} {
		switch {
		case x.on && repo:
			userOnly(x.name + ": true")
		case x.on:
			*x.dst = true
		}
	}
	cfg.ProtectedPaths = append(cfg.ProtectedPaths, c.ProtectedPaths...)
	cfg.ProtectedResources = append(cfg.ProtectedResources, c.ProtectedResources...)
	for _, w := range c.Wrappers {
		// A wrapper skips its first arguments to find the command it runs;
		// declared over a shell, an engine or an interpreter it would hide
		// what that program runs.
		// Under a managed install a wrapper comes from the system config:
		// one skips its first arguments, which can hide what it runs.
		if repo && (wellKnown[w.Name] || classify.ModelledProgram(w.Name)) || l == layerUserManaged {
			ignored("wrappers: " + w.Name)
			continue
		}
		cfg.Wrappers = append(cfg.Wrappers, w)
	}
	return nil
}

// onErrorRank orders on_error values from loosest to strictest.
func onErrorRank(v string) int {
	switch v {
	case "allow":
		return 0
	case "block":
		return 2
	}
	return 1 // auto, or unset
}

// wellKnown are programs a repository config may not redeclare as wrappers.
var wellKnown = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "env": true, "sudo": true,
	"terraform": true, "tofu": true, "terragrunt": true, "aws": true, "az": true, "gcloud": true, "kubectl": true, "helm": true,
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true, "make": true, "rm": true, "mv": true, "cp": true,
	"applygate": true, "git": true, "xargs": true, "eval": true,
	// The credential and secrets runners the analyzer unwraps itself, and
	// the other shells and runners it models: a repository wrapper of the
	// same name would replace that and drop the profile they supply.
	"aws-vault": true, "aws-okta": true, "gds": true, "saml2aws": true, "aws-sso": true, "doppler": true, "op": true, "chamber": true,
	"infisical": true, "dotenvx": true, "envchain": true, "aws-runas": true, "nohup": true, "exec": true, "command": true, "time": true,
	"timeout": true, "nice": true, "ssh": true, "docker": true, "podman": true, "find": true, "watch": true, "flock": true, "script": true,
	"su": true, "doas": true, "csh": true, "tcsh": true, "pwsh": true, "php": true, "osascript": true, "awk": true, "direnv": true, "mise": true,
	"asdf": true, "nix": true, "nix-shell": true, "devbox": true, "sops": true, "chroot": true, "unbuffer": true, "setsid": true, "stdbuf": true,
	"parallel": true, "tmux": true, "screen": true, "caffeinate": true, "kubectl-": false}

func init() {
	// A repository config may not redeclare a program the classifier reads
	// the arguments of (file writers and readers, cloud and Kubernetes tools,
	// package managers): a wrapper's skipped arguments would hide what it
	// writes, removes or deletes, and lower a block to an ask.
	for _, n := range []string{"tee", "dd", "shred", "truncate", "ln", "sed", "gsed", "curl", "wget", "install", "gzip", "gunzip", "unlink",
		"rmdir", "srm", "rsync", "ditto", "sponge", "patch", "cpio", "chmod", "chown", "chattr", "touch", "tar", "zip", "unzip", "oc",
		"gsutil", "rclone", "pulumi", "cdktf", "eksctl", "gh", "glab", "vault", "opa", "trivy", "checkov", "tflint", "infracost",
		"conftest", "kustomize", "jq", "yq", "cat", "less", "more", "head", "tail", "grep", "rg", "base64", "xxd", "od", "strings",
		"bat", "nl", "scp", "vi", "vim", "nvim", "nano", "emacs", "ed", "ex", "go", "cargo", "npm", "pnpm", "yarn", "npx", "bunx", "uv",
		"pip", "pip3", "node", "bun", "deno", "tfsec", "terraform-docs", "actionlint", "shellcheck", "gofmt", "printf", "echo", "test",
		"find", "sort", "diff", "cmp", "mkdir", "rm", "mv", "cp", "git", "kubectl", "helm", "aws", "az", "gcloud", "docker", "podman",
		"nerdctl", "terraform", "tofu", "terragrunt", "make", "gmake", "perl", "ruby", "python", "python3", "lua", "php", "java"} {
		wellKnown[n] = true
	}
}

// ShellWrappers returns the configured wrappers keyed by program name.
func (c *Config) ShellWrappers() map[string]shell.WrapperSpec {
	if len(c.Wrappers) == 0 {
		return nil
	}
	m := make(map[string]shell.WrapperSpec, len(c.Wrappers))
	for _, w := range c.Wrappers {
		m[w.Name] = shell.WrapperSpec{Skip: w.Skip, ProfileArg: w.ProfileArg}
	}
	return m
}

func (c *Config) validate() error {
	for _, w := range c.Wrappers {
		if w.Name == "" || strings.ContainsAny(w.Name, "/ \t") {
			return fmt.Errorf("wrappers: name must be a program name, not %q", w.Name)
		}
		if w.Skip < 0 || w.ProfileArg < 0 || w.ProfileArg > w.Skip {
			return fmt.Errorf("wrappers: %s: skip and profile_arg must be >= 0 and profile_arg <= skip", w.Name)
		}
	}
	switch c.Mode {
	case "enforce", "observe":
	default:
		return fmt.Errorf("mode must be enforce or observe, not %q", c.Mode)
	}
	switch c.OnError {
	case "auto", "block", "allow":
	default:
		return fmt.Errorf("on_error must be auto, block or allow, not %q", c.OnError)
	}
	switch c.UnknownDir {
	case "", UnknownDirMostProtected, UnknownDirSessionRoot:
	default:
		return fmt.Errorf("unknown_dir must be %s or %s, not %q", UnknownDirMostProtected, UnknownDirSessionRoot, c.UnknownDir)
	}
	switch c.Judge.Backend {
	case "", JudgeBackendOpenAI:
		// A missing base_url or model is not a config error: the judge is
		// then not asked, and the rules decide as they do without it.
	case JudgeBackendCommand:
		if c.JudgeOn() && len(c.Judge.Command) == 0 {
			return errors.New("judge: backend command needs a command")
		}
	default:
		return fmt.Errorf("judge: backend must be %s or %s, not %q", JudgeBackendOpenAI, JudgeBackendCommand, c.Judge.Backend)
	}
	if c.Judge.BaseURL != "" && !strings.HasPrefix(c.Judge.BaseURL, "https://") && !strings.HasPrefix(c.Judge.BaseURL, "http://") {
		return fmt.Errorf("judge: base_url must be an http or https URL, not %q", c.Judge.BaseURL)
	}
	if c.Judge.Timeout != "" {
		if d, err := time.ParseDuration(c.Judge.Timeout); err != nil || d <= 0 {
			return fmt.Errorf("judge: timeout must be a duration such as 10s, not %q", c.Judge.Timeout)
		}
	}
	for _, g := range c.Judge.SkipMCP {
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf("judge: skip_mcp: bad pattern %q", g)
		}
	}
	for _, t := range append([]Tier{c.DefaultTier}, tiersOf(c.Environments)...) {
		switch t {
		case "", Protected, Standard, Disposable:
		default:
			return fmt.Errorf("unknown tier %q", t)
		}
	}
	return nil
}

func tiersOf(es []Environment) []Tier {
	var out []Tier
	for _, e := range es {
		if e.Tier == "" {
			out = append(out, "missing")
			continue
		}
		out = append(out, e.Tier)
	}
	return out
}

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

// Signals are what preflight knows about where a command runs.
type Signals struct {
	Dir        string
	Workspace  string
	Backend    string // "s3://bucket/key" or "local" or ""
	AWSProfile string
	AWSAccount string
	// KubeContext, GCPProject and AzureSubscription are what a kubectl or
	// helm, gcloud or az command targets; AzureSubscriptionID is the id of
	// the subscription when its name is known too.
	KubeContext         string
	GCPProject          string
	AzureSubscription   string
	AzureSubscriptionID string
	// BackendConfig is the -backend-config file or value an init in the
	// same command points at; only used for name hints.
	BackendConfig string
	// BackendValues are the backend's configuration values (from the
	// recorded backend or from -backend-config). The keys in
	// BackendHintKeys get the same name hints as the backend URL.
	BackendValues map[string]string
	// BackendUnknown says why the backend's configuration could not be
	// read; the state it points at may be any environment's.
	BackendUnknown string
	// ProviderProfiles and ProviderRoles are the profiles and role ARNs the
	// configuration's aws provider blocks name; each is a possible target.
	ProviderProfiles []string
	ProviderRoles    []string
	// ProviderUnknown says why a provider's profile or role is not known:
	// it may target any account.
	ProviderUnknown string
	// ProviderProjects, ProviderContexts and ProviderSubscriptions are the
	// google project, kubernetes context and azurerm subscription the
	// configuration's provider blocks name.
	ProviderProjects, ProviderContexts, ProviderSubscriptions []string
	// WorkspaceUnknown says why the selected workspace is not known.
	WorkspaceUnknown string
	// StateDirs are the directories of local state files the command
	// reads or writes (-state=, -state-out=, a local backend's path): each
	// brings its own directory's environment (4H11).
	StateDirs []string
	// SourceDirs are local directories the configuration that runs comes
	// from (a terragrunt terraform.source or --source): their backend
	// block, and so their environment, may be the one used (4H12).
	SourceDirs []string
}

// BackendHintKeys are the backend settings whose values can name an
// environment. bucket and key are also part of the backend URL.
var BackendHintKeys = []string{"bucket", "key", "workspace_key_prefix", "dynamodb_table", "address"}

// Resolution is the outcome of tier resolution.
type Resolution struct {
	Tier    Tier
	Env     string   // environment name, or "unknown"
	Matched []string // which signals matched, for messages
	Unknown bool
	// DirUnknown is set by ResolveUnknownDir: the tier is the most
	// protected one the command could be in under the session root, not
	// the tier of a known directory.
	DirUnknown bool
}

// Name hints: prod, production, prd or live as a whole word between the
// separators / _ . : - or the ends of the value, so acme-prod-tfstate matches
// and acme-products-tfstate does not. The word is ignored when the word just
// before it negates it (non-prod, not_prod, pre-prod) or the word just after
// it marks a stand-in (prod-like, prod-test, prod-sandbox). Only the adjacent
// words count: non-prod/us-east-1/prod still names a prod directory. Glued
// forms (nonprod, preprod) never matched, since prod is not a whole word
// there.
var (
	prodWords      = map[string]bool{"prod": true, "production": true, "prd": true, "live": true}
	prodNegPrefix  = map[string]bool{"non": true, "not": true, "no": true, "pre": true}
	prodNegSuffix  = map[string]bool{"like": true, "test": true, "sandbox": true}
	hintSeparators = "/_.:-@+=,~ \t"
)

// LooksProd reports whether a path, workspace, profile or backend value
// names production under the name-hint rule.
func LooksProd(v string) bool {
	words := strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return strings.ContainsRune(hintSeparators, r) })
	for i, w := range words {
		if !prodWords[w] {
			continue
		}
		if i > 0 && prodNegPrefix[words[i-1]] {
			continue
		}
		if i+1 < len(words) && prodNegSuffix[words[i+1]] {
			continue
		}
		return true
	}
	return false
}

// Resolve maps signals to a tier. When several environments match, the most
// protected one wins.
func (c *Config) Resolve(s Signals) Resolution {
	if len(c.Untrusted) > 0 {
		u := c.Untrusted[len(c.Untrusted)-1]
		why := "the repository config " + u + " is not trusted (new, or changed since it was trusted), so it is not read and every directory is protected; a person reviews it and runs " + TrustCommand()
		if u == SystemPath() {
			why = "the system config " + u + " is not owned and writable by root only, so it is not read and every directory is protected; run applygate doctor"
		}
		return Resolution{Tier: Protected, Env: "untrusted config", Unknown: true, Matched: []string{why}}
	}
	best := Resolution{Tier: Disposable, Env: "", Unknown: true}
	consider := func(env string, t Tier, why string) {
		if best.Unknown || t.Rank() > best.Tier.Rank() {
			best = Resolution{Tier: t, Env: env, Matched: []string{why}}
		} else if t == best.Tier && !slices.Contains(best.Matched, why) {
			best.Matched = append(best.Matched, why)
		}
	}
	// A directory is matched as written and as it resolves (symlinks
	// followed, case folded where the file system ignores it): an alias
	// such as envs/dev/p -> ../prod and its target may be in different
	// environments, and the stricter one wins.
	var dirs []string
	if s.Dir != "" {
		dirs = append(dirs, filepath.ToSlash(s.Dir))
		if filepath.IsAbs(s.Dir) {
			if canon := guard.Canonical(s.Dir); canon != dirs[0] {
				dirs = append(dirs, canon)
			}
		}
	}
	pathMatched := make([]bool, len(dirs))
	for _, e := range c.Environments {
		m := e.Match
		for _, p := range m.Paths {
			pats := []string{p}
			if filepath.IsAbs(p) {
				pats = append(pats, guard.CanonicalGlob(p))
			}
			why := ""
			for i, d := range dirs {
				for _, q := range pats {
					// Where the file system ignores case, the whole pattern
					// and path are compared folded: **/Payments/** matches
					// team/payments, the same directory.
					fq, fd := q, d
					if guard.FoldCase {
						fq, fd = guard.Fold(q), guard.Fold(d)
					}
					if classify.MatchGlob(q, d) || classify.MatchGlob(strings.TrimSuffix(q, "/**"), d) ||
						classify.MatchGlob(fq, fd) || classify.MatchGlob(strings.TrimSuffix(fq, "/**"), fd) {
						pathMatched[i] = true
						if why == "" {
							why = "path " + p
							if d != dirs[0] {
								why += " (" + s.Dir + " resolves to " + d + ")"
							}
						}
						break
					}
				}
			}
			if why != "" {
				consider(e.Name, e.Tier, why)
			}
		}
		for _, w := range m.Workspaces {
			// A local backend's workspaces are directories, which a case-
			// insensitive file system does not tell apart: Payments is payments.
			if s.Workspace != "" && globEq(strings.ToLower(w), strings.ToLower(s.Workspace)) {
				consider(e.Name, e.Tier, "workspace "+s.Workspace)
			}
		}
		for _, b := range m.Backends {
			if s.Backend != "" && backendMatch(b, s.Backend) {
				consider(e.Name, e.Tier, "backend "+s.Backend)
			}
		}
		for _, p := range m.AWSProfiles {
			if s.AWSProfile != "" && globEq(p, s.AWSProfile) {
				consider(e.Name, e.Tier, "AWS profile "+s.AWSProfile)
			}
		}
		for _, p := range m.AWSProfiles {
			for _, pp := range s.ProviderProfiles {
				if globEq(p, pp) {
					consider(e.Name, e.Tier, "provider profile "+pp)
				}
			}
		}
		for _, a := range m.AWSAccounts {
			if s.AWSAccount != "" && a == s.AWSAccount {
				consider(e.Name, e.Tier, "AWS account "+s.AWSAccount)
			}
			for _, r := range s.ProviderRoles {
				if strings.Contains(r, ":"+a+":") {
					consider(e.Name, e.Tier, "provider role "+r)
				}
			}
		}
		for _, k := range m.KubeContexts {
			if s.KubeContext != "" && globEq(k, s.KubeContext) {
				consider(e.Name, e.Tier, "kube context "+s.KubeContext)
			}
			for _, c := range s.ProviderContexts {
				if globEq(k, c) {
					consider(e.Name, e.Tier, "provider kube context "+c)
				}
			}
		}
		for _, g := range m.GCPProjects {
			if s.GCPProject != "" && globEq(g, s.GCPProject) {
				consider(e.Name, e.Tier, "GCP project "+s.GCPProject)
			}
			for _, p := range s.ProviderProjects {
				if globEq(g, p) {
					consider(e.Name, e.Tier, "provider GCP project "+p)
				}
			}
		}
		for _, z := range m.AzureSubscriptions {
			for _, v := range append([]string{s.AzureSubscription, s.AzureSubscriptionID}, s.ProviderSubscriptions...) {
				if v != "" && globEq(strings.ToLower(z), strings.ToLower(v)) {
					consider(e.Name, e.Tier, "Azure subscription "+v)
					break
				}
			}
		}
	}
	// A link into a directory no environment matches: the target gets the
	// rule for an unmatched directory, as it would if named directly.
	if len(dirs) > 1 && pathMatched[0] && !pathMatched[1] {
		if c.IsStrict() {
			consider("unknown", Protected, s.Dir+" resolves to "+dirs[1]+", which no environment matches; strict mode treats it as protected")
		} else if t := c.DefaultTier; t != "" {
			consider("unknown", t, s.Dir+" resolves to "+dirs[1]+", which no environment matches; using default_tier "+string(t))
		} else {
			consider("unknown", Standard, s.Dir+" resolves to "+dirs[1]+", which no environment matches; using default_tier standard")
		}
	}
	if s.WorkspaceUnknown != "" {
		consider("unknown workspace", Protected, s.WorkspaceUnknown+", so the state it selects is unknown and judged as protected")
	}
	if s.BackendUnknown != "" {
		consider("unknown backend", Protected, s.BackendUnknown+", so the state it points at is unknown and judged as protected")
	}
	if s.ProviderUnknown != "" {
		consider("unknown provider target", Protected, s.ProviderUnknown+", so the account it changes is unknown and judged as protected")
	}
	if c.UseNameHints() {
		relOf := func(d string) string {
			for _, root := range []string{c.Root, guard.Canonical(c.Root)} {
				if root == "" || c.Root == "" {
					continue
				}
				if r, err := filepath.Rel(root, d); err == nil && !strings.HasPrefix(r, "..") {
					return r
				}
			}
			return d
		}
		rel := relOf(s.Dir)
		canonRel := ""
		if len(dirs) > 1 {
			if canonRel = relOf(dirs[1]); strings.EqualFold(canonRel, rel) {
				canonRel = ""
			}
		}
		hints := []struct{ what, v string }{{"path", rel}, {"resolved path", canonRel}, {"workspace", s.Workspace}, {"backend", s.Backend}, {"AWS profile", s.AWSProfile}, {"backend config", s.BackendConfig},
			{"kube context", s.KubeContext}, {"GCP project", s.GCPProject}, {"Azure subscription", s.AzureSubscription}}
		for _, v := range s.ProviderProfiles {
			hints = append(hints, struct{ what, v string }{"provider profile", v})
		}
		for _, v := range s.ProviderRoles {
			hints = append(hints, struct{ what, v string }{"provider role", v})
		}
		for _, v := range s.ProviderContexts {
			hints = append(hints, struct{ what, v string }{"provider kube context", v})
		}
		for _, v := range s.ProviderProjects {
			hints = append(hints, struct{ what, v string }{"provider GCP project", v})
		}
		for _, v := range s.ProviderSubscriptions {
			hints = append(hints, struct{ what, v string }{"provider Azure subscription", v})
		}
		for _, k := range BackendHintKeys {
			// Values already in the backend URL were checked above.
			if v := s.BackendValues[k]; v != "" && !strings.Contains(s.Backend, v) {
				hints = append(hints, struct{ what, v string }{"backend " + k, v})
			}
		}
		for _, h := range hints {
			if h.v != "" && LooksProd(h.v) {
				consider("prod (name hint)", Protected, h.what+" "+h.v+" looks like production")
			}
		}
	}
	for _, d := range s.StateDirs {
		// A state file's directory brings its tier even when no
		// environment matches it: then the tier for an unknown directory
		// (protected under strict), since the state can be any
		// environment's.
		r := c.Resolve(Signals{Dir: d})
		consider(r.Env, r.Tier, "the state file it uses is in "+d+" ("+strings.Join(r.Matched, "; ")+")")
	}
	for _, d := range s.SourceDirs {
		if r := c.Resolve(Signals{Dir: d}); !r.Unknown {
			consider(r.Env, r.Tier, "the configuration it runs is from "+d+" ("+strings.Join(r.Matched, "; ")+")")
		}
	}
	if best.Unknown {
		if c.IsStrict() {
			return Resolution{Tier: Protected, Env: "unknown", Unknown: true, Matched: []string{"no environment matched; strict mode treats it as protected"}}
		}
		t := c.DefaultTier
		if t == "" {
			t = Standard
		}
		return Resolution{Tier: t, Env: "unknown", Unknown: true, Matched: []string{"no environment matched; using default_tier " + string(t)}}
	}
	return best
}

// backendMatch matches a backend URL against a pattern in which * and **
// match any text, / included (s3://bucket/* matches every key in the
// bucket), and ? one character.
func backendMatch(pattern, v string) bool {
	pattern, v = normalizeBackend(pattern), normalizeBackend(v)
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(v)
}

// normalizeBackend puts a backend URL in one spelling, so that the host in
// another case, the default port, percent-encoding, doubled slashes and a
// prefix with leading or trailing slashes (s3, gcs, http) name the same state
// as the pattern does.
func normalizeBackend(s string) string {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return s
	}
	scheme = strings.ToLower(scheme)
	host, p, _ := strings.Cut(rest, "/")
	if scheme == "http" || scheme == "https" {
		host = strings.ToLower(host)
		host = strings.TrimSuffix(host, map[string]string{"http": ":80", "https": ":443"}[scheme])
	}
	if d, err := url.PathUnescape(p); err == nil {
		p = d
	}
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + "/" + p
}

func globEq(pattern, v string) bool {
	if ok, err := filepath.Match(pattern, v); err == nil && ok {
		return true
	}
	return classify.MatchGlob(pattern, v)
}

// ResolveUnknownDir resolves the tier for a command whose directory the host
// did not report, so it could run in root or in any directory under it. The
// result is the most protected of: the root itself (with its signals, as
// Resolve sees them), every environment whose path globs could match a
// directory under root, every environment matched by workspace, backend,
// AWS profile or account (a directory under root could carry any of those),
// and the strict or default_tier rule for a directory under root that
// matches no environment. Name hints on subdirectory names are not
// considered: only the config decides what is under the root. agent names
// the host for the message.
func (c *Config) ResolveUnknownDir(agent, root string, s Signals) Resolution {
	if agent == "" {
		agent = "the host"
	}
	return c.ResolveUnder(root, s, "command directory not reported by "+agent)
}

// ResolveUnder resolves a command whose directory is not known, only that
// it is root or somewhere under it, at the most protected tier that could
// apply there. why says why the directory is not known.
func (c *Config) ResolveUnder(root string, s Signals, why string) Resolution {
	s.Dir = root
	best := c.Resolve(s)
	consider := func(env string, t Tier, why string) {
		if t.Rank() > best.Tier.Rank() {
			best = Resolution{Tier: t, Env: env, Matched: []string{why}}
		} else if t == best.Tier && !slices.Contains(best.Matched, why) {
			best.Matched = append(best.Matched, why)
		}
	}
	covered := false
	for _, e := range c.Environments {
		m := e.Match
		for _, p := range m.Paths {
			if root != "" && globCouldMatchUnder(p, root) {
				consider(e.Name, e.Tier, "path "+p+" could match a directory under the root")
				if globCoversSubtree(p, root) {
					covered = true
				}
			}
		}
		if len(m.Workspaces)+len(m.Backends)+len(m.AWSProfiles)+len(m.AWSAccounts) > 0 {
			consider(e.Name, e.Tier, "environment "+e.Name+" matches by workspace, backend or profile, which a directory under the root could carry")
		}
	}
	if !covered {
		if c.IsStrict() {
			consider("unknown", Protected, "a directory under the root that matches no environment is protected in strict mode")
		} else {
			t := c.DefaultTier
			if t == "" {
				t = Standard
			}
			consider("unknown", t, "a directory under the root that matches no environment uses default_tier "+string(t))
		}
	}
	best.DirUnknown = true
	best.Matched = append([]string{fmt.Sprintf("%s; judged at the most protected tier under %s (%s, tier %s)", why, root, best.Env, best.Tier)}, best.Matched...)
	return best
}

// globCouldMatchUnder reports whether a path glob can match root or some
// directory under it. Patterns are compared segment by segment, as
// classify.MatchGlob does; a pattern starting with ** or without a leading
// slash can anchor anywhere, so it is tried at every depth of root.
func globCouldMatchUnder(pattern, root string) bool {
	pattern = filepath.ToSlash(pattern)
	pp := strings.Split(strings.Trim(pattern, "/"), "/")
	rs := strings.Split(strings.Trim(filepath.ToSlash(root), "/"), "/")
	if strings.HasPrefix(pattern, "/") {
		return couldMatchSegs(pp, rs)
	}
	for i := 0; i <= len(rs); i++ {
		if couldMatchSegs(pp, rs[i:]) {
			return true
		}
	}
	return false
}

// couldMatchSegs is matchSegs with the root's segments allowed to run out:
// whatever pattern remains can still match a deeper directory.
func couldMatchSegs(pp, rs []string) bool {
	if len(rs) == 0 {
		return true
	}
	if len(pp) == 0 {
		return false
	}
	if pp[0] == "**" {
		for i := 0; i <= len(rs); i++ {
			if couldMatchSegs(pp[1:], rs[i:]) {
				return true
			}
		}
		return false
	}
	ok, err := filepath.Match(pp[0], rs[0])
	if err != nil || !ok {
		return false
	}
	return couldMatchSegs(pp[1:], rs[1:])
}

// globCoversSubtree reports whether a glob ending in /** matches root and
// everything under it, so no directory under root is left unmatched.
func globCoversSubtree(pattern, root string) bool {
	pattern = filepath.ToSlash(pattern)
	if pattern == "**" {
		return true
	}
	prefix, ok := strings.CutSuffix(pattern, "/**")
	if !ok {
		return false
	}
	for d := filepath.ToSlash(root); ; d = pathDir(d) {
		if classify.MatchGlob(prefix, d) {
			return true
		}
		if d == "/" || d == "." || d == "" {
			return false
		}
	}
}

func pathDir(d string) string {
	p := filepath.ToSlash(filepath.Dir(filepath.FromSlash(d)))
	if p == d {
		return "/"
	}
	return p
}
