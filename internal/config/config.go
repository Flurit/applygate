// Package config loads applygate configuration and resolves environment tiers.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Flurit/applygate/internal/classify"
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

// Config is the merged configuration.
type Config struct {
	Version     int    `yaml:"version"`
	Mode        string `yaml:"mode"` // enforce | observe
	Strict      *bool  `yaml:"strict"`
	DefaultTier Tier   `yaml:"default_tier"`
	OnError     string `yaml:"on_error"` // auto | block | allow
	LogPath     string `yaml:"log_path"`
	NameHints   *bool  `yaml:"name_hints"`
	// UnknownDir says how to judge a command whose directory the host did
	// not report: "most_protected" (default) takes the most protected tier
	// the command could be in under the session root; "session_root" judges
	// it at the root as if the command ran there. A repository config may
	// tighten this to most_protected but not loosen it.
	UnknownDir string            `yaml:"unknown_dir"`
	Aliases    map[string]string `yaml:"aliases"`
	// Approvals lets a person allow one asked command with `applygate
	// approve` on agents that cannot show an ask prompt (default true). A
	// repository config may turn it off but not on.
	Approvals *bool `yaml:"approvals"`
	// Judge sends calls the rules let through without recognizing anything
	// to a language model, which may make the verdict stricter, never
	// looser. Off by default; only the user config can turn it on or
	// configure it, because the call leaves the machine. A repository config
	// may turn it off.
	Judge Judge `yaml:"judge"`

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
	// Backend is openai (default: any OpenAI-compatible chat completions
	// endpoint, with the user's own key) or command (a program the user
	// names).
	Backend string `yaml:"backend"`
	// BaseURL is the endpoint (default Anthropic's OpenAI-compatible
	// endpoint, https://api.anthropic.com/v1). Set it for any other
	// provider or a local server; Model is then required too.
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"` // default claude-haiku-5-5
	// APIKeyEnv names the environment variable holding the API key
	// (default ANTHROPIC_API_KEY with the default endpoint; none for
	// another endpoint unless set). The key itself never goes in a config.
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

// Judge defaults.
const (
	JudgeBackendOpenAI  = "openai"
	JudgeBackendCommand = "command"
	DefaultJudgeBaseURL = "https://api.anthropic.com/v1"
	DefaultJudgeModel   = "claude-haiku-5-5"
	DefaultJudgeKeyEnv  = "ANTHROPIC_API_KEY"
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
func (c *Config) ApprovalsOn() bool     { return on(c.Approvals, true) }
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
	// Hook files of the hosts whose adapters were written from their
	// documentation (docs/hosts.md).
	"**/.gemini/settings.json", "**/.github/hooks/**", "**/.github/copilot/settings*.json",
	"**/.copilot/hooks/**", "**/.copilot/settings.json", "**/.windsurf/hooks.json", "**/.codeium/windsurf/hooks.json",
	"**/.codeium/hooks.json", "**/.devin/config.json", "**/.devin/hooks.v1.json", "**/.config/devin/config.json",
	"**/.opencode/plugins/**", "**/.config/opencode/plugins/**", "**/.clinerules/hooks/**", "**/.cline/hooks/**",
	"**/Documents/Cline/Hooks/**",
}

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

func userPathFor(name string) string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
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
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
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

// Load reads the user config (if userPath is non-empty and exists) and the
// repository config found from dir, repository values taking precedence.
func Load(userPath, dir string) (*Config, error) {
	cfg := Default()
	if userPath != "" {
		if err := merge(cfg, userPath, false); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if dir != "" {
		if p := FindRepoConfig(dir); p != "" {
			if err := merge(cfg, p, true); err != nil {
				return nil, err
			}
		}
	}
	return cfg, cfg.validate()
}

// LoadFile reads one config file on top of the defaults.
func LoadFile(path string) (*Config, error) {
	cfg := Default()
	if err := merge(cfg, path, true); err != nil {
		return nil, err
	}
	return cfg, cfg.validate()
}

func merge(cfg *Config, path string, repo bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
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
	if repo {
		cfg.Root = filepath.Dir(path)
	}
	if c.Mode != "" {
		cfg.Mode = c.Mode
	}
	if c.Strict != nil {
		cfg.Strict = c.Strict
	}
	if c.DefaultTier != "" {
		cfg.DefaultTier = c.DefaultTier
	}
	if c.OnError != "" {
		cfg.OnError = c.OnError
	}
	if c.LogPath != "" && !repo {
		// A repository cannot redirect the log; only the user config can.
		cfg.LogPath = c.LogPath
	}
	if c.NameHints != nil {
		cfg.NameHints = c.NameHints
	}
	if c.Approvals != nil && (!repo || !*c.Approvals) {
		// A repository may turn approvals off, never back on.
		cfg.Approvals = c.Approvals
	}
	if repo {
		// The judge sends calls off the machine with the user's key: a
		// repository may turn it off, nothing else.
		if c.Judge.Enabled != nil && !*c.Judge.Enabled {
			cfg.Judge.Enabled = c.Judge.Enabled
		}
	} else {
		cfg.Judge = c.Judge
	}
	switch c.UnknownDir {
	case "":
	case UnknownDirMostProtected, UnknownDirSessionRoot:
		// A repository cannot opt out of fail-closed directory handling;
		// only the user config can. It may switch it back on.
		if !repo || c.UnknownDir == UnknownDirMostProtected {
			cfg.UnknownDir = c.UnknownDir
		}
	default:
		return fmt.Errorf("%s: unknown_dir must be %s or %s, not %q", path, UnknownDirMostProtected, UnknownDirSessionRoot, c.UnknownDir)
	}
	for k, v := range c.Aliases {
		cfg.Aliases[k] = v
	}
	base := filepath.Dir(path)
	for _, e := range c.Environments {
		for i, p := range e.Match.Paths {
			if !filepath.IsAbs(p) && !strings.HasPrefix(p, "**") {
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
			cfg.PlanGate.MaxDestroy[k] = v
		}
	}
	if len(c.PlanGate.Scope) > 0 {
		cfg.PlanGate.Scope = c.PlanGate.Scope
	}
	if c.PlanGate.RunShow != nil {
		cfg.PlanGate.RunShow = c.PlanGate.RunShow
	}
	if c.PlanGate.ShowTimeout != "" {
		cfg.PlanGate.ShowTimeout = c.PlanGate.ShowTimeout
	}
	if c.Preflight.StaleState != nil {
		cfg.Preflight.StaleState = c.Preflight.StaleState
	}
	if c.Preflight.Lockfile != nil {
		cfg.Preflight.Lockfile = c.Preflight.Lockfile
	}
	if c.Preflight.Backend != nil {
		cfg.Preflight.Backend = c.Preflight.Backend
	}
	if c.Preflight.LiveIdentity && !repo {
		cfg.Preflight.LiveIdentity = true // network access is a user decision
	}
	if c.Preflight.LiveState && !repo {
		cfg.Preflight.LiveState = true // network access is a user decision
	}
	cfg.ProtectedPaths = append(cfg.ProtectedPaths, c.ProtectedPaths...)
	cfg.ProtectedResources = append(cfg.ProtectedResources, c.ProtectedResources...)
	cfg.Wrappers = append(cfg.Wrappers, c.Wrappers...)
	return nil
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
		if c.JudgeOn() && c.Judge.BaseURL != "" && c.Judge.Model == "" {
			return errors.New("judge: a base_url other than the default needs a model")
		}
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

// GuardPaths returns all protected path patterns, including the log.
func (c *Config) GuardPaths() []string {
	out := append([]string(nil), DefaultProtectedPaths...)
	out = append(out, c.ProtectedPaths...)
	if c.LogPath != "" {
		out = append(out, c.LogPath)
	}
	return append(out, ApprovalsPath(), JudgeCachePath())
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
	hintSeparators = "/_.:-"
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
	best := Resolution{Tier: Disposable, Env: "", Unknown: true}
	consider := func(env string, t Tier, why string) {
		if best.Unknown || t.Rank() > best.Tier.Rank() {
			best = Resolution{Tier: t, Env: env, Matched: []string{why}}
		} else if t == best.Tier && !slices.Contains(best.Matched, why) {
			best.Matched = append(best.Matched, why)
		}
	}
	for _, e := range c.Environments {
		m := e.Match
		for _, p := range m.Paths {
			if s.Dir != "" && (classify.MatchGlob(p, filepath.ToSlash(s.Dir)) || classify.MatchGlob(strings.TrimSuffix(p, "/**"), filepath.ToSlash(s.Dir))) {
				consider(e.Name, e.Tier, "path "+p)
			}
		}
		for _, w := range m.Workspaces {
			if s.Workspace != "" && globEq(w, s.Workspace) {
				consider(e.Name, e.Tier, "workspace "+s.Workspace)
			}
		}
		for _, b := range m.Backends {
			if s.Backend != "" && globEq(b, s.Backend) {
				consider(e.Name, e.Tier, "backend "+s.Backend)
			}
		}
		for _, p := range m.AWSProfiles {
			if s.AWSProfile != "" && globEq(p, s.AWSProfile) {
				consider(e.Name, e.Tier, "AWS profile "+s.AWSProfile)
			}
		}
		for _, a := range m.AWSAccounts {
			if s.AWSAccount != "" && a == s.AWSAccount {
				consider(e.Name, e.Tier, "AWS account "+s.AWSAccount)
			}
		}
		for _, k := range m.KubeContexts {
			if s.KubeContext != "" && globEq(k, s.KubeContext) {
				consider(e.Name, e.Tier, "kube context "+s.KubeContext)
			}
		}
		for _, g := range m.GCPProjects {
			if s.GCPProject != "" && globEq(g, s.GCPProject) {
				consider(e.Name, e.Tier, "GCP project "+s.GCPProject)
			}
		}
		for _, z := range m.AzureSubscriptions {
			for _, v := range []string{s.AzureSubscription, s.AzureSubscriptionID} {
				if v != "" && globEq(z, v) {
					consider(e.Name, e.Tier, "Azure subscription "+v)
					break
				}
			}
		}
	}
	if c.UseNameHints() {
		rel := s.Dir
		if c.Root != "" {
			if r, err := filepath.Rel(c.Root, s.Dir); err == nil && !strings.HasPrefix(r, "..") {
				rel = r
			}
		}
		hints := []struct{ what, v string }{{"path", rel}, {"workspace", s.Workspace}, {"backend", s.Backend}, {"AWS profile", s.AWSProfile}, {"backend config", s.BackendConfig},
			{"kube context", s.KubeContext}, {"GCP project", s.GCPProject}, {"Azure subscription", s.AzureSubscription}}
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
	if agent == "" {
		agent = "the host"
	}
	best.DirUnknown = true
	best.Matched = append([]string{fmt.Sprintf("command directory not reported by %s; judged at the most protected tier under %s (%s, tier %s)", agent, root, best.Env, best.Tier)}, best.Matched...)
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
