// Package config loads seatbelt configuration and resolves environment tiers.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Flurit/seatbelt/internal/classify"
	"github.com/Flurit/seatbelt/internal/shell"
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
const FileName = ".seatbelt.yaml"

// Config is the merged configuration.
type Config struct {
	Version     int               `yaml:"version"`
	Mode        string            `yaml:"mode"` // enforce | observe
	Strict      *bool             `yaml:"strict"`
	DefaultTier Tier              `yaml:"default_tier"`
	OnError     string            `yaml:"on_error"` // auto | block | allow
	LogPath     string            `yaml:"log_path"`
	NameHints   *bool             `yaml:"name_hints"`
	Aliases     map[string]string `yaml:"aliases"`

	Environments   []Environment `yaml:"environments"`
	PlanGate       PlanGate      `yaml:"plan_gate"`
	Preflight      Preflight     `yaml:"preflight"`
	ProtectedPaths []string      `yaml:"protected_paths"`
	// Wrappers are extra programs that run the command in their arguments
	// (a team's own credential or environment runner), so seatbelt
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

func (c *Config) IsStrict() bool        { return on(c.Strict, true) }
func (c *Config) UseNameHints() bool    { return on(c.NameHints, true) }
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
	"**/.seatbelt.yaml", "**/.seatbelt.yml", "**/.config/seatbelt/**", "**/.local/state/seatbelt/**",
	"**/.cursor/hooks.json",
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{Version: 1, Mode: "enforce", OnError: "auto", Aliases: map[string]string{"tf": "terraform"}}
}

// UserPath returns the user-level config path.
func UserPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "seatbelt", "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "seatbelt", "config.yaml")
}

// DefaultLogPath returns the decision log path, outside any repository.
func DefaultLogPath() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "seatbelt", "decisions.jsonl")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "seatbelt", "decisions.jsonl")
}

// FindRepoConfig walks up from dir to find .seatbelt.yaml.
func FindRepoConfig(dir string) string {
	for d := dir; d != "" && d != "/" && d != "."; d = filepath.Dir(d) {
		p := filepath.Join(d, FileName)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
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
	return out
}

// Signals are what preflight knows about where a command runs.
type Signals struct {
	Dir        string
	Workspace  string
	Backend    string // "s3://bucket/key" or "local" or ""
	AWSProfile string
	AWSAccount string
	// BackendConfig is the -backend-config file or value an init in the
	// same command points at; only used for name hints.
	BackendConfig string
}

// Resolution is the outcome of tier resolution.
type Resolution struct {
	Tier    Tier
	Env     string   // environment name, or "unknown"
	Matched []string // which signals matched, for messages
	Unknown bool
}

var prodHint = regexp.MustCompile(`(?i)(^|[/_.:\-])(prod|production|prd|live)($|[/_.:\-])`)

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
	}
	if c.UseNameHints() {
		rel := s.Dir
		if c.Root != "" {
			if r, err := filepath.Rel(c.Root, s.Dir); err == nil && !strings.HasPrefix(r, "..") {
				rel = r
			}
		}
		for _, h := range []struct{ what, v string }{{"path", rel}, {"workspace", s.Workspace}, {"backend", s.Backend}, {"AWS profile", s.AWSProfile}, {"backend config", s.BackendConfig}} {
			if h.v != "" && prodHint.MatchString(h.v) {
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
