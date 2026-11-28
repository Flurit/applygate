// Package config loads applygate configuration and resolves environment tiers.
package config

import (
	"path"
	"time"
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
// seatbelt (2026-10-29). It is not read: Load notes one that has no
// .applygate.yaml beside it in Config.Deprecations, and it stays a protected
// guard file.
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
	// Deprecations holds notes for the person: a .seatbelt.yaml that is not
	// read, a setting a repository config may not make, a config that cannot
	// be read. doctor and check print them.
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
	// NoRepoConfig is set by Load when the directory it looked up has no
	// repository config at all, trusted or not. Strict shapes then ask only
	// about a command that names an infrastructure tool or a guard file
	// (ShapesByWord).
	NoRepoConfig bool `yaml:"-"`
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
func (c *Config) UseNameHints() bool   { return on(c.NameHints, true) }
func (c *Config) StrictShapesOn() bool { return on(c.StrictShapes, true) }

// ShapesByWord reports whether strict shapes, in a directory that is
// protected only because no environment names it, ask about a command that
// is not plain only when it names an infrastructure tool or a guard file.
// That is the default in a repository with no config: nobody chose
// strictness there, and development work (tests, builds, one-line scripts)
// is not plain. strict_shapes: true in any config, a repository config
// (trusted or not) and a managed install keep the full rule.
func (c *Config) ShapesByWord() bool {
	return c.StrictShapes == nil && c.NoRepoConfig && !Managed()
}
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

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{Version: 1, Mode: "enforce", OnError: "auto", UnknownDir: UnknownDirMostProtected, Aliases: map[string]string{"tf": "terraform"}}
}
