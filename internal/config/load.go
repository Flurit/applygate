package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/safefile"
	"github.com/Flurit/applygate/internal/shell"
)

// UserPath returns the user-level config path. A config left at the
// pre-rename location (~/.config/seatbelt/config.yaml) is not read.
func UserPath() string { return userPathFor("applygate") }

// UserDir is the applygate user configuration directory.
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
// log left at the pre-rename location (~/.local/state/seatbelt) is not read.
func DefaultLogPath() string { return logPathFor("applygate") }

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

// FindRepoConfig walks up from dir to find .applygate.yaml.
func FindRepoConfig(dir string) string {
	for d := dir; d != "" && d != "/" && d != "."; d = filepath.Dir(d) {
		p := filepath.Join(d, FileName)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// legacyConfigNotes names each .seatbelt.yaml on the way up from dir that has
// no .applygate.yaml beside it. It is not read, so a repository that kept
// only the old name would otherwise look like one with no config.
func legacyConfigNotes(dir string) []string {
	var out []string
	for d := dir; d != "" && d != "."; d = filepath.Dir(d) {
		old := filepath.Join(d, LegacyFileName)
		if _, err := os.Lstat(old); err == nil {
			if _, err := os.Lstat(filepath.Join(d, FileName)); err != nil {
				out = append(out, old+" is not read (the project was renamed from seatbelt): rename it to "+FileName+" and trust it again")
			}
		}
		if parent := filepath.Dir(d); parent == d {
			break
		}
	}
	return out
}

// RepoConfigs returns every repository config from the outermost ancestor
// of dir down to dir, outermost first. The ancestors are those of where dir
// really is, after symlinks: a directory reached through a link from outside
// the repository still gets the repository's config. Configs on the
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
		// Lstat: a symlink or other non-regular entry is listed too, so
		// that Load can refuse it rather than skip it.
		p := filepath.Join(d, FileName)
		if _, err := os.Lstat(p); err == nil {
			out = append([]string{p}, out...)
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
		cfg.NoRepoConfig = len(repoConfigs) == 0
		cfg.Deprecations = append(cfg.Deprecations, legacyConfigNotes(dir)...)
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
		// agent's user may neither turn it off nor name a command
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
