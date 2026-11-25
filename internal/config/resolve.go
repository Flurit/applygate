package config

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Flurit/applygate/internal/guard"
)

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
	// brings its own directory's environment.
	StateDirs []string
	// SourceDirs are local directories the configuration that runs comes
	// from (a terragrunt terraform.source or --source): their backend
	// block, and so their environment, may be the one used.
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
	// ByDefault is set when the tier is only the default for a directory
	// nothing names (protected under strict, default_tier otherwise): no
	// environment, name hint or unknown signal matched, and under a root
	// no environment could.
	ByDefault bool
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
					if guard.MatchGlob(q, d) || guard.MatchGlob(strings.TrimSuffix(q, "/**"), d) ||
						guard.MatchGlob(fq, fd) || guard.MatchGlob(strings.TrimSuffix(fq, "/**"), fd) {
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
			return Resolution{Tier: Protected, Env: "unknown", Unknown: true, ByDefault: true, Matched: []string{"no environment matched; strict mode treats it as protected"}}
		}
		t := c.DefaultTier
		if t == "" {
			t = Standard
		}
		return Resolution{Tier: t, Env: "unknown", Unknown: true, ByDefault: true, Matched: []string{"no environment matched; using default_tier " + string(t)}}
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
	return guard.MatchGlob(pattern, v)
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
	byDefault := best.ByDefault
	consider := func(env string, t Tier, why string) {
		if t.Rank() > best.Tier.Rank() {
			best = Resolution{Tier: t, Env: env, Matched: []string{why}}
		} else if t == best.Tier && !slices.Contains(best.Matched, why) {
			best.Matched = append(best.Matched, why)
		}
	}
	// An environment that could match under the root at this tier or a
	// stricter one means the tier is no longer only the default.
	named := func(t Tier) {
		if t.Rank() >= best.Tier.Rank() {
			byDefault = false
		}
	}
	covered := false
	for _, e := range c.Environments {
		m := e.Match
		for _, p := range m.Paths {
			if root != "" && globCouldMatchUnder(p, root) {
				named(e.Tier)
				consider(e.Name, e.Tier, "path "+p+" could match a directory under the root")
				if globCoversSubtree(p, root) {
					covered = true
				}
			}
		}
		if len(m.Workspaces)+len(m.Backends)+len(m.AWSProfiles)+len(m.AWSAccounts) > 0 {
			named(e.Tier)
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
	best.ByDefault = byDefault && best.Env == "unknown"
	best.Matched = append([]string{fmt.Sprintf("%s; judged at the most protected tier under %s (%s, tier %s)", why, root, best.Env, best.Tier)}, best.Matched...)
	return best
}

// globCouldMatchUnder reports whether a path glob can match root or some
// directory under it. Patterns are compared segment by segment, as
// guard.MatchGlob does; a pattern starting with ** or without a leading
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
		if guard.MatchGlob(prefix, d) {
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
