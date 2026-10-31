// Package suggest proposes a repository config from the decision log that
// observe mode collected: which directories ran Terraform, what their names
// say about the environment, which workspaces, backends and AWS profiles were
// seen, and which asks and blocks a reviewer should look at. It never
// decides a tier for a directory whose name says nothing; those stay
// commented out, and strict mode keeps them protected until a person picks.
package suggest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

// Options select the log entries and the baseline.
type Options struct {
	// Root is the absolute repository root. Actions that ran outside it are
	// ignored, so one user log serves several repositories.
	Root string
	// Existing is the repository config already in place, or nil. Its
	// environments are kept and directories they cover are not proposed
	// again.
	Existing *config.Config
	// Now is the time written in the header; zero means time.Now().
	Now time.Time
}

// Env is a proposed or carried-over environment.
type Env struct {
	Name       string
	Tier       config.Tier
	Paths      []string // globs relative to the config file
	Workspaces []string
	Backends   []string
	Profiles   []string
	// Clusters and clouds: kube contexts, GCP projects, Azure subscriptions.
	KubeContexts       []string
	GCPProjects        []string
	AzureSubscriptions []string
	Evidence           []string // "12 in examples/simple": engine commands per directory
	Existing           bool     // carried over from Options.Existing
}

// DirUse is a directory where the engine ran.
type DirUse struct {
	Rel  string
	Runs int
}

// Flag is one group of asks or blocks worth a reviewer's look.
type Flag struct {
	Class   classify.Class
	Verdict policy.Verdict
	Command string
	Count   int
	Tier    config.Tier
	Env     string
	Advice  string
}

// Proposal is what Build derives from the log.
type Proposal struct {
	Root      string
	Entries   int // entries read
	InScope   int // entries that ran in Root
	WouldFlag int // in-scope entries whose policy verdict was ask or block
	From, To  time.Time
	Agents    []string
	Now       time.Time
	Existing  *config.Config

	Envs         []Env
	Unclassified []DirUse // engine ran there, the name says nothing
	RootRuns     int      // engine commands at the root itself
	Loose        []string // workspaces, backends and profiles seen without a hint
	Wrappers     []string // programs asked about as unknown wrappers
	Flags        []Flag
}

// Name hints beyond the production words config.LooksProd knows. A word is
// a whole component of a path, workspace, backend or profile between the
// separators / _ . : - (the same rule as the production hint).
var (
	standardWords   = map[string]bool{"staging": true, "stage": true, "stg": true, "uat": true, "preprod": true, "qa": true, "nonprod": true, "int": true, "integration": true, "perf": true}
	disposableWords = map[string]bool{"dev": true, "development": true, "sandbox": true, "sbx": true, "test": true, "tests": true, "testing": true, "example": true, "examples": true, "demo": true, "scratch": true, "playground": true, "tmp": true, "local": true}
	separators      = "/_.:-"
)

// hint classifies one value by its words. ok is false when no word says
// anything. Production wins over the others, as it does in the gate.
func hint(v string) (config.Tier, bool) {
	if config.LooksProd(v) {
		return config.Protected, true
	}
	words := strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return strings.ContainsRune(separators, r) })
	tier, ok := config.Tier(""), false
	for i, w := range words {
		switch {
		case standardWords[w], (w == "prod" || w == "production") && i > 0 && (words[i-1] == "non" || words[i-1] == "pre" || words[i-1] == "not"):
			// non-prod, pre-prod and the staging words: a place that stands in
			// for production but is not it.
			if !ok || tier == config.Disposable {
				tier, ok = config.Standard, true
			}
		case disposableWords[w]:
			if !ok {
				tier, ok = config.Disposable, true
			}
		}
	}
	return tier, ok
}

// dirHint finds the path component that names the environment for a
// directory relative to the root. It returns the glob prefix up to that
// component, the component itself as a name, and the tier. The most
// protected component wins; among equals the shallowest.
func dirHint(rel string) (glob, name string, tier config.Tier, ok bool) {
	parts := strings.Split(rel, "/")
	best := -1
	for i, p := range parts {
		t, h := hint(p)
		if !h {
			continue
		}
		if best < 0 || t.Rank() > tier.Rank() {
			best, tier = i, t
		}
	}
	if best < 0 {
		return "", "", "", false
	}
	return strings.Join(parts[:best+1], "/") + "/**", strings.ToLower(parts[best]), tier, true
}

// Build derives a proposal from log entries.
func Build(entries []decisionlog.Entry, opts Options) *Proposal {
	root := filepath.Clean(opts.Root)
	p := &Proposal{Root: root, Entries: len(entries), Now: opts.Now, Existing: opts.Existing}
	if p.Now.IsZero() {
		p.Now = time.Now()
	}
	under := func(dir string) (string, bool) {
		if dir == "" {
			return "", false
		}
		dir = filepath.Clean(dir)
		if dir == root {
			return ".", true
		}
		if strings.HasPrefix(dir, root+string(filepath.Separator)) {
			return filepath.ToSlash(dir[len(root)+1:]), true
		}
		return "", false
	}
	covered := func(dir string) bool {
		if opts.Existing == nil {
			return false
		}
		r := opts.Existing.Resolve(config.Signals{Dir: dir})
		return !r.Unknown && !strings.Contains(r.Env, "name hint")
	}

	dirs := map[string]int{}
	agents := map[string]bool{}
	type sig struct{ kind, value, dir string }
	sigs := map[sig]int{}
	type flagKey struct {
		class   classify.Class
		verdict policy.Verdict
		command string
	}
	flags := map[flagKey]*Flag{}
	wrappers := map[string]bool{}

	for _, e := range entries {
		in := false
		if _, ok := under(e.Cwd); ok {
			in = true
		}
		for _, a := range e.Actions {
			rel, ok := under(a.Dir)
			if !ok {
				continue
			}
			in = true
			if a.Engine != "" {
				if rel == "." {
					p.RootRuns++
				} else if !covered(a.Dir) {
					dirs[rel]++
				}
			}
			if a.Workspace != "" && a.Workspace != "default" {
				sigs[sig{"workspace", a.Workspace, rel}]++
			}
			if strings.HasPrefix(a.Backend, "s3://") {
				sigs[sig{"backend", a.Backend, rel}]++
			}
			if a.Profile != "" {
				sigs[sig{"profile", a.Profile, rel}]++
			}
			if a.KubeContext != "" {
				sigs[sig{"kube context", a.KubeContext, rel}]++
			}
			if a.GCPProject != "" {
				sigs[sig{"GCP project", a.GCPProject, rel}]++
			}
			if a.AzureSubscription != "" {
				sigs[sig{"Azure subscription", a.AzureSubscription, rel}]++
			}
			if a.Verdict != policy.Allow {
				k := flagKey{a.Class, a.Verdict, shorten(a.Command, 100)}
				f := flags[k]
				if f == nil {
					f = &Flag{Class: a.Class, Verdict: a.Verdict, Command: k.command, Tier: a.Tier, Env: a.Env}
					flags[k] = f
				}
				f.Count++
				if a.Class == classify.UnknownWrapper {
					if fields := strings.Fields(a.Command); len(fields) > 0 {
						wrappers[filepath.Base(fields[0])] = true
					}
				}
			}
		}
		if !in {
			continue
		}
		p.InScope++
		if e.Verdict != policy.Allow {
			p.WouldFlag++
		}
		if e.Agent != "" {
			agents[e.Agent] = true
		}
		if p.From.IsZero() || e.Time.Before(p.From) {
			p.From = e.Time
		}
		if e.Time.After(p.To) {
			p.To = e.Time
		}
	}
	for a := range agents {
		p.Agents = append(p.Agents, a)
	}
	sort.Strings(p.Agents)

	// Existing environments come first, as they are.
	envs := map[string]*Env{}
	var order []string
	add := func(name string, tier config.Tier) *Env {
		key := name + "/" + string(tier)
		if e := envs[key]; e != nil {
			return e
		}
		e := &Env{Name: name, Tier: tier}
		envs[key] = e
		order = append(order, key)
		return e
	}
	if opts.Existing != nil {
		for _, x := range opts.Existing.Environments {
			e := add(x.Name, x.Tier)
			e.Existing = true
			for _, path := range x.Match.Paths {
				rel := path
				if r, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(r, "..") {
					rel = filepath.ToSlash(r)
				}
				e.Paths = appendUnique(e.Paths, rel)
			}
			e.Workspaces = appendUnique(e.Workspaces, x.Match.Workspaces...)
			e.Backends = appendUnique(e.Backends, x.Match.Backends...)
			e.Profiles = appendUnique(e.Profiles, x.Match.AWSProfiles...)
			e.KubeContexts = appendUnique(e.KubeContexts, x.Match.KubeContexts...)
			e.GCPProjects = appendUnique(e.GCPProjects, x.Match.GCPProjects...)
			e.AzureSubscriptions = appendUnique(e.AzureSubscriptions, x.Match.AzureSubscriptions...)
		}
	}

	// Directories, most used first, so evidence lists read in that order.
	var rels []string
	for r := range dirs {
		rels = append(rels, r)
	}
	sort.Slice(rels, func(i, j int) bool {
		if dirs[rels[i]] != dirs[rels[j]] {
			return dirs[rels[i]] > dirs[rels[j]]
		}
		return rels[i] < rels[j]
	})
	unclassified := map[string]int{}
	for _, rel := range rels {
		glob, name, tier, ok := dirHint(rel)
		if !ok {
			unclassified[rel] = dirs[rel]
			continue
		}
		e := add(name, tier)
		e.Paths = appendUnique(e.Paths, glob)
		e.Evidence = append(e.Evidence, fmt.Sprintf("%d in %s", dirs[rel], rel))
	}
	// A directory under another unclassified one is covered by the
	// parent's glob, so its runs count towards the parent.
	for rel, n := range unclassified {
		for parent := filepath.Dir(rel); parent != "." && parent != "/"; parent = filepath.Dir(parent) {
			if _, ok := unclassified[parent]; ok {
				unclassified[parent] += n
				delete(unclassified, rel)
				break
			}
		}
	}
	for rel, n := range unclassified {
		p.Unclassified = append(p.Unclassified, DirUse{Rel: rel, Runs: n})
	}
	sort.Slice(p.Unclassified, func(i, j int) bool {
		a, b := p.Unclassified[i], p.Unclassified[j]
		if a.Runs != b.Runs {
			return a.Runs > b.Runs
		}
		return a.Rel < b.Rel
	})

	// Signals: a hinted value joins the environment of its tier and name; an
	// unhinted one is reported for the reviewer.
	var sigList []sig
	for s := range sigs {
		sigList = append(sigList, s)
	}
	sort.Slice(sigList, func(i, j int) bool {
		a, b := sigList[i], sigList[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.value != b.value {
			return a.value < b.value
		}
		return a.dir < b.dir
	})
	seenLoose := map[string]bool{}
	for _, s := range sigList {
		tier, ok := hint(s.value)
		if !ok {
			line := fmt.Sprintf("%s %s seen in %s", s.kind, s.value, s.dir)
			if !seenLoose[s.kind+s.value] {
				seenLoose[s.kind+s.value] = true
				p.Loose = append(p.Loose, line)
			}
			continue
		}
		e := envFor(envs, order, tier)
		if e == nil {
			e = add(envName(s.value, tier), tier)
		}
		switch s.kind {
		case "workspace":
			e.Workspaces = appendUnique(e.Workspaces, s.value)
		case "backend":
			e.Backends = appendUnique(e.Backends, s.value)
		case "profile":
			e.Profiles = appendUnique(e.Profiles, s.value)
		case "kube context":
			e.KubeContexts = appendUnique(e.KubeContexts, s.value)
		case "GCP project":
			e.GCPProjects = appendUnique(e.GCPProjects, s.value)
		case "Azure subscription":
			e.AzureSubscriptions = appendUnique(e.AzureSubscriptions, s.value)
		}
	}

	for _, k := range order {
		p.Envs = append(p.Envs, *envs[k])
	}
	// Proposed environments after the existing ones, most protected first.
	sort.SliceStable(p.Envs, func(i, j int) bool {
		a, b := p.Envs[i], p.Envs[j]
		if a.Existing != b.Existing {
			return a.Existing
		}
		if a.Existing {
			return false
		}
		return a.Tier.Rank() > b.Tier.Rank()
	})

	for w := range wrappers {
		p.Wrappers = append(p.Wrappers, w)
	}
	sort.Strings(p.Wrappers)
	for _, f := range flags {
		f.Advice = advice(*f)
		p.Flags = append(p.Flags, *f)
	}
	sort.Slice(p.Flags, func(i, j int) bool {
		a, b := p.Flags[i], p.Flags[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Command < b.Command
	})
	return p
}

// envFor returns the first environment of a tier that a hinted signal can
// join: a proposed one by preference, else an existing one.
func envFor(envs map[string]*Env, order []string, tier config.Tier) *Env {
	var existing *Env
	for _, k := range order {
		e := envs[k]
		if e.Tier != tier {
			continue
		}
		if !e.Existing {
			return e
		}
		if existing == nil {
			existing = e
		}
	}
	return existing
}

// envName names an environment created for a hinted workspace, backend or
// profile: the hinted word itself.
func envName(v string, tier config.Tier) string {
	words := strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return strings.ContainsRune(separators, r) })
	for _, w := range words {
		if t, ok := hint(w); ok && t == tier {
			return w
		}
	}
	return string(tier)
}

func advice(f Flag) string {
	var parts []string
	if f.Env == "unknown" {
		parts = append(parts, "judged as "+string(f.Tier)+" because no environment matched; the environments above decide it")
	}
	switch f.Class {
	case classify.UnknownWrapper:
		parts = append(parts, "a program ran the engine from its arguments; add it under wrappers if it is yours")
	case classify.Dynamic:
		parts = append(parts, "an interpreter was fed code that mentions Terraform or state; no config key changes this, and disposable tiers do not ask")
	case classify.StateSurgery:
		parts = append(parts, "init -migrate-state, a bare init -reconfigure and state rm/mv/push move state; they ask outside protected tiers and block inside them")
	case classify.ApplySavedPlan:
		parts = append(parts, "the plan gate found something in the saved plan; the log entry lists the findings")
	case classify.Destroy, classify.UnreviewedApply, classify.CloudDestructive:
		parts = append(parts, "this is what the gate is for; expected")
	case classify.Tampering:
		parts = append(parts, "an edit to a hook, config or log file; always blocked")
	default:
		parts = append(parts, "see docs/policy.md for the class")
	}
	return strings.Join(parts, "; ")
}

// YAML renders the proposal as a .applygate.yaml with the evidence in
// comments. The result parses as a config (see Check).
func (p *Proposal) YAML() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# .applygate.yaml proposed by \"applygate suggest\" on %s from %d logged decisions,\n", p.Now.UTC().Format("2006-01-02"), p.Entries)
	span := ""
	if !p.From.IsZero() {
		span = fmt.Sprintf(", %s to %s UTC", p.From.UTC().Format("2006-01-02 15:04"), p.To.UTC().Format("2006-01-02 15:04"))
	}
	w("# %d of them in %s (agents: %s%s).\n", p.InScope, p.Root, orNone(strings.Join(p.Agents, ", ")), span)
	w("# Tiers are guessed from names. Check every one before switching to enforce.\n")
	w("version: 1\n")
	mode, strict, onError := "observe", "true", "auto"
	if x := p.Existing; x != nil {
		mode = x.Mode
		if !x.IsStrict() {
			strict = "false"
		}
		onError = x.OnError
	}
	w("mode: %s%s\n", mode, pad(mode, 8)+fmt.Sprintf("# %d of %d decisions would have asked or blocked; see the list at the end", p.WouldFlag, p.InScope))
	w("strict: %s%s\n", strict, pad(strict, 6)+"# an unmatched directory is protected")
	w("on_error: %s\n", onError)
	if x := p.Existing; x != nil && x.DefaultTier != "" {
		w("default_tier: %s\n", x.DefaultTier)
	}

	if len(p.Envs) > 0 {
		w("environments:\n")
		for _, e := range p.Envs {
			w("  - name: %s\n", e.Name)
			note := "# guessed from the name; confirm"
			if e.Existing {
				note = "# from the existing config"
			}
			w("    tier: %s%s\n", e.Tier, pad(string(e.Tier), 10)+note)
			w("    match:\n")
			if len(e.Paths) > 0 {
				ev := ""
				if len(e.Evidence) > 0 {
					ev = "   # engine commands: " + strings.Join(e.Evidence, ", ")
				}
				w("      paths: %s%s\n", list(e.Paths), ev)
			}
			if len(e.Workspaces) > 0 {
				w("      workspaces: %s\n", list(e.Workspaces))
			}
			if len(e.Backends) > 0 {
				w("      backends: %s\n", list(e.Backends))
			}
			if len(e.Profiles) > 0 {
				w("      aws_profiles: %s\n", list(e.Profiles))
			}
			if len(e.KubeContexts) > 0 {
				w("      kube_contexts: %s\n", list(e.KubeContexts))
			}
			if len(e.GCPProjects) > 0 {
				w("      gcp_projects: %s\n", list(e.GCPProjects))
			}
			if len(e.AzureSubscriptions) > 0 {
				w("      azure_subscriptions: %s\n", list(e.AzureSubscriptions))
			}
		}
	} else if len(p.Unclassified) > 0 {
		w("environments:   # none proposed; the directories below need a tier from you\n")
	} else {
		w("environments: []\n")
	}
	if len(p.Unclassified) > 0 {
		w("# Directories where the engine ran and whose names say nothing about the\n")
		w("# environment. Strict mode treats them as protected until you give each a\n")
		w("# tier: move the ones you choose under environments.\n")
		for _, d := range p.Unclassified {
			w("#  - name: %s\n", filepath.Base(d.Rel))
			w("#    tier: protected | standard | disposable\n")
			w("#    match: {paths: [%s]}   # %d engine command%s\n", q(d.Rel+"/**"), d.Runs, plural(d.Runs))
		}
	}
	if p.RootRuns > 0 {
		w("# The engine ran %d time%s at the repository root itself; the root takes the\n", p.RootRuns, plural(p.RootRuns))
		w("# default tier (protected under strict), which no paths glob should override.\n")
	}
	if len(p.Loose) > 0 {
		w("# Signals seen without a name hint; add the ones that identify an environment\n")
		w("# to its match (workspaces, backends, aws_profiles, kube_contexts, gcp_projects,\n")
		w("# azure_subscriptions):\n")
		for _, l := range p.Loose {
			w("#   %s\n", l)
		}
	}

	w("plan_gate:\n")
	maxDestroy := map[config.Tier]int{config.Protected: 0}
	if x := p.Existing; x != nil && len(x.PlanGate.MaxDestroy) > 0 {
		maxDestroy = x.PlanGate.MaxDestroy
	}
	var md []string
	for _, t := range []config.Tier{config.Protected, config.Standard, config.Disposable} {
		if v, ok := maxDestroy[t]; ok {
			md = append(md, fmt.Sprintf("%s: %d", t, v))
		}
	}
	w("  max_destroy: {%s}\n", strings.Join(md, ", "))
	if x := p.Existing; x != nil && len(x.ProtectedResources) > 0 {
		w("protected_resources: %s\n", list(x.ProtectedResources))
	} else {
		w("# protected_resources: [\"aws_instance.bastion\", \"module.data.*\"]   # address globs whose destroy is always critical\n")
	}
	if x := p.Existing; x != nil && len(x.Wrappers) > 0 {
		w("wrappers:\n")
		for _, wr := range x.Wrappers {
			w("  - {name: %s, skip: %d, profile_arg: %d}\n", wr.Name, wr.Skip, wr.ProfileArg)
		}
	}
	if len(p.Wrappers) > 0 {
		w("# Programs that ran the engine from their arguments and were asked about as\n")
		w("# unknown wrappers. If one is your team's runner, declare it:\n")
		w("# wrappers:\n")
		for _, name := range p.Wrappers {
			w("#   - {name: %s, skip: 1}   # the command starts after 1 positional argument, or after \"--\"\n", name)
		}
	}

	if len(p.Flags) > 0 {
		w("#\n# Asks and blocks in this repository, most frequent first. Each is a possible\n")
		w("# false positive to review before enforce:\n")
		for _, f := range p.Flags {
			w("#   %dx %-5s %-17s %s   [%s, %s]\n", f.Count, f.Verdict, f.Class, f.Command, f.Tier, orNone(f.Env))
			w("#      -> %s\n", f.Advice)
		}
	} else if p.InScope > 0 {
		w("#\n# No asks or blocks in this repository.\n")
	}
	return b.String()
}

// Check parses the rendered YAML as a config and returns any error, so a
// proposal that would not load is never written.
func (p *Proposal) Check() error {
	dir, err := os.MkdirTemp("", "applygate-suggest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte(p.YAML()), 0o600); err != nil {
		return err
	}
	_, err = config.LoadFile(path)
	return err
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func list(vals []string) string {
	qs := make([]string, len(vals))
	for i, v := range vals {
		qs[i] = q(v)
	}
	return "[" + strings.Join(qs, ", ") + "]"
}

// q quotes a YAML double-quoted scalar.
func q(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func pad(s string, width int) string {
	if n := width - len(s); n > 0 {
		return strings.Repeat(" ", n)
	}
	return " "
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
