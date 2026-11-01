package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) *Config {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResolve(t *testing.T) {
	c := load(t, `
environments:
  - {name: prod, tier: protected, match: {paths: ["envs/prod/**"], workspaces: [prod], aws_profiles: ["prod-*"]}}
  - {name: dev, tier: disposable, match: {paths: ["envs/dev/**"], workspaces: [dev]}}
`)
	root := c.Root
	cases := []struct {
		s    Signals
		tier Tier
		env  string
	}{
		{Signals{Dir: root + "/envs/prod"}, Protected, "prod"},
		{Signals{Dir: root + "/envs/prod/modules/db"}, Protected, "prod"},
		{Signals{Dir: root + "/envs/dev"}, Disposable, "dev"},
		// The most protected match wins: dev directory, prod profile.
		{Signals{Dir: root + "/envs/dev", AWSProfile: "prod-admin"}, Protected, "prod"},
		{Signals{Dir: root + "/envs/dev", Workspace: "prod"}, Protected, "prod"},
		// Unknown in strict mode is protected.
		{Signals{Dir: root + "/other"}, Protected, "unknown"},
		// Name hint: production-looking workspace with no config match.
		{Signals{Dir: root + "/other", Workspace: "production"}, Protected, "prod (name hint)"},
		// "products" is not "prod".
		{Signals{Dir: root + "/products"}, Protected, "unknown"},
		// A negated word is not a hint: non-prod stays unknown here, and
		// the configured standard environment wins where one exists.
		{Signals{Dir: root + "/non-prod/us-east-1/qa"}, Protected, "unknown"},
		{Signals{Dir: root + "/other", Workspace: "pre-prod"}, Protected, "unknown"},
		{Signals{Dir: root + "/other", Workspace: "prod-like"}, Protected, "unknown"},
		// The config's own globs are not name hints: prod-* matches prod-like.
		{Signals{Dir: root + "/other", AWSProfile: "prod-like"}, Protected, "prod"},
		// A real prod segment after a negated one still counts.
		{Signals{Dir: root + "/non-prod/us-east-1/prod"}, Protected, "prod (name hint)"},
	}
	for _, x := range cases {
		r := c.Resolve(x.s)
		if r.Tier != x.tier || r.Env != x.env {
			t.Errorf("%+v: got %s/%s, want %s/%s (%v)", x.s, r.Tier, r.Env, x.tier, x.env, r.Matched)
		}
	}
	nonStrict := load(t, "strict: false\ndefault_tier: standard\n")
	if r := nonStrict.Resolve(Signals{Dir: "/x/y"}); r.Tier != Standard {
		t.Errorf("non-strict unknown: %s", r.Tier)
	}
	// The trial config: non-prod/** is standard, prod/** is protected. The
	// name hint used to turn non-prod into "prod (name hint)" (protected).
	trial := load(t, `
environments:
  - {name: prod, tier: protected, match: {paths: ["prod/**"]}}
  - {name: non-prod, tier: standard, match: {paths: ["non-prod/**"]}}
`)
	for dir, want := range map[string]struct {
		tier Tier
		env  string
	}{
		"/non-prod/us-east-1/qa":                 {Standard, "non-prod"},
		"/non-prod/us-east-1/stage/webserver":    {Standard, "non-prod"},
		"/prod/us-east-1/prod/mysql":             {Protected, "prod"},
		"/non-prod/us-east-1/prod/mysql-replica": {Protected, "prod (name hint)"},
	} {
		r := trial.Resolve(Signals{Dir: trial.Root + dir})
		if r.Tier != want.tier || r.Env != want.env {
			t.Errorf("%s: got %s/%s, want %s/%s (%v)", dir, r.Tier, r.Env, want.tier, want.env, r.Matched)
		}
	}
}

func TestLooksProd(t *testing.T) {
	yes := []string{
		"prod", "my-prod", "production", "acme-prod-tfstate", "envs/prod", "PROD", "prd", "live",
		"s3://acme-tf-state-prod/key", "prod.backend", "prod:eu", "team_prod", "live-eu-west",
		// Only the adjacent words negate: a real prod segment deeper in a
		// non-prod path, or after a stand-in word, still counts.
		"non-prod/us-east-1/prod", "prod-like/prod", "prod-test-prod",
		"nonprod-live", "x-non-prod-prod",
	}
	no := []string{
		"non-prod", "nonprod", "preprod", "pre-prod", "prod-like", "NON-PROD", "non_prod", "non.prod",
		"not-prod", "no-prod", "pre_production", "non-production", "non-live", "pre-live", "nonproduction",
		"prod-test", "prod-sandbox", "prod_like", "products", "acme-products-tfstate", "reproduction",
		"non-prod/us-east-1/qa", "envs/pre-prod/eu", "staging", "",
	}
	for _, v := range yes {
		if !LooksProd(v) {
			t.Errorf("%q should look like production", v)
		}
	}
	for _, v := range no {
		if LooksProd(v) {
			t.Errorf("%q should not look like production", v)
		}
	}
}

func TestRepoConfigCannotEnableNetworkOrMoveLog(t *testing.T) {
	c := load(t, "log_path: /tmp/elsewhere.jsonl\npreflight: {live_identity: true, live_state: true}\n")
	if c.LogPath != "" || c.Preflight.LiveIdentity || c.Preflight.LiveState {
		t.Fatalf("repo config changed user-only settings: log %q live %v state %v", c.LogPath, c.Preflight.LiveIdentity, c.Preflight.LiveState)
	}
}

func TestProtectedResources(t *testing.T) {
	c := load(t, "protected_resources: [\"aws_instance.bastion\", \"module.data.*\"]\n")
	if len(c.ProtectedResources) != 2 || c.ProtectedResources[1] != "module.data.*" {
		t.Fatalf("protected_resources: %v", c.ProtectedResources)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("mdoe: observe\n"), 0o644)
	if _, err := Load("", dir); err == nil {
		t.Fatal("typo in config was accepted")
	}
}

func TestWrappersConfig(t *testing.T) {
	c := load(t, "wrappers:\n  - {name: company-run, skip: 1, profile_arg: 1}\n  - {name: tfw}\n")
	w := c.ShellWrappers()
	if len(w) != 2 || w["company-run"].Skip != 1 || w["company-run"].ProfileArg != 1 || w["tfw"].Skip != 0 {
		t.Fatalf("wrappers = %+v", w)
	}
	for _, bad := range []string{"wrappers: [{name: \"\"}]", "wrappers: [{name: a/b}]", "wrappers: [{name: x, skip: -1}]", "wrappers: [{name: x, skip: 1, profile_arg: 2}]"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, FileName), []byte(bad+"\n"), 0o644)
		if _, err := Load("", dir); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBackendValueHints(t *testing.T) {
	c := load(t, "strict: false\ndefault_tier: standard\n")
	cases := []struct {
		values map[string]string
		want   Tier
	}{
		{map[string]string{"bucket": "acme-prod-tfstate"}, Protected},
		{map[string]string{"bucket": "acme-shared", "workspace_key_prefix": "production"}, Protected},
		{map[string]string{"bucket": "acme-shared", "dynamodb_table": "locks-prd"}, Protected},
		{map[string]string{"address": "https://state.example.com/live/app"}, Protected},
		{map[string]string{"bucket": "acme-products-tfstate", "key": "reproduce/terraform.tfstate"}, Standard},
		{map[string]string{"bucket": "acme-staging-tfstate", "workspace_key_prefix": "qa"}, Standard},
		// Keys outside the hint list are ignored.
		{map[string]string{"bucket": "acme-shared", "region": "prod-region-1"}, Standard},
	}
	for _, x := range cases {
		if r := c.Resolve(Signals{Dir: "/x/y", BackendValues: x.values}); r.Tier != x.want {
			t.Errorf("%v: got %s, want %s (%v)", x.values, r.Tier, x.want, r.Matched)
		}
	}
}

func TestResolveUnknownDir(t *testing.T) {
	c := load(t, `
strict: false
default_tier: standard
name_hints: false
environments:
  - {name: prod, tier: protected, match: {paths: ["envs/prod/**"]}}
  - {name: dev, tier: disposable, match: {paths: ["envs/dev/**"]}}
`)
	root := c.Root
	// The root could hold a prod directory: protected, with the reason first.
	r := c.ResolveUnknownDir("codex", root, Signals{})
	if r.Tier != Protected || r.Env != "prod" || !r.DirUnknown {
		t.Fatalf("root: %+v", r)
	}
	if r.Matched[0] != "command directory not reported by codex; judged at the most protected tier under "+root+" (prod, tier protected)" {
		t.Fatalf("matched: %v", r.Matched)
	}
	// Under envs/dev nothing protected can be reached, and dev/** covers the
	// subtree, so the default tier does not apply either.
	if r := c.ResolveUnknownDir("codex", root+"/envs/dev", Signals{}); r.Tier != Disposable || r.Env != "dev" {
		t.Fatalf("dev: %+v", r)
	}
	// Under envs/other only the default tier applies.
	if r := c.ResolveUnknownDir("codex", root+"/envs/other", Signals{}); r.Tier != Standard || r.Env != "unknown" {
		t.Fatalf("other: %+v", r)
	}
	// Known signals still count: a prod profile from the environment.
	c2 := load(t, "strict: false\ndefault_tier: disposable\nname_hints: false\nenvironments:\n  - {name: prod, tier: protected, match: {aws_profiles: [prod]}}\n")
	if r := c2.ResolveUnknownDir("codex", c2.Root, Signals{}); r.Tier != Protected {
		t.Fatalf("profile matcher: %+v", r)
	}
	// Strict mode: an unmatched directory under the root is protected.
	c3 := load(t, "environments:\n  - {name: dev, tier: disposable, match: {paths: [\"envs/dev/**\"]}}\n")
	if r := c3.ResolveUnknownDir("", c3.Root, Signals{}); r.Tier != Protected || !strings.HasPrefix(r.Matched[0], "command directory not reported by the host") {
		t.Fatalf("strict: %+v", r)
	}
}

func TestGlobCouldMatchUnder(t *testing.T) {
	cases := []struct {
		pattern, root string
		could, covers bool
	}{
		{"/r/envs/prod/**", "/r", true, false},
		{"/r/envs/prod/**", "/r/envs", true, false},
		{"/r/envs/prod/**", "/r/envs/prod", true, true},
		{"/r/envs/prod/**", "/r/envs/prod/modules", true, true},
		{"/r/envs/prod/**", "/r/envs/staging", false, false},
		{"/r/envs/prod", "/r/envs/prod/x", false, false},
		{"/r/envs/*/live", "/r/envs/a/x", false, false},
		{"/r/envs/*/live", "/r/envs/a", true, false},
		{"/r/**", "/r/a/b", true, true},
		{"**", "/anything", true, true},
		{"**/prod/**", "/r/a", true, false},
		{"**/prod/**", "/r/prod/a", true, true},
		{"/other/**", "/r", false, false},
	}
	for _, c := range cases {
		if got := globCouldMatchUnder(c.pattern, c.root); got != c.could {
			t.Errorf("could %q under %q: got %v want %v", c.pattern, c.root, got, c.could)
		}
		if got := globCoversSubtree(c.pattern, c.root); got != c.covers {
			t.Errorf("covers %q under %q: got %v want %v", c.pattern, c.root, got, c.covers)
		}
	}
}

func TestUnknownDirMerge(t *testing.T) {
	if c := load(t, "unknown_dir: session_root\n"); !c.UnknownDirMostProtected() {
		t.Fatal("a repository config must not loosen unknown_dir")
	}
	if _, err := LoadFile(func() string {
		p := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(p, []byte("unknown_dir: whatever\n"), 0o644)
		return p
	}()); err == nil || !strings.Contains(err.Error(), "unknown_dir") {
		t.Fatalf("bad value should be rejected: %v", err)
	}
}

// The project was renamed from seatbelt; a repository that still has
// .seatbelt.yaml is read with a deprecation note, and .applygate.yaml wins
// when both exist.
func TestLegacyConfigFileName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LegacyFileName), []byte("mode: observe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("", filepath.Join(dir))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" || len(cfg.Sources) != 1 || filepath.Base(cfg.Sources[0]) != LegacyFileName {
		t.Fatalf("legacy file not loaded: mode %s sources %v", cfg.Mode, cfg.Sources)
	}
	if len(cfg.Deprecations) != 1 || !strings.Contains(cfg.Deprecations[0], FileName) {
		t.Fatalf("want one deprecation naming %s, got %v", FileName, cfg.Deprecations)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("mode: enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "enforce" || len(cfg.Deprecations) != 0 || filepath.Base(cfg.Sources[0]) != FileName {
		t.Fatalf("new file should win silently: mode %s sources %v deprecations %v", cfg.Mode, cfg.Sources, cfg.Deprecations)
	}
	for _, p := range DefaultProtectedPaths {
		if p == "**/.seatbelt.yaml" {
			return
		}
	}
	t.Fatal("legacy config name is not in DefaultProtectedPaths")
}

func TestRepoConfigCanOnlyDisableApprovals(t *testing.T) {
	if c := load(t, "approvals: false\n"); c.ApprovalsOn() {
		t.Fatal("repo config could not turn approvals off")
	}
	off := false
	c := Default()
	c.Approvals = &off
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	os.WriteFile(p, []byte("version: 1\napprovals: true\n"), 0o644)
	if err := merge(c, p, true); err != nil {
		t.Fatal(err)
	}
	if c.ApprovalsOn() {
		t.Fatal("repo config turned approvals back on")
	}
}

func TestClusterAndCloudMatchers(t *testing.T) {
	c := load(t, `environments:
  - name: prod
    tier: protected
    match: {kube_contexts: ["eks-blue", "arn:aws:eks:*:111111111111:cluster/*"], gcp_projects: ["acme-payments-9f2"], azure_subscriptions: ["2222"]}
  - name: dev
    tier: disposable
    match: {paths: ["dev/**"], kube_contexts: ["kind-*"]}
`)
	dev := filepath.Join(c.Root, "dev")
	for _, s := range []Signals{
		{Dir: dev, KubeContext: "eks-blue"},
		{Dir: dev, KubeContext: "arn:aws:eks:us-east-1:111111111111:cluster/payments"},
		{Dir: dev, GCPProject: "acme-payments-9f2"},
		{Dir: dev, AzureSubscription: "Payments", AzureSubscriptionID: "2222"},
	} {
		if r := c.Resolve(s); r.Tier != Protected || r.Env != "prod" {
			t.Errorf("%+v: %+v", s, r)
		}
	}
	if r := c.Resolve(Signals{Dir: dev, KubeContext: "kind-dev"}); r.Tier != Disposable {
		t.Errorf("kind-dev: %+v", r)
	}
	if r := c.Resolve(Signals{Dir: dev, KubeContext: "gke_acme_us-east1_prod"}); r.Tier != Protected || r.Env != "prod (name hint)" {
		t.Errorf("name hint: %+v", r)
	}
}
