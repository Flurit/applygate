package config

import (
	"os"
	"path/filepath"
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
}

func TestRepoConfigCannotEnableNetworkOrMoveLog(t *testing.T) {
	c := load(t, "log_path: /tmp/elsewhere.jsonl\npreflight: {live_identity: true}\n")
	if c.LogPath != "" || c.Preflight.LiveIdentity {
		t.Fatalf("repo config changed user-only settings: log %q live %v", c.LogPath, c.Preflight.LiveIdentity)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("mdoe: observe\n"), 0o644)
	if _, err := Load("", dir); err == nil {
		t.Fatal("typo in config was accepted")
	}
}
