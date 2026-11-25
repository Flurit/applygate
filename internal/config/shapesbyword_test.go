package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShapesByWord(t *testing.T) {
	oldSys := SystemDir
	SystemDir = ""
	defer func() { SystemDir = oldSys }()
	base := t.TempDir()
	bare := filepath.Join(base, "work", "app")
	covered := filepath.Join(base, "team", "svc")
	os.MkdirAll(bare, 0o755)
	os.MkdirAll(covered, 0o755)
	os.WriteFile(filepath.Join(base, "team", FileName), []byte("mode: enforce\n"), 0o600)
	user := func(body string) string {
		p := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	load := func(userPath, dir string) *Config {
		t.Helper()
		c, err := Load(userPath, dir)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if c := load("", bare); !c.NoRepoConfig || !c.ShapesByWord() || !c.StrictShapesOn() {
		t.Errorf("no config: NoRepoConfig %v, ShapesByWord %v, StrictShapesOn %v; want all true", c.NoRepoConfig, c.ShapesByWord(), c.StrictShapesOn())
	}
	if c := load("", covered); c.NoRepoConfig || c.ShapesByWord() {
		t.Errorf("a repository config: NoRepoConfig %v, ShapesByWord %v; want both false", c.NoRepoConfig, c.ShapesByWord())
	}
	if c := load(user("strict_shapes: true\n"), bare); c.ShapesByWord() || !c.StrictShapesOn() {
		t.Errorf("strict_shapes: true: ShapesByWord %v, StrictShapesOn %v; want false, true", c.ShapesByWord(), c.StrictShapesOn())
	}
	if c := load(user("strict_shapes: false\n"), bare); c.ShapesByWord() || c.StrictShapesOn() {
		t.Errorf("strict_shapes: false: ShapesByWord %v, StrictShapesOn %v; want both false", c.ShapesByWord(), c.StrictShapesOn())
	}
	// A config built without Load (tests, the defaults) keeps the full rule.
	if Default().ShapesByWord() {
		t.Error("Default(): ShapesByWord is true; only Load, for a directory with no repository config, sets it")
	}
	// Under a managed install the full rule holds in every repository.
	SystemDir = filepath.Join(base, "etc")
	os.MkdirAll(SystemDir, 0o755)
	os.WriteFile(SystemPath(), []byte("mode: enforce\n"), 0o600)
	if c := load("", bare); !Managed() || c.ShapesByWord() {
		t.Errorf("managed install: Managed %v, ShapesByWord %v; want true, false", Managed(), c.ShapesByWord())
	}
}

func TestResolutionByDefault(t *testing.T) {
	c := Default()
	if r := c.Resolve(Signals{Dir: "/work/app"}); !r.ByDefault || r.Tier != Protected {
		t.Errorf("nothing names the directory: %+v; want ByDefault and protected", r)
	}
	if r := c.Resolve(Signals{Dir: "/work/prod"}); r.ByDefault {
		t.Errorf("a name hint: %+v; want not ByDefault", r)
	}
	if r := c.ResolveUnder("/work/app", Signals{}, "why"); !r.ByDefault {
		t.Errorf("under a root nothing names: %+v; want ByDefault", r)
	}
	c.Environments = []Environment{{Name: "payments", Tier: Protected, Match: Match{AWSProfiles: []string{"payments-admin"}}}}
	if r := c.Resolve(Signals{Dir: "/work/app"}); !r.ByDefault {
		t.Errorf("an environment that does not match this directory: %+v; want ByDefault", r)
	}
	if r := c.ResolveUnder("/work/app", Signals{}, "why"); r.ByDefault {
		t.Errorf("an environment a directory under the root could carry: %+v; want not ByDefault", r)
	}
	c.Environments = []Environment{{Name: "dev", Tier: Disposable, Match: Match{AWSProfiles: []string{"dev"}}}}
	if r := c.ResolveUnder("/work/app", Signals{}, "why"); !r.ByDefault {
		t.Errorf("a less protected environment under the root: %+v; want ByDefault", r)
	}
}
