package shell

import (
	"strings"
	"testing"
)

func analyze(cmd, dir string) *Result {
	return Analyze(cmd, Options{Dir: dir, Env: map[string]string{"HOME": "/home/u"}, ReadFile: func(string) ([]byte, error) { return nil, errNone{} }})
}

type errNone struct{}

func (errNone) Error() string { return "none" }

// dirOf returns the directory of the last invocation of prog, "?" if none.
func dirOf(r *Result, prog string) string {
	d := "?"
	for _, inv := range r.Invocations {
		if len(inv.Args) > 0 && inv.Args[0].Text == prog {
			d = inv.Dir
		}
	}
	return d
}

func TestZshCdWithTwoOperandsIsUnknown(t *testing.T) {
	for _, cmd := range []string{"cd envs/dev envs/prod && terraform destroy", "pushd envs/dev envs/prod && terraform destroy", "cd -P envs/dev envs/prod && terraform destroy"} {
		if d := dirOf(analyze(cmd, "/r/envs/dev"), "terraform"); d != "" {
			t.Errorf("%s: directory %q, want unknown", cmd, d)
		}
	}
	if d := dirOf(analyze("cd ../prod && terraform plan", "/r/envs/dev"), "terraform"); d != "/r/envs/prod" {
		t.Errorf("a single operand: %q", d)
	}
	if d := dirOf(analyze("cd -- ../prod && terraform plan", "/r/envs/dev"), "terraform"); d != "/r/envs/prod" {
		t.Errorf("cd -- DIR: %q", d)
	}
}

func TestRedirectBraceExpansionAndClobber(t *testing.T) {
	targets := func(cmd string) []string {
		var out []string
		for _, inv := range analyze(cmd, "/r/envs/prod").Invocations {
			for _, r := range inv.Redirs {
				if r.Write {
					out = append(out, r.Target.Text)
				}
			}
		}
		return out
	}
	if got := strings.Join(targets("echo x > f{,.bak}"), ","); got != "f,f.bak" {
		t.Errorf("brace redirect: %q", got)
	}
	for _, cmd := range []string{"echo x >! f", "echo x >>! f", "echo x >&! f", "echo x &>! f", "echo >! f x"} {
		got := targets(cmd)
		if len(got) != 1 || got[0] != "f" {
			t.Errorf("%s: write targets %v", cmd, got)
		}
	}
	// The file is no longer an argument of echo.
	for _, inv := range analyze("echo a >! f", "/r").Invocations {
		if len(inv.Args) > 0 && inv.Args[0].Text == "echo" && len(inv.Args) != 2 {
			t.Errorf("the clobber target stayed an argument: %v", inv.Args)
		}
	}
}

func TestTildeForms(t *testing.T) {
	for _, c := range []struct{ cmd, want string }{{"rm ~+/x", "/r/envs/prod/x"}, {"rm ~+", "/r/envs/prod"}} {
		var got string
		for _, inv := range analyze(c.cmd, "/r/envs/prod").Invocations {
			if len(inv.Args) > 1 && inv.Args[0].Text == "rm" && inv.Args[1].Resolved {
				got = inv.Args[1].Text
			}
		}
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.cmd, got, c.want)
		}
	}
	for _, cmd := range []string{"rm ~-", "rm ~root/x", "rm ~1"} {
		for _, inv := range analyze(cmd, "/r/envs/prod").Invocations {
			if len(inv.Args) > 1 && inv.Args[0].Text == "rm" && inv.Args[1].Resolved {
				t.Errorf("%s: resolved to %q", cmd, inv.Args[1].Text)
			}
		}
	}
}

func TestUnreportedBaseDirectory(t *testing.T) {
	a := func(cmd string) *Result {
		return Analyze(cmd, Options{Dir: "/r", UnknownBase: true, Env: map[string]string{}, ReadFile: func(string) ([]byte, error) { return nil, errNone{} }})
	}
	if d := dirOf(a("cd envs/dev && terraform plan"), "terraform"); d != "" {
		t.Errorf("relative cd: %q", d)
	}
	if d := dirOf(a("cd /r/envs/dev && terraform plan"), "terraform"); d != "/r/envs/dev" {
		t.Errorf("absolute cd: %q", d)
	}
	if d := dirOf(a("cd /r/envs && cd dev && terraform plan"), "terraform"); d != "/r/envs/dev" {
		t.Errorf("relative cd after an absolute one: %q", d)
	}
	if d := dirOf(a("env -C envs/dev terraform plan"), "terraform"); d != "" {
		t.Errorf("env -C relative: %q", d)
	}
	if inv := a("terraform plan").Invocations; len(inv) != 1 || !inv[0].Approx {
		t.Errorf("the plain command is not marked approximate: %+v", inv)
	}
}

func TestDevRunnersLoadAnUnknownEnvironment(t *testing.T) {
	for _, cmd := range []string{"devbox run -- terraform plan", "direnv exec . terraform plan", "mise exec -- terraform plan", "asdf exec terraform plan", "nix develop -c terraform plan"} {
		found := false
		for _, inv := range analyze(cmd, "/r/envs/dev").Invocations {
			if len(inv.Args) > 0 && inv.Args[0].Text == "terraform" {
				if v, ok := inv.Env["AWS_PROFILE"]; ok && v == "" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s: AWS_PROFILE is not unknown", cmd)
		}
	}
}

func TestGitCommandOptionsInClustersAndPrefixes(t *testing.T) {
	for _, cmd := range []string{
		"git rebase -qx 'terraform destroy' HEAD~1", "git rebase --exe 'terraform destroy' HEAD~1", "git difftool -yx 'terraform destroy' HEAD",
		"git difftool --extc='terraform destroy' HEAD", "git grep --open-f='terraform destroy' x", "git filter-branch --tree-f 'terraform destroy' HEAD",
		"git rebase -x 'terraform destroy' HEAD~1",
	} {
		if d := dirOf(analyze(cmd, "/r/envs/prod"), "terraform"); d == "?" {
			t.Errorf("%s: the command was not followed", cmd)
		}
	}
}

func TestHugeCommandIsNotParsed(t *testing.T) {
	r := Analyze("terraform plan;"+strings.Repeat("a;", maxAnalyzeBytes), Options{Dir: "/r", Env: map[string]string{}})
	if len(r.Problems) == 0 {
		t.Error("an over-size command was parsed")
	}
}

func TestKnownProgram(t *testing.T) {
	for _, n := range []string{"cd", "rm", "terraform", "curl", "yq", "pnpm", "eval"} {
		if !KnownProgram(n) {
			t.Errorf("%s is known", n)
		}
	}
	if KnownProgram("company-run") {
		t.Error("company-run is not known")
	}
}

func TestYqSystemOperatorIsNotPlain(t *testing.T) {
	cmd := "yq -n --security-enable-system-operator 'system(\"id\")'"
	if ok, _ := PlainShape(cmd, analyze(cmd, "/r")); ok {
		t.Error("yq with the system operator is plain")
	}
	plain := "yq '.a' x.yaml"
	if ok, why := PlainShape(plain, analyze(plain, "/r")); !ok {
		t.Errorf("an ordinary yq is not plain: %s", why)
	}
}
