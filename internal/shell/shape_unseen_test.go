package shell

import (
	"os"
	"testing"
)

// A command that is not plain only in its syntax is followed by the
// analysis; one that can run code it does not follow is not.
func TestPlainShapeUnseen(t *testing.T) {
	cases := []struct {
		cmd    string
		plain  bool
		unseen bool
	}{
		{"ls -la && cat main.tf | head -5", true, false},
		{"for f in a b; do wc -l $f; done", false, false},
		{"f() { ls; }; f", false, false},
		{"echo $((1+2))", false, false},
		{"x=5; [[ $x -gt 3 ]] && echo ok", false, false},
		{"echo hello | xargs -I{} echo {}", false, false},
		{"python3 -c 'print(1)'", false, true},
		{"for d in a b; do python3 -c 'print(1)'; done", false, true},
		{"perl -e 'system(\"ls\")'", false, true},
		{"awk 'BEGIN{system(\"ls\")}'", false, true},
		{"codex exec hi", false, true},
		{"ls $(", false, true},
		// Round 10: constructs whose shell semantics the analysis does not model.
		{"exec <<< 'terraform destroy'; bash", false, true},
		{"bash <> script.sh", false, true},
		{"echo x | tee >(bash)", false, true},
		{"bash --version", true, false},
		{"echo ls | bash", false, false},
		{"x='a[$(id)]'; echo ${!x}", false, true},
		{"x='$(id)'; echo ${x@P}", false, true},
		{"echo ${x@Q}", false, false},
		{"./tool.py terraform", false, true},
		{"foo terraform; foo -x", false, true},
		{"docker run --rm alpine sh -c 'terraform destroy'", false, true},
		{"docker run --rm hashicorp/terraform version; docker run --rm alpine true", false, true},
		{"echo a | xargs -0 bash -c", false, true},
		{"f() { echo; }; command f", false, true},
		{"alias terraform=echo; terraform plan", false, false},
		{"alias tf=terraform; tf plan", false, false},
	}
	for _, c := range cases {
		res := Analyze(c.cmd, Options{Dir: "/tmp", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
		ok, why, unseen := PlainShapeUnseen(c.cmd, res)
		if ok != c.plain || (unseen != "") != c.unseen {
			t.Errorf("%q: plain=%v (%s) unseen=%q, want plain=%v unseen=%v", c.cmd, ok, why, unseen, c.plain, c.unseen)
		}
	}
}

// make -j and -l take an optional number: in "make -j destroy" destroy is a
// target, and the analysis must read the Makefile's destroy, not its default.
func TestMakeJobsOptionIsOptional(t *testing.T) {
	files := map[string]string{"Makefile": "all:\n\t@echo hello\ndestroy:\n\tterraform destroy -auto-approve\n"}
	read := func(p string) ([]byte, error) {
		for k, v := range files {
			if p == "/w/"+k {
				return []byte(v), nil
			}
		}
		return nil, os.ErrNotExist
	}
	for _, cmd := range []string{"make -j destroy", "make -l destroy", "make -sj destroy", "make -j4 destroy", "make -j 4 destroy"} {
		res := Analyze(cmd, Options{Dir: "/w", ReadFile: read})
		found := false
		for _, inv := range res.Invocations {
			if len(inv.Args) > 0 && inv.Args[0].Text == "terraform" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: the destroy recipe was not read", cmd)
		}
	}
}

// The image of docker run is the first word after the options: a later word
// that mentions terraform is a path or a command in the container.
func TestContainerImageIsFirstWord(t *testing.T) {
	for _, cmd := range []string{
		"docker run --rm -v /p:/w alpine rm /w/terraform.tfstate",
		"docker run --rm alpine sh -c 'terraform destroy'",
		"docker exec ctr sh -c 'terraform destroy'",
	} {
		res := Analyze(cmd, Options{Dir: "/w", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
		for _, inv := range res.Invocations {
			if len(inv.Args) > 0 && inv.Args[0].Text == "terraform" {
				t.Errorf("%q: read as a terraform call: %v", cmd, inv.Via)
			}
		}
	}
	res := Analyze("docker run --rm -v /p:/w -w /w hashicorp/terraform:1.9 destroy", Options{Dir: "/w", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	found := false
	for _, inv := range res.Invocations {
		if len(inv.Args) > 0 && inv.Args[0].Text == "terraform" {
			found = true
		}
	}
	if !found {
		t.Error("a terraform image is not followed")
	}
}
