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
	}
	for _, c := range cases {
		res := Analyze(c.cmd, Options{Dir: "/tmp", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
		ok, why, unseen := PlainShapeUnseen(c.cmd, res)
		if ok != c.plain || (unseen != "") != c.unseen {
			t.Errorf("%q: plain=%v (%s) unseen=%q, want plain=%v unseen=%v", c.cmd, ok, why, unseen, c.plain, c.unseen)
		}
	}
}
