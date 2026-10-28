package shell

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// quoteRandomly rewrites word so a shell still reads it as the same text,
// mixing plain, single-quoted, double-quoted, backslash-escaped and $'\xNN'
// characters.
func quoteRandomly(r *rand.Rand, word string) string {
	var b strings.Builder
	for _, c := range word {
		switch r.Intn(5) {
		case 0:
			b.WriteRune(c)
		case 1:
			fmt.Fprintf(&b, "'%c'", c)
		case 2:
			fmt.Fprintf(&b, `"%c"`, c)
		case 3:
			fmt.Fprintf(&b, `\%c`, c)
		case 4:
			fmt.Fprintf(&b, `$'\x%02x'`, c)
		}
	}
	return b.String()
}

// TestQuotingProperty: however the words are quoted, the analyzer resolves
// the same argv the shell would run.
func TestQuotingProperty(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	argvs := [][]string{
		{"terraform", "destroy", "-auto-approve"},
		{"tofu", "apply", "-destroy"},
		{"terraform", "state", "rm", "aws_db_instance.main"},
		{"aws", "s3", "rb", "s3://bucket", "--force"},
	}
	for i := 0; i < 2000; i++ {
		argv := argvs[i%len(argvs)]
		parts := make([]string, len(argv))
		for j, w := range argv {
			parts[j] = quoteRandomly(r, w)
		}
		cmd := strings.Join(parts, " ")
		// Sometimes wrap the command in another layer the analyzer unwraps.
		switch r.Intn(4) {
		case 1:
			cmd = "bash -c " + shellQuoteForTest(cmd)
		case 2:
			cmd = "eval " + shellQuoteForTest(cmd)
		case 3:
			cmd = "env FOO=1 " + cmd
		}
		res := Analyze(cmd, Options{Dir: "/r", ReadFile: fakeFS(nil)})
		if len(res.Problems) > 0 || len(res.Invocations) != 1 {
			t.Fatalf("%q: %v", cmd, render(res))
		}
		got := texts(res.Invocations[0].Args)
		if strings.Join(got, "\x00") != strings.Join(argv, "\x00") {
			t.Fatalf("%q: got %q, want %q", cmd, got, argv)
		}
	}
}

func shellQuoteForTest(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FuzzAnalyze checks that arbitrary input never panics and that every
// invocation either resolves or is marked unresolved.
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		"terraform destroy", "d=destroy; terraform $d", "echo aGk= | base64 -d | sh", "bash -c 'x'",
		"make destroy", "f(){ terraform $1; }; f destroy", "for i in a b; do $i; done", "a=$(b) c=${d:-e} f",
		"cat <<EOF | sh\nterraform destroy\nEOF", "eval \"$(printf %s terraform) destroy\"", "$'\\x74' x",
		"((x++)); [[ -n $y ]] && z", "coproc tf { terraform plan; }", "time ( cd a; b ) | c &",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ch := make(chan *Result, 1)
		go func() { ch <- Analyze(s, Options{Dir: "/r", Env: map[string]string{"HOME": "/h"}, ReadFile: fakeFS(nil), MaxDepth: 6}) }()
		var res *Result
		select {
		case res = <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("analysis did not finish in 2s for %q", s)
		}
		for _, inv := range res.Invocations {
			for _, w := range inv.Args {
				if !w.Resolved && w.Text != "" && !strings.HasPrefix(w.Text, w.Prefix) {
					t.Fatalf("prefix %q not a prefix of %q", w.Prefix, w.Text)
				}
			}
		}
	})
}
