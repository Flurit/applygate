package shell

import (
	"strings"
	"testing"
)

// Constructs from the v0.6.0 review's C findings, checked on the analyzer
// alone: what the shell would run (want), or that it is unresolved (an
// invocation whose name is unresolved, or a problem). The harness attack
// pack checks the verdicts end to end.

func ran(r *Result) []string {
	var out []string
	for _, inv := range r.Invocations {
		out = append(out, joinWords(inv.Args)+" @"+inv.Dir)
	}
	return out
}

func analyzeIn(cmd string, files map[string]string) *Result {
	return Analyze(cmd, Options{Dir: "/r/envs/prod", Env: map[string]string{"HOME": "/h"}, ReadFile: fakeFS(files)})
}

func TestReviewCRuns(t *testing.T) {
	cases := []struct{ cmd, want string }{
		// C2: output that is known exactly.
		{`$(echo -e "\0164erraform") destroy`, "terraform destroy @/r/envs/prod"},
		{`$(printf -- terraform) destroy`, "terraform destroy @/r/envs/prod"},
		{`$(echo -E '\x74') x`, `\x74 x @/r/envs/prod`},
		// C3: background statements, functions and the directory stack.
		{`cd ../dev & terraform destroy`, "terraform destroy @/r/envs/prod"},
		{`f() { cd ../dev; }; f; terraform destroy`, "terraform destroy @/r/envs/dev"},
		{`f() { local x=echo; }; x=terraform; f; $x destroy`, "terraform destroy @/r/envs/prod"},
		{`pushd ../dev >/dev/null; popd >/dev/null; terraform destroy`, "terraform destroy @/r/envs/prod"},
		{`set -- terraform; $1 destroy`, "terraform destroy @/r/envs/prod"},
		{`f() { shift; $1 destroy; }; f echo terraform`, "terraform destroy @/r/envs/prod"},
		// C4: walked constructs.
		{`case $(terraform destroy) in *) ;; esac`, "terraform destroy @/r/envs/prod"},
		{`export "$(terraform destroy)"`, "terraform destroy @/r/envs/prod"},
		{`trap 'terraform destroy' EXIT`, "terraform destroy @/r/envs/prod"},
		{`for ((i=$(terraform destroy); i<1; i++)); do :; done`, "terraform destroy @/r/envs/prod"},
		{`echo ${x:-$(terraform destroy)}`, "terraform destroy @/r/envs/prod"},
		// C6: placeholders with known input.
		{`echo terraform | xargs -I{} {} destroy`, "terraform destroy @/r/envs/prod"},
		{`echo destroy | xargs terraform`, "terraform destroy @/r/envs/prod"},
		{`parallel 'terraform {}' ::: destroy`, "terraform destroy @/r/envs/prod"},
		// C8: commands run through options.
		{`git -c alias.x='!terraform destroy' x`, "terraform destroy @/r/envs/prod"},
		{`git rebase -x 'terraform destroy' HEAD~1`, "terraform destroy @/r/envs/prod"},
		{`ssh -oProxyCommand='terraform destroy' h`, "terraform destroy @/r/envs/prod"},
		{`flock /tmp/l terraform destroy`, "terraform destroy @/r/envs/prod"},
		{`conda run -n base --cwd ../dev terraform destroy`, "terraform destroy @/r/envs/dev"},
		{`nix run nixpkgs#opentofu -- destroy`, "tofu destroy @/r/envs/prod"},
		{`env -S"terraform destroy"`, "terraform destroy @/r/envs/prod"},
		// C13: alias text is shell source; a self-referential alias expands once.
		{"alias x='cd ../dev && terraform destroy'\nx", "terraform destroy @/r/envs/dev"},
		{"alias terraform='terraform destroy'\nterraform -no-color", "terraform destroy -no-color @/r/envs/prod"},
	}
	for _, c := range cases {
		got := ran(analyzeIn(c.cmd, nil))
		// The invocation may carry more arguments than want lists.
		args, dir, _ := strings.Cut(c.want, " @")
		found := false
		for _, g := range got {
			found = found || strings.HasPrefix(g, args) && strings.HasSuffix(g, " @"+dir)
		}
		if !found {
			t.Errorf("%q: want %q among %q", c.cmd, c.want, got)
		}
	}
}

func TestReviewCUnresolved(t *testing.T) {
	files := map[string]string{"/r/envs/prod/run.sh": "echo old\n"}
	for _, cmd := range []string{
		// C2: words the shell resolves differently or against the disk.
		`=terraform destroy`,
		`/usr/local/bin/terr[a]form destroy`,
		"$'\\u0074erraform' destroy",
		`$(echo '\x74erraform') destroy`,
		// C5: variables assigned at run time.
		`x=echo; read x <<< terraform; $x destroy`,
		`x=echo; printf -v x %s terraform; $x destroy`,
		`x=echo; mapfile -t x <<< terraform; $x destroy`,
		`x=echo; declare -n x=y; y=terraform; $x destroy`,
		`x=echo; builtin declare -n x=y; $x destroy`,
		// C6: placeholders with unknown input.
		`cat list | xargs -I{} sh -c '{}'`,
		// C11: files written earlier in the command.
		`printf 'terraform destroy\n' > run.sh; bash run.sh`,
		`echo x > run.sh; source run.sh`,
	} {
		r := analyzeIn(cmd, files)
		unresolved := len(r.Problems) > 0
		for _, inv := range r.Invocations {
			unresolved = unresolved || len(inv.Args) > 0 && !inv.Args[0].Resolved
		}
		if !unresolved {
			t.Errorf("%q: want unresolved, got %q", cmd, ran(r))
		}
	}
}

// The stricter word rules must not touch text the shell never globs.
func TestReviewCBenignStaysResolved(t *testing.T) {
	for _, cmd := range []string{
		"cat <<'EOF'\nfiles: *.tf [a-z]?\nEOF",
		`x=*.tf; echo done`,
		`echo 'terraform [a]' "x*"`,
		`printf '%s\n' a b`,
		`echo -e 'a\tb'`,
		`[ -f x ] && echo y`,
	} {
		r := analyzeIn(cmd, nil)
		if len(r.Problems) > 0 {
			t.Errorf("%q: problems %+v", cmd, r.Problems)
		}
		for _, inv := range r.Invocations {
			for _, w := range inv.Args {
				if !w.Resolved {
					t.Errorf("%q: %q unresolved", cmd, joinWords(inv.Args))
				}
			}
		}
	}
	// cd into a directory made with mkdir earlier is still a known path.
	r := analyzeIn("mkdir -p ../dev/new && cd ../dev/new && terraform plan", nil)
	if got := ran(r); len(got) == 0 || !strings.HasSuffix(got[len(got)-1], "@/r/envs/dev/new") {
		t.Errorf("mkdir then cd: %q", got)
	}
	// cd into a link made earlier is not.
	r = analyzeIn("ln -s ../prod p && cd p && terraform destroy", nil)
	if got := ran(r); len(got) == 0 || !strings.HasSuffix(got[len(got)-1], " @") {
		t.Errorf("ln then cd: %q", got)
	}
}

// Builtins are not case-folded: CD does not change the shell's directory.
func TestReviewCBuiltinsKeepCase(t *testing.T) {
	r := analyzeIn("CD ../dev && terraform destroy", nil)
	if got := ran(r); len(got) == 0 || !strings.HasSuffix(got[len(got)-1], "@/r/envs/prod") {
		t.Errorf("CD then destroy: %q", got)
	}
	r = analyzeIn("Source Type: CSW", nil)
	if len(r.Problems) != 0 {
		t.Errorf("Source is not the source builtin: %+v", r.Problems)
	}
}
