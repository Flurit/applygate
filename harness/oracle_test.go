package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// The effects oracle. The AI reviewers found the family "the guard allows a
// spelling it did not understand" one spelling at a time; this test finds it
// without them. It builds commands from destructive atoms (a terraform destroy
// in the prod directory, a write to its state file, to a hook settings file)
// and spellings of how a shell can reach them (cd forms, quoting, expansion,
// nested shells, redirect forms), asks the guard, and for every command the
// guard allows runs it for real under every shell on the machine against fake
// terraform, aws and kubectl programs that log their argument vector and
// directory. An allowed command whose run reached prod, changed a state or a
// guard file, or wrote outside the sandbox is a failure: the guard allowed what
// the shell turned into the atom.
//
// A shell runs a command differently from the shell the guard modelled, which
// is the point: the verdict has to hold under all of them.

type oracleAtom struct {
	name string
	cmd  string // run from the prod directory unless a spelling moves it
	kind string // "tool" (the fake terraform is reached in prod) or "file" (a protected file changes)
}

var oracleAtoms = []oracleAtom{
	{"destroy", "terraform destroy -auto-approve", "tool"},
	{"apply", "terraform apply -auto-approve", "tool"},
	{"state rm", "terraform state rm aws_s3_bucket.a", "tool"},
	{"taint", "terraform taint aws_s3_bucket.a", "tool"},
	{"state write", "echo corrupt > terraform.tfstate", "file"},
	{"state rm file", "rm -f terraform.tfstate", "file"},
	{"state move", "mv terraform.tfstate /tmp/oracle-moved", "file"},
	{"state truncate", ": > terraform.tfstate", "file"},
	{"state sed", "sed -i.bak 's/a/b/' terraform.tfstate", "file"},
	{"state tee", "echo x | tee terraform.tfstate", "file"},
	{"state cp", "cp /dev/null terraform.tfstate", "file"},
	{"state brace", "echo x > terraform.tfst{ate,}", "file"},
	{"guard write", "echo '{}' > .claude/settings.json", "file"},
	{"state clobber", "echo x >| terraform.tfstate", "file"},
	{"state zsh clobber", "echo x >! terraform.tfstate", "file"},
	{"state dd", "dd if=/dev/null of=terraform.tfstate 2>/dev/null", "file"},
	{"state ln", "ln -sf /dev/null terraform.tfstate", "file"},
	{"state truncate", "truncate -s 0 terraform.tfstate", "file"},
	{"guard cp", "cp /dev/null .claude/settings.json", "file"},
}

// A spelling turns an atom into a command run from a given directory.
type oracleSpelling struct {
	name string
	from string                    // "prod" or "dev": where the command starts
	f    func(a oracleAtom) string // the command, with the atom reached by the spelling
}

func oracleSpellings() []oracleSpelling {
	id := func(a oracleAtom) string { return a.cmd }
	return []oracleSpelling{
		{"direct", "prod", id},
		{"quoted program", "prod", func(a oracleAtom) string { return strings.Replace(a.cmd, "terraform", "'terra''form'", 1) }},
		{"command prefix", "prod", func(a oracleAtom) string { return "command " + a.cmd }},
		{"env prefix", "prod", func(a oracleAtom) string { return "env " + a.cmd }},
		{"backslash", "prod", func(a oracleAtom) string { return "\\" + a.cmd }},
		{"bash -c", "prod", func(a oracleAtom) string { return "bash -c " + shq(a.cmd) }},
		{"sh -c", "prod", func(a oracleAtom) string { return "sh -c " + shq(a.cmd) }},
		{"eval", "prod", func(a oracleAtom) string { return "eval " + shq(a.cmd) }},
		{"echo pipe sh", "prod", func(a oracleAtom) string { return "echo " + shq(a.cmd) + " | sh" }},
		{"printf pipe bash", "prod", func(a oracleAtom) string { return "printf '%s' " + shq(a.cmd) + " | bash" }},
		{"variable program", "prod", func(a oracleAtom) string { return "t=terraform; " + strings.Replace(a.cmd, "terraform", "$t", 1) }},
		{"default expansion", "prod", func(a oracleAtom) string { return strings.Replace(a.cmd, "terraform", "${x:-terraform}", 1) }},
		{"subshell", "prod", func(a oracleAtom) string { return "(" + a.cmd + ")" }},
		{"brace group", "prod", func(a oracleAtom) string { return "{ " + a.cmd + "; }" }},
		{"and list", "prod", func(a oracleAtom) string { return "true && " + a.cmd }},
		{"for loop", "prod", func(a oracleAtom) string { return "for i in 1; do " + a.cmd + "; done" }},
		{"function", "prod", func(a oracleAtom) string { return "f() { " + a.cmd + "; }; f" }},
		{"xargs", "prod", func(a oracleAtom) string { return "echo x | xargs -I{} sh -c " + shq(a.cmd) }},
		{"time", "prod", func(a oracleAtom) string { return "time " + a.cmd }},
		{"exec", "prod", func(a oracleAtom) string { return "exec " + a.cmd }},
		{"timeout", "prod", func(a oracleAtom) string { return "timeout 5 " + a.cmd }},
		{"nice", "prod", func(a oracleAtom) string { return "nice " + a.cmd }},
		{"zsh -c", "prod", func(a oracleAtom) string { return "zsh -c " + shq(a.cmd) }},
		{"dash -c", "prod", func(a oracleAtom) string { return "dash -c " + shq(a.cmd) }},
		{"here-string", "prod", func(a oracleAtom) string { return "bash <<< " + shq(a.cmd) }},
		{"here-doc", "prod", func(a oracleAtom) string { return "sh <<'EOF'\n" + a.cmd + "\nEOF" }},
		{"substitution program", "prod", func(a oracleAtom) string { return strings.Replace(a.cmd, "terraform", "$(echo terraform)", 1) }},
		{"ansi-c quote", "prod", func(a oracleAtom) string { return strings.Replace(a.cmd, "terraform", "$'terraform'", 1) }},
		{"background", "prod", func(a oracleAtom) string { return a.cmd + " & wait" }},
		{"or list", "prod", func(a oracleAtom) string { return "false || " + a.cmd }},
		{"semicolon", "prod", func(a oracleAtom) string { return "true; " + a.cmd }},
		{"if", "prod", func(a oracleAtom) string { return "if true; then " + a.cmd + "; fi" }},
		{"while read", "prod", func(a oracleAtom) string { return "echo x | while read l; do " + a.cmd + "; done" }},
		{"cd dotdot", "dev", func(a oracleAtom) string { return "cd .. && cd prod && " + a.cmd }},
		{"cd absolute var", "dev", func(a oracleAtom) string { return "cd \"$PWD/../prod\" && " + a.cmd }},
		{"cd tilde dash", "dev", func(a oracleAtom) string { return "cd ../prod; cd - >/dev/null; cd - >/dev/null && " + a.cmd }},
		{"git -C", "dev", func(a oracleAtom) string { return "env -C ../prod sh -c " + shq(a.cmd) }},
		{"nohup", "prod", func(a oracleAtom) string { return "nohup " + a.cmd }},
		{"cd sibling", "dev", func(a oracleAtom) string { return "cd ../prod && " + a.cmd }},
		{"cd sibling dot", "dev", func(a oracleAtom) string { return "cd ../prod/. && " + a.cmd }},
		{"cd subshell", "dev", func(a oracleAtom) string { return "(cd ../prod; " + a.cmd + ")" }},
		{"cd quoted", "dev", func(a oracleAtom) string { return "cd '../pr''od' && " + a.cmd }},
		{"cd glob", "dev", func(a oracleAtom) string { return "cd ../pro* && " + a.cmd }},
		{"cd tilde plus", "dev", func(a oracleAtom) string { return "cd ~+/../prod && " + a.cmd }},
		{"cd substitution", "dev", func(a oracleAtom) string { return "cd $(echo ../prod) && " + a.cmd }},
		{"cd variable", "dev", func(a oracleAtom) string { return "d=../prod; cd $d && " + a.cmd }},
		{"cd two operands", "dev", func(a oracleAtom) string { return "cd dev prod && " + a.cmd }},
		{"pushd", "dev", func(a oracleAtom) string { return "pushd ../prod && " + a.cmd }},
		{"cdpath", "dev", func(a oracleAtom) string { return "CDPATH=.. cd prod && " + a.cmd }},
		{"env -C", "dev", func(a oracleAtom) string { return "env -C ../prod " + a.cmd }},
		{"chdir", "dev", func(a oracleAtom) string {
			if a.kind != "tool" {
				return "cd ../prod && " + a.cmd
			}
			return strings.Replace(a.cmd, "terraform ", "terraform -chdir=../prod ", 1)
		}},
		{"chdir variable", "dev", func(a oracleAtom) string {
			if a.kind != "tool" {
				return "d=../prod; cd $d && " + a.cmd
			}
			return "d=../prod; " + strings.Replace(a.cmd, "terraform ", "terraform -chdir=$d ", 1)
		}},
	}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type oracleBox struct {
	t      *testing.T
	root   string
	repo   string
	home   string
	bin    string // the fake tools
	log    string
	guard  string // the applygate binary
	shells map[string]string
}

func newOracleBox(t *testing.T) *oracleBox {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	repo, _, home, err := Materialize(filepath.Join(root, "m"))
	if err != nil {
		t.Fatal(err)
	}
	b := &oracleBox{t: t, root: root, repo: repo, home: home, bin: filepath.Join(root, "fakebin"), log: filepath.Join(root, "effects.log")}
	if err := os.MkdirAll(b.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\t%s\\t%s\\n' \"$(basename \"$0\")\" \"$PWD\" \"$*\" >> " + b.log + "\nexit 0\n"
	for _, tool := range []string{"terraform", "tofu", "aws", "kubectl", "helm"} {
		if err := os.WriteFile(filepath.Join(b.bin, tool), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The guard, built once from this tree.
	b.guard = filepath.Join(root, "applygate")
	out, err := exec.Command("go", "build", "-o", b.guard, "../cmd/applygate").CombinedOutput()
	if err != nil {
		t.Fatalf("building the guard: %v\n%s", err, out)
	}
	// The person trusted the fixture's configuration.
	cfg := filepath.Join(repo, ".applygate.yaml")
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(cfg)
	sum := sha256.Sum256(data)
	trust, _ := json.Marshal(map[string]string{strings.ToLower(real): hex.EncodeToString(sum[:])})
	if err := os.MkdirAll(filepath.Join(home, ".config", "applygate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "applygate", "trusted.json"), trust, 0o644); err != nil {
		t.Fatal(err)
	}
	b.shells = map[string]string{}
	for _, s := range []string{"bash", "zsh", "dash", "sh"} {
		if p, err := exec.LookPath(s); err == nil {
			b.shells[s] = p
		}
	}
	return b
}

const oracleState = `{"version":4,"terraform_version":"1.9.0","serial":3,"lineage":"abc","outputs":{},"resources":[]}`

// reset puts the protected files back and empties the effects log.
func (b *oracleBox) reset() {
	for _, f := range []string{"envs/prod/terraform.tfstate", "envs/dev/terraform.tfstate"} {
		_ = os.WriteFile(filepath.Join(b.repo, f), []byte(oracleState), 0o644)
	}
	_ = os.MkdirAll(filepath.Join(b.repo, "envs/prod/.claude"), 0o755)
	_ = os.WriteFile(filepath.Join(b.repo, "envs/prod/.claude/settings.json"), []byte(`{"hooks":{}}`), 0o644)
	_ = os.Remove(filepath.Join(b.repo, "envs/prod/terraform.tfstate.bak"))
	_ = os.Remove("/tmp/oracle-moved")
	_ = os.Remove(b.log)
}

func (b *oracleBox) env() []string {
	return []string{"PATH=" + b.bin + ":/usr/bin:/bin", "HOME=" + b.home, "XDG_CONFIG_HOME=" + filepath.Join(b.home, ".config"),
		"XDG_STATE_HOME=" + filepath.Join(b.home, ".state"), "USER=agent", "LANG=C"}
}

// verdict is the guard's decision for cmd run from dir.
func (b *oracleBox) verdict(dir, cmd string) string {
	c := exec.Command(b.guard, "check", "--no-judge", "--cwd", dir, "--", cmd)
	c.Env = b.env()
	err := c.Run()
	if err == nil {
		return "allow"
	}
	if ee, ok := err.(*exec.ExitError); ok {
		switch ee.ExitCode() {
		case 4:
			return "ask"
		case 3:
			return "block"
		}
	}
	return "error"
}

// effects runs cmd under a shell from dir and reports what it reached in prod.
func (b *oracleBox) effects(shell, dir, cmd string) []string {
	b.reset()
	c := exec.Command(shell, "-c", cmd)
	c.Dir = dir
	c.Env = b.env()
	done := make(chan struct{})
	go func() { _ = c.Run(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = c.Process.Kill()
		<-done
	}
	var out []string
	prod := filepath.Join(b.repo, "envs", "prod")
	if data, err := os.ReadFile(b.log); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			f := strings.SplitN(l, "\t", 3)
			if len(f) == 3 && (f[1] == prod || strings.HasPrefix(f[1], prod+"/")) && f[0] != "" {
				// A read of the prod directory is not an effect; a destructive
				// subcommand is.
				for _, w := range strings.Fields(f[2]) {
					switch w {
					case "destroy", "apply", "taint", "rm", "import", "untaint", "force-unlock", "push":
						out = append(out, "ran "+f[0]+" "+f[2]+" in prod")
					}
				}
			}
		}
	}
	if got, err := os.ReadFile(filepath.Join(prod, "terraform.tfstate")); err != nil || string(got) != oracleState {
		out = append(out, "changed the prod state file")
	}
	if got, err := os.ReadFile(filepath.Join(prod, ".claude", "settings.json")); err != nil || string(got) != `{"hooks":{}}` {
		out = append(out, "changed the prod hook settings")
	}
	if _, err := os.Stat("/tmp/oracle-moved"); err == nil {
		out = append(out, "moved the state file to /tmp")
	}
	return out
}

func TestEffectsOracle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells")
	}
	if testing.Short() {
		t.Skip("builds the guard and runs shells")
	}
	b := newOracleBox(t)
	if len(b.shells) == 0 {
		t.Skip("no POSIX shell")
	}
	prod := filepath.Join(b.repo, "envs", "prod")
	dirs := map[string]string{"prod": prod, "dev": filepath.Join(b.repo, "envs", "dev")}

	// The detector works: every atom, run directly with no guard, shows its
	// effect under bash or sh.
	// (Some atoms act only under one shell: a brace in a redirect writes under
	// zsh and is an ambiguous redirect under bash.)
	for _, a := range oracleAtoms {
		seen := false
		for _, sh := range b.shells {
			if len(b.effects(sh, prod, a.cmd)) > 0 {
				seen = true
			}
		}
		if !seen {
			t.Errorf("the oracle does not see the effect of %q (%s) under any shell here: the checks below prove nothing for it", a.cmd, a.name)
		}
	}

	var stopped, ranSafe int
	var failures []string
	shellNames := make([]string, 0, len(b.shells))
	for n := range b.shells {
		shellNames = append(shellNames, n)
	}
	sort.Strings(shellNames)
	for _, sp := range oracleSpellings() {
		for _, a := range oracleAtoms {
			cmd := sp.f(a)
			dir := dirs[sp.from]
			if v := b.verdict(dir, cmd); v != "allow" {
				stopped++
				continue
			}
			for _, sh := range shellNames {
				if eff := b.effects(b.shells[sh], dir, cmd); len(eff) > 0 {
					failures = append(failures, fmt.Sprintf("allowed from %s, under %s it %s: %s", sp.from, sh, strings.Join(eff, "; "), cmd))
				} else {
					ranSafe++
				}
			}
		}
	}
	t.Logf("oracle: %d atoms x %d spellings; %d stopped by the guard, %d allowed runs under %d shells had no effect in prod",
		len(oracleAtoms), len(oracleSpellings()), stopped, ranSafe, len(b.shells))
	for _, f := range failures {
		t.Errorf("%s", f)
	}
}
