package shell

import (
	"context"
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

// Every option an entry of allowProgs lists is run, with the real program of
// this machine, in a scratch directory next to a bystander directory that holds
// a file and a canary program on PATH. An entry is wrong when the run changes
// anything outside the scratch directory, creates a file there that the
// operands do not account for, or starts the canary: that is an option that
// writes or runs something the plain call is not supposed to. GNU and BSD
// builds differ, so an option the installed program does not know just fails
// and proves nothing for that machine; CI runs both.
func TestAllowListEntriesDoWhatTheyAreListedFor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX tools")
	}
	names := make([]string, 0, len(allowProgs))
	for n := range allowProgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			continue
		}
		p := allowProgs[name]
		type entry struct {
			opt string
			val bool
		}
		var entries []entry
		for o := range p.flags {
			entries = append(entries, entry{o, false})
		}
		for o := range p.vals {
			entries = append(entries, entry{o, true})
		}
		for o := range p.optVal {
			entries = append(entries, entry{o, false})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].opt < entries[j].opt })
		for _, e := range entries {
			e := e
			if name == "tail" && (strings.Contains(e.opt, "follow") || e.opt == "-f" || e.opt == "-F" || e.opt == "--retry") {
				continue // follows the file until it is stopped: it only reads
			}
			t.Run(name+" "+e.opt, func(t *testing.T) {
				for _, problem := range conformance(t, name, e.opt, e.val) {
					t.Error(problem)
				}
			})
		}
	}
}

// A wrong entry is caught: sort writes the file -o names.
func TestConformanceCatchesAWrongEntry(t *testing.T) {
	if _, err := exec.LookPath("sort"); err != nil {
		t.Skip("no sort")
	}
	if len(conformance(t, "sort", "-o", true)) == 0 {
		t.Errorf("sort -o writes a file, and the check did not notice")
	}
	if len(conformance(t, "sort", "-n", false)) != 0 {
		t.Errorf("sort -n is fine")
	}
}

func conformance(t *testing.T, name string, opt string, val bool) (problems []string) {
	return conformanceCmd(t, name, nil, allowProgs[name], opt, val)
}

// Every option of every leaf of a tree (git and the other programs with
// subcommands) is run the same way: the program, the subcommand words, the
// option and, for an option with a value, a program name; git runs in a
// repository with one commit.
func TestAllowTreeEntriesDoWhatTheyAreListedFor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX tools")
	}
	if path, err := exec.LookPath("git"); err == nil {
		// One repository with one commit, copied for every run.
		tpl := t.TempDir()
		must := func(a ...string) {
			c := exec.Command(path, a...)
			c.Dir = tpl
			c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + tpl, "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"}
			if out, err := c.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", a, err, out)
			}
		}
		if err := os.WriteFile(filepath.Join(tpl, "in.txt"), []byte("b\na\nb\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		must("init", "-q", "--template=")
		must("add", "in.txt")
		must("commit", "-q", "-m", "x")
		gitTemplate = tpl
		t.Cleanup(func() { gitTemplate = "" })
	}
	ran := map[string]bool{}
	for _, c := range allowCmds {
		c := c
		if _, err := exec.LookPath(c.name); err != nil {
			continue
		}
		type entry struct {
			opt string
			val bool
		}
		var entries []entry
		for o := range c.p.flags {
			if !c.p.derived[o] {
				entries = append(entries, entry{o, false})
			}
		}
		for o := range c.p.vals {
			entries = append(entries, entry{o, true})
		}
		for o := range c.p.optVal {
			entries = append(entries, entry{o, false})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].opt < entries[j].opt })
		for _, e := range entries {
			e := e
			fam := c.p.family
			if fam == "" && c.name != "git" {
				// The forge and container CLIs start slowly and spell one option
				// the same in every subcommand: each is run once per program, with
				// the first subcommand that lists it.
				fam = "*"
			}
			if fam != "" {
				// git's log, show, rev-list and the others read one set of options.
				if k := c.name + fam + e.opt; ran[k] {
					continue
				} else {
					ran[k] = true
				}
			}
			t.Run(c.name+" "+strings.Join(c.words, " ")+" "+e.opt, func(t *testing.T) {
				t.Parallel()
				for _, problem := range conformanceCmd(t, c.name, c.words, c.p, e.opt, e.val) {
					t.Error(problem)
				}
			})
		}
	}
}

func conformanceCmd(t *testing.T, name string, words []string, pr *prog, opt string, val bool) (problems []string) {
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	work := filepath.Join(root, "work")
	by := filepath.Join(root, "bystander")
	tmp := filepath.Join(root, "tmp") // programs make their temporary files here (yq does, for every run)
	bin := filepath.Join(root, "canary")
	for _, d := range []string{work, by, tmp, bin, filepath.Join(work, "d")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(root, "canary.log")
	script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
	for _, c := range []string{"canary-exec", "sh", "bash", "zsh", "dash", "python3", "perl", "ruby", "less", "more", "vi", "vim", "pr", "gzip", "bzip2", "xz", "zstd", "pager", "editor"} {
		if c == name || c == "gzip" && name == "gunzip" { // gunzip is a script that runs gzip
			continue
		}
		if err := os.WriteFile(filepath.Join(bin, c), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must := func(f, s string) {
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(work, "in.txt"), "b\na\nb\n")
	must(filepath.Join(work, "d", "x.txt"), "x\n")
	must(filepath.Join(by, "keep.txt"), "keep\n")
	// A value that is a program name or a path outside the scratch directory.
	value := "canary-exec"
	args := append(append([]string{}, words...), opt)
	if val {
		args = append(args, value)
	}
	args = append(args, pr.with...)
	switch name {
	case "date":
		args = append(args, "+%Y")
	case "hostname", "printf", "tflint", "actionlint":
		if name == "printf" {
			args = append(args, "x")
		}
	case "find":
		args = append([]string{"."}, args...)
	case "git":
		args = append(args, "in.txt")
	case "curl":
		args = append(args, "file://"+work+"/in.txt")
	case "wget":
		args = append(args, "http://127.0.0.1:9/in.txt")
	case "zip":
		args = append(args, "out.zip", "in.txt")
	case "yq":
		args = append(args, ".")
		args = append(args, "in.txt")
	case "rg":
		args = append(args, "x", "in.txt")
	default:
		args = append(args, "in.txt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path, _ := exec.LookPath(name)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = work
	gitEnv := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"}
	if name == "git" {
		copyTree(t, gitTemplate, work)
	}
	// The canary directory comes first: a program that starts sh, a pager or a
	// compressor finds the canary.
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "HOME=" + root, "PAGER=canary-exec", "EDITOR=canary-exec", "TMPDIR=" + tmp, "LANG=C"}
	if name == "git" {
		cmd.Env = append(cmd.Env, gitEnv...)
	}
	cmd.Stdin = strings.NewReader("")
	before := snapshot(t, root)
	_ = cmd.Run()
	after := snapshot(t, root)
	if b, err := os.ReadFile(log); err == nil {
		bad("%s %v started a program: %s", name, args, b)
	}
	for f, h := range after {
		if f == log {
			continue
		}
		old, existed := before[f]
		if strings.HasPrefix(f, by) && (!existed || old != h) {
			bad("%s %v changed %s outside the scratch directory", name, args, f)
		}
		listed := pr.writes[opt] && filepath.Base(f) == "canary-exec"
		if name == "git" && strings.Contains(f, string(filepath.Separator)+".git"+string(filepath.Separator)) {
			continue // the repository's own files
		}
		if !existed && strings.HasPrefix(f, work) && !listed && !strings.Contains(strings.TrimPrefix(f, work), "in.txt") && filepath.Base(f) != "out.zip" && !strings.HasSuffix(f, "d") {
			bad("%s %v created %s, which its operands do not name", name, args, f)
		}
	}
	for f := range before {
		if _, ok := after[f]; !ok && strings.HasPrefix(f, by) {
			bad("%s %v removed %s outside the scratch directory", name, args, f)
		}
	}
	return problems
}

// snapshot maps every path under root to its size, mode and mtime.
func snapshot(t *testing.T, root string) map[string]string {
	m := map[string]string{}
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		m[p] = fi.Mode().String() + fi.ModTime().String() + string(rune(fi.Size()))
		return nil
	})
	return m
}

// gitTemplate is the repository the git entries are run in.
var gitTemplate string

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, fi.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}
