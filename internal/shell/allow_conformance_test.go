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
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	work := filepath.Join(root, "work")
	by := filepath.Join(root, "bystander")
	bin := filepath.Join(root, "canary")
	for _, d := range []string{work, by, bin, filepath.Join(work, "d")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(root, "canary.log")
	script := "#!/bin/sh\necho \"$0 $*\" >> " + log + "\nexit 0\n"
	for _, c := range []string{"canary-exec", "sh", "bash", "zsh", "dash", "python3", "perl", "ruby", "less", "more", "vi", "vim", "pr", "gzip", "bzip2", "xz", "zstd", "pager", "editor"} {
		if c == name {
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
	args := []string{opt}
	if val {
		args = append(args, value)
	}
	switch name {
	case "date":
		args = append(args, "+%Y")
	case "hostname":
	case "find":
		args = append([]string{"."}, args...)
	default:
		args = append(args, "in.txt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path, _ := exec.LookPath(name)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = work
	// The canary directory comes first: a program that starts sh, a pager or a
	// compressor finds the canary.
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "HOME=" + root, "PAGER=canary-exec", "EDITOR=canary-exec", "TMPDIR=" + by, "LANG=C"}
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
		if !existed && strings.HasPrefix(f, work) && !strings.Contains(filepath.Base(f), "in.txt") && !strings.HasSuffix(f, "d") {
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
