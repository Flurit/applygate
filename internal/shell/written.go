package shell

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// Files written earlier in the same command are not what is on disk when
// the hook runs: printf '…' > run.sh; bash run.sh runs the new text. The
// analyzer records what each step writes, and a later read of one of those
// paths (a script, a sourced file, $(cat f), a Makefile) is unresolved. A
// directory a step links, moves, copies or extracts into may now hold
// symlinks, so cd into it makes the directory unknown.

// writeKind says how a step changed a path.
type writeKind int

const (
	wroteFile     writeKind = iota + 1 // the file's content (redirect, tee, sed -i, curl -o)
	wroteContents                      // files under the path (git checkout, pull, ...)
	wroteTree                          // anything at or under it, symlinks too (tar -C, cp, mv, ln)
	madeDir                            // a directory created (mkdir), which may also be read
)

type writtenError struct{ path string }

func (e *writtenError) Error() string {
	if e.path == "" {
		return "a step earlier in this command writes to a path that cannot be resolved, which may be this file"
	}
	return "it is written by an earlier step of this command (" + e.path + "), so its content is not known"
}

func errorsIsWritten(err error) bool {
	var w *writtenError
	return errors.As(err, &w)
}

// read reads a file the command uses, unless an earlier step wrote it.
func (a *analyzer) read(st *state, p string) ([]byte, error) {
	abs := a.abs(st, p)
	if w := a.writtenAt(abs, false); w != "" || a.writtenUnknown {
		return nil, &writtenError{path: w}
	}
	return a.opt.ReadFile(abs)
}

// writtenAt returns the recorded write that covers p: p itself, or a
// directory above it that a step wrote a tree into. With dirOnly, only
// writes that may have left symlinks count (for cd).
func (a *analyzer) writtenAt(p string, dirOnly bool) string {
	for w, k := range a.written {
		if k == madeDir {
			continue
		}
		if p == w && (!dirOnly || k == wroteTree) {
			return w
		}
		if (k == wroteTree || k == wroteContents && !dirOnly) && strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
			return w
		}
	}
	return ""
}

// created reports whether an earlier step may have created directory p:
// mkdir, or a write into a tree above it (clone, checkout, extract, copy).
func (a *analyzer) created(p string) bool {
	if a.writtenUnknown {
		return true
	}
	for w, k := range a.written {
		if p == w || k != wroteFile && strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
			return true
		}
	}
	return false
}

func (a *analyzer) wrote(st *state, w Word, k writeKind) {
	if !w.Resolved || st.dir == "" && !filepath.IsAbs(w.Text) {
		a.writtenUnknown = true
		return
	}
	if a.written == nil {
		a.written = map[string]writeKind{}
	}
	p := a.abs(st, w.Text)
	if old, ok := a.written[p]; !ok || old == madeDir || old < k && k != madeDir {
		a.written[p] = k
	}
}

// noteWrites records the paths a program writes.
func (a *analyzer) noteWrites(bn string, rest []Word, st *state) {
	var pos []Word
	for _, w := range rest {
		if !strings.HasPrefix(w.Text, "-") || w.Text == "-" {
			pos = append(pos, w)
		}
	}
	last := func(k writeKind) {
		if len(pos) > 0 {
			a.wrote(st, pos[len(pos)-1], k)
		}
	}
	flagVal := func(names ...string) (Word, bool) {
		for i, w := range rest {
			for _, n := range names {
				if w.Text == n && i+1 < len(rest) {
					return rest[i+1], true
				}
				if v, ok := strings.CutPrefix(w.Text, n+"="); ok && strings.HasPrefix(n, "--") {
					return Word{Text: v, Resolved: w.Resolved, Prefix: v}, true
				}
			}
		}
		return Word{}, false
	}
	switch bn {
	case "mkdir":
		for _, w := range pos {
			a.wrote(st, w, madeDir)
		}
	case "tee":
		for _, w := range pos {
			a.wrote(st, w, wroteFile)
		}
	case "cp", "mv", "ln", "install", "rsync", "ditto", "gcp", "gmv":
		if t, ok := flagVal("-t", "--target-directory"); ok {
			a.wrote(st, t, wroteTree)
			return
		}
		last(wroteTree)
	case "dd":
		for _, w := range rest {
			if v, ok := strings.CutPrefix(w.Text, "of="); ok {
				a.wrote(st, Word{Text: v, Resolved: w.Resolved, Prefix: v}, wroteFile)
			}
		}
	case "sed", "gsed", "perl", "yq", "ruby":
		if InPlaceEdit(rest) {
			for _, w := range pos {
				a.wrote(st, w, wroteFile)
			}
		}
	case "curl", "wget":
		if o, ok := flagVal("-o", "--output", "-O", "--output-document"); ok && (bn == "wget" || o.Text != "") {
			a.wrote(st, o, wroteFile)
		}
		if d, ok := flagVal("--output-dir", "-P", "--directory-prefix"); ok {
			a.wrote(st, d, wroteTree)
		} else if bn == "wget" || hasFlag(rest, "-O", "--remote-name", "-J", "--remote-name-all") {
			a.wrote(st, Word{Text: ".", Resolved: true}, wroteTree)
		}
	case "tar", "bsdtar", "gtar", "unzip", "7z", "cpio", "patch", "git":
		extract := bn != "tar" && bn != "bsdtar" && bn != "gtar" && bn != "git"
		for _, w := range rest {
			t := w.Text
			if (bn == "tar" || bn == "bsdtar" || bn == "gtar") && (t == "--extract" || t == "--get" || !strings.HasPrefix(t, "--") && strings.Contains(strings.TrimPrefix(t, "-"), "x") && (strings.HasPrefix(t, "-") || w == rest[0])) {
				extract = true
			}
		}
		if bn == "git" {
			// clone, checkout, restore, apply, pull, ... rewrite the tree.
			if len(pos) > 0 && toSet("clone", "checkout", "switch", "restore", "apply", "am", "pull", "merge", "rebase", "reset", "stash", "worktree", "cherry-pick", "revert")[pos[0].Text] {
				a.wrote(st, Word{Text: ".", Resolved: true}, wroteContents)
			}
			return
		}
		if !extract {
			return
		}
		if d, ok := flagVal("-C", "--directory", "-d"); ok {
			a.wrote(st, d, wroteTree)
		} else {
			a.wrote(st, Word{Text: ".", Resolved: true}, wroteTree)
		}
	}
}

func hasFlag(ws []Word, names ...string) bool {
	for _, w := range ws {
		for _, n := range names {
			if w.Text == n {
				return true
			}
		}
	}
	return false
}

// decodeUTF16Base64 decodes PowerShell's -EncodedCommand.
func decodeUTF16Base64(w Word) (Word, bool) {
	if !w.Resolved {
		return Word{}, false
	}
	b, err := base64.StdEncoding.DecodeString(w.Text)
	if err != nil || len(b)%2 != 0 {
		return Word{}, false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	s := string(utf16.Decode(u))
	return Word{Text: s, Resolved: true, Prefix: s}, true
}

// InPlaceEdit reports whether a sed, perl, ruby or yq command line edits
// its files in place: --in-place or --inplace, or an -i inside a cluster of
// short options (-i, -Ei, -ni, -pi, -Pi, -yi, -i.bak) before any option that
// takes the rest of the word as its argument.
func InPlaceEdit(args []Word) bool {
	for _, w := range args {
		t := w.Text
		if t == "--" {
			return false
		}
		if t == "--in-place" || t == "--inplace" || strings.HasPrefix(t, "--in-place=") || strings.HasPrefix(t, "--inplace=") {
			return true
		}
		if len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		for k := 1; k < len(t); k++ {
			c := t[k]
			if c == 'i' {
				return true
			}
			if strings.IndexByte("efFlmMIxV0", c) >= 0 {
				break
			}
		}
	}
	return false
}

// TarWrites reports whether a tar command extracts or creates a file (a
// listing writes nothing).
func TarWrites(args []Word) bool {
	for i := 0; i < len(args); i++ {
		t := args[i].Text
		switch {
		case t == "--extract" || t == "--get" || t == "--create":
			return true
		case strings.HasPrefix(t, "--"):
		case strings.HasPrefix(t, "-") || i == 0 && t != "":
			for _, ch := range strings.TrimPrefix(t, "-") {
				if ch == 'x' || ch == 'c' || ch == 'r' || ch == 'u' {
					return true
				}
				if strings.ContainsRune("CfITXFKL", ch) {
					break
				}
			}
		}
	}
	return false
}
