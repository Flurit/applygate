package shell

import (
	"os"
	"path/filepath"
	"strings"
)

// evalSymlinks is replaced by tests.
var evalSymlinks = filepath.EvalSymlinks

// PhysicalJoin joins p to dir the way the kernel resolves it: a ".." goes up
// from where the path so far really is, after its symlinks, not from its
// text. filepath.Join drops "m/.." even when m links to another tree (4T1).
// A path with no ".." is only cleaned, and so is one whose physical form is
// the same place as its text; a part that does not exist is joined as text.
func PhysicalJoin(dir, p string) string {
	if !filepath.IsAbs(p) {
		if dir == "" {
			return filepath.Clean(p)
		}
		p = dir + string(filepath.Separator) + p
	}
	parts := strings.FieldsFunc(p[len(filepath.VolumeName(p)):], func(r rune) bool { return r < 0x80 && os.IsPathSeparator(uint8(r)) })
	if !containsDotDot(parts) {
		return filepath.Clean(p)
	}
	cur := filepath.VolumeName(p) + string(filepath.Separator)
	for _, c := range parts {
		switch c {
		case ".":
		case "..":
			if r, err := evalSymlinks(cur); err == nil {
				cur = r
			}
			cur = filepath.Dir(cur)
		default:
			cur = filepath.Join(cur, c)
		}
	}
	if logical := filepath.Clean(p); samePlace(logical, cur) {
		return logical
	}
	return cur
}

func containsDotDot(parts []string) bool {
	for _, c := range parts {
		if c == ".." {
			return true
		}
	}
	return false
}

// samePlace reports whether a and b name the same path once their symlinks
// are resolved (as far as they exist).
func samePlace(a, b string) bool {
	if a == b {
		return true
	}
	ra, ea := evalSymlinks(a)
	rb, eb := evalSymlinks(b)
	return ea == nil && eb == nil && ra == rb
}
