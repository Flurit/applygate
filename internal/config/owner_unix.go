//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
)

func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// userWritable reports whether this user can write directory d, or create
// it (a missing directory under a writable parent).
func userWritable(d string) bool {
	for p := d; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			return syscall.Access(p, 2) == nil
		}
		if filepath.Dir(p) == p {
			return false
		}
	}
}
