//go:build !windows

package gitx

import (
	"os"
	"strings"
	"syscall"
)

func rootOwned(p string, fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	// Every directory above it must be root's and not writable by others.
	for d := p; ; {
		d = d[:strings.LastIndexByte(d, '/')]
		if d == "" {
			return true
		}
		di, err := os.Stat(d)
		if err != nil {
			return false
		}
		ds, ok := di.Sys().(*syscall.Stat_t)
		if !ok || ds.Uid != 0 || di.Mode().Perm()&0o022 != 0 && di.Mode()&os.ModeSticky == 0 {
			return false
		}
	}
}
