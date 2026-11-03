//go:build !windows

package policy

import (
	"os"
	"syscall"
)

// hardLinked reports whether a file has more than one name.
func hardLinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}
