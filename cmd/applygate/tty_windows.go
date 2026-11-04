//go:build windows

package main

import (
	"io"
	"os"
	"syscall"
)

// terminal asks the console: a pipe, a file or NUL has no console mode.
func terminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
