// Package safefile opens the files the hook reads and writes on every call
// (its config, decision log, approval store, judge cache, telemetry
// settings) without ever blocking: a FIFO, a device or a socket at one of
// those paths is refused instead of hanging the hook past the host's
// timeout.
package safefile

import (
	"fmt"
	"io"
	"os"
)

// ReadFile reads path if it is a regular file.
func ReadFile(path string) ([]byte, error) {
	f, err := open(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// OpenAppend opens path for appending, creating it with perm, if it is a
// regular file or does not exist.
func OpenAppend(path string, perm os.FileMode) (*os.File, error) {
	return open(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, perm)
}

// OpenFile opens path with flag if it is a regular file or, when flag has
// O_CREATE, does not exist yet.
func OpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	return open(path, flag, perm)
}

func open(path string, flag int, perm os.FileMode) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%s)", path, fi.Mode().Type())
	}
	f, err := os.OpenFile(path, flag|nonBlock, perm)
	if err != nil {
		return nil, err
	}
	// The path may have been swapped between the check and the open.
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}
