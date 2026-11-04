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
	return ReadFileMax(path, MaxRead)
}

// MaxRead is the most ReadFile reads. applygate's own files are small; a
// larger one (a sparse file of gigabytes costs nothing on disk) would take
// longer to read and hash than the host waits for the hook.
const MaxRead = 4 << 20

// ReadFileMax is ReadFile for a file of at most max bytes; a larger file is
// an error, found before it is read.
func ReadFileMax(path string, max int64) ([]byte, error) {
	f, err := open(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		return nil, fmt.Errorf("%s is %d bytes, more than the %d applygate reads", path, fi.Size(), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		return nil, fmt.Errorf("%s is more than the %d bytes applygate reads", path, max)
	}
	return b, err
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
