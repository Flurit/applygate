//go:build !windows

package safefile

import "syscall"

// nonBlock keeps opening a FIFO with no peer from blocking.
const nonBlock = syscall.O_NONBLOCK
