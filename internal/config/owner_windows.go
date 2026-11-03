//go:build windows

package config

import "os"

func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
