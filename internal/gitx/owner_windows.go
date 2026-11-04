package gitx

import "os"

// rootOwned: a managed install is not supported on Windows.
func rootOwned(string, os.FileInfo) bool { return false }
