package policy

import "os"

func hardLinked(os.FileInfo) bool { return false }
