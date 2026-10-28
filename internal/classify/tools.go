package classify

import "strings"

// FileWrite classifies a direct file edit by an agent tool (Write, Edit,
// apply_patch). It returns nothing for ordinary files.
func FileWrite(tool, path, dir string, opt Options) []Action {
	p := absPath(dir, path, opt.Home)
	base := Action{Engine: "file", Dir: dir, Command: tool + " " + p}
	switch {
	case IsProtectedPath(p, opt.ProtectedPaths):
		base.Class, base.Why = Tampering, tool+" edits guard file "+p
	case isStateFile(p):
		base.Class, base.Why, base.TouchesState = StateSurgery, tool+" edits state file "+p, true
	default:
		return nil
	}
	return []Action{base}
}

// FileRead classifies a direct file read by an agent tool.
func FileRead(tool, path, dir string, opt Options) []Action {
	p := absPath(dir, path, opt.Home)
	if !IsCredentialPath(p) {
		return nil
	}
	return []Action{{Class: CredentialAccess, Engine: "file", Dir: dir, Command: tool + " " + p, Why: tool + " reads credential file " + p}}
}

// PatchPaths extracts the file paths touched by a Codex apply_patch body.
func PatchPaths(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		for _, pfx := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if p, ok := strings.CutPrefix(strings.TrimSpace(line), pfx); ok {
				out = append(out, strings.TrimSpace(p))
			}
		}
	}
	return out
}
