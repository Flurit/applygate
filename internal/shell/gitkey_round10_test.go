package shell

import "testing"

// A promisor remote makes a local read fetch from the network.
func TestGitSafeKeyPartialClone(t *testing.T) {
	for _, k := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter", "extensions.partialclone"} {
		if GitSafeKey(k, "true", false) {
			t.Errorf("%s is on the safe list", k)
		}
	}
	if !GitSafeKey("extensions.worktreeconfig", "true", false) {
		t.Error("extensions.worktreeConfig should stay safe")
	}
}
