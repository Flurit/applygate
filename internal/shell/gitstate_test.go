package shell

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitSafeKey(t *testing.T) {
	cases := []struct {
		k, v    string
		network bool
		safe    bool
	}{
		{"user.name", "x", false, true},
		{"core.autocrlf", "input", false, true},
		{"core.fsmonitor", "true", false, true},
		{"core.fsmonitor", "sh -c x", false, false},
		{"core.hookspath", "/tmp/h", false, false},
		{"core.sshcommand", "ssh", false, false},
		{"core.editor", "vim", false, true},
		{"core.editor", "vim; terraform destroy", false, false},
		{"core.editor", "/tmp/vim", false, false},
		{"core.pager", "less -FRX", false, true},
		{"pager.log", "false", false, true},
		{"alias.st", "status", false, true},
		{"alias.x", "!sh -c x", false, false},
		{"gpg.ssh.defaultkeycommand", "x", false, false},
		{"gpg.program", "gpg", false, true},
		{"credential.helper", "!sh -c x", false, true},
		{"credential.helper", "!sh -c x", true, false},
		{"credential.helper", "osxkeychain", true, true},
		{"credential.https://github.com.helper", "!/opt/homebrew/bin/gh auth git-credential", true, true},
		{"remote.origin.url", "git@github.com:a/b.git", false, true},
		{"remote.origin.url", "/tmp/b", false, false},
		{"remote.origin.uploadpack", "x", false, false},
		{"url.https://github.com/.insteadof", "gh:", false, true},
		{"url./tmp/x.insteadof", "https://github.com/", false, false},
		{"filter.lfs.clean", "git-lfs clean -- %f", false, true},
		{"filter.x.clean", "sh", false, false},
		{"diff.x.textconv", "sh", false, false},
		{"init.templatedir", "/tmp/t", false, false},
		{"interactive.difffilter", "x", false, false},
		{"submodule.x.update", "!sh", false, false},
		{"unknown.key", "x", false, false},
	}
	for _, c := range cases {
		if got := GitSafeKey(c.k, c.v, c.network); got != c.safe {
			t.Errorf("GitSafeKey(%q, %q, %v) = %v, want %v", c.k, c.v, c.network, got, c.safe)
		}
	}
}

func TestParseGitConfig(t *testing.T) {
	e, ok := parseGitConfig("[core]\n\tbare = false\n\tfsmonitor = \"sh -c 'x' # not a comment\" ; comment\n[remote \"Origin\"]\n\turl = a\\\nb\n[x]\n\tflag\n")
	if !ok {
		t.Fatal("did not parse")
	}
	want := []gitEntry{{"core.bare", "false"}, {"core.fsmonitor", "sh -c 'x' # not a comment"}, {"remote.origin.url", "ab"}, {"x.flag", "true"}}
	if len(e) != len(want) {
		t.Fatalf("got %v", e)
	}
	for i := range want {
		if e[i] != want[i] {
			t.Errorf("entry %d: got %v, want %v", i, e[i], want[i])
		}
	}
	if _, ok := parseGitConfig("[core\nx = y\n"); ok {
		t.Error("a broken section parsed")
	}
}

// The repository state check follows includes, bare repositories and
// submodules.
func TestGitState(t *testing.T) {
	home := t.TempDir()
	old := gitEnv
	gitEnv = func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	}
	defer func() { gitEnv = old }()
	resetConfigCache()
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\tbare = false\n"), 0o644)
	if why := gitState(repo, "status"); why != "" {
		t.Fatalf("a clean repository: %s", why)
	}
	os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[include]\n\tpath = extra\n"), 0o644)
	os.WriteFile(filepath.Join(home, "extra"), []byte("[core]\n\tfsmonitor = sh -c x\n"), 0o644)
	resetConfigCache()
	if why := gitState(repo, "status"); why == "" {
		t.Fatal("an fsmonitor in an included global config was plain")
	}
	os.Remove(filepath.Join(home, ".gitconfig"))
	resetConfigCache()
	sub := filepath.Join(repo, ".git", "modules", "m")
	for _, d := range []string{"objects", "refs"} {
		os.MkdirAll(filepath.Join(sub, d), 0o755)
	}
	os.WriteFile(filepath.Join(sub, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	os.WriteFile(filepath.Join(sub, "config"), []byte("[core]\n\tfsmonitor = sh -c x\n"), 0o644)
	if why := gitState(repo, "status"); why == "" {
		t.Fatal("a submodule's fsmonitor was plain")
	}
	bare := filepath.Join(t.TempDir(), "b.git")
	for _, d := range []string{"objects", "refs"} {
		os.MkdirAll(filepath.Join(bare, d), 0o755)
	}
	os.WriteFile(filepath.Join(bare, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	os.WriteFile(filepath.Join(bare, "config"), []byte("[core]\n\tsshCommand = x\n"), 0o644)
	if why := gitState(bare, "ls-remote"); why == "" {
		t.Fatal("a bare repository's sshCommand was plain")
	}
}
