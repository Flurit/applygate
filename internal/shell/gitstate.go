package shell

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Flurit/applygate/internal/gitx"
)

// The state git reads on its own, checked before a git command counts as
// plain: every git directory the command can reach (the repository's,
// a bare repository's, each submodule's), their hooks, and every config
// file git reads (system, global, the repository's and its worktree's, and
// what they include). A key is plain only when it is on the safe list below
// or, for the keys that name a program, when the program is a known one:
// an unknown key asks, so a key that runs a command and is missing from a
// list cannot allow a call.

// gitEnv is the environment git would run with; tests replace it.
var gitEnv = os.Getenv

// gitNetwork are the subcommands that reach a remote, and so run the
// credential helper and the transport.
var gitNetwork = toSet("fetch", "pull", "push", "clone", "ls-remote", "remote", "submodule")

// gitState reports why git, run in dir for subcommand sub, is not plain.
func gitState(dir, sub string) string {
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_EXEC_PATH", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
		"GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "GIT_TEMPLATE_DIR", "GIT_SEQUENCE_EDITOR"} {
		if gitEnv(k) != "" {
			return "git with " + k + " set in the agent's environment"
		}
	}
	for _, k := range []string{"GIT_EDITOR", "GIT_PAGER"} {
		if v := gitEnv(k); v != "" && !knownProgram(v, gitEditors) && !knownProgram(v, gitPagers) {
			return "git with " + k + " set in the agent's environment"
		}
	}
	network := gitNetwork[sub]
	var files []string
	if p := gitEnv("GIT_CONFIG_SYSTEM"); p != "" {
		files = append(files, p)
	} else if gitEnv("GIT_CONFIG_NOSYSTEM") == "" {
		files = append(files, gitSystemConfigs...)
	}
	if p := gitEnv("GIT_CONFIG_GLOBAL"); p != "" {
		files = append(files, p)
	} else if home := gitEnv("HOME"); home != "" {
		xdg := gitEnv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		files = append(files, filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig"))
	}
	allFiles := append([]string(nil), files...)
	for _, f := range files {
		if why := gitConfigCheck(f, network, 0); why != "" {
			return why
		}
	}
	if dir == "" {
		return "a git repository in an unknown directory"
	}
	// git walks up the physical directory, as getcwd gives it.
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	gitDir, common, ok := gitDiscover(dir)
	if why := gitAgrees(dir, gitDir, common, ok); why != "" {
		return why
	}
	if !ok {
		return "" // not in a repository: git init, clone, or an error
	}
	if gitDir == "" {
		return "a git directory that cannot be read"
	}
	dirs := []string{common}
	if gitDir != common {
		dirs = append(dirs, gitDir)
	}
	// Submodules keep their git directories under modules/; a command in
	// the superproject (status, diff, checkout with submodule.recurse) runs
	// git in each of them.
	_ = filepath.WalkDir(filepath.Join(common, "modules"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if isGitDir(p) {
			dirs = append(dirs, p)
		}
		if len(dirs) > 200 {
			return filepath.SkipAll
		}
		return nil
	})
	if len(dirs) > 200 {
		return "more submodules than applygate checks"
	}
	for _, d := range dirs {
		if why := gitHooks(d); why != "" {
			return why
		}
		for _, f := range []string{filepath.Join(d, "config"), filepath.Join(d, "config.worktree")} {
			allFiles = append(allFiles, f)
			if why := gitConfigCheck(f, network, 0); why != "" {
				return why
			}
		}
	}
	// A subcommand that writes the working tree runs Git LFS's smudge
	// filter, which calls the credential helper and the transfer agent:
	// with LFS configured, the keys only a remote operation uses count too.
	if !network && gitWorktree[sub] {
		for _, f := range allFiles {
			if configHasLFS(f, 0) {
				for _, f := range allFiles {
					if why := gitConfigCheck(f, true, 0); why != "" {
						return why + " (git-lfs runs it when this command writes files)"
					}
				}
				break
			}
		}
	}
	return ""
}

// gitWorktree are the subcommands that write the working tree, and so run
// the smudge filters.
var gitWorktree = toSet("checkout", "switch", "reset", "restore", "stash", "merge", "rebase", "pull", "cherry-pick", "revert",
	"clone", "worktree", "am", "apply", "read-tree", "sparse-checkout", "submodule")

var lfsCache sync.Map // path -> bool

// configHasLFS reports whether config file p (or what it includes) sets a
// filter.lfs.* key.
func configHasLFS(p string, depth int) bool {
	if v, ok := lfsCache.Load(p); ok {
		return v.(bool)
	}
	has := false
	if depth <= 10 {
		if b, err := readSmall(p); err == nil {
			if entries, ok := parseGitConfig(string(b)); ok {
				for _, e := range entries {
					switch {
					case strings.HasPrefix(e.key, "filter.lfs."), strings.HasPrefix(e.key, "lfs."):
						has = true
					case e.key == "include.path" || strings.HasPrefix(e.key, "includeif.") && strings.HasSuffix(e.key, ".path"):
						inc := e.value
						if strings.HasPrefix(inc, "~/") {
							inc = filepath.Join(gitEnv("HOME"), inc[2:])
						} else if !filepath.IsAbs(inc) {
							inc = filepath.Join(filepath.Dir(p), inc)
						}
						has = has || configHasLFS(inc, depth+1)
					}
				}
			}
		}
	}
	lfsCache.Store(p, has)
	return has
}

// gitSystemConfigs are where git installs read their system config:
// $(prefix)/etc/gitconfig for the usual prefixes, and the Xcode and
// Command Line Tools copies on macOS.
var gitSystemConfigs = []string{"/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig",
	"/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig",
	"/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig"}

// gitDiscover finds the git directory for dir as git does: walking up, a
// .git directory or gitfile, or the directory itself when it is a git
// directory (a bare repository, or inside .git). common is the directory
// commondir names (a linked worktree's main git directory). ok is false
// outside a repository; gitDir is "" when an entry cannot be followed.
func gitDiscover(dir string) (gitDir, common string, ok bool) {
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, ".git")
		fi, err := os.Lstat(p)
		switch {
		case err == nil && fi.IsDir() && isGitDir(p):
			gitDir = p
		case err == nil && fi.IsDir():
			// git passes over a .git directory that is not a repository and
			// tries the directory itself, then its parent.
			if isGitDir(d) {
				gitDir = d
			}
		case err == nil && fi.Mode().IsRegular():
			b, err := readSmall(p)
			if err != nil {
				return "", "", true
			}
			g, found := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
			if !found {
				return "", "", true
			}
			if g = strings.TrimSpace(g); !filepath.IsAbs(g) {
				g = filepath.Join(d, g)
			}
			gitDir = g
		case err == nil:
			return "", "", true // a symlink or another kind of entry
		case !os.IsNotExist(err):
			return "", "", true
		case isGitDir(d):
			gitDir = d
		}
		if gitDir != "" {
			common = gitDir
			if b, err := readSmall(filepath.Join(gitDir, "commondir")); err == nil {
				c := strings.TrimSpace(string(b))
				if !filepath.IsAbs(c) {
					c = filepath.Join(gitDir, c)
				}
				common = filepath.Clean(c)
			} else if !os.IsNotExist(err) {
				return "", "", true
			}
			return gitDir, common, true
		}
		if filepath.Dir(d) == d {
			return "", "", false
		}
	}
}

// isGitDir reports whether d looks like a git directory to git: HEAD, and
// objects and refs directories.
func isGitDir(d string) bool {
	if fi, err := os.Stat(filepath.Join(d, "HEAD")); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	for _, s := range []string{"objects", "refs"} {
		if fi, err := os.Stat(filepath.Join(d, s)); err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

// gitHooks reports a hook in git directory d other than git's samples.
func gitHooks(d string) string {
	ents, err := os.ReadDir(filepath.Join(d, "hooks"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return "git hooks that cannot be read"
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".sample") {
			return "the git hook " + filepath.Join(d, "hooks", e.Name())
		}
	}
	return ""
}

// configCache holds the verdict on each config file for the process: one
// command may run git many times.
var configCache sync.Map // "path\x00network" -> string

// gitConfigCheck reports why config file p (and what it includes) is not
// plain for a local or a network subcommand. A file that does not exist is
// fine, as git ignores it.
func gitConfigCheck(p string, network bool, depth int) string {
	key := p + "\x00" + map[bool]string{true: "n", false: "l"}[network]
	if v, ok := configCache.Load(key); ok {
		return v.(string)
	}
	why := gitConfigRead(p, network, depth)
	configCache.Store(key, why)
	return why
}

func gitConfigRead(p string, network bool, depth int) string {
	if depth > 10 {
		return "git config includes nested too deeply"
	}
	b, err := readSmall(p)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return "the git config " + p + " cannot be read"
	}
	entries, ok := parseGitConfig(string(b))
	if !ok {
		return "the git config " + p + " does not parse"
	}
	for _, e := range entries {
		if e.key == "include.path" || strings.HasPrefix(e.key, "includeif.") && strings.HasSuffix(e.key, ".path") {
			inc := e.value
			if strings.HasPrefix(inc, "~") && !strings.HasPrefix(inc, "~/") || strings.HasPrefix(inc, "%(") {
				// ~user/ and %(prefix)/ name other places git expands.
				return "a git config include (" + inc + ") applygate does not follow, in " + p
			}
			if strings.HasPrefix(inc, "~/") {
				inc = filepath.Join(gitEnv("HOME"), inc[2:])
			} else if !filepath.IsAbs(inc) {
				inc = filepath.Join(filepath.Dir(p), inc)
			}
			if why := gitConfigCheck(inc, network, depth+1); why != "" {
				return why
			}
			continue
		}
		if !GitSafeKey(e.key, e.value, network) {
			return "the git config key " + e.key + " in " + p
		}
	}
	return ""
}

type gitEntry struct{ key, value string }

// parseGitConfig reads git's config syntax: sections with optional quoted
// subsections, key = value with quotes, escapes, comments and continued
// lines, and a bare key meaning true. Keys are lower case; a subsection's
// text is kept, lowered, between the dots.
func parseGitConfig(s string) ([]gitEntry, bool) {
	var out []gitEntry
	sec := ""
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(strings.TrimSuffix(lines[i], "\r"))
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '[' {
			end := strings.IndexByte(l, ']')
			if end < 0 {
				return nil, false
			}
			h := l[1:end]
			if name, sub, has := strings.Cut(h, " "); has {
				sub = strings.TrimSpace(sub)
				if !strings.HasPrefix(sub, `"`) || !strings.HasSuffix(sub, `"`) || len(sub) < 2 {
					return nil, false
				}
				sec = strings.ToLower(strings.TrimSpace(name)) + "." + strings.ToLower(strings.ReplaceAll(sub[1:len(sub)-1], `\"`, `"`))
			} else {
				// [section.sub] is the old lower-cased form.
				sec = strings.ToLower(strings.TrimSpace(h))
			}
			if l = strings.TrimSpace(l[end+1:]); l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
		}
		if sec == "" {
			return nil, false
		}
		k, v, hasV := strings.Cut(l, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" || strings.ContainsAny(k, " \t\"") {
			return nil, false
		}
		if !hasV {
			out = append(out, gitEntry{sec + "." + k, "true"})
			continue
		}
		// A value continues on the next line after a trailing backslash
		// outside quotes.
		raw := v
		for {
			val, cont, ok := gitValue(raw)
			if !ok {
				return nil, false
			}
			if !cont {
				out = append(out, gitEntry{sec + "." + k, val})
				break
			}
			if i+1 >= len(lines) {
				return nil, false
			}
			i++
			raw = raw[:len(raw)-1] + lines[i]
		}
	}
	return out, true
}

// gitValue unquotes a config value. cont is true when the line ends in a
// backslash that continues it.
func gitValue(raw string) (val string, cont, ok bool) {
	var b strings.Builder
	quoted := false
	raw = strings.TrimRight(strings.TrimSuffix(raw, "\r"), " \t")
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\\':
			if i+1 == len(raw) {
				return "", true, true
			}
			i++
			switch raw[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'b':
				return "", false, false
			case '"', '\\':
				b.WriteByte(raw[i])
			default:
				return "", false, false
			}
		case c == '"':
			quoted = !quoted
		case !quoted && (c == '#' || c == ';'):
			return strings.TrimSpace(b.String()), false, !quoted
		default:
			b.WriteByte(c)
		}
	}
	if quoted {
		return "", false, false
	}
	return strings.TrimSpace(b.String()), false, true
}

// Sections whose every key is safe: none names a program or a file git
// runs or reads config from.
var gitSafeSections = toSet("user", "author", "committer", "color", "column", "advice", "status", "log", "format", "blame",
	"commit", "gc", "pack", "index", "feature", "fetch", "rebase", "push", "pull", "safe", "lfs", "http", "transfer",
	"receive", "maintenance", "rerere", "help", "i18n", "branch", "tag", "notes", "grep", "am", "apply", "checkout",
	"clean", "clone", "worktree", "extensions", "difftool", "mergetool", "sendemail", "gui", "versionsort", "reset",
	"stash", "showbranch", "splitindex", "fastimport", "add", "hub", "github", "gitlab", "init", "merge", "diff",
	"interactive", "credential", "submodule", "remote", "url", "filter", "alias", "protocol", "core", "sequence",
	"pager", "gpg", "uploadpack", "web", "browser", "guitool", "trace2", "include", "includeif")

// gitSafeCore are the core keys that only tune how git reads and writes.
var gitSafeCore = toSet("repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase", "precomposeunicode",
	"symlinks", "autocrlf", "safecrlf", "eol", "quotepath", "excludesfile", "attributesfile", "whitespace", "compression",
	"loosecompression", "abbrev", "sharedrepository", "untrackedcache", "preloadindex", "commentchar", "commentstring",
	"checkstat", "trustctime", "splitindex", "fscache", "longpaths", "warnambiguousrefs", "multipackindex", "commitgraph",
	"packedgitlimit", "packedgitwindowsize", "deltabasecachelimit", "bigfilethreshold", "sparsecheckout",
	"sparsecheckoutcone", "worktree", "hidedotfiles", "notesref", "protecthfs", "protectntfs", "fsync", "fsyncmethod",
	"fsyncobjectfiles", "createobject", "maxtreedepth")

// GitSafeKey reports whether config key k (lower case) with value v is
// known not to make git run a program or read config from elsewhere. For
// a local subcommand the keys only a remote operation uses (the credential
// helper) do not matter.
func GitSafeKey(k, v string, network bool) bool {
	parts := strings.Split(k, ".")
	if len(parts) < 2 {
		return false
	}
	sec, name := parts[0], parts[len(parts)-1]
	sub := strings.Join(parts[1:len(parts)-1], ".")
	v = strings.TrimSpace(v)
	if !gitSafeSections[sec] {
		return false
	}
	switch sec {
	case "core":
		switch {
		case sub != "":
			return false
		case name == "fsmonitor":
			return gitBool(v) // the built-in daemon, not a program
		case name == "editor":
			return knownProgram(v, gitEditors)
		case name == "pager":
			return v == "" || knownProgram(v, gitPagers)
		}
		return gitSafeCore[name]
	case "sequence":
		return sub == "" && name == "editor" && knownProgram(v, gitEditors)
	case "pager":
		return gitBool(v) || v == "" || knownProgram(v, gitPagers)
	case "alias":
		return !strings.HasPrefix(v, "!")
	case "init":
		return name != "templatedir"
	case "merge":
		return name != "driver"
	case "diff":
		return name != "external" && name != "textconv" && name != "command" && name != "trustexitcode"
	case "interactive":
		return name != "difffilter"
	case "difftool", "mergetool":
		// The tools run only for git difftool and mergetool, which are not
		// plain.
		return true
	case "credential":
		if name != "helper" || !network {
			return true
		}
		return v == "" || knownHelper(v)
	case "gpg":
		switch {
		case name == "format":
			return v == "openpgp" || v == "ssh" || v == "x509"
		case name == "program":
			return knownProgram(v, gitSigners)
		case name == "defaultkeycommand":
			return false
		}
		return name == "allowedsignersfile" || name == "revocationfile" || name == "mintrustlevel"
	case "remote":
		switch name {
		case "uploadpack", "receivepack", "vcs":
			return false
		case "url", "pushurl":
			return networkURL(v)
		}
		return true
	case "url":
		// url.<base>.insteadOf rewrites URLs to base.
		return (name == "insteadof" || name == "pushinsteadof") && networkURL(sub)
	case "submodule":
		if name == "update" {
			return v == "checkout" || v == "rebase" || v == "merge" || v == "none"
		}
		if name == "url" {
			return networkURL(v) || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../")
		}
		return true
	case "lfs":
		// Git LFS runs the programs extension and customtransfer entries
		// name (and standalonetransferagent selects one) from clean, smudge
		// and transfers; its other keys are URLs, limits and switches.
		switch {
		case strings.HasPrefix(sub, "extension"), strings.HasPrefix(sub, "customtransfer"), name == "standalonetransferagent",
			name == "extension", name == "customtransfer":
			return false
		}
		return true
	case "filter":
		// Git LFS's filter, the one most users have.
		if sub != "lfs" {
			return false
		}
		switch name {
		case "clean", "smudge", "process":
			return v == "git-lfs clean -- %f" || v == "git-lfs smudge -- %f" || v == "git-lfs filter-process"
		}
		return name == "required"
	case "protocol":
		return sub != "ext" && sub != "fd"
	case "uploadpack", "web", "browser", "guitool", "trace2":
		return false
	case "include", "includeif":
		return false // followed by the caller
	}
	return true
}

func gitBool(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false", "yes", "no", "on", "off", "1", "0", "":
		return true
	}
	return false
}

// Programs git may be told to run for a key, by name: each is one an
// agent may not place on PATH (config.PathPrograms).
var (
	gitEditors = toSet("vi", "vim", "nvim", "nano", "emacs", "emacsclient", "code", "code-insiders", "subl", "mate", "cursor",
		"zed", "hx", "micro", "nvi", "ed", "pico", "kak", "true", "cat")
	gitPagers  = toSet("less", "more", "cat", "most", "delta", "bat")
	gitSigners = toSet("gpg", "gpg2", "gpgsm", "ssh-keygen")
	gitHelpers = toSet("osxkeychain", "cache", "store", "manager", "manager-core", "libsecret", "wincred", "gnome-keyring")
)

// GitPrograms are the programs config may name that a plain git runs.
func GitPrograms() []string {
	var out []string
	for _, s := range []map[string]bool{gitEditors, gitPagers, gitSigners} {
		for n := range s {
			out = append(out, n)
		}
	}
	for n := range gitHelpers {
		out = append(out, "git-credential-"+n)
	}
	return append(out, "git-lfs", "gh")
}

// gitSystemBins are where a program named by its full path may be.
var gitSystemBins = toSet("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin")

// knownProgram reports whether v runs a program in set, by name or by a
// full path in a system directory, with plain arguments and nothing the
// shell would interpret.
func knownProgram(v string, set map[string]bool) bool {
	if v == "" || strings.ContainsAny(v, "$`;|&<>()\\'\"*?[]{}!~\n") {
		return false
	}
	f := strings.Fields(v)
	if len(f) == 0 {
		return false
	}
	// Editors, pagers and signers have options that run code (vim -S, emacs
	// -l, nano --rcfile, bat --pager, gpg --agent-program): the value is
	// the program, or the program with a few flags known to change nothing.
	for _, o := range f[1:] {
		if !harmlessFlag[o] {
			return false
		}
	}
	p := f[0]
	if strings.Contains(p, "/") {
		if !filepath.IsAbs(p) || !gitSystemBins[filepath.Dir(p)] {
			return false
		}
		p = filepath.Base(p)
	}
	return set[p]
}

// knownHelper reports whether a credential.helper value is one of git's
// own helpers, GitHub CLI's, or Git Credential Manager by its full path.
func knownHelper(v string) bool {
	if gitHelpers[strings.Fields(v + " x")[0]] && !strings.ContainsAny(v, "$`;|&<>()\\'\"!") {
		return true
	}
	if rest, ok := strings.CutPrefix(v, "!"); ok {
		// gh auth setup-git writes "!/path/to/gh auth git-credential".
		f := strings.Fields(rest)
		return len(f) == 3 && f[1] == "auth" && f[2] == "git-credential" && knownProgram(f[0], toSet("gh"))
	}
	if filepath.IsAbs(v) && !strings.ContainsAny(v, " $`;|&<>()") {
		b := filepath.Base(v)
		return (b == "git-credential-manager" || b == "git-credential-manager-core") &&
			(gitSystemBins[filepath.Dir(v)] || strings.HasPrefix(v, "/usr/local/share/gcm-core/"))
	}
	return false
}

// networkURL reports whether a remote URL reaches another machine (https,
// ssh, git, or scp-like user@host:path), not a local path, a file:// URL
// or a transport that runs a command.
func networkURL(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"https://", "http://", "ssh://", "git://", "git+ssh://", "ssh+git://"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if strings.Contains(v, "://") {
		// Any other scheme runs git-remote-<scheme> from PATH.
		return false
	}
	// scp-like: [user@]host:path, where host has no slash before the colon.
	if i := strings.IndexByte(v, ':'); i > 0 && !strings.Contains(v[:i], "/") && !strings.Contains(l, "::") {
		return true
	}
	return false
}

// resetConfigCache forgets the cached verdicts (tests).
func resetConfigCache() {
	configCache.Range(func(k, _ any) bool { configCache.Delete(k); return true })
	askCache.Range(func(k, _ any) bool { askCache.Delete(k); return true })
	lfsCache.Range(func(k, _ any) bool { lfsCache.Delete(k); return true })
}

// gitAsk asks the hook's own git where the git directory for dir is. It is
// a variable so that tests can replace it. found is false outside a
// repository; failed is set when git could not answer (no git, a timeout).
var gitAsk = func(dir string) (gitDir, common string, found, failed bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := gitx.Command(ctx, dir, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if strings.Contains(errb.String(), "not a git repository") {
			return "", "", false, false
		}
		return "", "", false, true
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		return "", "", false, true
	}
	return lines[0], lines[1], true, false
}

var askCache sync.Map // dir -> string

// gitAgrees reports why the git directory applygate found for dir is not
// the one git itself uses ("" when they agree, or git cannot be asked).
func gitAgrees(dir, gitDir, common string, ok bool) string {
	if v, hit := askCache.Load(dir); hit {
		return v.(string)
	}
	why := ""
	g, c, found, failed := gitAsk(dir)
	switch {
	case failed:
	case found != ok:
		if found {
			why = "git finds a repository at " + g + ", which applygate's walk does not"
		} else {
			why = "applygate finds a git directory git does not use"
		}
	case found && (!samePath(g, gitDir) || !samePath(c, common)):
		why = "git uses the git directory " + g + ", not " + gitDir
	}
	askCache.Store(dir, why)
	return why
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		a = r
	}
	if r, err := filepath.EvalSymlinks(b); err == nil {
		b = r
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

var remoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// gitConfiguredRemote reports whether name is a remote configured in the
// repository dir is in (git takes it as the remote, not as a path).
//
// A name that is not configured is taken as a path when a directory of
// that name exists (in dir or at the top of the work tree), and otherwise
// fails in git: only the first is local.
func gitConfiguredRemote(dir, name string) bool {
	if dir == "" || !remoteName.MatchString(name) {
		return false
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	gitDir, common, ok := gitDiscover(dir)
	local := isDirPath(filepath.Join(dir, name))
	if ok && filepath.Base(gitDir) == ".git" {
		local = local || isDirPath(filepath.Join(filepath.Dir(gitDir), name))
	}
	if !ok || common == "" {
		return !local
	}
	b, err := readSmall(filepath.Join(common, "config"))
	if err != nil {
		return false
	}
	entries, ok := parseGitConfig(string(b))
	if !ok {
		return false
	}
	want := "remote." + strings.ToLower(name) + ".url"
	configured := false
	for _, e := range entries {
		if e.key == want {
			if !networkURL(e.value) {
				return false
			}
			configured = true
		}
	}
	return configured || !local
}

func isDirPath(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// harmlessFlag are the flags an editor, pager or signer named in git config
// may carry: they wait for the editor, set a paging or display mode, or
// silence the program, and run no code.
var harmlessFlag = toSet("-w", "--wait", "-n", "--new-window", "--reuse-window", "-nw", "-F", "-R", "-X", "-S", "-i", "-r", "-E",
	"-M", "-q", "-FRX", "-FRSX", "-FRXi", "-RFX", "-XFR", "-+F", "-+X", "-+S", "-FX", "-FR", "-RX", "--quit-if-one-screen",
	"--RAW-CONTROL-CHARS", "--no-init", "--ignore-case", "--batch", "--no-tty", "--quiet", "--no-greeting", "--no-pager",
	"-p", "--paging=never", "--plain", "--style=plain")
