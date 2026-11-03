package shell

import (
	"os"
	"path/filepath"
	"strings"
)

// A shape says which calls of one program are plain: it returns "" when
// args (the words after the program name) can run no other program, else
// what can. Programs missing from shapes are not plain. A nil shape takes
// any arguments: the program has no option, variable or file that makes it
// run another program, and the files it writes are judged as writes.
type shape func(args []Word, inv Invocation) string

var shapes = map[string]shape{}

func init() {
	for _, n := range []string{
		"cd", "pwd", "echo", "true", "false", "test", "[", "exit", "unset", "sleep", "date", "which", "type",
		"ls", "cat", "head", "tail", "wc", "grep", "egrep", "uniq", "cut", "tr", "tee", "diff", "cmp", "tree", "stat",
		"file", "du", "df", "basename", "dirname", "realpath", "readlink", "mkdir", "touch", "cp", "mv", "rm", "ln",
		"chmod", "find", "jq", "yq", "column", "xxd", "od", "base64", "sha256sum", "shasum", "md5sum", "gzip", "gunzip",
		"unzip", "nl", "fold", "comm", "join", "paste", "seq", "id", "whoami", "uname", "hostname", "printenv", "curl",
		"gofmt", "terraform", "tofu", "terragrunt", "tflint", "tfsec", "terraform-docs", "infracost", "shellcheck",
		"actionlint", "gsutil", "vault", "applygate", "make", "env",
	} {
		shapes[n] = nil
	}
	shapes["printf"] = denyOpts("-v")
	shapes["sort"] = denyOpts("--compress-program")
	shapes["rg"] = rgShape
	shapes["sed"] = sedShape
	shapes["tar"] = tarShape
	shapes["zip"] = denyOpts("-TT", "--unzip-command")
	shapes["wget"] = denyOpts("--use-askpass", "-e", "--execute", "--config")
	shapes["git"] = gitShape
	shapes["gh"] = valuedSubcommands(toSet("-R", "--repo"), "auth status", "api", "cache", "gist", "issue", "label", "org", "pr", "project", "release",
		"repo", "run", "ruleset", "search", "secret", "status", "variable", "workflow", "config get", "config list")
	shapes["glab"] = valuedSubcommands(toSet("-R", "--repo"), "api", "auth status", "ci", "issue", "label", "mr", "release", "repo", "variable",
		"config get")
	shapes["go"] = valuedSubcommands(toSet("-C"), "version", "env", "doc", "help", "list", "mod graph", "mod why", "mod verify")
	shapes["docker"] = valuedSubcommands(toSet("-H", "--host", "--context", "-c", "-l", "--log-level"), "ps", "images", "image ls", "image inspect", "version", "info", "logs", "inspect",
		"context ls", "context show", "compose ps", "compose ls", "compose config", "compose logs", "compose version")
	// docker --config names a config whose credsStore is a helper program.
	dockerShape := shapes["docker"]
	shapes["docker"] = func(args []Word, inv Invocation) string {
		if hasOpt(args, "--config") {
			return "the option --config"
		}
		return dockerShape(args, inv)
	}
	shapes["podman"] = shapes["docker"]
	shapes["kubectl"] = kubectlShape
	shapes["helm"] = helmShape
	shapes["kustomize"] = denyOpts("--enable-alpha-plugins", "--enable-exec")
	shapes["checkov"] = denyOpts("--external-checks-dir", "--external-checks-git")
	shapes["trivy"] = subcommands("config", "fs", "filesystem", "repo", "repository", "image", "version", "sbom", "k8s")
	shapes["conftest"] = subcommands("test", "verify", "parse", "fmt", "version")
	shapes["opa"] = subcommands("eval", "test", "fmt", "check", "version", "inspect", "parse", "build")
	shapes["aws"] = awsShape
	shapes["az"] = denySub("extension", "upgrade", "interactive")
	shapes["gcloud"] = denySub("components", "interactive")
	// `go env -w` and `-u` write the go environment file, which later
	// builds read.
	goShape := shapes["go"]
	shapes["go"] = func(args []Word, inv Invocation) string {
		if why := goShape(args, inv); why != "" {
			return why
		}
		if len(args) > 0 && args[0].Text == "env" {
			return denyOpts("-w", "-u")(args, inv)
		}
		return ""
	}
}

// plainEnv are the variables a plain command may set: they choose a profile,
// region, workspace or locale, and none names a program to run. The values
// of the pager variables must be empty or cat.
var plainEnv = toSet("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_DEFAULT_OUTPUT", "TF_IN_AUTOMATION", "TF_INPUT",
	"TF_LOG", "TF_LOG_CORE", "TF_LOG_PROVIDER", "TF_WORKSPACE", "TF_DATA_DIR", "TF_PLUGIN_CACHE_DIR", "NO_COLOR", "CLICOLOR",
	"TERM", "LANG", "TZ", "CI", "DEBUG", "VERBOSE", "GOOS", "GOARCH", "CGO_ENABLED", "CLOUDSDK_CORE_PROJECT",
	"GOOGLE_CLOUD_PROJECT", "ARM_SUBSCRIPTION_ID", "ARM_TENANT_ID", "AZURE_SUBSCRIPTION_ID")

var pagerEnv = toSet("PAGER", "GIT_PAGER", "AWS_PAGER")

// plainEnvVar reports why setting name to v is not plain ("" when it is).
func plainEnvVar(name, v string, resolved bool) string {
	switch {
	case plainEnv[name], strings.HasPrefix(name, "TF_VAR_"), strings.HasPrefix(name, "LC_"):
		return ""
	case pagerEnv[name] && resolved && (v == "" || v == "cat"):
		return ""
	}
	return "the variable " + name
}

// shapeOf reports why one invocation is not plain.
func shapeOf(inv Invocation) string {
	n := ProgName(inv.Args[0].Text)
	s, ok := shapes[n]
	if !ok {
		return "the program " + n
	}
	for k, v := range inv.Env {
		if why := plainEnvVar(k, v, true); why != "" {
			return why
		}
	}
	if s == nil {
		return ""
	}
	return s(inv.Args[1:], inv)
}

// optText is an argument's text, or its literal prefix when it does not
// resolve: an option whose value is not known still names the option.
func optText(w Word) string {
	if w.Resolved {
		return w.Text
	}
	return w.Prefix
}

// hasOpt reports whether args use the option o: alone, with =value, or a
// short option glued to its value (-Ifoo) or clustered with others.
func hasOpt(args []Word, o string) bool {
	for _, w := range args {
		t := optText(w)
		if t == "--" {
			return false
		}
		switch {
		case t == o, strings.HasPrefix(o, "--") && strings.HasPrefix(t, o+"="):
			return true
		case len(o) == 2 && o[0] == '-' && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t[1:], rune(o[1])):
			return true
		case strings.HasPrefix(o, "--") && strings.HasPrefix(t, "--"):
			// GNU long options may be abbreviated to any unique prefix.
			k, _, _ := strings.Cut(t, "=")
			if len(k) >= 4 && strings.HasPrefix(o, k) {
				return true
			}
		}
	}
	return false
}

func denyOpts(opts ...string) shape {
	return func(args []Word, _ Invocation) string {
		for _, o := range opts {
			if hasOpt(args, o) {
				return "the option " + o
			}
		}
		return ""
	}
}

// positional returns the words that are not options, up to n of them.
// An option in valued takes the next word as its value. An unresolved word
// is returned as "" so that it never matches a subcommand.
func positional(args []Word, n int, valued map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		w := args[i]
		if len(out) == n {
			break
		}
		if t := optText(w); strings.HasPrefix(t, "-") {
			if valued[t] {
				i++
			}
			continue
		}
		if !w.Resolved {
			out = append(out, "")
			continue
		}
		out = append(out, w.Text)
	}
	return out
}

// subcommands accepts only the listed subcommands ("pr", "config get"):
// plugins, aliases and extensions run programs of their own.
func subcommands(subs ...string) shape {
	return valuedSubcommands(nil, subs...)
}

func valuedSubcommands(valued map[string]bool, subs ...string) shape {
	return func(args []Word, _ Invocation) string {
		pos := positional(args, 2, valued)
		for _, s := range subs {
			f := strings.Fields(s)
			if len(pos) >= len(f) && strings.Join(pos[:len(f)], " ") == s {
				return ""
			}
		}
		if len(pos) == 0 {
			return ""
		}
		return "the subcommand " + strings.Join(pos, " ")
	}
}

func denySub(subs ...string) shape {
	return func(args []Word, _ Invocation) string {
		pos := positional(args, 1, cloudValued)
		for _, s := range subs {
			if len(pos) == 1 && pos[0] == s {
				return "the subcommand " + s
			}
		}
		return ""
	}
}

// rgShape: --pre runs a preprocessor, and -z runs decompressors.
func rgShape(args []Word, inv Invocation) string {
	if why := denyOpts("--pre", "--pre-glob", "--search-zip")(args, inv); why != "" {
		return why
	}
	if hasOpt(args, "-z") {
		return "the option -z"
	}
	return ""
}

// tarShape accepts the usual create, extract and list options. The options
// that run a program (-I, -F, --use-compress-program, --checkpoint-action,
// --to-command, --info-script, --rsh-command), write outside the directory
// (-P) or read a remote archive (host:file) are not plain.
func tarShape(args []Word, _ Invocation) string {
	const shortOK = "cxtruvfzjJaOpCmkhoSsWlBMG"
	longOK := toSet("--file", "--directory", "--extract", "--create", "--list", "--get", "--gzip", "--gunzip", "--bzip2",
		"--xz", "--zstd", "--verbose", "--exclude", "--exclude-from", "--strip-components", "--wildcards", "--no-same-owner",
		"--same-permissions", "--preserve-permissions", "--keep-old-files", "--overwrite", "--to-stdout", "--force-local",
		"--transform", "--owner", "--group", "--mtime", "--sort", "--numeric-owner", "--exclude-vcs", "--totals",
		"--one-file-system", "--dereference", "--null", "--files-from", "-T", "-X", "--warning", "--format", "--anchored")
	local := false
	for i, w := range args {
		t := optText(w)
		switch {
		case !w.Resolved && strings.HasPrefix(t, "-"):
			return "an option that cannot be resolved"
		case strings.HasPrefix(t, "--"):
			k, _, _ := strings.Cut(t, "=")
			if !longOK[k] {
				return "the option " + k
			}
			local = local || k == "--force-local"
		case strings.HasPrefix(t, "-") && len(t) > 1:
			if longOK[t] {
				continue
			}
			for _, c := range t[1:] {
				if !strings.ContainsRune(shortOK, c) {
					return "the option -" + string(c)
				}
			}
		case i == 0 && !strings.ContainsAny(t, "/.") && t != "":
			// The old style: the first word is a cluster without a dash.
			for _, c := range t {
				if !strings.ContainsRune(shortOK, c) {
					return "the option " + string(c)
				}
			}
		}
	}
	if !local {
		for _, w := range args {
			if t := optText(w); !strings.HasPrefix(t, "-") && strings.Contains(t, ":") && !strings.HasPrefix(t, "/") {
				return "a remote archive"
			}
		}
	}
	return ""
}

// sedShape accepts scripts whose commands neither run a program (e, and
// the e flag of s) nor write a file the analyzer does not see (w, W, the w
// flag). A script from a file (-f) is not read.
func sedShape(args []Word, _ Invocation) string {
	var scripts []Word
	explicit := false
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := optText(w)
		switch {
		case t == "--":
			i = len(args)
		case t == "-f" || strings.HasPrefix(t, "--file") || strings.HasPrefix(t, "-f") && !strings.HasPrefix(t, "--"):
			return "a sed script from a file"
		case t == "-e" || t == "--expression":
			explicit = true
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1])
				i++
			}
		case strings.HasPrefix(t, "--expression="):
			explicit = true
			scripts = append(scripts, Word{Text: strings.TrimPrefix(w.Text, "--expression="), Resolved: w.Resolved})
		case strings.HasPrefix(t, "-e") && !strings.HasPrefix(t, "--"):
			explicit = true
			scripts = append(scripts, Word{Text: w.Text[2:], Resolved: w.Resolved})
		case strings.HasPrefix(t, "-"):
		default:
			if !explicit && len(scripts) == 0 {
				scripts = append(scripts, w)
			}
		}
	}
	for _, s := range scripts {
		if !s.Resolved {
			return "a sed script that cannot be resolved"
		}
		if why := sedScript(s.Text); why != "" {
			return why
		}
	}
	return ""
}

// sedScript reads a sed script command by command.
func sedScript(s string) string {
	i := 0
	skipAddr := func() {
		for i < len(s) {
			switch c := s[i]; {
			case c >= '0' && c <= '9' || c == '$' || c == ',' || c == '~' || c == '+' || c == '!' || c == ' ' || c == '\t':
				i++
			case c == '/' || c == '\\':
				d := byte('/')
				if c == '\\' && i+1 < len(s) {
					i++
					d = s[i]
				}
				i++
				for i < len(s) && s[i] != d {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				i++
				for i < len(s) && (s[i] == 'I' || s[i] == 'M') {
					i++
				}
			default:
				return
			}
		}
	}
	for i < len(s) {
		for i < len(s) && strings.IndexByte(" \t\n;{}", s[i]) >= 0 {
			i++
		}
		if i >= len(s) {
			break
		}
		skipAddr()
		if i >= len(s) {
			break
		}
		c := s[i]
		i++
		switch c {
		case 'e':
			return "the sed command e"
		case 'w', 'W':
			return "the sed command " + string(c)
		case 's', 'y':
			if i >= len(s) {
				return "a sed command that does not parse"
			}
			d := s[i]
			i++
			for part := 0; part < 2; part++ {
				for i < len(s) && s[i] != d {
					if s[i] == '\\' {
						i++
					}
					i++
				}
				if i >= len(s) {
					return "a sed command that does not parse"
				}
				i++
			}
			if c == 's' {
				for i < len(s) && strings.IndexByte(";\n}", s[i]) < 0 {
					switch s[i] {
					case 'e':
						return "the sed flag e"
					case 'w':
						return "the sed flag w"
					}
					i++
				}
			}
		case 'a', 'i', 'c', 'r', 'R', ':', 'b', 't', 'T', 'q', 'Q', 'l', 'L', 'v':
			// The rest of the line is text, a file to read or a label.
			for i < len(s) && s[i] != '\n' && !(c != 'a' && c != 'i' && c != 'c' && s[i] == ';') {
				i++
			}
		case 'p', 'P', 'd', 'D', 'n', 'N', 'g', 'G', 'h', 'H', 'x', '=', 'z', 'F', '#':
			if c == '#' {
				for i < len(s) && s[i] != '\n' {
					i++
				}
			}
		default:
			return "the sed command " + string(c)
		}
	}
	return ""
}

// gitSubs are the git subcommands a plain command may run. Others run a
// program by design (filter-branch, bisect run, submodule foreach, difftool,
// mergetool), or are aliases.
var gitSubs = toSet("status", "log", "diff", "show", "branch", "checkout", "switch", "add", "commit", "restore", "reset",
	"stash", "fetch", "pull", "push", "merge", "rebase", "tag", "remote", "rev-parse", "rev-list", "ls-files", "ls-tree",
	"blame", "describe", "config", "init", "clone", "mv", "rm", "cherry-pick", "revert", "worktree", "grep", "shortlog",
	"reflog", "ls-remote", "apply", "clean", "cat-file", "name-rev", "merge-base", "for-each-ref", "symbolic-ref",
	"show-ref", "check-ignore", "version", "help", "notes", "range-diff", "whatchanged", "count-objects", "fsck", "gc",
	"sparse-checkout", "format-patch", "am", "archive", "bundle")

// gitDeny are options of any git subcommand that run a program or read
// config the analyzer does not see: the transport commands, archive and
// rebase --exec, an external diff or textconv, a difftool, a template
// directory, another git directory or exec path.
var gitDeny = []string{"--upload-pack", "--receive-pack", "--exec", "--ext-diff", "--textconv", "--filters", "--tool",
	"--template", "--git-dir", "--work-tree", "--exec-path", "--config-env", "--open-files-in-pager"}

// gitShape: a git command is plain when its global options are harmless,
// its subcommand is listed, it uses none of gitDeny (nor rebase -x, grep -O,
// clone or ls-remote -u), its config edits name no key that runs a command,
// no URL uses the ext:: or fd:: transport, and its repository holds no
// hooks and no such keys (gitRepoState).
func gitShape(args []Word, inv Invocation) string {
	i := 0
	for i < len(args) && strings.HasPrefix(optText(args[i]), "-") {
		switch t := optText(args[i]); t {
		case "-C":
			i += 2
			continue
		case "--no-pager", "--no-optional-locks", "--bare", "--literal-pathspecs", "--no-replace-objects":
		default:
			// -c, -p, --git-dir, --exec-path and the rest.
			return "the git option " + t
		}
		i++
	}
	if i >= len(args) {
		return ""
	}
	if !args[i].Resolved {
		return "a git subcommand that cannot be resolved"
	}
	sub := args[i].Text
	if !gitSubs[sub] {
		return "the git subcommand " + sub
	}
	rest := args[i+1:]
	for _, o := range gitDeny {
		if hasOpt(rest, o) {
			return "the git option " + o
		}
	}
	switch {
	case sub == "rebase" && hasOpt(rest, "-x"):
		return "the git option -x"
	case sub == "grep" && hasOpt(rest, "-O"):
		return "the git option -O"
	case (sub == "clone" || sub == "ls-remote") && hasOpt(rest, "-u"):
		return "the git option -u"
	}
	for _, w := range rest {
		t := strings.ToLower(optText(w))
		if strings.HasPrefix(t, "ext::") || strings.HasPrefix(t, "fd::") || strings.Contains(t, "=ext::") {
			return "the ext:: transport"
		}
	}
	if sub == "config" {
		if why := gitConfigShape(rest); why != "" {
			return why
		}
	}
	return gitRepoState(inv.Dir, args[:i])
}

// gitConfigShape: reading config is plain; setting a key is plain unless
// the key runs a command or brings in another file.
func gitConfigShape(args []Word) string {
	var pos []Word
	read := false
	for _, w := range args {
		t := optText(w)
		switch {
		case t == "--get" || t == "--get-all" || t == "--get-regexp" || t == "-l" || t == "--list" || t == "--show-origin" ||
			t == "--show-scope" || t == "--name-only" || t == "get" || t == "list":
			read = true
		case t == "--file" || t == "-f" || t == "--blob" || strings.HasPrefix(t, "--file="):
			return "git config on another file"
		case strings.HasPrefix(t, "-"):
		default:
			pos = append(pos, w)
		}
	}
	if read || len(pos) < 2 {
		return ""
	}
	k := pos[0]
	if len(pos) >= 3 && (pos[0].Text == "set" || pos[0].Text == "add") {
		k = pos[1]
	}
	if !k.Resolved {
		return "a git config key that cannot be resolved"
	}
	if GitRunsKey(strings.ToLower(k.Text), "") {
		return "the git config key " + k.Text
	}
	return ""
}

// GitRunsKey reports whether a git config key (lower case) with value v
// makes git run a command, or brings in config or a transport that can.
// v is "" for a key being set, which is judged by its name alone.
func GitRunsKey(k, v string) bool {
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`))
	boolean := v == "true" || v == "false" || v == "yes" || v == "no" || v == "on" || v == "off" || v == "1" || v == "0"
	switch {
	case k == "core.fsmonitor", strings.HasPrefix(k, "pager."):
		return !boolean
	case strings.HasPrefix(k, "alias."):
		return v == "" || strings.HasPrefix(v, "!")
	case strings.HasPrefix(k, "submodule.") && strings.HasSuffix(k, ".update"):
		return v == "" || strings.HasPrefix(v, "!")
	case strings.HasPrefix(k, "remote.") || strings.HasPrefix(k, "url."):
		if strings.HasSuffix(k, ".uploadpack") || strings.HasSuffix(k, ".receivepack") || strings.HasSuffix(k, ".vcs") {
			return true
		}
		if strings.HasSuffix(k, ".url") || strings.HasSuffix(k, ".pushurl") || strings.HasSuffix(k, ".insteadof") || strings.HasSuffix(k, ".pushinsteadof") {
			return v == "" && strings.HasPrefix(k, "url.") || strings.HasPrefix(v, "ext::") || strings.HasPrefix(v, "fd::") ||
				strings.HasPrefix(k, "url.ext::") || strings.HasPrefix(k, "url.fd::")
		}
		return false
	case gitExecKey(k), k == "core.alternaterefscommand", k == "core.gitproxy", k == "include.path",
		strings.HasPrefix(k, "includeif."), strings.HasPrefix(k, "protocol."), strings.HasSuffix(k, ".driver"),
		strings.HasPrefix(k, "credential.") && strings.HasSuffix(k, ".helper"), strings.HasPrefix(k, "gpg.") && strings.HasSuffix(k, ".program"):
		return true
	}
	return false
}

// gitRepoState reports why the repository a git command runs in is not
// plain: it has hooks, or its config sets a key that runs a command. git
// reads both on its own, so a plain command can run what an earlier one
// planted. A repository whose git directory cannot be read is not plain.
func gitRepoState(dir string, globalOpts []Word) string {
	if dir == "" {
		return "a git repository in an unknown directory"
	}
	for i := 0; i+1 < len(globalOpts); i++ {
		if globalOpts[i].Text == "-C" {
			if !globalOpts[i+1].Resolved {
				return "a git -C directory that cannot be resolved"
			}
			dir = PhysicalJoin(dir, globalOpts[i+1].Text)
		}
	}
	gitDir, common, ok := findGitDir(dir)
	if !ok {
		return "" // not in a repository: git init, clone, or an error
	}
	if gitDir == "" {
		return "a git directory that cannot be read"
	}
	if ents, err := os.ReadDir(filepath.Join(common, "hooks")); err == nil {
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".sample") {
				return "the repository's git hook " + e.Name()
			}
		}
	} else if !os.IsNotExist(err) {
		return "git hooks that cannot be read"
	}
	for _, f := range []string{filepath.Join(common, "config"), filepath.Join(gitDir, "config.worktree")} {
		if why := gitConfigFile(f); why != "" {
			return why
		}
	}
	return ""
}

// findGitDir walks up from dir to the repository's git directory and its
// common directory (they differ in a linked worktree). ok is false outside
// a repository; gitDir is "" when a .git entry cannot be followed.
func findGitDir(dir string) (gitDir, common string, ok bool) {
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, ".git")
		fi, err := os.Lstat(p)
		switch {
		case err == nil && fi.IsDir():
			gitDir = p
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
		}
		if gitDir != "" {
			common = gitDir
			if b, err := readSmall(filepath.Join(gitDir, "commondir")); err == nil {
				c := strings.TrimSpace(string(b))
				if !filepath.IsAbs(c) {
					c = filepath.Join(gitDir, c)
				}
				common = filepath.Clean(c)
			}
			return gitDir, common, true
		}
		if filepath.Dir(d) == d {
			return "", "", false
		}
	}
}

func readSmall(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return nil, os.ErrInvalid
	}
	return os.ReadFile(p)
}

// gitConfigFile reports a key in a git config file that runs a command.
// Keys are compared in lower case.
func gitConfigFile(p string) string {
	b, err := readSmall(p)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return "a git config that cannot be read"
	}
	sec := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '[' {
			end := strings.IndexByte(l, ']')
			if end < 0 {
				return "a git config that does not parse"
			}
			name, sub, hasSub := strings.Cut(l[1:end], " ")
			sec = strings.TrimSpace(name)
			if hasSub {
				sec += "." + strings.Trim(strings.TrimSpace(sub), `"`)
			}
			sec = strings.ToLower(sec)
			if l = strings.TrimSpace(l[end+1:]); l == "" {
				continue
			}
		}
		k, v, _ := strings.Cut(l, "=")
		if key := sec + "." + strings.ToLower(strings.TrimSpace(k)); GitRunsKey(key, v) {
			return "the git config key " + key
		}
	}
	return ""
}

// kubectlSubs are kubectl's own subcommands: anything else is a plugin, a
// program found on PATH.
var kubectlSubs = toSet("get", "describe", "logs", "apply", "create", "delete", "edit", "patch", "replace", "scale",
	"rollout", "expose", "run", "set", "label", "annotate", "autoscale", "top", "cordon", "uncordon", "drain", "taint",
	"certificate", "cluster-info", "explain", "diff", "exec", "port-forward", "proxy", "cp", "auth", "debug", "events",
	"wait", "api-resources", "api-versions", "version", "kustomize", "completion", "attach", "config")

// kubectlShape: a plugin, another kubeconfig (its users may run an exec
// credential plugin), a config edit, or kustomize plugins are not plain.
func kubectlShape(args []Word, inv Invocation) string {
	if hasOpt(args, "--kubeconfig") {
		return "the option --kubeconfig"
	}
	if hasOpt(args, "--enable-alpha-plugins") || hasOpt(args, "--enable-exec") {
		return "kustomize plugins"
	}
	pos := positional(args, 2, kubeValued)
	if len(pos) == 0 {
		return ""
	}
	if !kubectlSubs[pos[0]] {
		return "the kubectl subcommand " + pos[0]
	}
	if pos[0] == "config" {
		if len(pos) < 2 || pos[1] != "view" && pos[1] != "get-contexts" && pos[1] != "current-context" && pos[1] != "get-clusters" && pos[1] != "use-context" {
			return "a kubectl config edit"
		}
	}
	return ""
}

// kubeValued and cloudValued are the global options of kubectl and helm,
// and of the cloud CLIs, that take a value.
var kubeValued = toSet("-n", "--namespace", "--context", "--cluster", "--user", "-s", "--server", "--as", "--as-group",
	"--request-timeout", "--kube-context", "--token", "--certificate-authority", "--tls-server-name")

var cloudValued = toSet("--profile", "--region", "--output", "--endpoint-url", "--query", "--project", "--account",
	"--configuration", "--subscription", "-o", "--format")

var helmSubs = toSet("completion", "create", "dependency", "env", "get", "help", "history", "install", "lint", "list",
	"ls", "package", "pull", "push", "registry", "repo", "rollback", "search", "show", "status", "template", "test",
	"uninstall", "upgrade", "verify", "version")

// helmShape: a plugin or a post-renderer runs a program.
func helmShape(args []Word, _ Invocation) string {
	if hasOpt(args, "--post-renderer") {
		return "the option --post-renderer"
	}
	pos := positional(args, 1, kubeValued)
	if len(pos) == 1 && !helmSubs[pos[0]] {
		return "the helm subcommand " + pos[0]
	}
	return ""
}

// awsShape: another config file can hold a credential_process, and aws
// configure writes the config later calls read.
func awsShape(args []Word, _ Invocation) string {
	pos := positional(args, 2, cloudValued)
	if len(pos) == 2 && pos[0] == "configure" && pos[1] != "get" && pos[1] != "list" && pos[1] != "list-profiles" && pos[1] != "export-credentials" {
		return "aws configure " + pos[1]
	}
	return ""
}
