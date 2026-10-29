package shell

import "strings"

// WrapperSpec describes a program, listed in the user's config, that runs
// another command given in its arguments: the command follows "--" when
// there is one, otherwise it starts after Skip positional arguments.
// ProfileArg (1-based, 0 = none) names the positional that is an AWS
// profile, used as a tier signal like AWS_PROFILE.
type WrapperSpec struct {
	Skip       int
	ProfileArg int
}

// tfEngines are the program names whose appearance as a standalone argument
// of an unrecognized program triggers the backstop.
var tfEngines = map[string]bool{"terraform": true, "tofu": true, "terragrunt": true}

// notWrappers are programs that take "terraform" as data, not as a command
// to run: text handling, search, version control, editors, file and package
// management, and tools applygate already classifies itself. The backstop
// never fires for them.
var notWrappers = toSet(
	// text output, search and processing
	"echo", "printf", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack", "ack-grep", "sed", "gsed", "awk", "gawk",
	"mawk", "cat", "bat", "less", "more", "most", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "tee", "column",
	"fold", "fmt", "nl", "jq", "yq", "xq", "diff", "cmp", "comm", "patch", "strings", "od", "hexdump", "xxd", "base64",
	"logger", "say", "cowsay", "figlet", "notify-send", "mail", "wall", "write", "printenv", "test", "[", "[[",
	// documentation and lookup
	"man", "info", "whatis", "apropos", "help", "tldr", "which", "whereis", "type", "hash", "command",
	// version control and code hosting
	"git", "hg", "svn", "gh", "glab", "hub", "tig", "git-lfs",
	// editors and clipboards
	"code", "vim", "vi", "nvim", "nano", "emacs", "subl", "open", "xdg-open", "pbcopy", "pbpaste", "wl-copy", "xclip",
	// files and archives
	"ls", "tree", "file", "stat", "find", "fd", "locate", "mkdir", "rmdir", "touch", "cp", "mv", "rm", "ln", "chmod",
	"chown", "du", "df", "realpath", "readlink", "basename", "dirname", "tar", "zip", "unzip", "gzip", "gunzip",
	"rsync", "scp", "md5sum", "sha256sum", "shasum",
	// network clients
	"curl", "wget", "http", "https",
	// package and version managers (install/uninstall terraform is not running it)
	"brew", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman", "apk", "zypper", "port", "snap", "flatpak",
	"pip", "pip3", "pipx", "gem", "cargo", "go", "conda", "mamba", "choco", "scoop", "winget", "nix-env",
	"tfenv", "tofuenv", "tgenv", "tfswitch", "aqua",
	// infrastructure tools applygate classifies itself, and linters that take a directory
	"terraform", "tofu", "opentofu", "terragrunt", "aws", "kubectl", "oc", "helm", "applygate",
	"claude", "codex", "cursor-agent", "copilot", "gemini", "opencode",
	"tflint", "tfsec", "checkov", "trivy", "terraform-docs", "infracost", "tfupdate", "pre-commit",
)

// messageFlags take free text as their value; "terraform" right after one
// is a message, not a command.
var messageFlags = toSet("-m", "--message", "--title", "-t", "--body", "-b", "--description", "--comment",
	"--reason", "--subject", "--summary", "--note", "--msg", "--text", "--label", "--grep", "--search", "--query",
	"--pattern", "-e", "--filter")

// shellStringFlags take a shell command line as their value
// (nix-shell --run 'terraform destroy', foo --command "terraform apply").
var shellStringFlags = toSet("--run", "--command", "-c", "--cmd", "--exec", "-x", "--shell-command")

func toSet(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// configWrapper finds the command a config-declared wrapper runs.
func configWrapper(spec WrapperSpec, rest []Word) (cmd []Word, profile Word, ok bool) {
	n := 0
	for i, w := range rest {
		if w.Text == "--" && w.Resolved {
			return rest[i+1:], profile, i+1 < len(rest)
		}
		if strings.HasPrefix(w.Text, "-") && w.Resolved {
			continue
		}
		if n < spec.Skip {
			n++
			if n == spec.ProfileArg {
				profile = w
			}
			continue
		}
		return rest[i:], profile, true
	}
	return nil, profile, false
}

// envRunner finds the command run by development-environment runners:
//
//	direnv exec DIR cmd          mise|rtx exec|x [tool@version ...] [--] cmd
//	asdf exec cmd                devbox run [--] cmd
//	nix develop|shell [...] -c|--command cmd ...
//	nix-shell [...] --run|--command 'command line'
//
// A command line given as one string is returned in script instead.
func envRunner(bn string, rest []Word) (cmd []Word, script *Word, ok bool) {
	afterDashDash := func(ws []Word) ([]Word, bool) {
		for i, w := range ws {
			if w.Text == "--" && w.Resolved {
				return ws[i+1:], i+1 < len(ws)
			}
		}
		return nil, false
	}
	switch bn {
	case "direnv":
		if len(rest) >= 3 && rest[0].Text == "exec" {
			return rest[2:], nil, true
		}
	case "mise", "rtx":
		if len(rest) >= 2 && (rest[0].Text == "exec" || rest[0].Text == "x") {
			if c, ok := afterDashDash(rest[1:]); ok {
				return c, nil, true
			}
			for i, w := range rest[1:] {
				if !strings.HasPrefix(w.Text, "-") && !strings.Contains(w.Text, "@") {
					return rest[1+i:], nil, true
				}
			}
		}
	case "asdf":
		if len(rest) >= 2 && rest[0].Text == "exec" {
			return rest[1:], nil, true
		}
	case "devbox":
		if len(rest) >= 2 && rest[0].Text == "run" {
			if c, ok := afterDashDash(rest[1:]); ok {
				return c, nil, true
			}
			return skipFlags(rest[1:], nil), nil, true
		}
	case "nix":
		if len(rest) >= 2 && (rest[0].Text == "develop" || rest[0].Text == "shell") {
			for i, w := range rest[1:] {
				if w.Text == "-c" || w.Text == "--command" {
					return rest[2+i:], nil, 2+i < len(rest)
				}
			}
		}
	case "nix-shell":
		for i, w := range rest {
			if (w.Text == "--run" || w.Text == "--command") && i+1 < len(rest) {
				return nil, &rest[i+1], true
			}
		}
	}
	return nil, nil, false
}

// backstop handles a program applygate does not recognize. If one of its
// arguments is exactly terraform, tofu or terragrunt (not part of a longer
// string, not the value of a message flag), the arguments from that word on
// are analyzed as the command the program would run. A shell-string flag
// (--run, --command, -c, ...) whose value starts with one of those programs
// is analyzed as a command line. It reports whether it found a command.
func (a *analyzer) backstop(bn string, rest []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) bool {
	if notWrappers[bn] {
		return false
	}
	label := bn + " (unrecognized wrapper)"
	for i, w := range rest {
		if !w.Resolved {
			continue
		}
		flag, inline, hasInline := strings.Cut(w.Text, "=")
		if shellStringFlags[flag] {
			val := Word{}
			switch {
			case hasInline:
				val = Word{Text: inline, Resolved: true}
			case i+1 < len(rest):
				val = rest[i+1]
			}
			if f := strings.Fields(val.Text); val.Resolved && len(f) > 0 && tfEngines[base(f[0])] {
				a.source(val.Text, cmdSt.childState(), append(via, label+" "+flag), depth+1)
				return true
			}
		}
		if !tfEngines[w.Text] && !(strings.Contains(w.Text, "/") && tfEngines[base(w.Text)] && !strings.HasSuffix(w.Text, "/")) {
			continue
		}
		if i > 0 && rest[i-1].Resolved && messageFlags[rest[i-1].Text] {
			continue
		}
		a.call(rest[i:], redirs, cmdSt, st, append(via, label), depth+1, stdin{})
		return true
	}
	return false
}

// IsBackstopVia reports whether an invocation was reached through the
// backstop for unrecognized wrappers.
func IsBackstopVia(via []string) bool {
	for _, v := range via {
		if strings.Contains(v, "(unrecognized wrapper)") {
			return true
		}
	}
	return false
}
