package shell

import (
	"strings"
)

// gitExecKeys are git configuration keys whose value is a command git runs
// through the shell.
var gitExecKeys = toSet("core.pager", "core.sshcommand", "core.fsmonitor", "core.editor", "core.askpass", "core.hookspath",
	"sequence.editor", "diff.external", "credential.helper", "gpg.program", "gpg.ssh.program", "uploadpack.packobjectshook")

// gitExecEnv are environment variables whose value is a command git runs.
var gitExecEnv = []string{"GIT_SSH_COMMAND", "GIT_SSH", "GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_EXTERNAL_DIFF",
	"GIT_ASKPASS", "GIT_PROXY_COMMAND", "EDITOR", "VISUAL", "PAGER", "SSH_ASKPASS", "SUDO_EDITOR", "KUBE_EDITOR", "GH_EDITOR",
	"HELM_EDITOR", "GLAB_EDITOR", "PSQL_EDITOR", "FCEDIT"}

// git analyzes the commands git runs through its own options: -c alias.X=!cmd
// when X is the subcommand, -c keys whose value is a command, bisect run,
// rebase -x/--exec, submodule foreach, and the GIT_* command variables.
func (a *analyzer) git(rest []Word, cmdSt, st *state, via []string, depth int) {
	child := cmdSt.childState()
	run := func(w Word, label string) {
		a.reparseIn([]Word{w}, child.clone(), via, label, depth)
	}
	// Options that name a program git runs: the transport's upload-pack and
	// receive-pack, archive's --exec, and filter-branch's filters.
	for i := 0; i < len(rest); i++ {
		k, v, eq := strings.Cut(rest[i].Text, "=")
		if full := gitLongName(k, gitRunOpts); full != "" {
			if eq {
				run(Word{Text: v, Resolved: rest[i].Resolved, Prefix: v}, "git "+full)
			} else if i+1 < len(rest) {
				run(rest[i+1], "git "+full)
				i++
			}
		}
	}
	for _, k := range gitExecEnv {
		if v, ok := cmdSt.vars[k]; ok && cmdSt.isExp(k) && (v.text != "" || !v.ok) {
			run(Word{Text: v.text, Resolved: v.ok, Prefix: v.text}, "git "+k)
		}
	}
	// GIT_CONFIG_COUNT with GIT_CONFIG_KEY_n and GIT_CONFIG_VALUE_n are
	// -c pairs; GIT_CONFIG_PARAMETERS and other config files may hold any.
	envVal := func(k string) (value, bool) {
		v, ok := cmdSt.vars[k]
		return v, ok && cmdSt.isExp(k)
	}
	for k := range cmdSt.vars {
		n, ok := strings.CutPrefix(k, "GIT_CONFIG_KEY_")
		if !ok || !cmdSt.isExp(k) {
			continue
		}
		key, val := cmdSt.vars[k], value{}
		if v, ok := envVal("GIT_CONFIG_VALUE_" + n); ok {
			val = v
		}
		if !key.ok || gitExecKey(strings.ToLower(key.text)) || strings.HasPrefix(strings.ToLower(key.text), "alias.") {
			run(Word{Text: val.text, Resolved: val.ok && key.ok, Prefix: val.text}, "git "+k)
		}
	}
	for _, k := range []string{"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG"} {
		if v, ok := envVal(k); ok && !(v.ok && (v.text == "" || v.text == "/dev/null")) {
			a.problem(st, via, "git "+joinWords(rest), k+" gives git configuration applygate cannot read, which may run programs")
		}
	}
	aliases := map[string]Word{}
	i := 0
	for i < len(rest) {
		t := rest[i].Text
		switch {
		case t == "-c" && i+1 < len(rest):
			kv := rest[i+1]
			k, v, _ := strings.Cut(kv.Text, "=")
			if !kv.Resolved {
				k, v, _ = strings.Cut(kv.Prefix, "=")
			}
			k = strings.ToLower(k)
			val := Word{Text: v, Resolved: kv.Resolved, Prefix: v}
			switch {
			case strings.HasPrefix(k, "alias."):
				aliases[strings.TrimPrefix(k, "alias.")] = val
			case gitExecKey(k):
				run(val, "git -c "+k)
			}
			i += 2
			continue
		case t == "-C" && i+1 < len(rest):
			if rest[i+1].Resolved {
				child.dir = a.dirAbs(child, rest[i+1].Text)
			} else {
				child.dir = ""
			}
			i += 2
			continue
		case (t == "--git-dir" || t == "--work-tree" || t == "--namespace" || t == "--exec-path" || t == "--config-env") && i+1 < len(rest):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(rest) {
		return
	}
	sub, args := rest[i].Text, rest[i+1:]
	if v, ok := aliases[strings.ToLower(sub)]; ok && strings.HasPrefix(v.Prefix, "!") {
		v.Text, v.Prefix = strings.TrimPrefix(v.Text, "!"), strings.TrimPrefix(v.Prefix, "!")
		line := append([]Word{v}, args...)
		if !allResolved(line) {
			a.problem(st, via, "git "+joinWords(rest), "git alias runs a command that cannot be resolved statically")
			return
		}
		a.source(joinWords(line), child, append(via, "git alias "+sub), depth+1)
		return
	}
	switch sub {
	case "bisect":
		if len(args) > 1 && args[0].Text == "run" {
			a.call(args[1:], nil, child, child, append(via, "git bisect run"), depth+1, stdin{})
		}
	case "rebase":
		gitCmdOpt(args, "-x", "--exec", run, "git rebase --exec")
	case "difftool", "mergetool":
		gitCmdOpt(args, "-x", "--extcmd", run, "git "+sub+" --extcmd")
	case "grep":
		// -O and --open-files-in-pager take their pager only glued on.
		for _, w := range args {
			if k, v, eq := strings.Cut(w.Text, "="); eq && gitLongName(k, []string{"--open-files-in-pager"}) != "" {
				run(Word{Text: v, Resolved: w.Resolved, Prefix: v}, "git grep -O")
			} else if v, ok := strings.CutPrefix(w.Text, "-O"); ok && v != "" && !strings.HasPrefix(w.Text, "--") {
				run(Word{Text: v, Resolved: w.Resolved, Prefix: strings.TrimPrefix(w.Prefix, "-O")}, "git grep -O")
			}
		}
	case "submodule":
		for j, w := range args {
			if w.Text == "foreach" {
				if r := skipFlags(args[j+1:], nil); len(r) > 0 {
					a.reparseIn(r, child.clone(), via, "git submodule foreach", depth)
				}
				break
			}
		}
	}
}

// gitExecKey reports whether a git config key's value is a command.
func gitExecKey(k string) bool {
	return gitExecKeys[k] || strings.HasPrefix(k, "pager.") || strings.HasSuffix(k, ".textconv") ||
		strings.HasPrefix(k, "filter.") || strings.HasSuffix(k, ".command") || strings.HasSuffix(k, ".cmd")
}

// gitRunOpts are the long options whose value is a program git runs.
var gitRunOpts = []string{"--upload-pack", "--receive-pack", "--exec", "--upload-archive", "--tree-filter", "--index-filter", "--msg-filter",
	"--env-filter", "--commit-filter", "--tag-name-filter", "--parent-filter", "--subdirectory-filter"}

// gitLongName returns the long option k (a --name without its value) stands
// for among the candidates: git takes any unique prefix of a long option, so
// --exe is --exec and --tree-f is --tree-filter. A prefix that fits more
// than one (git refuses it) is taken as the first, the safe reading here.
func gitLongName(k string, candidates []string) string {
	if !strings.HasPrefix(k, "--") || len(k) < 4 {
		return ""
	}
	for _, c := range candidates {
		if strings.HasPrefix(c, k) {
			return c
		}
	}
	return ""
}

// gitCmdOpt runs the value of an option that takes a command: separate
// (-x cmd, --exec cmd), with = (--exec=cmd), glued to the short form (-xcmd),
// after other short options in a cluster (-qx cmd), or through an
// abbreviated long name (--exe cmd).
func gitCmdOpt(args []Word, short, long string, run func(Word, string), label string) {
	for j, w := range args {
		k, v, eq := strings.Cut(w.Text, "=")
		switch {
		case w.Text == short || gitLongName(k, []string{long}) != "" && !eq:
			if j+1 < len(args) {
				run(args[j+1], label)
			}
		case eq && gitLongName(k, []string{long}) != "":
			run(Word{Text: v, Resolved: w.Resolved, Prefix: strings.TrimPrefix(w.Prefix, k+"=")}, label)
		case strings.HasPrefix(w.Text, "-") && !strings.HasPrefix(w.Text, "--") && strings.Contains(w.Text[1:], short[1:]):
			// The short option's letter inside a cluster: what follows it is
			// the command, or the next word when it ends the cluster.
			cl := w.Text[1:]
			at := strings.Index(cl, short[1:])
			if rest := cl[at+1:]; rest != "" {
				run(Word{Text: rest, Resolved: w.Resolved, Prefix: rest}, label)
			} else if j+1 < len(args) {
				run(args[j+1], label)
			}
		}
	}
}
