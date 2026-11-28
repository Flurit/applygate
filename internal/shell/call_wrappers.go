package shell

import (
	"strings"
)

// environmentWrapper handles wrappers that load an environment or credentials
// and then run a command: direnv and the version managers, the AWS credential
// helpers, sudo, su and the Python environment runners.
// Every return inside the switch means the call is handled; falling out of it
// leaves the call to the code after the dispatch in call0.
func (a *analyzer) environmentWrapper(c *callCtx) (handled bool) {
	args, rest, bn, redirs, cmdSt, st, via, depth, in, record := c.args, c.rest, c.bn, c.redirs, c.cmdSt, c.st, c.via, c.depth, c.in, c.record
	handled = true
	switch bn {
	case "direnv", "mise", "rtx", "asdf", "devbox", "nix", "nix-shell", "sops":
		if cmd, script, ok := envRunner(bn, rest); ok {
			if script != nil {
				if !script.Resolved {
					a.problem(st, via, joinWords(args), bn+" runs a command line that cannot be resolved statically")
					return
				}
				a.source(script.Text, cmdSt.childState(), append(via, bn), depth+1)
				return
			}
			// The environment these runners load (.envrc, mise.toml [env],
			// devbox.json, a flake's shell hook) is not read here, so any of
			// the tier signals in it is unknown, not absent.
			es := cmdSt.clone()
			for _, k := range TierEnv {
				if _, set := es.vars[k]; !set {
					es.vars[k] = value{}
					es.exported[k] = true
				}
			}
			if n := len(rest) - len(cmd); n >= 0 && movesDir(rest[:n]) {
				es.dir = "" // mise -C DIR, mise exec --cd DIR
			}
			a.call(cmd, redirs, es, st, append(via, bn), depth+1, in)
			return
		}
	case "aws-vault", "aws-okta", "gds", "saml2aws", "aws-sso", "doppler", "op", "chamber", "infisical", "dotenvx", "envchain", "aws-runas":
		if cmd, script, profile, ok := credentialWrapper(bn, rest); ok {
			// The wrapped command runs with the wrapper's credentials; the
			// profile or role it names is a tier signal like AWS_PROFILE.
			ws := cmdSt.clone()
			switch {
			case profile.Resolved && profile.Text != "":
				ws.vars["AWS_PROFILE"] = value{text: profile.Text, ok: true}
				ws.exported["AWS_PROFILE"] = true
			case profile.Text != "":
				// A profile that cannot be resolved is unknown, not absent.
				ws.vars["AWS_PROFILE"] = value{}
				ws.exported["AWS_PROFILE"] = true
			}
			if secretsRunners[bn] {
				// A secrets runner sets variables from a store the hook
				// cannot read, any of the tier signals among them.
				for _, k := range TierEnv {
					if _, set := ws.vars[k]; !set {
						ws.vars[k] = value{}
						ws.exported[k] = true
					}
				}
			}
			if script != nil {
				if !script.Resolved {
					a.problem(st, via, joinWords(args), bn+" runs a command line that cannot be resolved statically")
					return
				}
				a.source(script.Text, ws.childState(), append(via, bn), depth+1)
				return
			}
			a.call(cmd, redirs, ws, st, append(via, bn), depth+1, in)
			return
		}
		// Not a shape it knows: the backstop still looks for a standalone
		// terraform, tofu or terragrunt argument.
		record()
		a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
		return
	case "sudo", "doas":
		// sudo -D DIR and --chdir=DIR run the command in DIR (when sudoers
		// allows it): the directory is DIR, or unknown when DIR is not.
		ss := cmdSt
		for i, w := range rest {
			t := w.Text
			if !strings.HasPrefix(t, "-") {
				break
			}
			var dir Word
			switch {
			case t == "-D" && i+1 < len(rest):
				dir = rest[i+1]
			case strings.HasPrefix(t, "--chdir="):
				dir = Word{Text: strings.TrimPrefix(t, "--chdir="), Resolved: w.Resolved, Prefix: strings.TrimPrefix(t, "--chdir=")}
			case strings.HasPrefix(t, "-D") && len(t) > 2 && !strings.HasPrefix(t, "--"):
				dir = Word{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}
			default:
				continue
			}
			ss = cmdSt.clone()
			if dir.Resolved {
				ss.dir = a.dirAbs(ss, dir.Text)
			} else {
				ss.dir = ""
			}
		}
		a.call(skipFlags(rest, map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true}), redirs, ss, st, append(via, bn), depth+1, in)
		return
	case "su", "runuser":
		// su [opts] [-] [user [args]] -c 'command line': a login shell (-, -l)
		// starts in the user's home.
		child := cmdSt.childState()
		for i, w := range rest {
			t := w.Text
			if t == "-" || t == "-l" || t == "--login" {
				child.dir = ""
			}
			if t == "-c" || t == "--command" || t == "--session-command" {
				a.reparseIn(rest[i+1:min(i+2, len(rest))], child, via, bn+" -c", depth)
				return
			}
			if v, ok := strings.CutPrefix(t, "--command="); ok {
				a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child, via, bn+" -c", depth)
				return
			}
		}
		record()
		return
	case "conda", "mamba", "micromamba", "pixi", "uv", "poetry", "pipenv", "hatch", "pdm", "rye":
		// <tool> run [opts] command... runs the command in the environment.
		if cmd, dir, ok := envRun(rest); ok {
			es := cmdSt.clone()
			if dir != nil {
				if dir.Resolved {
					es.dir = a.dirAbs(es, dir.Text)
				} else {
					es.dir = ""
				}
			}
			a.call(cmd, redirs, es, st, append(via, bn+" run"), depth+1, in)
			return
		}
		// Options before "run" (poetry -C DIR run ...): the backstop still
		// finds a standalone engine, in a directory it no longer knows.
		record()
		a.backstop(bn, rest, redirs, cmdSt, st, via, depth)
		return
	}
	return false
}

// processWrapper handles wrappers that run a command with a changed process
// setting or inside another process: exec and command, nice, flock, repeat,
// timeout, env, watch, script, chroot and the terminal multiplexers.
// Every return inside the switch means the call is handled; falling out of it
// leaves the call to the code after the dispatch in call0.
func (a *analyzer) processWrapper(c *callCtx) (handled bool) {
	args, rest, bn, redirs, cmdSt, st, via, depth, in, record := c.args, c.rest, c.bn, c.redirs, c.cmdSt, c.st, c.via, c.depth, c.in, c.record
	handled = true
	switch bn {
	case "tmux", "screen":
		// A command a new session, window or pane runs: tmux new-session -d
		// 'cmd', split-window, respawn-pane, run-shell; screen -dmS NAME cmd.
		// It runs in the pane's directory (-c), else one not known.
		if cmd, dir, ok := multiplexerCommand(bn, rest); ok {
			child := st.childState()
			child.dir = ""
			if dir != nil {
				if dir.Resolved {
					child.dir = a.dirAbs(st, dir.Text)
				}
			}
			a.reparseIn(cmd, child, via, bn, depth)
			return
		}
		// Keys typed into another terminal run there: tmux send-keys -t PANE
		// 'cmd' Enter, screen -X stuff 'cmd\n'. The pane's directory is not
		// known.
		if text, ok, resolved := typedText(bn, rest); ok {
			if !resolved {
				a.problem(st, via, joinWords(args), bn+" types text into another terminal that cannot be resolved statically")
				return
			}
			child := st.childState()
			child.dir = ""
			a.source(text, child, append(via, bn+" send-keys"), depth+1)
			return
		}
	case "exec", "command", "builtin", "nohup", "time", "chronic", "unbuffer", "setsid", "caffeinate", "noglob", "nocorrect", "-":
		if bn == "command" || bn == "type" {
			// command's own options come before the command: -v and -V look a
			// name up, and a -v after the command is that command's option.
			for _, w := range rest {
				if w.Text == "-v" || w.Text == "-V" {
					return // lookup only
				}
				if !strings.HasPrefix(w.Text, "-") || w.Text == "--" {
					break
				}
			}
		}
		a.call(skipFlags(rest, map[string]bool{"-a": true}), redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "nice", "ionice", "stdbuf", "taskset":
		valued := map[string]bool{"-n": true, "-c": true, "-p": true, "-i": true, "-o": true, "-e": true, "-w": true}
		r := skipFlags(rest, valued)
		if bn == "taskset" {
			if len(r) > 0 {
				r = r[1:] // CPU mask
			}
		}
		a.call(r, redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "flock":
		// flock [opts] FILE -c 'command line' | flock -c 'command line' FILE |
		// flock [opts] FILE command...
		for i, w := range rest {
			t := w.Text
			if cmd, ok := strings.CutPrefix(t, "--command="); ok {
				a.reparseIn([]Word{{Text: cmd, Resolved: w.Resolved, Prefix: cmd}}, cmdSt.childState(), via, "flock -c", depth)
				return
			}
			if (t == "-c" || t == "--command" || strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.HasSuffix(t, "c")) && i+1 < len(rest) {
				a.reparseIn(rest[i+1:i+2], cmdSt.childState(), via, "flock -c", depth)
				return
			}
		}
		r := skipFlags(rest, toSet("-w", "--timeout", "-E", "--conflict-exit-code"))
		if len(r) > 0 {
			r = r[1:]
		}
		if len(r) > 0 && (r[0].Text == "-c" || r[0].Text == "--command") {
			a.reparseIn(r[1:min(2, len(r))], cmdSt.childState(), via, "flock -c", depth)
			return
		}
		a.call(r, redirs, cmdSt, st, append(via, bn), depth+1, in)
		return
	case "repeat":
		// zsh: repeat N command... runs the command N times, a cd included.
		if len(rest) >= 2 {
			a.call(rest[1:], redirs, cmdSt, st, append(via, "repeat"), depth+1, in)
			return
		}
	case "timeout":
		r := skipFlags(rest, map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true})
		if len(r) > 0 {
			r = r[1:] // duration
		}
		a.call(r, redirs, cmdSt, st, append(via, "timeout"), depth+1, in)
		return
	case "env":
		a.env(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "watch":
		r := skipFlags(rest, map[string]bool{"-n": true, "--interval": true, "-d": false})
		a.reparse(r, st, via, "watch", depth)
		return
	case "script":
		// script [-q] [-c command] file; -c takes the command. The short flag
		// is often bundled into a cluster, e.g. "script -qc '<cmd>' out".
		for i, w := range rest {
			t := w.Text
			cFlag := t == "-c" || t == "--command" ||
				(len(t) >= 2 && t[0] == '-' && t[1] != '-' && strings.HasSuffix(t, "c"))
			if cFlag && i+1 < len(rest) {
				a.reparse(rest[i+1:i+2], st, via, "script -c", depth)
				return
			}
		}
		// BSD and macOS: script [-adkpqr] [-F pipe] [-t time] file command...
		// runs the trailing argv in a new pseudo-terminal.
		if r := skipFlags(rest, map[string]bool{"-F": true, "-t": true, "-T": true}); len(r) > 1 {
			a.call(r[1:], redirs, cmdSt, st, append(via, "script"), depth+1, in)
			return
		}
		record()
		return
	case "chroot":
		// chroot [options] newroot [command ...]; the trailing argv is a
		// command that runs inside the new root. Skip options and newroot.
		r := skipFlags(rest, map[string]bool{"--userspec": true, "--groups": true})
		if len(r) > 1 {
			a.call(r[1:], redirs, cmdSt, st, append(via, "chroot"), depth+1, in)
			return
		}
		record()
		return
	}
	return false
}
