package shell

import (
	"strings"
)

// credentialWrapper finds the command that a credential or secrets runner
// executes, and the AWS profile or role it runs it under:
//
//	aws-vault exec PROFILE [--] cmd     aws-okta exec PROFILE [--] cmd
//	gds aws ROLE [--] cmd               aws-runas PROFILE cmd
//	saml2aws exec [--exec-profile P] [--] cmd
//	aws-sso exec [-p P] [--] cmd        envchain NAMESPACE cmd
//	doppler run [flags] [--] cmd        op run [flags] [--] cmd
//	chamber exec SERVICE... -- cmd      infisical run [flags] [--] cmd
//	dotenvx run [flags] [--] cmd
//	doppler|infisical run [flags] --command 'command line'
//
// A command line given as one string is returned in script instead. ok is
// false when the arguments do not have that shape (for example "aws-vault
// list" or "op read"), in which case nothing is executed.
func credentialWrapper(bn string, rest []Word) (cmd []Word, script *Word, profile Word, ok bool) {
	sub := map[string]string{"aws-vault": "exec", "aws-okta": "exec", "gds": "aws", "saml2aws": "exec",
		"aws-sso": "exec", "doppler": "run", "op": "run", "chamber": "exec", "infisical": "run", "dotenvx": "run"}
	if want, has := sub[bn]; has {
		if len(rest) == 0 || rest[0].Text != want {
			return nil, nil, Word{}, false
		}
		rest = rest[1:]
	}
	// Tools whose first positional argument names the profile or role.
	positionalProfile := bn == "aws-vault" || bn == "aws-okta" || bn == "gds" || bn == "aws-runas" || bn == "envchain"
	// Secrets runners whose flags name no AWS profile. Their command normally
	// follows "--"; without it, it starts at the first argument that is not a
	// flag or a flag's value (chamber's leading arguments are service names,
	// so there only "--" or the end of the arguments decides).
	secretsRunner := bn == "doppler" || bn == "op" || bn == "chamber" || bn == "infisical" || bn == "dotenvx"
	profileFlags := map[string]bool{"--exec-profile": true, "-p": true, "--profile": true}
	valued := map[string]bool{"--duration": true, "-d": true, "--region": true, "--mfa-token": true, "-t": true,
		"--prompt": true, "--exec-profile": true, "-p": true, "--profile": true, "-a": true, "--idp-account": true,
		"--project": true, "--config": true, "-c": true, "--env-file": true, "--env": true, "--account": true,
		"--role": true, "--session-ttl": true, "--assume-role-ttl": true,
		// doppler, infisical, dotenvx
		"--token": true, "--mount": true, "--mount-format": true, "--mount-template": true, "--fallback": true,
		"--name-transformer": true, "--projectId": true, "--path": true, "--tags": true, "--domain": true,
		"-f": true, "-fk": true, "--env-keys-file": true, "-e": true, "--convention": true}
	firstPos := -1
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		if !w.Resolved {
			t = w.Prefix
		}
		name, val, eq := strings.Cut(t, "=")
		switch {
		case t == "--" && w.Resolved:
			return rest[i+1:], nil, profile, i+1 < len(rest)
		case secretsRunner && name == "--command" && (bn == "doppler" || bn == "infisical"):
			if eq {
				return nil, &Word{Text: val, Resolved: w.Resolved, Prefix: val}, profile, true
			}
			if i+1 < len(rest) {
				return nil, &rest[i+1], profile, true
			}
			return nil, nil, profile, false
		case secretsRunner && strings.HasPrefix(t, "-"):
			if !eq && valued[name] {
				i++
			}
		case secretsRunner && bn != "chamber":
			return rest[i:], nil, profile, true
		case secretsRunner:
			if firstPos < 0 {
				firstPos = i
			}
		case strings.HasPrefix(t, "-"):
			if profileFlags[name] {
				if eq {
					profile = presentWord(Word{Text: val, Resolved: w.Resolved, Prefix: val})
				} else if i+1 < len(rest) {
					profile = presentWord(rest[i+1])
				}
			}
			if !eq && valued[name] {
				i++
			}
		case positionalProfile:
			profile = presentWord(w)
			positionalProfile = false
		default:
			return rest[i:], nil, profile, true
		}
	}
	if firstPos >= 0 {
		return rest[firstPos:], nil, profile, true
	}
	return nil, nil, profile, false
}

// sshOptions analyzes the commands ssh, scp, sftp and rsync run on this
// machine: -o ProxyCommand=..., LocalCommand, KnownHostsCommand, and
// rsync's -e/--rsh program.
func (a *analyzer) sshOptions(bn string, rest []Word, cmdSt *state, via []string, depth int) {
	child := cmdSt.childState()
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		t := w.Text
		var opt Word
		switch {
		case bn == "rsync" && (t == "-e" || t == "--rsh") && i+1 < len(rest):
			a.reparseIn([]Word{rest[i+1]}, child.clone(), via, "rsync "+t, depth)
			i++
			continue
		case bn == "rsync" && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && len(t) > 2 && strings.Contains(t[1:], "e"):
			// -e'cmd', -ze 'cmd': e takes the rest of the cluster, else the next word.
			k := strings.IndexByte(t, 'e')
			if v := t[k+1:]; v != "" {
				a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child.clone(), via, "rsync -e", depth)
			} else if i+1 < len(rest) {
				a.reparseIn([]Word{rest[i+1]}, child.clone(), via, "rsync -e", depth)
				i++
			}
			continue
		case (bn == "scp" || bn == "sftp") && t == "-S" && i+1 < len(rest):
			// -S names the program that makes the connection.
			a.reparseIn([]Word{rest[i+1]}, child.clone(), via, bn+" -S", depth)
			i++
			continue
		case (bn == "scp" || bn == "sftp") && strings.HasPrefix(t, "-S") && len(t) > 2:
			a.reparseIn([]Word{{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}}, child.clone(), via, bn+" -S", depth)
			continue
		case bn == "rsync" && strings.HasPrefix(t, "--rsh="):
			v := strings.TrimPrefix(t, "--rsh=")
			a.reparseIn([]Word{{Text: v, Resolved: w.Resolved, Prefix: v}}, child.clone(), via, "rsync --rsh", depth)
			continue
		case t == "-o" && i+1 < len(rest):
			opt = rest[i+1]
			i++
		case strings.HasPrefix(t, "-o") && len(t) > 2:
			opt = Word{Text: t[2:], Resolved: w.Resolved, Prefix: t[2:]}
		default:
			continue
		}
		text := opt.Text
		if !opt.Resolved {
			text = opt.Prefix
		}
		// ssh splits keyword and value at the first space, tab or =:
		// "ProxyCommand terraform -chdir=../prod destroy" is a space form.
		var k, v string
		if i := strings.IndexAny(text, " \t="); i >= 0 {
			k, v = text[:i], strings.TrimLeft(text[i+1:], " \t=")
		} else {
			k = text
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "proxycommand", "localcommand", "knownhostscommand":
			if v = strings.TrimSpace(v); strings.EqualFold(v, "none") {
				continue
			}
			a.reparseIn([]Word{{Text: v, Resolved: opt.Resolved, Prefix: v}}, child.clone(), via, bn+" -o "+k, depth)
		}
	}
}

// multiplexerCommand returns the shell command a tmux or screen invocation
// starts, and the directory given with -c, if any.
func multiplexerCommand(bn string, rest []Word) (cmd []Word, dir *Word, ok bool) {
	switch bn {
	case "tmux":
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i].Text, "-") { // global options
			if t := rest[i].Text; t == "-L" || t == "-S" || t == "-f" || t == "-T" {
				i++
			}
			i++
		}
		if i >= len(rest) {
			return nil, nil, false
		}
		switch rest[i].Text {
		case "new-session", "new", "new-window", "neww", "split-window", "splitw", "respawn-pane", "respawnp",
			"respawn-window", "respawnw", "run-shell", "run", "display-popup", "popup":
		default:
			return nil, nil, false
		}
		valued := toSet("-c", "-e", "-F", "-l", "-n", "-s", "-t", "-x", "-y", "-b", "-d", "-h", "-w", "-T")
		boolean := toSet("-d", "-P", "-k", "-a", "-b", "-h", "-v", "-f", "-Z", "-E", "-B", "-C", "-A", "-D", "-X")
		for j := i + 1; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "--":
				return rest[j+1:], dir, j+1 < len(rest)
			case t == "-c" && j+1 < len(rest):
				dir = &rest[j+1]
				j++
			case boolean[t]:
			case valued[t]:
				j++
			case strings.HasPrefix(t, "-") && len(t) > 1:
			default:
				return rest[j:], dir, true
			}
		}
		return nil, nil, false
	case "screen":
		valued := toSet("-S", "-t", "-c", "-e", "-h", "-p", "-s", "-T", "-X", "-Logfile")
		for j := 0; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "-X":
				return nil, nil, false // a command to a running session (stuff)
			case valued[t]:
				j++
			case strings.HasPrefix(t, "-"):
			default:
				return rest[j:], nil, true
			}
		}
	}
	return nil, nil, false
}

// secretsRunners set variables from a secrets store.
var secretsRunners = toSet("doppler", "op", "chamber", "infisical", "dotenvx")
