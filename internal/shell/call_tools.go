package shell

import (
	"strings"
)

// toolRunner handles programs that run commands of their own or name what
// they will touch: git, scp and rsync, terragrunt, xargs, parallel, ssh, find,
// make and the container CLIs.
// Every return inside the switch means the call is handled; falling out of it
// leaves the call to the code after the dispatch in call0.
func (a *analyzer) toolRunner(c *callCtx) (handled bool) {
	args, rest, bn, redirs, cmdSt, st, via, depth, in, record := c.args, c.rest, c.bn, c.redirs, c.cmdSt, c.st, c.via, c.depth, c.in, c.record
	handled = true
	switch bn {
	case "git":
		a.git(rest, cmdSt, st, via, depth)
		record()
		return
	case "scp", "sftp", "rsync":
		a.sshOptions(bn, rest, cmdSt, via, depth)
		record()
		return
	case "terragrunt", "tg":
		// terragrunt exec [--] CMD ARGS...: CMD runs in the unit's directory.
		if len(rest) > 0 && rest[0].Text == "exec" {
			r := rest[1:]
			for len(r) > 0 && r[0].Resolved && strings.HasPrefix(r[0].Text, "-") && r[0].Text != "--" {
				r = r[1:]
			}
			if len(r) > 0 && r[0].Text == "--" {
				r = r[1:]
			}
			if len(r) > 0 {
				record()
				a.call(r, redirs, cmdSt, st, append(via, "terragrunt exec"), depth+1, in)
				return
			}
		}
	case "xargs":
		a.xargs(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "parallel":
		a.parallel(rest, redirs, cmdSt, st, via, depth, in)
		return
	case "ssh":
		a.sshOptions(bn, rest, cmdSt, via, depth)
		// ssh [opts] host [command...]: the remote command runs elsewhere,
		// but we still look at it so a remote terraform destroy is not hidden.
		r := skipFlags(rest, map[string]bool{"-p": true, "-i": true, "-l": true, "-o": true, "-F": true, "-J": true, "-L": true, "-R": true, "-D": true, "-E": true, "-S": true, "-W": true, "-b": true, "-c": true, "-m": true, "-O": true, "-Q": true, "-w": true, "-B": true, "-e": true, "-I": true})
		if len(r) > 1 {
			rs := st.childState()
			rs.dir = ""
			a.reparseIn(r[1:], rs, via, "ssh "+r[0].Text, depth)
		}
		record()
		return
	case "find", "fd":
		a.findExec(rest, redirs, cmdSt, st, via, depth)
		record()
		return
	case "make", "gmake":
		if a.make(args, cmdSt, st, via, depth) {
			return
		}
		record()
		return
	case "docker", "podman", "nerdctl":
		a.container(args, redirs, cmdSt, st, via, depth)
		record()
		return
	}
	return false
}
