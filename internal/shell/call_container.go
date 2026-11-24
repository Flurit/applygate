package shell

import (
	"path"
	"path/filepath"
	"strings"
)

// container unwraps "docker run ... <image> args" when the image is a
// Terraform or OpenTofu image, so the arguments are classified as such.
func (a *analyzer) container(args []Word, redirs []Redir, cmdSt, st *state, via []string, depth int) {
	// The subcommand: the first word that is not an option, and "container"
	// or "compose" are followed by theirs. Only run, create and exec start a
	// command in a container; the image of run and create is the first word
	// after the options that is not an option's value, and exec has a
	// container name instead. A later word that mentions terraform (the text
	// of sh -c, a path in the container) is not an image.
	sub, start := "", 0
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i].Text, "-") {
			continue
		}
		if sub == "" && (args[i].Text == "container" || args[i].Text == "compose") {
			sub = args[i].Text
			continue
		}
		sub, start = args[i].Text, i+1
		break
	}
	switch sub {
	case "run", "create", "exec":
	default:
		return
	}
	skip := false
	for i, w := range args {
		if i < start {
			continue
		}
		if skip {
			skip = false
			continue
		}
		// An option's value (-e TF_DATA_DIR=..., -v ...:/terraform) is not
		// the image; an image name has no "=".
		if t := w.Text; strings.HasPrefix(t, "-") {
			skip = !strings.Contains(t, "=") && containerValued[t]
			continue
		}
		if strings.Contains(w.Text, "=") {
			continue
		}
		if sub == "exec" {
			// The first word is the container; what follows runs inside it,
			// where the host's directory and mounts do not map back.
			if r := args[i+1:]; len(r) > 0 && tfEngines[base(r[0].Text)] {
				cs := cmdSt.clone()
				cs.dir = ""
				a.call(r, redirs, cs, st, append(via, args[0].Text+" exec"), depth+1, stdin{})
			}
			return
		}
		img := strings.ToLower(w.Text)
		engine := ""
		switch {
		case strings.Contains(img, "terragrunt"):
			engine = "terragrunt"
		case strings.Contains(img, "opentofu") || strings.Contains(img, "/tofu"):
			engine = "tofu"
		case strings.Contains(img, "terraform"):
			engine = "terraform"
		}
		if engine == "" || strings.HasPrefix(img, "-") {
			return
		}
		r := args[i+1:]
		if len(r) > 0 && (base(r[0].Text) == "terraform" || base(r[0].Text) == "tofu" || base(r[0].Text) == "terragrunt") {
			r = r[1:]
		}
		cs := cmdSt.clone()
		var toHost func(string) (string, bool)
		opts := splitShortOpts(args[1:i])
		cs.dir, toHost = a.containerDir(opts, cmdSt)
		// The container's environment: -e NAME=VALUE sets a variable,
		// -e NAME passes the host's (unknown here), and --env-file sets
		// what a file says, any tier signal among them.
		for k := 0; k < len(opts); k++ {
			t := opts[k].Text
			f, v, eq := strings.Cut(t, "=")
			switch f {
			case "-e", "--env":
				var e Word
				if eq {
					e = Word{Text: v, Resolved: opts[k].Resolved}
				} else if k+1 < len(opts) {
					k++
					e = opts[k]
				}
				name, val, has := strings.Cut(e.Text, "=")
				switch {
				case name == "":
				case !e.Resolved || !has:
					cs.vars[name] = value{}
				default:
					if hp, ok := toHost(val); ok {
						val = hp
					} else if strings.HasPrefix(val, "/") {
						cs.vars[name] = value{}
						cs.exported[name] = true
						continue
					}
					cs.vars[name] = value{text: val, ok: true}
				}
				cs.exported[name] = true
			case "--env-file":
				if !eq {
					k++
				}
				for _, n := range TierEnv {
					cs.vars[n] = value{}
					cs.exported[n] = true
				}
			}
		}
		// Absolute paths in the arguments are the container's: those under
		// a mount are the host paths it maps, others are not on the host.
		r = append([]Word(nil), r...)
		for k, x := range r {
			name, val, eq := strings.Cut(x.Text, "=")
			p := x.Text
			if eq && strings.HasPrefix(name, "-") {
				p = val
			}
			if !x.Resolved || !strings.HasPrefix(p, "/") {
				continue
			}
			if hp, ok := toHost(p); ok {
				if eq && strings.HasPrefix(name, "-") {
					r[k] = Word{Text: name + "=" + hp, Resolved: true, Prefix: name + "=" + hp}
				} else {
					r[k] = Word{Text: hp, Resolved: true, Prefix: hp}
				}
			} else {
				r[k] = Word{Text: strings.TrimSuffix(x.Text, p), Prefix: strings.TrimSuffix(x.Text, p)}
			}
		}
		a.call(append(lits(engine), r...), redirs, cs, st, append(via, args[0].Text+" image "+w.Text), depth+1, stdin{})
		return
	}
}

// splitShortOpts rewrites a short option glued to its value, alone or at the
// end of a cluster of flags (-eNAME=val, -ieNAME=val, -w/dir, -vSRC:DST), into
// the option and its value as two words, the way the program reads them.
func splitShortOpts(opts []Word) []Word {
	const flags, valued = "itdqPD", "evwupl"
	var out []Word
	for _, w := range opts {
		t := w.Text
		if len(t) < 3 || t[0] != '-' || t[1] == '-' {
			out = append(out, w)
			continue
		}
		k := 1
		for k < len(t) && strings.IndexByte(flags, t[k]) >= 0 {
			k++
		}
		if k >= len(t) || strings.IndexByte(valued, t[k]) < 0 {
			out = append(out, w)
			continue
		}
		for _, f := range t[1:k] {
			out = append(out, Word{Text: "-" + string(f), Resolved: true, Prefix: "-" + string(f)})
		}
		out = append(out, Word{Text: "-" + string(t[k]), Resolved: true, Prefix: "-" + string(t[k])})
		if rest := t[k+1:]; rest != "" {
			out = append(out, Word{Text: rest, Resolved: w.Resolved, Prefix: rest})
		}
	}
	return out
}

// containerDir is the host directory a container's command runs in: the
// mount source under its working directory (-v SRC:DST -w DST/sub), or ""
// (unknown) when that cannot be followed. Without both a mount and a
// working directory the command runs in the image's own directory, which is
// not the host's either.
func (a *analyzer) containerDir(opts []Word, cmdSt *state) (string, func(string) (string, bool)) {
	type mount struct{ src, dst string }
	var mounts []mount
	wd, ok := "", true
	val := func(i int, name string) (string, int) {
		t := opts[i].Text
		if v, found := strings.CutPrefix(t, name+"="); found {
			ok = ok && opts[i].Resolved
			return v, i
		}
		if i+1 < len(opts) {
			ok = ok && opts[i+1].Resolved
			return opts[i+1].Text, i + 1
		}
		return "", i
	}
	for i := 0; i < len(opts); i++ {
		t := opts[i].Text
		f, _, _ := strings.Cut(t, "=")
		switch f {
		case "-v", "--volume":
			v, j := val(i, f)
			i = j
			src, dst, found := strings.Cut(v, ":")
			if found {
				dst, _, _ = strings.Cut(dst, ":")
				mounts = append(mounts, mount{src, dst})
			}
		case "--mount":
			v, j := val(i, f)
			i = j
			var m mount
			for _, kv := range strings.Split(v, ",") {
				k, x, _ := strings.Cut(kv, "=")
				switch k {
				case "src", "source":
					m.src = x
				case "dst", "destination", "target":
					m.dst = x
				}
			}
			mounts = append(mounts, m)
		case "-w", "--workdir":
			wd, i = val(i, f)
		}
	}
	toHost := func(p string) (string, bool) {
		if !ok {
			return "", false
		}
		best := -1
		for k, m := range mounts {
			if m.src == "" || m.dst == "" {
				continue
			}
			if p == m.dst || strings.HasPrefix(p, strings.TrimSuffix(m.dst, "/")+"/") {
				if best < 0 || len(m.dst) > len(mounts[best].dst) {
					best = k
				}
			}
		}
		if best < 0 {
			return "", false
		}
		m := mounts[best]
		rel := strings.TrimPrefix(strings.TrimPrefix(p, m.dst), "/")
		return a.abs(cmdSt, filepath.Join(m.src, rel)), true
	}
	if !ok || wd == "" || !path.IsAbs(wd) {
		return "", toHost
	}
	d, _ := toHost(wd)
	return d, toHost
}

// containerValued are docker's and podman's run options that take the next
// word as their value.
var containerValued = toSet("-e", "--env", "--env-file", "-v", "--volume", "--mount", "-w", "--workdir", "--name", "-p",
	"--publish", "--network", "--net", "--entrypoint", "-u", "--user", "--platform", "-l", "--label", "--label-file",
	"-h", "--hostname", "--add-host", "--dns", "--cap-add", "--cap-drop", "--device", "-m", "--memory", "--cpus",
	"--pull", "--restart", "--log-driver", "--log-opt", "--tmpfs", "--ulimit", "--security-opt", "--volumes-from",
	"--secret", "--ssh", "--userns", "--pid", "--ipc", "--uts", "--cgroupns", "--runtime", "-a", "--attach", "--cidfile")
