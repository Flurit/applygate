package shell

import (
	"sort"
	"strings"
)

// Stage 6 of the allow-list: programs with subcommands, where each subcommand
// has its own exact option list (git, docker, gh and the policy scanners).
// A tree reads the program's global options, takes the first word that is not
// an option as the subcommand, and checks the rest against that subcommand's
// prog. A subcommand that is not in the tree is not plain.

// node is one subcommand: a leaf with its options, or a group with
// subcommands of its own (docker compose ps).
type node struct {
	p *prog
	t *tree
}

type tree struct {
	global *prog
	subs   map[string]node
}

func leaf(p *prog) node  { return node{p: p} }
func group(t *tree) node { return node{t: t} }
func gtree(global *prog, subs map[string]node) *tree {
	return &tree{global: global, subs: subs}
}

// cmdEntry is one leaf the conformance test runs: the program, the
// subcommand words in front of the option, and its options.
type cmdEntry struct {
	name  string
	words []string
	p     *prog
}

// allowCmds are the leaves of every tree and of git, in registration order.
var allowCmds []cmdEntry

// registerTree makes name a program that is plain only for the leaves of t.
func registerTree(name string, t *tree) {
	var walk func(words []string, t *tree)
	walk = func(words []string, t *tree) {
		keys := make([]string, 0, len(t.subs))
		for k := range t.subs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			n := t.subs[k]
			w := append(append([]string{}, words...), k)
			if n.t != nil {
				walk(w, n.t)
			} else if n.p != nil {
				allowCmds = append(allowCmds, cmdEntry{name, w, n.p})
			}
		}
	}
	walk(nil, t)
	shapes[name] = func(args []Word, _ Invocation) string { return t.check(name, args) }
}

func (t *tree) check(name string, args []Word) string {
	i := 0
	for i < len(args) {
		x := optText(args[i])
		if !strings.HasPrefix(x, "-") || x == "-" {
			break
		}
		if !args[i].Resolved {
			return "a " + name + " option that cannot be resolved"
		}
		if t.global.vals[x] {
			i++
		}
		i++
	}
	if why := t.global.check(name, args[:min(i, len(args))]); why != "" {
		return why
	}
	if i >= len(args) {
		return ""
	}
	if !args[i].Resolved {
		return "a " + name + " subcommand that cannot be resolved"
	}
	sub := args[i].Text
	n, ok := t.subs[sub]
	if !ok {
		return "the " + name + " subcommand " + sub
	}
	if n.t != nil {
		return n.t.check(name+" "+sub, args[i+1:])
	}
	return n.p.check(name+" "+sub, args[i+1:])
}

// The write kinds: the options by which a program writes a file other than the
// ones it reads (its report, dump or output). The classifier asks for them to
// know which path a call writes (guard files, state), also for the calls that
// are not plain, so they are kept next to the allow-list entry of the program
// and an unlisted option may still be named here.
var outputOptions = map[string][]string{}

// OutputOpts are the options of program name that write the file their value
// names.
func OutputOpts(name string) []string { return outputOptions[name] }

func regOutputs(name string, s string) {
	outputOptions[name] = append(outputOptions[name], strings.Fields(s)...)
}

func (p *prog) withOutputs(s string) *prog { p.outputs = strings.Fields(s); return p }
