package harness

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

// Generated spellings for the effects oracle. The hand-written spellings in
// oracle_test.go each do one thing; the generator composes them: a program
// form (quoting, variable indirection, expansion, a glob or quoted path into
// the fake bin), a directory change (cd with quoted, globbed, substituted and
// absolute operands), and a chain of up to three wrappers (sudo, env, xargs,
// bash -c, eval, here-documents, groups, loops, process substitution). The
// choices come from a seeded generator, so a run is repeatable: the seed is
// logged, and APPLYGATE_ORACLE_SEED repeats it.

const defaultOracleSeed = 20261106

func oracleSeed() int64 {
	if v := os.Getenv("APPLYGATE_ORACLE_SEED"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return defaultOracleSeed
}

func oracleGenCount() int {
	if v := os.Getenv("APPLYGATE_ORACLE_GEN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 400
}

// A wrapper turns a command into another command. word wrappers prefix command
// words and are only valid on a simple command; simpleAfter says whether the
// result is again a simple command.
type genWrapper struct {
	name        string
	word        bool
	simpleAfter bool
	f           func(string) string
}

func dq(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`")
	return `"` + r.Replace(s) + `"`
}

func genWrappers() []genWrapper {
	return []genWrapper{
		{"sudo", true, true, func(c string) string { return "sudo " + c }},
		{"sudo -n -E", true, true, func(c string) string { return "sudo -n -E " + c }},
		{"env", true, true, func(c string) string { return "env " + c }},
		{"env var", true, true, func(c string) string { return "env X=1 " + c }},
		{"env -i", true, true, func(c string) string { return `env -i PATH="$PATH" HOME="$HOME" ` + c }},
		{"command", true, true, func(c string) string { return "command " + c }},
		{"command --", true, true, func(c string) string { return "command -- " + c }},
		{"exec", true, true, func(c string) string { return "exec " + c }},
		{"time", true, true, func(c string) string { return "time " + c }},
		{"nice", true, true, func(c string) string { return "nice -n 5 " + c }},
		{"timeout", true, true, func(c string) string { return "timeout 5 " + c }},
		{"nohup", true, true, func(c string) string { return "nohup " + c }},
		{"bash -c", false, true, func(c string) string { return "bash -c " + shq(c) }},
		{"sh -c", false, true, func(c string) string { return "sh -c " + shq(c) }},
		{"dash -c", false, true, func(c string) string { return "dash -c " + shq(c) }},
		{"bash -c dq", false, true, func(c string) string { return "bash -c " + dq(c) }},
		{"bash -ec", false, true, func(c string) string { return "bash -ec " + shq(c) }},
		{"eval", false, false, func(c string) string { return "eval " + shq(c) }},
		{"eval dq", false, false, func(c string) string { return "eval " + dq(c) }},
		{"echo pipe sh", false, false, func(c string) string { return "echo " + shq(c) + " | sh" }},
		{"printf pipe bash", false, false, func(c string) string { return "printf '%s' " + shq(c) + " | bash" }},
		{"here-string", false, false, func(c string) string { return "bash <<< " + shq(c) }},
		{"here-doc quoted", false, false, func(c string) string { return "sh <<'EOF'\n" + c + "\nEOF" }},
		{"here-doc", false, false, func(c string) string { return "bash <<EOF\n" + c + "\nEOF" }},
		{"cat here-doc eval", false, false, func(c string) string { return "eval \"$(cat <<'EOF'\n" + c + "\nEOF\n)\"" }},
		{"xargs", false, false, func(c string) string { return "echo x | xargs -I{} sh -c " + shq(c) }},
		{"xargs -0", false, false, func(c string) string { return "printf 'x\\0' | xargs -0 -n1 sh -c " + shq(c) + " sh" }},
		{"subshell", false, false, func(c string) string { return "(" + c + "\n)" }},
		{"brace group", false, false, func(c string) string { return "{ " + c + "\n}" }},
		{"brace group redirect", false, false, func(c string) string { return "{ " + c + "\n} 2>&1" }},
		{"background", false, false, func(c string) string { return "{ " + c + "\n} & wait" }},
		{"if", false, false, func(c string) string { return "if true; then " + c + "\nfi" }},
		{"for", false, false, func(c string) string { return "for i in 1; do " + c + "\ndone" }},
		{"while read", false, false, func(c string) string { return "echo x | while read l; do " + c + "\ndone" }},
		{"function", false, false, func(c string) string { return "f() { " + c + "\n}; f" }},
		{"and list", false, false, func(c string) string { return "true && " + c }},
		{"or list", false, false, func(c string) string { return "false || " + c }},
		{"source process substitution", false, false, func(c string) string { return "source <(printf '%s\\n' " + shq(c) + ")" }},
		{"bash process substitution", false, false, func(c string) string { return "bash <(printf '%s\\n' " + shq(c) + ")" }},
		{"command substitution", false, false, func(c string) string { return "x=$(" + c + "\n)" }},
	}
}

// Program forms rewrite the program word. pre is a statement run first.
type genProg struct {
	name string
	f    func(p string) (pre, word string)
}

func genProgs() []genProg {
	return []genProg{
		{"quoted", func(p string) (string, string) {
			k := (len(p) + 1) / 2
			return "", "'" + p[:k] + "''" + p[k:] + "'"
		}},
		{"double quoted", func(p string) (string, string) { return "", `"` + p + `"` }},
		{"backslash", func(p string) (string, string) { return "", `\` + p }},
		{"backslash inside", func(p string) (string, string) { return "", p[:1] + `\` + p[1:] }},
		{"ansi-c", func(p string) (string, string) { return "", "$'" + p + "'" }},
		{"ansi-c hex", func(p string) (string, string) { return "", `$'\x` + fmt.Sprintf("%02x", p[0]) + p[1:] + `'` }},
		{"variable", func(p string) (string, string) { return "t=" + p + "; ", "$t" }},
		{"braced variable", func(p string) (string, string) { return "t=" + p + "; ", "${t}" }},
		{"variable split", func(p string) (string, string) { return "a=" + p[:2] + " b=" + p[2:] + "; ", "$a$b" }},
		{"default expansion", func(p string) (string, string) { return "", "${x:-" + p + "}" }},
		{"substring expansion", func(p string) (string, string) { return "x=zz" + p + "; ", "${x:2}" }},
		{"substitution", func(p string) (string, string) { return "", "$(echo " + p + ")" }},
		{"printf substitution", func(p string) (string, string) { return "", "$(printf %s " + p + ")" }},
		{"fake bin path", func(p string) (string, string) { return "", `"$FAKEBIN"/` + p }},
		{"fake bin glob", func(p string) (string, string) { return "", "$FAKEBIN/" + p[:len(p)-1] + "?" }},
		{"fake bin bracket glob", func(p string) (string, string) { return "", "$FAKEBIN/[" + p[:1] + "]" + p[1:] }},
		{"fake bin star glob", func(p string) (string, string) { return "", "$FAKEBIN/" + p[:2] + "*" }},
		{"alias", func(p string) (string, string) {
			return "shopt -s expand_aliases 2>/dev/null; alias z=" + p + "; ", "z"
		}},
	}
}

// Directory forms: how a command reaches the prod directory from dev.
func genDirs(prod string) []string {
	return []string{
		"../prod", "../prod/", "../prod/.", "..//prod", "../prod/../prod", "../../envs/prod", "$PWD/../prod", "'../pr''od'", `"../prod"`,
		`..\/prod`, "../pro*", "../p?od", "../[p]rod", "../pr[o]d", "~+/../prod", "$(echo ../prod)", "`echo ../prod`", "$d", "${d}", "${d:-../prod}",
		prod, shq(prod), prod[:len(prod)-1] + "?", prod[:len(prod)-2] + "*",
	}
}

func genCds(prod string) []func(c string) (string, bool) {
	var out []func(c string) (string, bool)
	for _, d := range genDirs(prod) {
		d := d
		pre := ""
		if strings.Contains(d, "$d") || strings.Contains(d, "${d}") {
			pre = "d=../prod; "
		}
		for _, w := range []string{"cd", "builtin cd", "command cd", "cd -P", "cd --", "pushd"} {
			w := w
			out = append(out,
				func(c string) (string, bool) { return pre + w + " " + d + " && " + c, false },
				func(c string) (string, bool) { return pre + w + " " + d + "; " + c, false },
				func(c string) (string, bool) { return "(" + pre + w + " " + d + "; " + c + "\n)", false },
			)
		}
		out = append(out, func(c string) (string, bool) { return pre + "CDPATH=.. cd prod && " + c, false })
	}
	// env -C wraps a simple command.
	out = append(out, func(c string) (string, bool) { return "env -C ../prod " + c, true })
	return out
}

func looksSimple(c string) bool {
	return !strings.ContainsAny(c, ";&|<>(){}$`\n\\'\"")
}

// generateCases builds n commands from seed. prod is the absolute prod
// directory (for absolute operands of cd).
func generateCases(seed int64, n int, shells map[string]string, prod string) []oracleCase {
	rng := rand.New(rand.NewSource(seed))
	var atoms []oracleAtom
	for _, a := range oracleAtoms {
		if a.needs == "" || shells[a.needs] != "" {
			atoms = append(atoms, a)
		}
	}
	wrappers := genWrappers()
	progs := genProgs()
	cds := genCds(prod)
	var out []oracleCase
	for i := 0; i < n; i++ {
		a := atoms[rng.Intn(len(atoms))]
		cmd := a.cmd
		simple := looksSimple(cmd)
		var recipe []string
		if rng.Intn(10) < 6 && a.kind != "file" {
			p := progs[rng.Intn(len(progs))]
			pre, word := p.f(a.pg())
			cmd = pre + a.with(word)
			simple = pre == "" && looksSimple(strings.Replace(a.cmd, a.pg(), "x", 1))
			recipe = append(recipe, "prog="+p.name)
		}
		layers := rng.Intn(4)
		cdAt := -1
		from := "prod"
		if rng.Intn(10) < 5 {
			cdAt = rng.Intn(layers + 1)
			from = "dev"
		}
		for l := 0; l <= layers; l++ {
			if l == cdAt {
				idx := rng.Intn(len(cds))
				c2, s2 := cds[idx](cmd)
				if strings.HasPrefix(c2, "env -C") && !simple {
					c2, s2 = "cd ../prod && "+cmd, false
				}
				cmd, simple = c2, s2
				recipe = append(recipe, fmt.Sprintf("cd#%d", idx))
			}
			if l == layers {
				break
			}
			var w genWrapper
			for tries := 0; ; tries++ {
				w = wrappers[rng.Intn(len(wrappers))]
				if !w.word || simple || tries > 50 {
					break
				}
			}
			if w.word && !simple {
				continue
			}
			cmd = w.f(cmd)
			simple = w.simpleAfter
			recipe = append(recipe, w.name)
		}
		out = append(out, oracleCase{spelling: fmt.Sprintf("gen#%d %s %s", i, a.name, strings.Join(recipe, " > ")), atom: a, from: from, cmd: cmd})
	}
	return out
}
