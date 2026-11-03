// Command strict-shapes measures the strict mode that decision D-3 of the
// v0.6.0 review asks for (workstream 9): in a protected tier, allow only
// commands whose every word resolved and whose structure is a plain list or
// pipeline of known programs, and ask about everything else.
//
//	go run ./experiments/strict-shapes -bin bin/applygate
//
// It reads benign traffic (the agent-driven trial's decision log, the OSS
// corpus commands recorded at commit 149ab67, the scenario pack's benign
// calls) and attacks (the scenario pack's dangerous calls and the review's
// attack pack), decides for each command whether it has a plain shape, and
// for the benign ones that do not, asks applygate (check, in the fixture
// repository's protected directory) whether it allows them today: those are
// the new asks the mode would add. Nothing here runs the commands.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/Flurit/applygate/internal/shell"
)

// known are the programs a plain command may run: shell builtins without
// side effects on other commands, text and file tools, version control,
// build tools and the infrastructure CLIs applygate classifies. Interpreters
// and shells are not here: their code is opaque.
var known = set(
	"cd", "pwd", "echo", "printf", "true", "false", "test", "[", "exit", "export", "unset", "sleep", "date", "which", "type",
	"ls", "cat", "head", "tail", "wc", "grep", "egrep", "rg", "sort", "uniq", "cut", "tr", "tee", "diff", "cmp", "less", "more",
	"tree", "stat", "file", "du", "df", "basename", "dirname", "realpath", "readlink", "mkdir", "touch", "cp", "mv", "rm",
	"ln", "chmod", "find", "jq", "yq", "sed", "column", "xxd", "od", "base64", "sha256sum", "shasum", "md5sum", "env",
	"tar", "unzip", "zip", "gzip", "gunzip", "curl", "wget", "nl", "fold", "comm", "join", "paste", "seq", "id", "whoami",
	"uname", "hostname", "printenv", "git", "gh", "glab", "go", "gofmt", "cargo", "rustc", "npm", "npx", "pnpm", "yarn",
	"make", "docker", "podman", "pre-commit", "terraform", "tofu", "terragrunt", "tflint", "tfsec", "checkov", "trivy",
	"terraform-docs", "infracost", "kubectl", "helm", "kustomize", "aws", "az", "gcloud", "gsutil", "packer", "vault",
	"conftest", "opa", "shellcheck", "actionlint", "brew", "pip", "pip3", "uv", "poetry",
)

func set(ss ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// argsMustResolve is the strict variant: every word, not only the program
// names, must resolve (set with -args).
var argsMustResolve = true

// plain reports whether cmd has a plain shape, and if not, why.
func plain(cmd string) (bool, string) {
	f, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return false, "does not parse"
	}
	why := ""
	syntax.Walk(f, func(n syntax.Node) bool {
		if why != "" || n == nil {
			// Walk calls f(nil) after a node's children.
			return why == ""
		}
		switch x := n.(type) {
		case *syntax.File, *syntax.Stmt, *syntax.CallExpr, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted,
			*syntax.Redirect, *syntax.Assign, *syntax.Comment:
			if s, ok := x.(*syntax.Stmt); ok && (s.Background || s.Coprocess) {
				why = "background"
			}
			if q, ok := x.(*syntax.SglQuoted); ok && q.Dollar {
				why = "$'...' string"
			}
		case *syntax.BinaryCmd:
			if x.Op != syntax.AndStmt && x.Op != syntax.OrStmt && x.Op != syntax.Pipe {
				why = "operator " + x.Op.String()
			}
		case *syntax.ParamExp:
			if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
				why = "parameter expansion"
			}
		default:
			why = strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax.")
		}
		return why == ""
	})
	if why != "" {
		return false, why
	}
	res := shell.Analyze(cmd, shell.Options{Dir: "/r", Env: map[string]string{"HOME": "/h"},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if len(res.Problems) > 0 {
		return false, "analyzer problem: " + res.Problems[0].Reason
	}
	for _, inv := range res.Invocations {
		if len(inv.Via) > 0 {
			continue // a recipe or a wrapped command; the top level decides
		}
		for i, w := range inv.Args {
			if !w.Resolved && (i == 0 || argsMustResolve) {
				return false, "unresolved word"
			}
		}
		if n := shell.ProgName(inv.Args[0].Text); !known[n] {
			return false, "program " + n
		}
	}
	return true, ""
}

type item struct {
	set, cmd string
	benign   bool
}

func main() {
	bin := flag.String("bin", "bin/applygate", "applygate binary for the current verdicts")
	repo := flag.String("repo", "harness/pack/fixtures/repo", "fixture repository")
	flag.BoolVar(&argsMustResolve, "args", true, "every argument must resolve, not only program names")
	flag.Parse()
	var items []item
	// Benign: the agent-driven trial (Bash calls only).
	readJSONL("review/agent-trial/results/2026-10-29-both/decisions.jsonl", func(m map[string]any) {
		if c, _ := m["command"].(string); c != "" && m["tool"] == "Bash" {
			items = append(items, item{"agent trial", c, true})
		}
	})
	// Benign: the OSS corpus, the lines the hand review labelled allow.
	out, err := exec.Command("git", "show", "149ab67:review/oss-corpus/results/config-after.jsonl").Output()
	must(err)
	scanJSONL(bytes.NewReader(out), func(m map[string]any) {
		if c, _ := m["command"].(string); c != "" && m["review"] == "allow" {
			items = append(items, item{"OSS corpus", c, true})
		}
	})
	for _, p := range []string{"harness/pack/scenarios.json", "harness/pack_attack/scenarios.json"} {
		var doc struct {
			Scenarios []struct {
				Kind      string         `json:"kind"`
				Tool      string         `json:"tool"`
				ToolInput map[string]any `json:"tool_input"`
			} `json:"scenarios"`
		}
		b, err := os.ReadFile(p)
		must(err)
		must(json.Unmarshal(b, &doc))
		name := "scenario pack"
		if strings.Contains(p, "attack") {
			name = "attack pack"
		}
		for _, s := range doc.Scenarios {
			c, _ := s.ToolInput["command"].(string)
			if s.Tool != "Bash" || c == "" {
				continue
			}
			items = append(items, item{name, c, s.Kind != "dangerous"})
		}
	}
	type tally struct{ total, nonPlain, newAsk int }
	tallies := map[string]*tally{}
	reasons := map[string]int{}
	var asks []string
	cwd, _ := filepath.Abs(filepath.Join(*repo, "envs/prod"))
	home, _ := os.MkdirTemp("", "strict-shapes")
	for _, it := range items {
		key := it.set + map[bool]string{true: " (benign)", false: " (dangerous)"}[it.benign]
		t := tallies[key]
		if t == nil {
			t = &tally{}
			tallies[key] = t
		}
		t.total++
		ok, why := plain(it.cmd)
		if ok {
			continue
		}
		t.nonPlain++
		if !it.benign {
			continue
		}
		reasons[strings.SplitN(why, ":", 2)[0]]++
		c := exec.Command(*bin, "check", "--no-judge", "--cwd", cwd, "--", it.cmd)
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_STATE_HOME="+home+"/.state")
		o, _ := c.Output()
		if v, _, _ := strings.Cut(string(o), "\n"); v == "allow" {
			t.newAsk++
			asks = append(asks, fmt.Sprintf("%s [%s] %q", it.set, why, short(it.cmd)))
		}
	}
	keys := make([]string, 0, len(tallies))
	for k := range tallies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("| Set | Commands | Not plain | Allowed in protected today, asked under strict shapes |")
	fmt.Println("|---|---|---|---|")
	for _, k := range keys {
		t := tallies[k]
		na := fmt.Sprint(t.newAsk)
		if strings.HasSuffix(k, "(dangerous)") {
			na = "n/a"
		}
		fmt.Printf("| %s | %d | %d | %s |\n", k, t.total, t.nonPlain, na)
	}
	fmt.Println("\nWhy benign commands are not plain:")
	rk := make([]string, 0, len(reasons))
	for k := range reasons {
		rk = append(rk, k)
	}
	sort.Slice(rk, func(i, j int) bool { return reasons[rk[i]] > reasons[rk[j]] })
	for _, k := range rk {
		fmt.Printf("- %s: %d\n", k, reasons[k])
	}
	fmt.Println("\nNew asks:")
	for _, a := range asks {
		fmt.Println("-", a)
	}
}

func short(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 110 {
		return s[:107] + "..."
	}
	return s
}

func readJSONL(p string, f func(map[string]any)) {
	fh, err := os.Open(p)
	must(err)
	defer fh.Close()
	scanJSONL(fh, f)
}

func scanJSONL(r interface{ Read([]byte) (int, error) }, f func(map[string]any)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			f(m)
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
