package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/plancomment"
)

// The CI scripts are tested against this package's own code: with
// APPLYGATE_TEST_MAIN set the test binary is applygate.
func TestMain(m *testing.M) {
	if os.Getenv("APPLYGATE_TEST_MAIN") == "1" {
		os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

const (
	destroyPlan = "../../review/real_plan/delete_real_shape.show.json"
	createPlan  = "../../review/real_plan/create.show.json"
)

// The text plan-check printed before the comment format existed, for the plan
// the Action's own workflow blocks on.
const destroyProtectedText = `tier protected: block (2 changes, 1 deletes, 0 replaces)
- high destroy-count: plan destroys or replaces 1 resources; the limit for this tier is 0
    aws_db_instance.main
- critical stateful-destroyed: plan destroys or replaces stateful resources
    aws_db_instance.main (aws_db_instance) is destroyed
- critical protection-removed: plan removes data protection
    aws_db_instance.main: automated backups deleted with the instance while it is being deleted
    aws_db_instance.main: final snapshot skipped while it is being deleted
- high unknown-watched: values the exposure and protection rules check are known only at apply time, so the plan cannot show they are safe
    aws_s3_bucket.assets: policy is known only after apply
`

func TestPlanCheckCommentFormatKeepsTheVerdict(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	want := map[string]int{"protected": 3, "standard": 4, "disposable": 0}
	for _, plan := range []string{destroyPlan, createPlan} {
		for _, tier := range []string{"protected", "standard", "disposable"} {
			var text, comment, errb bytes.Buffer
			rcText := cmdPlanCheck([]string{"--tier", tier, "--cwd", dir, plan}, &text, &errb)
			rcComment := cmdPlanCheck([]string{"--format", "comment", "--comment-key", "envs/prod/tfplan", "--tier", tier, "--cwd", dir, plan}, &comment, &errb)
			if rcText != rcComment {
				t.Errorf("%s in %s: text exits %d, the comment format %d", plan, tier, rcText, rcComment)
			}
			if plan == destroyPlan && rcText != want[tier] {
				t.Errorf("%s in %s exits %d, want %d", plan, tier, rcText, want[tier])
			}
			if !strings.HasPrefix(comment.String(), plancomment.Marker("envs/prod/tfplan", "default")+"\n### applygate plan check: ") {
				t.Errorf("%s in %s: the comment does not start with its marker and verdict:\n%s", plan, tier, comment.String())
			}
			if strings.Contains(text.String(), "<!--") || strings.Contains(text.String(), "###") {
				t.Errorf("the text format prints Markdown:\n%s", text.String())
			}
			if errb.Len() != 0 {
				t.Errorf("%s in %s wrote to stderr: %s", plan, tier, errb.String())
			}
		}
	}
	var text, errb bytes.Buffer
	if rc := cmdPlanCheck([]string{"--tier", "protected", "--cwd", dir, destroyPlan}, &text, &errb); rc != 3 || text.String() != destroyProtectedText {
		t.Errorf("the text output changed (exit %d):\n%s", rc, text.String())
	}
}

func TestPlanCheckCommentFlags(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, args := range [][]string{
		{"--format", "markdown", destroyPlan},
		{"--comment-key", "k", destroyPlan},
		{"--comment-commit", "5948de7", destroyPlan},
		{"--comment-error", "x", destroyPlan},
		{"--format", "comment", "--comment-commit", "main; rm -rf /", destroyPlan},
	} {
		var out, errb bytes.Buffer
		if rc := cmdPlanCheck(args, &out, &errb); rc != 2 || out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("plan-check %v: exit %d, stdout %q, stderr %q", args, rc, out.String(), errb.String())
		}
	}
}

// A check that fails writes the comment for the same plan, so a comment that
// said allow for an earlier commit is replaced by one that says error.
func TestPlanCheckCommentOnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	notAPlan := filepath.Join(dir, "state.json")
	os.WriteFile(notAPlan, []byte(`{"format_version":"1.0","values":{}}`), 0o644)
	marker := plancomment.Marker("envs/prod/tfplan", "default")
	for name, args := range map[string][]string{
		"missing file":  {filepath.Join(dir, "nope.json")},
		"not a plan":    {notAPlan},
		"unknown tier":  {"--tier", "prod", destroyPlan},
		"comment-error": {"--comment-error", "terraform show -json failed on tfplan"},
		"no plan named": {},
	} {
		var out, errb bytes.Buffer
		rc := cmdPlanCheck(append([]string{"--format", "comment", "--comment-key", "envs/prod/tfplan", "--cwd", dir}, args...), &out, &errb)
		if rc != 2 || errb.Len() == 0 {
			t.Errorf("%s: exit %d, stderr %q", name, rc, errb.String())
		}
		if !strings.HasPrefix(out.String(), marker+"\n### applygate plan check: ❌ error\n") {
			t.Errorf("%s: no error comment for the plan:\n%s", name, out.String())
		}
	}
	// The workspace is part of what a comment is for.
	t.Setenv("TF_WORKSPACE", "payments")
	var out, errb bytes.Buffer
	cmdPlanCheck([]string{"--format", "comment", "--comment-key", "envs/prod/tfplan", "--tier", "standard", "--cwd", dir, createPlan}, &out, &errb)
	if !strings.HasPrefix(out.String(), plancomment.Marker("envs/prod/tfplan", "payments")+"\n") || !strings.Contains(out.String(), "workspace `payments`") {
		t.Errorf("the workspace is not in the marker and the comment:\n%s", out.String())
	}
}

// selfBinary writes a script that runs this test binary as applygate.
func selfBinary(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "applygate")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nAPPLYGATE_TEST_MAIN=1 exec '"+self+"' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

type ciRun struct {
	code    int
	log     string
	outputs string
	comment string
}

// ciPlanCheck runs scripts/ci-plan-check.sh.
func ciPlanCheck(t *testing.T, bin, plan string, env ...string) ciRun {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	script, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "ci-plan-check.sh"))
	cmd := exec.Command("bash", script)
	cmd.Dir = dir
	outputs, comment := filepath.Join(dir, "github_output"), filepath.Join(dir, "comment.md")
	cmd.Env = append(os.Environ(), "APPLYGATE_BIN="+bin, "PLAN="+plan, "WORKDIR="+dir, "GITHUB_OUTPUT="+outputs,
		"XDG_CONFIG_HOME="+t.TempDir(), "GITHUB_ACTIONS=", "GITHUB_STEP_SUMMARY=", "TF_WORKSPACE=")
	for _, kv := range env {
		if kv == "COMMENT_FILE=1" {
			kv = "COMMENT_FILE=" + comment
		}
		cmd.Env = append(cmd.Env, kv)
	}
	b, err := cmd.CombinedOutput()
	r := ciRun{log: string(b)}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	o, _ := os.ReadFile(outputs)
	c, _ := os.ReadFile(comment)
	r.outputs, r.comment = string(o), string(c)
	if _, err := os.Stat(comment + ".tmp"); err == nil {
		t.Errorf("the script left %s.tmp behind", comment)
	}
	return r
}

func outputValue(outputs, name string) string {
	for _, line := range strings.Split(outputs, "\n") {
		if v, ok := strings.CutPrefix(line, name+"="); ok {
			return v
		}
	}
	return ""
}

// The Action with comment: true runs the check exactly as without it: the
// same exit code and the same outputs, and the comment beside them.
func TestCIPlanCheckCommentDoesNotChangeTheCheck(t *testing.T) {
	bin := selfBinary(t, t.TempDir())
	plan, _ := filepath.Abs(destroyPlan)
	for _, c := range []struct {
		tier, failOn, verdict string
		code                  int
	}{
		{"protected", "block", "block", 1},
		{"protected", "never", "block", 0},
		{"standard", "block", "ask", 0},
		{"standard", "ask", "ask", 1},
		{"disposable", "ask", "allow", 0},
	} {
		plain := ciPlanCheck(t, bin, plan, "TIER="+c.tier, "FAIL_ON="+c.failOn)
		with := ciPlanCheck(t, bin, plan, "TIER="+c.tier, "FAIL_ON="+c.failOn, "COMMENT_FILE=1", "COMMENT_COMMIT=5948de7aa11bb22cc33dd44")
		off := ciPlanCheck(t, bin, plan, "TIER="+c.tier, "FAIL_ON="+c.failOn, "COMMENT_FILE=1", "COMMENT=false")
		for name, r := range map[string]ciRun{"without a comment": plain, "with a comment": with, "with COMMENT=false": off} {
			if r.code != c.code || outputValue(r.outputs, "verdict") != c.verdict {
				t.Errorf("%s/%s %s: exit %d, verdict %q; want %d, %q\n%s", c.tier, c.failOn, name, r.code, outputValue(r.outputs, "verdict"), c.code, c.verdict, r.log)
			}
		}
		if plain.log != with.log || outputValue(plain.outputs, "exit-code") != outputValue(with.outputs, "exit-code") {
			t.Errorf("%s/%s: the comment changed the log or the exit-code output:\n%s\n---\n%s", c.tier, c.failOn, plain.log, with.log)
		}
		if plain.comment != "" || off.comment != "" {
			t.Errorf("%s/%s: a comment was written without being asked for", c.tier, c.failOn)
		}
		if !strings.Contains(with.comment, "### applygate plan check: ") || !strings.Contains(with.comment, " "+c.verdict+"\n") || !strings.Contains(with.comment, "judged at `5948de7aa11b`") {
			t.Errorf("%s/%s: the comment does not give the verdict %s:\n%s", c.tier, c.failOn, c.verdict, with.comment)
		}
	}
}

// The comment is named after the directory and the plan unless the workflow
// names it, and a second run for the same plan carries the same marker.
func TestCIPlanCheckCommentKey(t *testing.T) {
	bin := selfBinary(t, t.TempDir())
	plan, _ := filepath.Abs(createPlan)
	a := ciPlanCheck(t, bin, plan, "TIER=standard", "COMMENT_FILE=1")
	if !strings.HasPrefix(a.comment, plancomment.Marker(plan, "default")+"\n") {
		t.Errorf("the default key is not the plan's path:\n%s", a.comment)
	}
	b := ciPlanCheck(t, bin, plan, "TIER=standard", "COMMENT_FILE=1", "COMMENT_KEY=prod `eu` <b>")
	if !strings.HasPrefix(b.comment, plancomment.Marker("prod `eu` <b>", "default")+"\n") || !strings.Contains(b.comment, "Plan ``prod `eu` <b>``") {
		t.Errorf("COMMENT_KEY is not the comment's name:\n%s", b.comment)
	}
	c := ciPlanCheck(t, bin, plan, "TIER=standard", "COMMENT_FILE=1", "COMMENT_COMMIT=$(touch pwned)")
	if strings.Contains(c.comment, "judged at") || c.comment == "" {
		t.Errorf("a COMMENT_COMMIT that is no commit is shown, or stops the comment:\n%s", c.comment)
	}
}

// An error of the check fails the job as before and the comment says error.
func TestCIPlanCheckCommentOnError(t *testing.T) {
	bin := selfBinary(t, t.TempDir())
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	os.WriteFile(state, []byte(`{"format_version":"1.0","values":{}}`), 0o644)
	for name, r := range map[string]ciRun{
		"plan file not found": ciPlanCheck(t, bin, filepath.Join(dir, "nope.tfplan"), "COMMENT_FILE=1"),
		"state, not a plan":   ciPlanCheck(t, bin, state, "COMMENT_FILE=1"),
		"bad TRUST_CONFIG":    ciPlanCheck(t, bin, state, "COMMENT_FILE=1", "TRUST_CONFIG=yes"),
	} {
		if r.code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, r.code, r.log)
		}
		if !strings.Contains(r.comment, "### applygate plan check: ❌ error") {
			t.Errorf("%s: the comment does not say error:\n%s\n%s", name, r.comment, r.log)
		}
	}
	if r := ciPlanCheck(t, bin, state, "COMMENT_FILE=1", "COMMENT=maybe"); r.code != 2 || r.comment != "" {
		t.Errorf("COMMENT=maybe: exit %d, comment %q", r.code, r.comment)
	}
}

// A release without the comment format, or a second run that disagrees with
// the check, leaves the check's result as it is and writes no comment.
func TestCIPlanCheckCommentDegrades(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte("{}"), 0o644)
	old := filepath.Join(dir, "old")
	os.WriteFile(old, []byte("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --format) echo 'flag provided but not defined: -format' >&2; exit 2 ;; esac; done\necho 'tier protected: block (1 changes, 1 deletes, 0 replaces)'\nexit 3\n"), 0o755)
	r := ciPlanCheck(t, old, plan, "COMMENT_FILE=1")
	if r.code != 1 || outputValue(r.outputs, "verdict") != "block" || r.comment != "" || !strings.Contains(r.log, "no pull-request comment written") {
		t.Errorf("a release without the comment format: exit %d, comment %q\n%s", r.code, r.comment, r.log)
	}
	differs := filepath.Join(dir, "differs")
	os.WriteFile(differs, []byte("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --format) echo '<!-- applygate:plan-check 0000000000000000 -->'; echo allow; exit 0 ;; esac; done\necho 'tier protected: block'\nexit 3\n"), 0o755)
	r = ciPlanCheck(t, differs, plan, "COMMENT_FILE=1")
	if r.code != 1 || r.comment != "" || !strings.Contains(r.log, "no pull-request comment written") {
		t.Errorf("a comment that disagrees with the check was kept: exit %d, comment %q\n%s", r.code, r.comment, r.log)
	}
}

// fakeGH writes a gh that records its arguments and answers from files.
func fakeGH(t *testing.T, dir, listed string, writeFails bool) (pathDir, calls string) {
	t.Helper()
	calls = filepath.Join(dir, "gh-calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> '` + calls + `'
case "$*" in
  *"--method PATCH"*|*"--method POST"*)
    ` + map[bool]string{true: `echo 'gh: Resource not accessible by integration (HTTP 403)' >&2; exit 1`, false: `for a in "$@"; do case "$a" in body=@*) cp "${a#body=@}" '` + dir + `/posted' ;; esac; done; exit 0`}[writeFails] + ` ;;
  *) printf '%s' '` + listed + `' ;;
esac
`
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, calls
}

func ciPRComment(t *testing.T, ghDir string, env ...string) (int, string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "ci-pr-comment.sh"))
	cmd := exec.Command("bash", script)
	cmd.Env = append([]string{"PATH=" + ghDir + string(os.PathListSeparator) + os.Getenv("PATH"), "GITHUB_REPOSITORY=acme/infra", "GITHUB_SERVER_URL=https://github.com", "GH_TOKEN=t"}, env...)
	b, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(b)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(b)
}

func TestCIPRComment(t *testing.T) {
	marker := plancomment.Marker("envs/prod/tfplan", "default")
	// Plan text in the body must reach gh as a file only.
	body := marker + "\n### applygate plan check: ⛔ block\n\n- `aws_db_instance.x[\"$(touch pwned); --method DELETE\"]`\n"
	newFile := func(dir, content string) string {
		p := filepath.Join(dir, "comment.md")
		os.WriteFile(p, []byte(content), 0o644)
		return p
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	t.Run("posts a new comment", func(t *testing.T) {
		dir := t.TempDir()
		gh, calls := fakeGH(t, dir, "", false)
		file := newFile(dir, body)
		code, log := ciPRComment(t, gh, "COMMENT_FILE="+file, "PR_NUMBER=12", "PR_HEAD_REPO=acme/infra")
		c := read(calls)
		if code != 0 || !strings.Contains(c, "repos/acme/infra/issues/12/comments?per_page=100") || !strings.Contains(c, "--method POST repos/acme/infra/issues/12/comments -F body=@"+file) || strings.Contains(c, "PATCH") {
			t.Errorf("exit %d\n%s\ncalls:\n%s", code, log, c)
		}
		if !strings.Contains(c, `select(.user.login == "github-actions[bot]" and ((.body // "") | startswith("`+marker+`")))`) {
			t.Errorf("the comment is not looked for by its marker and author:\n%s", c)
		}
		if strings.Contains(c, "pwned") || strings.Contains(c, "DELETE") {
			t.Errorf("text from the plan is on gh's command line:\n%s", c)
		}
		if read(filepath.Join(dir, "posted")) != body {
			t.Errorf("the posted body is not the file's")
		}
		if _, err := os.Stat(file); err == nil {
			t.Errorf("the comment file is left for a later step to post again")
		}
		if !strings.Contains(log, "posted the plan-check comment on pull request #12") {
			t.Errorf("log: %s", log)
		}
	})
	t.Run("updates the comment an earlier run posted", func(t *testing.T) {
		dir := t.TempDir()
		gh, calls := fakeGH(t, dir, "4242\n4300\n", false)
		file := newFile(dir, body)
		code, log := ciPRComment(t, gh, "COMMENT_FILE="+file, "PR_NUMBER=12")
		c := read(calls)
		if code != 0 || !strings.Contains(c, "--method PATCH repos/acme/infra/issues/comments/4242 -F body=@"+file) || strings.Contains(c, "POST") {
			t.Errorf("exit %d\n%s\ncalls:\n%s", code, log, c)
		}
	})
	t.Run("a refused write does not fail the job", func(t *testing.T) {
		for _, head := range []string{"acme/infra", "contributor/infra"} {
			dir := t.TempDir()
			gh, _ := fakeGH(t, dir, "", true)
			code, log := ciPRComment(t, gh, "COMMENT_FILE="+newFile(dir, body), "PR_NUMBER=12", "PR_HEAD_REPO="+head)
			want := "pull-requests: write"
			if head != "acme/infra" {
				want = "comes from a fork"
			}
			if code != 0 || !strings.Contains(log, "::notice title=applygate plan check::The pull-request comment was not written") || !strings.Contains(log, want) || !strings.Contains(log, "HTTP 403") {
				t.Errorf("head %s: exit %d\n%s", head, code, log)
			}
		}
	})
	t.Run("nothing to do", func(t *testing.T) {
		for name, c := range map[string]struct {
			content string
			env     []string
			says    string
		}{
			"not a pull request":       {body, nil, "this run is not for a pull request"},
			"no comment written":       {"", []string{"PR_NUMBER=12"}, "plan-check wrote none"},
			"no marker":                {"### applygate plan check\n", []string{"PR_NUMBER=12"}, "does not start with its marker"},
			"a marker with more":       {marker + `")) or true or ((""` + "\n", []string{"PR_NUMBER=12"}, "does not start with its marker"},
			"a number that is not":     {body, []string{"PR_NUMBER=12/../../issues/1"}, "is not a number"},
			"a repository that is not": {body, []string{"PR_NUMBER=12", "GITHUB_REPOSITORY=acme/infra/../x"}, "is not owner/name"},
		} {
			dir := t.TempDir()
			gh, calls := fakeGH(t, dir, "", false)
			code, log := ciPRComment(t, gh, append([]string{"COMMENT_FILE=" + newFile(dir, c.content)}, c.env...)...)
			if code != 0 || !strings.Contains(log, c.says) || read(calls) != "" {
				t.Errorf("%s: exit %d, gh calls %q\n%s", name, code, read(calls), log)
			}
		}
	})
}

// The comment names the environment the tier came from, with the config's
// pattern as the config writes it, not the runner's absolute path.
func TestPlanCheckCommentNamesTheEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte("version: 1\nenvironments:\n  - {name: prod, tier: protected, match: {paths: [\"envs/prod/**\"]}}\n"), 0o644)
	prod := filepath.Join(root, "envs", "prod")
	os.MkdirAll(prod, 0o755)
	var out, errb bytes.Buffer
	rc := cmdPlanCheck([]string{"--trust-config", "--format", "comment", "--comment-key", "envs/prod/tfplan", "--cwd", prod, destroyPlan}, &out, &errb)
	if rc != 3 || !strings.Contains(out.String(), "Plan `envs/prod/tfplan` · environment `prod` (`path envs/prod/**`) · tier **protected** · ") {
		t.Errorf("exit %d:\n%s%s", rc, out.String(), errb.String())
	}
	if strings.Contains(out.String(), root) {
		t.Errorf("the comment shows the runner's path:\n%s", out.String())
	}
}
