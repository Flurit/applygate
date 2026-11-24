package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	destroyPlan = "../../testdata/real_plan/delete_real_shape.show.json"
	createPlan  = "../../testdata/real_plan/create.show.json"
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

// readComment runs plan-check with --comment-file and returns the exit code,
// the output and the comment it wrote.
func planCheckWithComment(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "comment.md")
	var out, errb bytes.Buffer
	rc := cmdPlanCheck(append([]string{"--comment-file", file}, args...), &out, &errb)
	b, _ := os.ReadFile(file)
	return rc, out.String(), errb.String(), string(b)
}

// plan-check with --comment-file is the same check: the same output and exit
// code, and the comment in a file beside them.
func TestPlanCheckCommentFileKeepsTheCheck(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	want := map[string]int{"protected": 3, "standard": 4, "disposable": 0}
	for _, plan := range []string{destroyPlan, createPlan} {
		for _, tier := range []string{"protected", "standard", "disposable"} {
			var text, errb bytes.Buffer
			rcText := cmdPlanCheck([]string{"--tier", tier, "--cwd", dir, plan}, &text, &errb)
			rc, out, stderr, comment := planCheckWithComment(t, "--comment-key", "envs/prod/tfplan", "--tier", tier, "--cwd", dir, plan)
			if rc != rcText || out != text.String() || stderr != "" || errb.Len() != 0 {
				t.Errorf("%s in %s: exit %d and output with the comment differ from exit %d without:\n%s---\n%s%s", plan, tier, rc, rcText, out, text.String(), stderr)
			}
			if plan == destroyPlan && rc != want[tier] {
				t.Errorf("%s in %s exits %d, want %d", plan, tier, rc, want[tier])
			}
			verdict := map[int]string{0: "allow", 4: "ask", 3: "block"}[rc]
			if !regexp.MustCompile(`^### applygate plan check: \S+ ` + verdict + `\n\nPlan .envs/prod/tfplan. · tier \*\*` + tier).MatchString(comment) {
				t.Errorf("%s in %s: the comment does not start with the verdict %s:\n%s", plan, tier, verdict, comment)
			}
			if strings.Contains(out, "###") {
				t.Errorf("the output prints Markdown:\n%s", out)
			}
		}
	}
	var text, errb bytes.Buffer
	if rc := cmdPlanCheck([]string{"--tier", "protected", "--cwd", dir, destroyPlan}, &text, &errb); rc != 3 || text.String() != destroyProtectedText {
		t.Errorf("the text output changed (exit %d):\n%s", rc, text.String())
	}
}

// The comment flags never decide the check: a value that cannot be shown is
// left out and a file that cannot be written is a line on stderr. Without
// --comment-file they are a mistake in the command.
func TestPlanCheckCommentFlags(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, args := range [][]string{
		{"--comment-key", "k", destroyPlan},
		{"--comment-commit", "5948de7", destroyPlan},
		{"--comment-job", "ci / plan", destroyPlan},
		{"--comment-error", "x", destroyPlan},
	} {
		var out, errb bytes.Buffer
		if rc := cmdPlanCheck(args, &out, &errb); rc != 2 || out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("plan-check %v: exit %d, stdout %q, stderr %q", args, rc, out.String(), errb.String())
		}
	}
	rc, _, _, comment := planCheckWithComment(t, "--tier", "protected", "--comment-commit", "main; rm -rf /", "--comment-job", "ci / plan", destroyPlan)
	if rc != 3 || strings.Contains(comment, "judged at") || !strings.Contains(comment, "· job `ci / plan` ·") {
		t.Errorf("a commit that is not one: exit %d\n%s", rc, comment)
	}
	var out, errb bytes.Buffer
	rc = cmdPlanCheck([]string{"--tier", "protected", "--comment-file", filepath.Join(t.TempDir(), "no", "such", "dir", "c.md"), destroyPlan}, &out, &errb)
	if rc != 3 || out.String() != destroyProtectedText || !strings.Contains(errb.String(), "the pull-request comment was not written") {
		t.Errorf("a comment file that cannot be written: exit %d, stderr %q\n%s", rc, errb.String(), out.String())
	}
}

// A check that fails writes the comment too, so a comment that said allow
// for an earlier commit is replaced by one that says error.
func TestPlanCheckCommentOnError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := t.TempDir()
	notAPlan := filepath.Join(dir, "state.json")
	os.WriteFile(notAPlan, []byte(`{"format_version":"1.0","values":{}}`), 0o644)
	for name, args := range map[string][]string{
		"missing file":  {filepath.Join(dir, "nope.json")},
		"not a plan":    {notAPlan},
		"unknown tier":  {"--tier", "prod", destroyPlan},
		"comment-error": {"--comment-error", "terraform show -json failed on tfplan"},
		"no plan named": {},
	} {
		rc, out, stderr, comment := planCheckWithComment(t, append([]string{"--comment-key", "envs/prod/tfplan", "--cwd", dir}, args...)...)
		if rc != 2 || stderr == "" || out != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, rc, out, stderr)
		}
		if !strings.HasPrefix(comment, "### applygate plan check: ❌ error\n\nPlan `envs/prod/tfplan`") {
			t.Errorf("%s: no error comment for the plan:\n%s", name, comment)
		}
	}
	t.Setenv("TF_WORKSPACE", "payments")
	_, _, _, comment := planCheckWithComment(t, "--comment-key", "envs/prod/tfplan", "--tier", "standard", "--cwd", dir, createPlan)
	if !strings.Contains(comment, "workspace `payments`") {
		t.Errorf("the workspace is not in the comment:\n%s", comment)
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

// ciPlanCheck runs scripts/ci-plan-check.sh in a new directory. The variables
// GitHub Actions sets are cleared, so the tests give the same result in CI.
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
		"XDG_CONFIG_HOME="+t.TempDir(), "GITHUB_ACTIONS=", "GITHUB_STEP_SUMMARY=", "TF_WORKSPACE=", "GITHUB_WORKSPACE=",
		"GITHUB_WORKFLOW=", "GITHUB_JOB=", "COMMENT_SCOPE=", "COMMENT_KEY=", "COMMENT_COMMIT=", "COMMENT=", "COMMENT_FILE=")
	for _, kv := range env {
		switch kv {
		case "COMMENT_FILE=1":
			kv = "COMMENT_FILE=" + comment
		case "COMMENT_FILE=stale":
			// A comment an earlier step left in the file.
			os.WriteFile(comment, []byte("### applygate plan check: ✅ allow\n"), 0o644)
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
// same exit code, outputs and log, and the comment beside them.
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
		with := ciPlanCheck(t, bin, plan, "TIER="+c.tier, "FAIL_ON="+c.failOn, "COMMENT_FILE=stale", "COMMENT_COMMIT=5948de7aa11bb22cc33dd44")
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
		if !regexp.MustCompile(`^### applygate plan check: \S+ `+c.verdict+`\n`).MatchString(with.comment) || !strings.Contains(with.comment, "judged at `5948de7aa11b`") {
			t.Errorf("%s/%s: the comment does not give the verdict %s:\n%s", c.tier, c.failOn, c.verdict, with.comment)
		}
	}
}

// The comment names the plan by its path in the repository, wherever the
// runner checked the repository out, or by COMMENT_KEY; and the job that
// judged it.
func TestCIPlanCheckCommentKey(t *testing.T) {
	bin := selfBinary(t, t.TempDir())
	src, _ := os.ReadFile(createPlan)
	for _, c := range []struct{ name, workdir, plan string }{
		{"a relative directory", "envs/prod", "plan.json"},
		{"an absolute directory", "ABS/envs/prod", "plan.json"},
		{"an absolute plan", "envs/prod", "ABS/envs/prod/plan.json"},
		{"a directory written with ./ and a slash", "./envs/prod/", "plan.json"},
	} {
		ws := t.TempDir()
		os.MkdirAll(filepath.Join(ws, "envs", "prod"), 0o755)
		os.WriteFile(filepath.Join(ws, "envs", "prod", "plan.json"), src, 0o644)
		abs := func(p string) string { return strings.Replace(p, "ABS", ws, 1) }
		workdir := abs(c.workdir)
		if !filepath.IsAbs(workdir) {
			// The script runs in a directory of its own; reach the workspace from there.
			workdir = filepath.Join(ws, workdir)
			if c.workdir != "envs/prod" {
				workdir = ws + "/" + c.workdir
			}
		}
		r := ciPlanCheck(t, bin, abs(c.plan), "TIER=standard", "COMMENT_FILE=1", "GITHUB_WORKSPACE="+ws, "WORKDIR="+workdir)
		if !strings.Contains(r.comment, "\nPlan `envs/prod/plan.json` · ") || strings.Contains(r.comment, ws) {
			t.Errorf("%s: the comment does not name the plan by its path in the repository:\n%s\n%s", c.name, r.comment, r.log)
		}
	}
	plan, _ := filepath.Abs(createPlan)
	r := ciPlanCheck(t, bin, plan, "TIER=standard", "COMMENT_FILE=1", "COMMENT_KEY=prod `eu` <b>", "GITHUB_WORKFLOW=terraform", "GITHUB_JOB=plan",
		"COMMENT_SCOPE={\n  \"env\": \"prod\"\n}", "COMMENT_COMMIT=$(touch pwned)")
	if !strings.Contains(r.comment, "Plan ``prod `eu` <b>`` · ") || !strings.Contains(r.comment, "· job `terraform / plan { \"env\": \"prod\" }` ·") || strings.Contains(r.comment, "judged at") {
		t.Errorf("COMMENT_KEY, the job or the commit are not as given:\n%s", r.comment)
	}
	r = ciPlanCheck(t, bin, plan, "TIER=standard", "COMMENT_FILE=1", "GITHUB_WORKFLOW=terraform", "GITHUB_JOB=plan", "COMMENT_SCOPE=null")
	if !strings.Contains(r.comment, "· job `terraform / plan` ·") {
		t.Errorf("a job without a matrix:\n%s", r.comment)
	}
}

// Every error of the check exits 2 and replaces the comment with one that
// says error, the ones before plan-check runs included: a comment that said
// allow for an earlier commit must not stay.
func TestCIPlanCheckCommentOnError(t *testing.T) {
	bin := selfBinary(t, t.TempDir())
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	os.WriteFile(state, []byte(`{"format_version":"1.0","values":{}}`), 0o644)
	// A plan-check that is killed before it gives a verdict or a comment.
	killed := filepath.Join(dir, "killed")
	os.WriteFile(killed, []byte("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -h|--comment-error) exec '"+bin+"' \"$@\" ;; esac; done\nkill -9 $$\n"), 0o755)
	for name, c := range map[string]struct {
		r    ciRun
		says string
	}{
		"plan file not found":         {ciPlanCheck(t, bin, filepath.Join(dir, "nope.tfplan"), "COMMENT_FILE=stale"), "plan file not found"},
		"state, not a plan":           {ciPlanCheck(t, bin, state, "COMMENT_FILE=stale"), "not a plan"},
		"TRUST_CONFIG not a boolean":  {ciPlanCheck(t, bin, state, "COMMENT_FILE=stale", "TRUST_CONFIG=yes"), "TRUST_CONFIG must be true or false"},
		"FAIL_ON not one of three":    {ciPlanCheck(t, bin, state, "COMMENT_FILE=stale", "FAIL_ON=sometimes"), "FAIL_ON must be block, ask or never"},
		"PLAN not set":                {ciPlanCheck(t, bin, "", "COMMENT_FILE=stale", "COMMENT_KEY=envs/prod/tfplan"), "PLAN is required"},
		"working directory not there": {ciPlanCheck(t, bin, state, "COMMENT_FILE=stale", "WORKDIR="+filepath.Join(dir, "gone")), "working directory not found"},
		"plan-check killed":           {ciPlanCheck(t, killed, state, "COMMENT_FILE=stale"), "before it gave a verdict"},
	} {
		if c.r.code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, c.r.code, c.r.log)
		}
		if !strings.HasPrefix(c.r.comment, "### applygate plan check: ❌ error\n") || !strings.Contains(c.r.comment, c.says) {
			t.Errorf("%s: the comment does not say error and why:\n%s\n%s", name, c.r.comment, c.r.log)
		}
	}
	// The same errors without a comment: the exit code is 2 as well.
	for name, r := range map[string]ciRun{
		"PLAN not set":                ciPlanCheck(t, bin, ""),
		"working directory not there": ciPlanCheck(t, bin, state, "WORKDIR="+filepath.Join(dir, "gone")),
		"FAIL_ON not one of three":    ciPlanCheck(t, bin, state, "FAIL_ON=sometimes"),
	} {
		if r.code != 2 || r.comment != "" {
			t.Errorf("%s, no comment asked for: exit %d, comment %q\n%s", name, r.code, r.comment, r.log)
		}
	}
	if r := ciPlanCheck(t, bin, state, "COMMENT_FILE=1", "COMMENT=maybe"); r.code != 2 || r.comment != "" {
		t.Errorf("COMMENT=maybe: exit %d, comment %q", r.code, r.comment)
	}
}

// A release without --comment-file is run as it always was, once, and gives
// its verdict; there is no comment, and a line in the log says why.
func TestCIPlanCheckCommentWithAReleaseThatHasNone(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	os.WriteFile(plan, []byte("{}"), 0o644)
	old, calls := filepath.Join(dir, "old"), filepath.Join(dir, "calls")
	os.WriteFile(old, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+calls+"'\nfor a in \"$@\"; do case \"$a\" in\n  -h) echo 'Usage of plan-check:' >&2; echo '  -tier string' >&2; exit 2 ;;\n  --comment-*) echo 'flag provided but not defined: -comment-file' >&2; exit 2 ;;\nesac; done\necho 'tier protected: block (1 changes, 1 deletes, 0 replaces)'\nexit 3\n"), 0o755)
	r := ciPlanCheck(t, old, plan, "COMMENT_FILE=stale")
	if r.code != 1 || outputValue(r.outputs, "verdict") != "block" || r.comment != "" || !strings.Contains(r.log, "no pull-request comment: this applygate cannot write one") {
		t.Errorf("exit %d, verdict %q, comment %q\n%s", r.code, outputValue(r.outputs, "verdict"), r.comment, r.log)
	}
	b, _ := os.ReadFile(calls)
	if got := strings.Count(string(b), "\n"); got != 2 || strings.Contains(string(b), "--comment") {
		t.Errorf("plan-check was run %d times, or with a flag it does not have:\n%s", got-1, b)
	}
}

// commentMarker is the first line ci-pr-comment.sh gives a comment.
func commentMarker(key, workflow, job, scope, workspace string) string {
	sum := sha256.Sum256([]byte(key + "\x00" + workflow + "\n" + job + "\n" + scope + "\n" + workspace))
	return "<!-- applygate:plan-check " + hex.EncodeToString(sum[:8]) + " -->"
}

type ghComment struct {
	ID   int    `json:"id"`
	User ghUser `json:"user"`
	Body string `json:"body"`
}

type ghUser struct {
	Login string `json:"login"`
}

type prRun struct {
	code   int
	log    string
	calls  string
	posted map[string]string // "POST" or the id of a patched comment -> body
	file   string
}

// ciPRComment runs scripts/ci-pr-comment.sh against a gh that answers the
// list of comments from existing, through the script's own jq program, and
// records what is written. env overrides the defaults: pull request 12 of
// acme/infra, run 500 attempt 1 of workflow "terraform", job "plan".
func ciPRComment(t *testing.T, existing []ghComment, fileBody string, env ...string) prRun {
	t.Helper()
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	if existing == nil {
		existing = []ghComment{}
	}
	list, _ := json.Marshal(existing)
	os.WriteFile(filepath.Join(dir, "comments.json"), list, 0o644)
	fake := `#!/bin/sh
cd '` + dir + `'
printf '%s\n' "$*" >> calls
method=GET; target=""; prog=""; body=""
while [ $# -gt 0 ]; do
  case "$1" in
    --method) method=$2; shift ;;
    --jq) prog=$2; shift ;;
    -F) body=${2#body=@}; shift ;;
    repos/*) target=$1 ;;
  esac
  shift
done
if [ "$method" = GET ]; then
  [ -n "$GH_FAKE_LIST_FAILS" ] && { echo 'gh: Not Found (HTTP 404)' >&2; exit 1; }
  # A warning on a call that works, as gh prints when a newer release exists.
  echo 'A new release of gh is available: 2.0.0 -> 3.0.0' >&2
  exec jq -r "$prog" comments.json
fi
[ -n "$GH_FAKE_WRITE_FAILS" ] && { echo 'gh: Resource not accessible by integration (HTTP 403)' >&2; exit 1; }
case "$method" in
  POST) cp "$body" posted.POST ;;
  PATCH) cp "$body" "posted.${target##*/}" ;;
esac
`
	os.WriteFile(filepath.Join(bin, "gh"), []byte(fake), 0o755)
	file := filepath.Join(dir, "comment.md")
	if fileBody != "" {
		os.WriteFile(file, []byte(fileBody), 0o644)
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "ci-pr-comment.sh"))
	cmd := exec.Command("bash", script)
	cmd.Env = append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "RUNNER_TEMP=" + dir,
		"GITHUB_REPOSITORY=acme/infra", "GITHUB_SERVER_URL=https://github.com", "GH_TOKEN=t", "COMMENT_FILE=" + file,
		"PR_NUMBER=12", "PR_HEAD_REPO=acme/infra", "WORKDIR=envs/prod", "PLAN=tfplan", "CHECK_OUTCOME=success",
		"GITHUB_WORKFLOW=terraform", "GITHUB_JOB=plan", "COMMENT_SCOPE=null", "GITHUB_RUN_ID=500", "GITHUB_RUN_ATTEMPT=1"}, env...)
	b, err := cmd.CombinedOutput()
	r := prRun{log: string(b), posted: map[string]string{}, file: file}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(filepath.Join(dir, "calls"))
	r.calls = string(c)
	posted, _ := filepath.Glob(filepath.Join(dir, "posted.*"))
	for _, p := range posted {
		pb, _ := os.ReadFile(p)
		r.posted[strings.TrimPrefix(filepath.Base(p), "posted.")] = string(pb)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "applygate-*")); len(left) > 0 {
		t.Errorf("the script left temporary files: %v", left)
	}
	if r.code != 0 {
		t.Errorf("the posting step exited %d; it must never fail the job\n%s", r.code, r.log)
	}
	return r
}

const (
	blockBody = "### applygate plan check: ⛔ block\n\n- `aws_db_instance.x[\"$(touch pwned); --method DELETE\"] is destroyed`\n"
	allowBody = "### applygate plan check: ✅ allow\n\nNothing in this plan needs a review.\n"
	bot       = "github-actions[bot]"
)

var defaultMarker = commentMarker("envs/prod/tfplan", "terraform", "plan", "null", "")

// ours is a comment the Action wrote for the default plan in run, attempt.
func ours(id, run, attempt int, verdict string) ghComment {
	return ghComment{ID: id, User: ghUser{bot}, Body: fmt.Sprintf("%s\n<!-- applygate:run %d %d %s -->\n### applygate plan check: x %s\n", defaultMarker, run, attempt, verdict, verdict)}
}

func TestCIPRCommentPostsAndUpdates(t *testing.T) {
	want := defaultMarker + "\n<!-- applygate:run 500 1 block -->\n" + blockBody
	r := ciPRComment(t, nil, blockBody)
	if r.posted["POST"] != want || len(r.posted) != 1 || !strings.Contains(r.log, "posted the plan-check comment on pull request #12") {
		t.Errorf("no comment yet:\n%s\ncalls:\n%s\nposted: %q", r.log, r.calls, r.posted)
	}
	if !strings.Contains(r.calls, "repos/acme/infra/issues/12/comments?per_page=100") || !strings.Contains(r.calls, "--method POST repos/acme/infra/issues/12/comments -F body=@") {
		t.Errorf("calls:\n%s", r.calls)
	}
	if strings.Contains(r.calls, "pwned") || strings.Contains(r.calls, "DELETE") {
		t.Errorf("text from the plan is on gh's command line:\n%s", r.calls)
	}
	if _, err := os.Stat(r.file); err == nil {
		t.Errorf("the comment file is left for a later step to post again")
	}

	// A comment from an earlier run is updated in place. gh's warning on
	// stderr is not taken for a comment, and other people's comments are
	// not ours: one that copies the marker, one without it.
	others := []ghComment{
		{ID: 7, User: ghUser{"contributor"}, Body: defaultMarker + "\n<!-- applygate:run 999 1 allow -->\n### applygate plan check: ✅ allow\n"},
		{ID: 8, User: ghUser{bot}, Body: "a comment of another workflow\n" + defaultMarker},
		{ID: 9, User: ghUser{bot}, Body: commentMarker("envs/stage/tfplan", "terraform", "plan", "null", "") + "\n<!-- applygate:run 499 1 allow -->\n"},
	}
	r = ciPRComment(t, append([]ghComment{ours(4242, 499, 1, "allow")}, others...), blockBody)
	if r.posted["4242"] != want || len(r.posted) != 1 || !strings.Contains(r.log, "updated the plan-check comment") {
		t.Errorf("an earlier comment:\n%s\ncalls:\n%s\nposted: %q", r.log, r.calls, r.posted)
	}
	if strings.Contains(r.log, "new release of gh") {
		t.Errorf("gh's warning on a call that worked is in the log:\n%s", r.log)
	}
	r = ciPRComment(t, others, blockBody)
	if r.posted["POST"] != want || len(r.posted) != 1 {
		t.Errorf("only other people's comments: posted %q\n%s", r.posted, r.log)
	}
	// A re-run of the same run, and a comment whose second line was edited away.
	for name, c := range map[string]ghComment{
		"an earlier attempt": ours(4242, 500, 0, "allow"),
		"no run line":        {ID: 4242, User: ghUser{bot}, Body: defaultMarker + "\r\n### applygate plan check: ✅ allow\r\n"},
		"CRLF line ends":     {ID: 4242, User: ghUser{bot}, Body: defaultMarker + "\r\n<!-- applygate:run 499 1 allow -->\r\n### x\r\n"},
	} {
		if r := ciPRComment(t, []ghComment{c}, blockBody); r.posted["4242"] != want || len(r.posted) != 1 {
			t.Errorf("%s: posted %q\n%s", name, r.posted, r.log)
		}
	}
	// A comment that exists twice, after two runs posted at once: both are updated.
	r = ciPRComment(t, []ghComment{ours(4242, 498, 1, "allow"), ours(4300, 499, 1, "ask")}, blockBody)
	if r.posted["4242"] != want || r.posted["4300"] != want || len(r.posted) != 2 || !strings.Contains(r.log, "it exists 2 times") {
		t.Errorf("a comment that exists twice: posted %q\n%s", r.posted, r.log)
	}
}

// A run for an older commit that ends late does not put its verdict over the
// one a later run wrote.
func TestCIPRCommentLeavesALaterRunsVerdict(t *testing.T) {
	for name, c := range map[string]ghComment{
		"a later run":                  ours(4242, 501, 1, "block"),
		"a later attempt":              ours(4242, 500, 2, "block"),
		"a run id longer than 32 bits": ours(4242, 43821528253, 1, "block"),
	} {
		r := ciPRComment(t, []ghComment{c}, allowBody)
		if len(r.posted) != 0 || !strings.Contains(r.log, "was written by a later run") {
			t.Errorf("%s: posted %q\n%s", name, r.posted, r.log)
		}
	}
	// With a duplicate from an old run beside it, nothing is written either.
	r := ciPRComment(t, []ghComment{ours(4242, 501, 1, "block"), ours(4300, 400, 1, "allow")}, allowBody)
	if len(r.posted) != 0 {
		t.Errorf("a later run's comment with an old duplicate: posted %q\n%s", r.posted, r.log)
	}
	// Outside GitHub Actions there is no run to compare: the comment is updated.
	r = ciPRComment(t, []ghComment{ours(4242, 501, 1, "block")}, allowBody, "GITHUB_RUN_ID=", "GITHUB_RUN_ATTEMPT=")
	if !strings.HasPrefix(r.posted["4242"], defaultMarker+"\n<!-- applygate:run 0 0 allow -->\n") {
		t.Errorf("no run id: posted %q\n%s", r.posted, r.log)
	}
}

// Two steps of one run that write the same comment: the more severe verdict
// stays, whichever came first, and a notice names comment-key.
func TestCIPRCommentSharedByTwoSteps(t *testing.T) {
	for _, c := range []struct {
		first, second string
		body          string
		replaced      bool
	}{
		{"allow", "block", blockBody, true},
		{"block", "allow", allowBody, false},
		{"ask", "allow", allowBody, false},
		{"allow", "ask", "### applygate plan check: ⚠️ ask\n", true},
		{"block", "block", blockBody, false},
		{"error", "allow", allowBody, false},
		{"allow", "error", "### applygate plan check: ❌ error\n", true},
		{"error", "block", blockBody, true},
		{"block", "error", "### applygate plan check: ❌ error\n", false},
	} {
		r := ciPRComment(t, []ghComment{ours(4242, 500, 1, c.first)}, c.body)
		_, replaced := r.posted["4242"]
		if replaced != c.replaced || len(r.posted) > 1 || !strings.Contains(r.log, "::notice title=applygate plan check::Two steps of this workflow run write the same pull-request comment") || !strings.Contains(r.log, "comment-key") {
			t.Errorf("%s then %s: replaced %v, want %v\n%s", c.first, c.second, replaced, c.replaced, r.log)
		}
	}
}

// Which comment a run writes: one per plan, workflow, job, matrix leg and
// TF_WORKSPACE, the same from run to run and wherever the runner checked the
// repository out.
func TestCIPRCommentIdentity(t *testing.T) {
	marker := func(env ...string) string {
		t.Helper()
		r := ciPRComment(t, nil, allowBody, env...)
		m, _, _ := strings.Cut(r.posted["POST"], "\n")
		if !regexp.MustCompile(`^<!-- applygate:plan-check [0-9a-f]{16} -->$`).MatchString(m) {
			t.Fatalf("env %v: first line %q\n%s", env, m, r.log)
		}
		return m
	}
	base := marker()
	if base != defaultMarker {
		t.Errorf("the marker is %s, want %s", base, defaultMarker)
	}
	for name, env := range map[string][]string{
		"a later run":                       {"GITHUB_RUN_ID=777", "GITHUB_RUN_ATTEMPT=3"},
		"the directory written differently": {"WORKDIR=./envs/prod/"},
		"an absolute directory":             {"WORKDIR=/home/runner/work/infra/infra/envs/prod", "GITHUB_WORKSPACE=/home/runner/work/infra/infra"},
		"another runner's checkout":         {"WORKDIR=/opt/actions-runner/_work/infra/infra/envs/prod", "GITHUB_WORKSPACE=/opt/actions-runner/_work/infra/infra/"},
		"an absolute plan":                  {"PLAN=/srv/ws/envs/prod/tfplan", "WORKDIR=.", "GITHUB_WORKSPACE=/srv/ws"},
		"a fork's pull request":             {"PR_HEAD_REPO=contributor/infra"},
	} {
		if m := marker(env...); m != base {
			t.Errorf("%s gives another comment: %s", name, m)
		}
	}
	seen := map[string]string{base: "the default"}
	for name, env := range map[string][]string{
		"another plan":                    {"PLAN=other.tfplan"},
		"another directory":               {"WORKDIR=envs/stage"},
		"another workflow":                {"GITHUB_WORKFLOW=drift"},
		"another job":                     {"GITHUB_JOB=apply"},
		"another matrix leg":              {"COMMENT_SCOPE={\n  \"region\": \"eu\"\n}"},
		"a third matrix leg":              {"COMMENT_SCOPE={\n  \"region\": \"us\"\n}"},
		"another workspace":               {"TF_WORKSPACE=payments"},
		"a comment-key":                   {"COMMENT_KEY=prod"},
		"a key that is not the same path": {"COMMENT_KEY=envs/prod/tfplan2"},
	} {
		m := marker(env...)
		if other, dup := seen[m]; dup {
			t.Errorf("%s shares a comment with %s", name, other)
		}
		seen[m] = name
	}
	if m := marker("COMMENT_KEY=x --> <script>`$(id)`", "GITHUB_WORKFLOW=a\"b --> c", "COMMENT_SCOPE=\"))) or true"); m == base {
		t.Errorf("hostile names give the default comment")
	}
}

// When applygate could not be installed the plan-check step does not run. A
// comment an earlier run wrote is changed to say the plan was not judged;
// where there is none, none is made.
func TestCIPRCommentWhenThePlanCheckDidNotRun(t *testing.T) {
	r := ciPRComment(t, []ghComment{ours(4242, 499, 1, "allow")}, "", "CHECK_OUTCOME=skipped")
	got := r.posted["4242"]
	if !strings.HasPrefix(got, defaultMarker+"\n<!-- applygate:run 500 1 error -->\n### applygate plan check: ❌ error\n") || !strings.Contains(got, "was not installed or could not start") || len(r.posted) != 1 {
		t.Errorf("an earlier allow, then a failed install: posted %q\n%s", r.posted, r.log)
	}
	r = ciPRComment(t, nil, "", "CHECK_OUTCOME=skipped")
	if len(r.posted) != 0 || !strings.Contains(r.log, "there is no earlier comment to correct") {
		t.Errorf("a failed install and no comment: posted %q\n%s", r.posted, r.log)
	}
	// The step ran and wrote no comment (a release that has none): nothing is posted.
	r = ciPRComment(t, []ghComment{ours(4242, 499, 1, "allow")}, "", "CHECK_OUTCOME=failure")
	if len(r.posted) != 0 || r.calls != "" || !strings.Contains(r.log, "plan-check wrote none") {
		t.Errorf("no comment file: posted %q, calls %q\n%s", r.posted, r.calls, r.log)
	}
}

func TestCIPRCommentCannotComment(t *testing.T) {
	for _, head := range []string{"acme/infra", "contributor/infra"} {
		want := "pull-requests: write"
		if head != "acme/infra" {
			want = "comes from a fork"
		}
		for name, env := range map[string]string{"the write": "GH_FAKE_WRITE_FAILS=1", "the list": "GH_FAKE_LIST_FAILS=1"} {
			r := ciPRComment(t, nil, blockBody, "PR_HEAD_REPO="+head, env)
			if !strings.Contains(r.log, "::notice title=applygate plan check::The pull-request comment was not written") || !strings.Contains(r.log, want) || !strings.Contains(r.log, "gh said: gh: ") || len(r.posted) != 0 {
				t.Errorf("head %s, %s refused:\n%s", head, name, r.log)
			}
		}
	}
	for name, c := range map[string]struct {
		body string
		env  []string
		says string
	}{
		"not a pull request":              {blockBody, []string{"PR_NUMBER="}, "this run is not for a pull request"},
		"a file plan-check did not write": {"# hello\n", nil, "is not one plan-check wrote"},
		"a verdict that is not one":       {"### applygate plan check: ✅ maybe\n", nil, "is not one plan-check wrote"},
		"a number that is not":            {blockBody, []string{"PR_NUMBER=12/../../issues/1"}, "is not a number"},
		"a repository that is not":        {blockBody, []string{"GITHUB_REPOSITORY=acme/infra/../x"}, "is not owner/name"},
	} {
		r := ciPRComment(t, nil, c.body, c.env...)
		if !strings.Contains(r.log, c.says) || r.calls != "" {
			t.Errorf("%s: gh calls %q\n%s", name, r.calls, r.log)
		}
	}
}

// The comment names the environment the tier came from, with the config's
// pattern as the config writes it, not the runner's absolute path.
func TestPlanCheckCommentNamesTheEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".applygate.yaml"), []byte("version: 1\nenvironments:\n  - {name: prod, tier: protected, match: {paths: [\"envs/prod/**\"]}}\n"), 0o644)
	prod := filepath.Join(root, "envs", "prod")
	os.MkdirAll(prod, 0o755)
	rc, _, stderr, comment := planCheckWithComment(t, "--trust-config", "--comment-key", "envs/prod/tfplan", "--cwd", prod, destroyPlan)
	if rc != 3 || !strings.Contains(comment, "Plan `envs/prod/tfplan` · environment `prod` (`path envs/prod/**`) · tier **protected** · ") {
		t.Errorf("exit %d:\n%s%s", rc, comment, stderr)
	}
	if strings.Contains(comment, root) {
		t.Errorf("the comment shows the runner's path:\n%s", comment)
	}
}
