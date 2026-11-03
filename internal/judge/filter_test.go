package judge

import (
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

func TestRelevant(t *testing.T) {
	cases := []struct {
		in   Input
		want bool
	}{
		{Input{Tool: "Bash", Command: "go test ./... && npm run build", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "rm -rf node_modules dist", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "git status && git log --oneline -5 | head", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "git push origin feat/x", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "pytest -k 'destroy or purge' -q", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "echo hi > /dev/null", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "git push --force origin main", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "echo ZHJvcGRi | base64 -d | sh", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "just db-restore prod ./dumps/x.sql", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "rm -rf /var/lib/postgresql/16/main", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "find . -name '*.log' -delete", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cat x > ~/.aws/credentials", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "npm run db:reset", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: `python3 -c "print(1)"`, Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "go run ./cmd/migrate down", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "./bin/cleanup --env prod", Cwd: "/repo"}, true},
		{Input{Tool: "Write", Paths: []string{"/repo/src/app.ts"}}, true},
		{Input{Tool: "Read", Paths: []string{"/repo/src/app.ts"}}, false},
		{Input{Tool: "Write", Paths: []string{".github/workflows/cleanup.yml"}}, true},
		{Input{Tool: "Edit", Paths: []string{"deploy/values-prod.yaml"}}, true},
		{Input{Tool: "Write", Paths: []string{"AGENTS.md"}}, true},
		{Input{Tool: "mcp__x__y"}, true},
		{Input{Tool: "Bash", Command: "env | grep -i token", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cat .env", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cat ~/.config/gcloud/application_default_credentials.json", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "grep -r password /etc", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "cat ~/.codex/plugins/cache/x/SKILL.md", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "ls -la ~/.kube", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cp build.zip /srv/www/", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cat < ~/.netrc", Cwd: "/repo"}, true},
		{Input{Tool: "Bash", Command: "cat src/main.go | grep -n token", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "echo deploying to /srv/app", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "head -50 /repo/README.md", Cwd: "/repo"}, false},
		{Input{Tool: "Bash", Command: "env GOOS=linux go build ./...", Cwd: "/repo"}, false},
	}
	for _, c := range cases {
		if got := Relevant(c.in); got != c.want {
			t.Errorf("Relevant(%s %q %v) = %v, want %v", c.in.Tool, c.in.Command, c.in.Paths, got, c.want)
		}
	}
}

// The two guards that keep the judge escalate-only, each on its own: Merge
// never lowers a verdict, and Residual sends only calls the rules allowed
// without recognizing anything.
func TestMergeNeverLowers(t *testing.T) {
	for _, rule := range []policy.Verdict{policy.Allow, policy.Ask, policy.Block} {
		for _, j := range []policy.Verdict{policy.Allow, policy.Ask, policy.Block, ""} {
			got := Merge(rule, Result{Verdict: j})
			if got != policy.Max(rule, j) && !(j == "" && got == rule) {
				t.Errorf("Merge(%s, %q) = %s", rule, j, got)
			}
		}
		if got := Merge(rule, Result{Verdict: policy.Allow, Err: "x"}); got != rule {
			t.Errorf("error changed %s to %s", rule, got)
		}
	}
}

func TestResidual(t *testing.T) {
	cases := []struct {
		d    policy.Decision
		want bool
	}{
		{policy.Decision{Verdict: policy.Allow}, true},
		{policy.Decision{Verdict: policy.Allow, Actions: []policy.ActionResult{{Engine: "terraform", Verdict: policy.Allow}}}, false},
		{policy.Decision{Verdict: policy.Ask}, false},
		{policy.Decision{Verdict: policy.Block}, false},
	}
	for _, c := range cases {
		if got := Residual(c.d); got != c.want {
			t.Errorf("Residual(%+v) = %v", c.d, got)
		}
	}
}

// Programs started through the environment or options, path traversal out
// of /tmp, and paths attached to options go to the judge (findings 2M9,
// 2M10); redaction that hides programs is caught (2M8).
func TestRelevantRound2(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"go env --w GOFLAGS=-toolexec=/tmp/x", true},
		{"CC=/tmp/evil go build ./...", true},
		{"RUSTC_WRAPPER=/tmp/w cargo build", true},
		{"cargo --config 'target.x86_64-unknown-linux-gnu.runner=\"sh\"' test", true},
		{"npm test --script-shell /tmp/x", true},
		{"PYTHONPATH=/tmp/m python3 -m pytest", true},
		{"NODE_OPTIONS=--require=/tmp/x.js npm test", true},
		{"sed 's/x/rm -rf ~/e' f.txt", true},
		{"sed -n '1e rm -rf ~' f.txt", true},
		{"sed -n 1,5p f.txt", false},
		{"sed 's/web/www/g' f.txt", false},
		{"rm -rf /tmp/../Users/me/work", true},
		{"rm -rf /tmp/build", false},
		{"cp --target-directory=/etc/x a", true},
		{"go test ./...", false},
	} {
		if got := Relevant(Input{Tool: "Bash", Command: c.cmd, Cwd: "/repo"}); got != c.want {
			t.Errorf("%s: relevant %v, want %v", c.cmd, got, c.want)
		}
	}
	if !HiddenByRedaction("API_TOKEN=`{pulumi,destroy,--yes}` true", "API_TOKEN=[REDACTED] true", "/repo") {
		t.Error("redaction that hides pulumi destroy was not caught")
	}
	if HiddenByRedaction("curl -H 'Authorization: Bearer abc' x", "curl -H 'Authorization: Bearer [REDACTED] x", "/repo") {
		t.Error("a redacted header counted as hiding programs")
	}
}
