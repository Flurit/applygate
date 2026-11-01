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
