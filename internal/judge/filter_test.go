package judge

import "testing"

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
		{Input{Tool: "Write", Paths: []string{"/repo/src/app.ts"}}, false},
		{Input{Tool: "Write", Paths: []string{"docs/runbook.md"}}, false},
		{Input{Tool: "Write", Paths: []string{".github/workflows/cleanup.yml"}}, true},
		{Input{Tool: "Edit", Paths: []string{"deploy/values-prod.yaml"}}, true},
		{Input{Tool: "Write", Paths: []string{"AGENTS.md"}}, true},
		{Input{Tool: "mcp__x__y"}, true},
	}
	for _, c := range cases {
		if got := Relevant(c.in); got != c.want {
			t.Errorf("Relevant(%s %q %v) = %v, want %v", c.in.Tool, c.in.Command, c.in.Paths, got, c.want)
		}
	}
}
