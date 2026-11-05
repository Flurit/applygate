package judge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGitCommandOptionInACluster(t *testing.T) {
	for _, cmd := range []string{"git rebase -qx 'pulumi destroy --yes' HEAD~2", "git difftool -yx 'x' HEAD", "git rebase --exe 'x' HEAD~1", "git grep -qO'x' y"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) != true {
			t.Errorf("%s is not judged", cmd)
		}
	}
	if Relevant(Input{Tool: "Bash", Command: "git rebase -q main", Cwd: "/repo"}) {
		t.Errorf("an ordinary rebase is judged")
	}
}

func TestOutsideTreeWritesByLocalPrograms(t *testing.T) {
	for _, cmd := range []string{
		"uniq /tmp/p ~/.claude/CLAUDE.md", "sort -o ~/AGENTS.md /tmp/p", "gofmt -w /Users/x/.zshrc", "go build -o /opt/homebrew/bin/aws ./cmd/x",
		"cargo build --target-dir /usr/local/bin", "find . -fprint /Users/x/out", "docker build --output type=local,dest=/Users/x/out .",
	} {
		if !Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%s is not judged", cmd)
		}
	}
	for _, cmd := range []string{"sort -o out.txt in.txt", "gofmt -w ./main.go", "go build -o bin/x ./cmd/x", "uniq in.txt out.txt"} {
		if Relevant(Input{Tool: "Bash", Command: cmd, Cwd: "/repo"}) {
			t.Errorf("%s is judged", cmd)
		}
	}
}

func TestWriteContentShowsADeletion(t *testing.T) {
	in := json.RawMessage(`{"file_path":"w.yml","old_string":"if: github.ref != 'refs/heads/prod'","new_string":""}`)
	if got := WriteContent(in); !strings.Contains(got, "github.ref") {
		t.Errorf("a deletion shows nothing: %q", got)
	}
	multi := json.RawMessage(`{"edits":[{"old_string":"guard: on","new_string":""}]}`)
	if got := WriteContent(multi); !strings.Contains(got, "guard: on") {
		t.Errorf("a MultiEdit deletion shows nothing: %q", got)
	}
}
