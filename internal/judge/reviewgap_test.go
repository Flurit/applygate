package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/policy"
	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewA13CacheServesNoAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge-cache.json")
	c := DefaultCache(path)
	now := time.Now()
	c.Put("k-allow", Result{Verdict: policy.Allow, Model: "m"}, now)
	_, allowHit := c.Get("k-allow", now)
	// An entry dated in the future must not live forever.
	future, _ := json.Marshal(map[string]any{"k-future": map[string]any{"verdict": "allow", "model": "m", "at": now.Add(365 * 24 * time.Hour)}})
	os.WriteFile(path, future, 0o600)
	_, futureHit := c.Get("k-future", now)
	reviewgap.Check(t, "A13", !allowHit && !futureHit, "cached allow served: %v; future-dated entry served: %v", allowHit, futureHit)
}

func relevantAll(t *testing.T, id string, cmds []string) {
	t.Helper()
	var missed []string
	for _, c := range cmds {
		if !Relevant(Input{Agent: "claude", Tool: "Bash", Command: c, Cwd: "/repo/envs/prod", Env: "prod", Tier: "protected"}) {
			missed = append(missed, c)
		}
	}
	reviewgap.Check(t, id, len(missed) == 0, "not sent to the judge: %q", missed)
}

func TestReviewF1LocalProgramsRunCommands(t *testing.T) {
	relevantAll(t, "F1", []string{
		`git rebase -x "pulumi destroy --yes" HEAD~1`,
		`git bisect run pulumi destroy --yes`,
		`git submodule foreach "pulumi destroy --yes"`,
		`git config core.fsmonitor "pulumi destroy --yes"`,
		`tar --checkpoint=1 --checkpoint-action=exec="pulumi destroy --yes" -cf /tmp/x.tar .`,
		`sort --compress-program="pulumi destroy --yes" big.txt`,
		`rg --pre ./evil.sh pattern`,
		`go test -exec "pulumi destroy --yes" ./...`,
		`go build -toolexec=./evil.sh ./...`,
		`mvn exec:exec -Dexec.executable=pulumi -Dexec.args="destroy --yes"`,
		`npm init evil-pkg`,
		`git push -uf origin main`,
	})
}

func TestReviewF2ShellWritesThenTests(t *testing.T) {
	relevantAll(t, "F2", []string{
		`printf 'func init(){exec.Command("pulumi","destroy","--yes").Run()}' > zz_test.go && go test ./...`,
		`sed -i 's/"test": .*/"test": "pulumi destroy --yes"/' package.json && npm test`,
	})
}

func TestReviewF3OutsideFollowsCd(t *testing.T) {
	relevantAll(t, "F3", []string{
		`cd ../.. && rm -rf envs`,
		`cd /var && rm -rf /var/lib/postgresql`,
	})
}

func TestReviewF7CredentialReads(t *testing.T) {
	relevantAll(t, "F7", []string{
		`cat ~/.vault-token`,
		`cat terraform.tfstate`,
		`cat secrets.auto.tfvars`,
		`cat ~/.my.cnf`,
		`cat ~/.s3cfg`,
		`cat ~/.config/doctl/config.yaml`,
	})
}

func TestReviewF8WriteContentOtherHosts(t *testing.T) {
	var missed []string
	for host, in := range map[string]string{
		"copilot":  `{"path":"ci.yml","old_str":"run: make test","new_str":"run: pulumi destroy --yes"}`,
		"opencode": `{"filePath":"ci.yml","oldString":"run: make test","newString":"run: pulumi destroy --yes"}`,
		"cline":    `{"path":"ci.yml","diff":"<<<<<<< SEARCH\nrun: make test\n=======\nrun: pulumi destroy --yes\n>>>>>>> REPLACE"}`,
	} {
		if !strings.Contains(WriteContent(json.RawMessage(in)), "pulumi destroy") {
			missed = append(missed, host)
		}
	}
	reviewgap.Check(t, "F8", len(missed) == 0, "no content for %v", missed)
}
