package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The files in examples/boundary are what the steps of the boundary report
// point to. These tests read them as a reviewer would: they fail when an
// example grants something the audit counts as destructive, or loses the
// condition that makes it an example of the boundary. They do not show that
// a provider accepts or enforces a file: that is in the table in
// docs/limits.md, from runs against the real service.

const examplesDir = "../../examples/boundary"

func exampleBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type iamPolicy struct {
	Version   string
	Statement []struct {
		Sid       string
		Effect    string
		Principal map[string]any
		Action    any
		NotAction any
		Resource  any
		Condition map[string]map[string]any
	}
}

func iamExample(t *testing.T, name string) iamPolicy {
	t.Helper()
	var p iamPolicy
	dec := json.NewDecoder(strings.NewReader(string(exampleBytes(t, name))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if p.Version != "2012-10-17" || len(p.Statement) == 0 {
		t.Fatalf("%s: not an IAM policy document: %+v", name, p)
	}
	return p
}

func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func TestAWSReadOnlyExampleAllowsNothingTheAuditCountsAsDestructive(t *testing.T) {
	p := iamExample(t, "aws-agent-readonly.json")
	for _, s := range p.Statement {
		if s.Effect != "Allow" || s.NotAction != nil || s.Principal != nil {
			t.Errorf("statement %q: want a plain Allow on actions: %+v", s.Sid, s)
		}
		actions := strs(s.Action)
		if len(actions) == 0 {
			t.Errorf("statement %q has no Action", s.Sid)
		}
		for _, a := range actions {
			if strings.ContainsAny(a, "?") || a == "*" {
				t.Errorf("statement %q: action %q is too wide to review by eye", s.Sid, a)
			}
			for _, d := range destructiveActions {
				if azActionCovers(a, d) {
					t.Errorf("statement %q: action %q allows %s, which the audit counts as destructive", s.Sid, a, d)
				}
			}
		}
		for _, r := range strs(s.Resource) {
			if r == "*" {
				t.Errorf("statement %q: Resource * (name the bucket or the role)", s.Sid)
			}
		}
	}
}

func TestAWSReadOnlyExampleLetsTheAuditSimulateItsOwnRole(t *testing.T) {
	// The audit asks the simulator as the identity it audits, so the role
	// needs iam:SimulatePrincipalPolicy and iam:GetRole on itself and nothing
	// wider (docs/credentials.md, "When AWS refuses the simulator call").
	p := iamExample(t, "aws-agent-readonly.json")
	for _, s := range p.Statement {
		got := strs(s.Action)
		if len(got) == 2 && got[0] == "iam:SimulatePrincipalPolicy" && got[1] == "iam:GetRole" {
			r := strs(s.Resource)
			if len(r) != 1 || !strings.HasSuffix(r[0], ":role/AgentReadOnly") {
				t.Errorf("the audit grant must name the role's own ARN: %v", r)
			}
			return
		}
	}
	t.Error("no statement lets the role simulate and read itself")
}

func TestMFATrustExampleNamesOnePersonAndRequiresRecentMFA(t *testing.T) {
	p := iamExample(t, "aws-apply-mfa-trust.json")
	if len(p.Statement) != 1 {
		t.Fatalf("want one statement, have %d", len(p.Statement))
	}
	s := p.Statement[0]
	who := strs(s.Principal["AWS"])
	if len(who) != 1 || strings.HasSuffix(who[0], ":root") || strings.Contains(who[0], "*") || !strings.Contains(who[0], ":user/") {
		t.Errorf("the trusted principal must be one named user, not an account root or a wildcard: %v", who)
	}
	if got := strs(s.Action); len(got) != 1 || got[0] != "sts:AssumeRole" {
		t.Errorf("action: %v", got)
	}
	if strs(s.Condition["Bool"]["aws:MultiFactorAuthPresent"])[0] != "true" {
		t.Error("the trust policy must require aws:MultiFactorAuthPresent")
	}
	if len(strs(s.Condition["NumericLessThan"]["aws:MultiFactorAuthAge"])) != 1 {
		t.Error("the trust policy must bound aws:MultiFactorAuthAge")
	}
}

func TestOIDCTrustExamplePinsTheRepositoryAndTheEnvironment(t *testing.T) {
	p := iamExample(t, "aws-apply-oidc-trust.json")
	if len(p.Statement) != 1 {
		t.Fatalf("want one statement, have %d", len(p.Statement))
	}
	s := p.Statement[0]
	if got := strs(s.Action); len(got) != 1 || got[0] != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("action: %v", got)
	}
	if f := strs(s.Principal["Federated"]); len(f) != 1 || !strings.HasSuffix(f[0], ":oidc-provider/token.actions.githubusercontent.com") {
		t.Errorf("the federated principal is GitHub's OIDC provider: %v", f)
	}
	eq := s.Condition["StringEquals"]
	if aud := strs(eq["token.actions.githubusercontent.com:aud"]); len(aud) != 1 || aud[0] != "sts.amazonaws.com" {
		t.Errorf("aud: %v", aud)
	}
	sub := strs(eq["token.actions.githubusercontent.com:sub"])
	if len(sub) != 1 || strings.Contains(sub[0], "*") || !strings.HasPrefix(sub[0], "repo:") || !strings.HasSuffix(sub[0], ":environment:production") {
		t.Errorf("sub must name one repository and the production environment, with no wildcard: %v", sub)
	}
	for k := range s.Condition {
		if strings.HasPrefix(k, "StringLike") || strings.HasPrefix(k, "ForAnyValue") {
			t.Errorf("condition operator %s can widen the pin", k)
		}
	}
}

func TestKubernetesExampleBindsOnlyTheViewRole(t *testing.T) {
	var b struct {
		Kind     string                                `yaml:"kind"`
		RoleRef  struct{ Kind, Name, APIGroup string } `yaml:"roleRef"`
		Subjects []struct{ Kind, Name string }         `yaml:"subjects"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(exampleBytes(t, "k8s-agent-view.yaml"))))
	if err := dec.Decode(&b); err != nil {
		t.Fatal(err)
	}
	if b.Kind != "ClusterRoleBinding" || b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != "view" {
		t.Errorf("want a ClusterRoleBinding to the view ClusterRole: %+v", b)
	}
	if len(b.Subjects) != 1 || b.Subjects[0].Name == "" {
		t.Errorf("want one subject: %+v", b.Subjects)
	}
	var extra map[string]any
	if dec.Decode(&extra) == nil {
		t.Error("the file holds more than one document")
	}
}

// script returns the commands of a shell example: lines that are neither
// comments nor blank.
func script(t *testing.T, name string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(string(exampleBytes(t, name)), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestScriptExamplesParseAndChangeNothingByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	for _, name := range []string{"gcp-agent-viewer.sh", "azure-agent-reader.sh"} {
		path := filepath.Join(examplesDir, name)
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		// Unset values stop it before anything runs.
		cmd := exec.Command("sh", path)
		cmd.Env = []string{"PATH=" + t.TempDir()} // no gcloud, no az: a run would fail, not print
		out, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(out), "would run") {
			t.Errorf("%s ran with its values unset: %v\n%s", name, err, out)
		}
		// With values set and no APPLY, it prints and runs nothing.
		cmd = exec.Command("sh", path)
		cmd.Env = []string{"PATH=" + t.TempDir(), "PROJECT=p", "AGENT_SA=a@p.iam.gserviceaccount.com", "APPLY_SA=b@p.iam.gserviceaccount.com",
			"PERSON=x@example.com", "STATE_BUCKET=b", "SUBSCRIPTION_ID=s", "AGENT=i"}
		out, err = cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "would run: ") {
			t.Errorf("%s without APPLY: want a dry run, got %v\n%s", name, err, out)
		}
	}
}

func TestGCPExampleGivesTheAgentOnlyReadRoles(t *testing.T) {
	for _, l := range script(t, "gcp-agent-viewer.sh") {
		if !strings.Contains(l, "--role=") {
			continue
		}
		agent := strings.Contains(l, "$AGENT_SA")
		role := l[strings.Index(l, "--role=")+len("--role="):]
		role = strings.Fields(role)[0]
		if agent && role != "roles/viewer" && role != "roles/storage.objectViewer" {
			t.Errorf("the agent's account must get only viewer roles: %s", l)
		}
		for _, bad := range []string{"serviceAccountTokenCreator", "serviceAccountUser", "owner", "editor", "admin"} {
			if agent && strings.Contains(strings.ToLower(role), strings.ToLower(bad)) {
				t.Errorf("the agent gets a role the audit counts as destructive or as acting as another account: %s", l)
			}
		}
		if strings.Contains(role, "serviceAccountTokenCreator") && !strings.Contains(l, `--member="user:$PERSON"`) {
			t.Errorf("only the person may impersonate the apply account: %s", l)
		}
	}
}

func TestAzureExampleGivesTheAgentOnlyReader(t *testing.T) {
	n := 0
	for _, l := range script(t, "azure-agent-reader.sh") {
		if !strings.Contains(l, "az role assignment create") {
			continue
		}
		n++
		if !strings.Contains(l, "--role Reader ") || !strings.Contains(l, `--assignee "$AGENT"`) {
			t.Errorf("want Reader for the agent: %s", l)
		}
		if !azReadOnlyRoles["reader"] {
			t.Error("the audit no longer counts Reader as read-only")
		}
	}
	if n != 1 {
		t.Errorf("want one role assignment, have %d", n)
	}
}

func TestEveryExampleIsInTheStatusTableAndTheReadme(t *testing.T) {
	limits, err := os.ReadFile("../../docs/limits.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(exampleBytes(t, "README.md"))
	entries, err := os.ReadDir(examplesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "README.md" {
			continue
		}
		if !strings.Contains(string(limits), "examples/boundary/"+e.Name()) {
			t.Errorf("docs/limits.md has no status row for %s", e.Name())
		}
		if !strings.Contains(readme, "]("+e.Name()+")") {
			t.Errorf("examples/boundary/README.md does not list %s", e.Name())
		}
	}
}
