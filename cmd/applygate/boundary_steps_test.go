package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/scan"
)

func chk(level int, status, step, subject string) boundaryCheck {
	return boundaryCheck{level: level, status: status, text: "x", step: step, subject: subject}
}

// stepIDs are the ids of the steps printed, found by their titles.
func stepIDs(t *testing.T, s *scan.Steps) []string {
	t.Helper()
	if s == nil {
		return nil
	}
	var ids []string
	for _, it := range s.Items {
		found := ""
		for id, d := range stepTable {
			if d.title == it.Title {
				found = id
			}
		}
		if found == "" {
			t.Fatalf("a step with a title that is not in the table: %q", it.Title)
		}
		ids = append(ids, found)
	}
	return ids
}

func TestNextStepsForEachKindOfMachine(t *testing.T) {
	files := []boundaryCheck{
		chk(2, "not verified", stepCredentialFile, "/home/u/.aws/credentials"),
		chk(2, "not verified", stepCredentialFile, "/home/u/.kube/config"),
	}
	for _, c := range []struct {
		name    string
		r       *boundaryResult
		target  int
		want    []string
		subject map[string][]string
		note    bool
	}{
		{"L0: no managed install, a production credential that can change things, readable files",
			&boundaryResult{audited: true, reached: 0, checks: append([]boundaryCheck{
				chk(1, "not verified", stepManagedInstall, ""),
				chk(2, "FAIL", stepAWSReadOnly, "aws profile prod-admin"),
				chk(2, "ok", "", ""),
			}, files...)}, 2,
			[]string{stepManagedInstall, stepAWSReadOnly, stepCredentialFile, stepWhoApplies},
			map[string][]string{stepAWSReadOnly: {"aws profile prod-admin"}, stepCredentialFile: {"/home/u/.aws/credentials", "/home/u/.kube/config"}}, true},
		{"L1: managed, one credential fails",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{
				chk(1, "ok", "", ""),
				chk(2, "FAIL", stepKubeView, "kube context eks-blue"),
				chk(2, "FAIL", stepGCPViewer, "gcloud account a on project p"),
			}}, 2,
			[]string{stepKubeView, stepGCPViewer, stepWhoApplies}, nil, false},
		{"L1: managed, every credential harmless, files readable",
			&boundaryResult{audited: true, reached: 1, checks: append([]boundaryCheck{chk(1, "ok", "", ""), chk(2, "ok", "", "")}, files...)}, 2,
			[]string{stepCredentialFile, stepWhoApplies}, nil, false},
		{"L1 failing: the repair step, the CLI step, and no install step",
			&boundaryResult{audited: true, reached: 0, checks: []boundaryCheck{
				chk(1, "FAIL", stepManagedFix, ""), chk(1, "FAIL", stepAgentCLI, "claude"), chk(1, "FAIL", stepManagedFix, ""),
			}}, 1,
			[]string{stepManagedFix, stepAgentCLI}, map[string][]string{stepAgentCLI: {"claude"}}, false},
		{"not audited (scan without --boundary): ask the cloud, and nothing about who applies",
			&boundaryResult{audited: false, reached: 0, checks: append([]boundaryCheck{
				chk(1, "not verified", stepManagedInstall, ""), chk(2, "not verified", stepRunAudit, ""),
			}, files...)}, 2,
			[]string{stepManagedInstall, stepRunAudit, stepCredentialFile}, nil, true},
		{"a credential that cannot be checked, and one in no named environment",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{
				chk(1, "ok", "", ""),
				chk(2, "not verified", stepAWSSimulatorGrant, "aws profile a"),
				chk(2, "not verified", stepNotChecked, "aws profile b"),
				chk(2, "not verified", stepNameEnvs, "aws profile c"),
			}}, 2,
			[]string{stepAWSSimulatorGrant, stepNotChecked, stepNameEnvs, stepWhoApplies}, nil, false},
		{"nothing audited alone",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{chk(1, "ok", "", ""), chk(2, "not verified", stepNothingAudited, "")}}, 2,
			[]string{stepNothingAudited, stepWhoApplies}, nil, false},
		{"nothing audited clean, but credentials that have steps: the steps say it",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{
				chk(1, "ok", "", ""), chk(2, "not verified", stepNothingAudited, ""), chk(2, "FAIL", stepAWSReadOnly, "aws profile p"),
			}}, 2,
			[]string{stepAWSReadOnly, stepWhoApplies}, nil, false},
		{"a level asked for above L2 brings the L3 steps",
			&boundaryResult{audited: true, reached: 2, checks: []boundaryCheck{
				chk(1, "ok", "", ""), chk(2, "ok", "", ""),
				chk(3, "not verified", stepSandbox, ""), chk(3, "not verified", stepAttest, "ci_apply"), chk(3, "not verified", stepAttest, "state_guards"),
			}}, 3,
			[]string{stepSandbox, stepAttest}, map[string][]string{stepAttest: {"ci_apply", "state_guards"}}, false},
		{"L3 checks are not steps when L2 is asked for",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{
				chk(1, "ok", "", ""), chk(2, "not verified", stepCredentialFile, "/home/u/.aws/credentials"), chk(3, "not verified", stepSandbox, ""),
			}}, 2,
			[]string{stepCredentialFile, stepWhoApplies}, nil, false},
		{"a check that holds never has a step",
			&boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{
				chk(1, "ok", stepManagedInstall, ""), chk(2, "attested", stepAttest, "x"), chk(2, "not verified", stepCredentialFile, "/f"),
			}}, 2,
			[]string{stepCredentialFile, stepWhoApplies}, nil, false},
	} {
		s := nextSteps(c.r, c.target)
		got := stepIDs(t, s)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: steps %v, want %v", c.name, got, c.want)
			continue
		}
		for id, want := range c.subject {
			for _, it := range s.Items {
				if it.Title == stepTable[id].title && !slices.Equal(it.Subjects, want) {
					t.Errorf("%s: %s names %v, want %v", c.name, id, it.Subjects, want)
				}
			}
		}
		if c.note != (s.Note != "") {
			t.Errorf("%s: note %q, want one: %v", c.name, s.Note, c.note)
		}
		if s.Header != "Steps to L"+string(rune('0'+c.target)) {
			t.Errorf("%s: header %q", c.name, s.Header)
		}
	}
}

func TestNextStepsOnceTheLevelIsReached(t *testing.T) {
	l2 := &boundaryResult{audited: true, reached: 2, checks: []boundaryCheck{chk(1, "ok", "", ""), chk(2, "ok", "", "")}}
	s := nextSteps(l2, 2)
	if s == nil || len(s.Items) != 1 || !strings.Contains(s.Header, "L2 is reached") || !strings.Contains(strings.Join(s.Items[0].Lines, " "), "vouched for, not checked") {
		t.Errorf("L2 reached: %+v", s)
	}
	if ids := stepIDs(t, s); !slices.Equal(ids, []string{stepL3Pointers}) {
		t.Errorf("L2 reached: %v", ids)
	}
	l3 := &boundaryResult{audited: true, reached: 3}
	if s := nextSteps(l3, 3); s == nil || len(s.Items) != 0 || !strings.HasPrefix(s.Header, "Reached L3") {
		t.Errorf("L3 reached: %+v", s)
	}
	if s := nextSteps(l3, 2); s == nil || !strings.HasPrefix(s.Header, "Reached L3") {
		t.Errorf("L3 reached, L2 asked for: %+v", s)
	}
	l1 := &boundaryResult{audited: true, reached: 1, checks: []boundaryCheck{chk(1, "ok", "", "")}}
	if s := nextSteps(l1, 1); s != nil {
		t.Errorf("L1 asked for and reached: %+v", s)
	}
	if s := nextSteps(&boundaryResult{}, 0); s != nil {
		t.Errorf("L0 asked for: %+v", s)
	}
}

func TestStepTargetIsTheRequiredLevelOrL2(t *testing.T) {
	for in, want := range map[string]int{"": 2, "L0": 0, "l1": 1, "L2": 2, "L3": 3, "L9": 0} {
		if got := stepTarget(in); got != want {
			t.Errorf("stepTarget(%q) = %d, want %d", in, got, want)
		}
	}
}

// Every step the table names has a title and lines, and every id a check can
// carry is in the table and in the order.
func TestStepTableIsComplete(t *testing.T) {
	for id, d := range stepTable {
		if d.title == "" || len(d.lines) == 0 || d.level < 1 || d.level > 3 {
			t.Errorf("step %s is incomplete: %+v", id, d)
		}
		if id != stepL3Pointers && !slices.Contains(stepOrder, id) {
			t.Errorf("step %s is not in stepOrder, so it would never be printed", id)
		}
	}
	for _, id := range stepOrder {
		if _, ok := stepTable[id]; !ok {
			t.Errorf("stepOrder names %s, which has no entry", id)
		}
	}
	// No step claims protection the design cannot give.
	for id, d := range stepTable {
		text := strings.ToLower(d.title + " " + strings.Join(d.lines, " "))
		for _, w := range []string{"guarantee", "secure", "safe ", "safely", "protects you"} {
			if strings.Contains(text, w) {
				t.Errorf("step %s says %q", id, w)
			}
		}
	}
}

// A check that is not met names a step in the table. A new finding in the
// credential audit that prints no step fails here.
func TestEveryUnmetCheckHasAStep(t *testing.T) {
	boundaryHome(t, "version: 1\n")
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI, gcpTestPermissions = fakeCloud(t), fakeGCPPermissions(t)
	defer func() { runCLI, gcpTestPermissions = old, oldHTTP }()
	cfg := credsConfig()
	n := 0
	for _, f := range auditAll(cfg) {
		if f.level == "ok" {
			if f.step != "" || f.subject != "" {
				t.Errorf("an ok finding carries a step: %+v", f)
			}
			continue
		}
		n++
		if _, ok := stepTable[f.step]; !ok {
			t.Errorf("finding %q has no step (%q)", f.text, f.step)
		}
		if f.level == "FAIL" && f.subject == "" {
			t.Errorf("a failing finding does not name its credential: %q", f.text)
		}
	}
	if n < 8 {
		t.Fatalf("only %d unmet findings from the stubs; the test does not cover the audit", n)
	}
	// And through the whole report, audited and not.
	for _, audit := range []bool{true, false} {
		r := evalBoundaryWith(cfg, audit)
		for _, c := range r.checks {
			if c.level == 0 || c.status == "ok" || c.status == "attested" {
				continue
			}
			if _, ok := stepTable[c.step]; !ok {
				t.Errorf("audit %v: L%d check %q (%s) has no step (%q)", audit, c.level, c.text, c.status, c.step)
			}
		}
	}
}

func TestAssumedRoleErrorsPickTheirStep(t *testing.T) {
	if stepForRoleErr(errString("iam get-role Admin failed (AccessDenied)")) != stepAWSSimulatorGrant {
		t.Error("a refused iam:GetRole is closed by a grant")
	}
	if stepForRoleErr(errString("an identity ARN applygate cannot read (x)")) != stepNotChecked {
		t.Error("another failure is closed by whatever the line names")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestDoctorBoundaryPrintsTheStepsToL2(t *testing.T) {
	boundaryHome(t, "version: 1\n")
	var out, errb bytes.Buffer
	if rc := cmdDoctorBoundary(nil, &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	got := out.String()
	i := strings.Index(got, "Steps to L2")
	if i < 0 {
		t.Fatalf("no steps:\n%s", got)
	}
	steps := got[i:]
	for _, want := range []string{
		"L1  Install a managed, exclusive copy of applygate",
		"/usr/bin/sudo /path/to/verified/applygate install --managed --exclusive",
		"L2  Make the aws CLI available to this command",
		"L2  Decide who applies production changes",
		"A person runs these; an agent should not.",
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("missing %q in:\n%s", want, steps)
		}
	}
	if strings.Index(got, "Assurance level reached: L0") > i {
		t.Errorf("the steps come before the level:\n%s", got)
	}
	for _, w := range []string{"guarantee", "secure", "safe ", "protected"} {
		if strings.Contains(strings.ToLower(steps), w) {
			t.Errorf("the steps say %q:\n%s", w, steps)
		}
	}
}

func TestDoctorBoundaryStepsFollowTheRequiredLevel(t *testing.T) {
	boundaryHome(t, "version: 1\nboundary:\n  require: L3\n")
	var out, errb bytes.Buffer
	if rc := cmdDoctorBoundary(nil, &out, &errb); rc != 1 {
		t.Fatalf("rc %d, want 1 (the exit code is the level's, not the steps')", rc)
	}
	got := out.String()
	for _, want := range []string{"Steps to L3", "L3  Turn on the host sandbox in managed settings", "L3  Attest what only you can vouch for: ci_apply, state_guards"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Index(got, "Steps to L3") > strings.Index(got, "Required level L3 not reached") {
		t.Errorf("the steps should come before the required-level line:\n%s", got)
	}

	// L1 asked for: no credential steps.
	boundaryHome(t, "version: 1\nboundary:\n  require: L1\n")
	out.Reset()
	cmdDoctorBoundary(nil, &out, &errb)
	if s := out.String(); !strings.Contains(s, "Steps to L1") || strings.Contains(s, "who applies") || strings.Contains(s, "agent holds no credential") {
		t.Errorf("require L1:\n%s", s)
	}

	// Nothing to say about L0.
	boundaryHome(t, "version: 1\nboundary:\n  require: L0\n")
	out.Reset()
	cmdDoctorBoundary(nil, &out, &errb)
	if strings.Contains(out.String(), "Steps to") {
		t.Errorf("require L0 printed steps:\n%s", out.String())
	}
}

func TestDoctorBoundaryNamesTheReadableCredentialFiles(t *testing.T) {
	boundaryHome(t, "version: 1\n")
	home, _ := os.UserHomeDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	cmdDoctorBoundary(nil, &out, &errb)
	got := out.String()
	if !strings.Contains(got, "Keep your own sessions out of the agent's reach: ~/.kube/config") || !strings.Contains(got, "so L2 is not reached") {
		t.Errorf("the readable file is not named in the steps:\n%s", got)
	}
}
