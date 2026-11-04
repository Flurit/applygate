package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
)

// fakeCloud answers the CLI calls doctor --creds makes, by profile and
// context.
func fakeCloud(t *testing.T) func(ctx context.Context, bin string, args ...string) ([]byte, error) {
	t.Helper()
	return func(_ context.Context, bin string, args ...string) ([]byte, error) {
		a := strings.Join(args, " ")
		profile := ""
		if i := strings.Index(a, "--profile "); i >= 0 {
			profile = strings.Fields(a[i+len("--profile "):])[0]
		}
		switch {
		case strings.HasPrefix(a, "configure list-profiles"):
			return []byte("prod-readonly\nprod-admin\nsandbox\nbroken\nmystery\n"), nil
		case strings.HasPrefix(a, "sts get-caller-identity"):
			switch profile {
			case "prod-readonly":
				return []byte(`{"Account":"111111111111","Arn":"arn:aws:sts::111111111111:assumed-role/ReadOnly/s"}`), nil
			case "prod-admin":
				return []byte(`{"Account":"111111111111","Arn":"arn:aws:iam::111111111111:user/admin"}`), nil
			case "sandbox":
				return []byte(`{"Account":"222222222222","Arn":"arn:aws:iam::222222222222:root"}`), nil
			case "mystery":
				return []byte(`{"Account":"333333333333","Arn":"arn:aws:iam::333333333333:user/ci"}`), nil
			}
			return nil, errors.New("The SSO session associated with this profile has expired")
		case strings.HasPrefix(a, "iam get-role --role-name ReadOnly"):
			return []byte(`{"Role":{"Arn":"arn:aws:iam::111111111111:role/team/ReadOnly"}}`), nil
		case strings.HasPrefix(a, "iam simulate-principal-policy"):
			if !strings.Contains(a, "aws:MultiFactorAuthPresent,ContextKeyValues=false") {
				t.Errorf("simulated without MFA absent: %s", a)
			}
			switch {
			case strings.Contains(a, "role/team/ReadOnly"):
				return []byte(`{"EvaluationResults":[{"EvalActionName":"ec2:TerminateInstances","EvalDecision":"implicitDeny"},{"EvalActionName":"s3:DeleteBucket","EvalDecision":"explicitDeny"}]}`), nil
			case strings.Contains(a, "user/admin"), strings.Contains(a, "user/ci"):
				return []byte(`{"EvaluationResults":[{"EvalActionName":"ec2:TerminateInstances","EvalDecision":"allowed"},{"EvalActionName":"s3:DeleteBucket","EvalDecision":"implicitDeny"}]}`), nil
			}
		case strings.HasPrefix(a, "config get-contexts"):
			return []byte("eks-blue\nkind-dev\n"), nil
		case strings.HasPrefix(a, "auth can-i"):
			if strings.Contains(a, "--context eks-blue") && strings.Contains(a, "delete namespaces") {
				return []byte("yes\n"), nil
			}
			return []byte("no\n"), errors.New("exit status 1")
		}
		t.Errorf("unexpected call: %s %s", bin, a)
		return nil, errors.New("unexpected")
	}
}

func credsConfig() *config.Config {
	cfg := config.Default()
	cfg.PlanGate.Engines = map[string]string{"aws": "/bin/true", "kubectl": "/bin/true"}
	cfg.Environments = []config.Environment{
		{Name: "prod", Tier: config.Protected, Match: config.Match{AWSAccounts: []string{"111111111111"}, KubeContexts: []string{"eks-blue"}}},
		{Name: "sandbox", Tier: config.Disposable, Match: config.Match{AWSProfiles: []string{"sandbox"}, KubeContexts: []string{"kind-*"}}},
	}
	return cfg
}

func TestDoctorCreds(t *testing.T) {
	old := runCLI
	runCLI = fakeCloud(t)
	defer func() { runCLI = old }()
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	cfg := credsConfig()
	got := map[string]credsFinding{}
	for _, f := range append(auditAWS(cfg), auditKube(cfg)...) {
		got[strings.SplitN(f.text, ":", 2)[0]] = f
	}
	want := map[string]string{
		"aws profile prod-readonly": "ok",   // read-only role in production
		"aws profile prod-admin":    "FAIL", // can terminate instances in production without MFA
		"aws profile sandbox":       "ok",   // root, but a disposable account
		"aws profile broken":        "WARN", // cannot be checked
		"aws profile mystery":       "WARN", // can destroy, and no environment says where
		"kube context eks-blue (environment prod, tier protected)":     "FAIL",
		"kube context kind-dev (environment sandbox, tier disposable)": "ok",
	}
	for k, lvl := range want {
		f, ok := got[k]
		if !ok {
			t.Errorf("no finding for %s; got %v", k, got)
			continue
		}
		if f.level != lvl {
			t.Errorf("%s: %s, want %s (%s)", k, f.level, lvl, f.text)
		}
	}
	if f := got["aws profile prod-admin"]; !strings.Contains(f.text, "ec2:TerminateInstances") || strings.Contains(f.text, "s3:DeleteBucket") {
		t.Errorf("prod-admin: %s", f.text)
	}
}

func TestDoctorCredsExit(t *testing.T) {
	old := runCLI
	runCLI = fakeCloud(t)
	defer func() { runCLI = old }()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	var out, errb bytes.Buffer
	// No config: the name hint makes prod-admin production, and it can
	// terminate instances without MFA, so the audit fails.
	code := cmdDoctorCreds(&out, &errb)
	if code != 1 || !strings.Contains(out.String(), "FAIL aws profile prod-admin") {
		t.Errorf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "gcloud and az are not audited") {
		t.Errorf("output: %s", out.String())
	}
}
