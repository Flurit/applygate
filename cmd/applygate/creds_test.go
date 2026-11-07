package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
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
		switch filepath.Base(bin) {
		case "gcloud":
			return fakeGCloud(t, a)
		case "az":
			return fakeAz(t, a)
		}
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

// fakeGCloud answers gcloud: four credentialed accounts, the active one an
// admin on the production project.
func fakeGCloud(t *testing.T, a string) ([]byte, error) {
	t.Helper()
	switch a {
	case "auth list --format=json":
		return []byte(`[{"account":"admin@acme.com","status":"ACTIVE"},{"account":"viewer@acme.com","status":""},{"account":"expired@acme.com","status":""},{"account":"ci@acme.com","status":""}]`), nil
	case "config list --format=json":
		return []byte(`{"core":{"account":"admin@acme.com","project":"acme-prod"}}`), nil
	case "config configurations list --format=json":
		return []byte(`[{"name":"default","is_active":true,"properties":{"core":{"account":"admin@acme.com","project":"acme-prod"}}},
{"name":"viewer","properties":{"core":{"account":"viewer@acme.com","project":"acme-prod"}}},
{"name":"old","properties":{"core":{"account":"expired@acme.com","project":"acme-prod"}}},
{"name":"ci","properties":{"core":{"account":"ci@acme.com","project":"zeta-42"}}},
{"name":"gone","properties":{"core":{"account":"nobody@acme.com","project":"acme-prod"}}}]`), nil
	case "auth print-access-token --account=admin@acme.com":
		return []byte("ya29.ADMIN-SECRET\n"), nil
	case "auth print-access-token --account=viewer@acme.com":
		return []byte("ya29.VIEWER-SECRET\n"), nil
	case "auth print-access-token --account=ci@acme.com":
		return []byte("ya29.CI-SECRET\n"), nil
	case "auth print-access-token --account=expired@acme.com":
		return nil, errors.New("ERROR: (gcloud.auth.print-access-token) Reauthentication failed")
	}
	t.Errorf("unexpected gcloud call: %s", a)
	return nil, errors.New("unexpected")
}

// fakeGCPPermissions answers testIamPermissions by token.
func fakeGCPPermissions(t *testing.T) func(ctx context.Context, token, project string, perms []string) ([]string, error) {
	return func(_ context.Context, token, project string, perms []string) ([]string, error) {
		if len(perms) != len(gcpDestructivePermissions) {
			t.Errorf("asked about %d permissions", len(perms))
		}
		switch token {
		case "ya29.ADMIN-SECRET":
			return []string{"compute.instances.delete", "iam.serviceAccounts.actAs"}, nil
		case "ya29.VIEWER-SECRET":
			return nil, nil
		case "ya29.CI-SECRET":
			if project != "zeta-42" {
				t.Errorf("ci checked on %s", project)
			}
			return []string{"storage.buckets.delete"}, nil
		}
		t.Errorf("unexpected token for %s", project)
		return nil, errors.New("unexpected")
	}
}

// fakeAz answers az: Owner on production, Reader elsewhere, a custom role
// that deletes VMs, and a subscription whose assignments cannot be listed.
func fakeAz(t *testing.T, a string) ([]byte, error) {
	t.Helper()
	sub := ""
	if i := strings.Index(a, "--subscription "); i >= 0 {
		sub = strings.Fields(a[i+len("--subscription "):])[0]
	}
	switch {
	case a == "account list --all --output json":
		return []byte(`[{"id":"sub-read","name":"Acme Readers","isDefault":false,"user":{"name":"me@acme.com","type":"user"}},
{"id":"sub-prod","name":"Acme Prod","isDefault":true,"user":{"name":"me@acme.com","type":"user"}},
{"id":"sub-custom","name":"Acme Custom","isDefault":false,"user":{"name":"11111111-aaaa","type":"servicePrincipal"}},
{"id":"sub-err","name":"Acme Broken","isDefault":false,"user":{"name":"me@acme.com","type":"user"}}]`), nil
	case strings.HasPrefix(a, "role assignment list"):
		for _, f := range []string{"--all", "--include-inherited", "--include-groups"} {
			if !strings.Contains(a, f) {
				t.Errorf("role assignment list without %s: %s", f, a)
			}
		}
		switch sub {
		case "sub-prod":
			return []byte(`[{"roleDefinitionName":"Reader","scope":"/subscriptions/sub-prod"},{"roleDefinitionName":"Owner","scope":"/subscriptions/sub-prod"}]`), nil
		case "sub-read":
			return []byte(`[{"roleDefinitionName":"Reader","scope":"/subscriptions/sub-read"},{"roleDefinitionName":"VM Starter","scope":"/subscriptions/sub-read"}]`), nil
		case "sub-custom":
			if !strings.Contains(a, "--assignee 11111111-aaaa") {
				t.Errorf("service principal not passed by appId: %s", a)
			}
			return []byte(`[{"roleDefinitionName":"VM Cleaner","scope":"/subscriptions/sub-custom/resourceGroups/rg1"}]`), nil
		}
		return nil, errors.New("AuthorizationFailed: no access")
	case strings.HasPrefix(a, "role definition list --name VM Starter"):
		return []byte(`[{"roleName":"VM Starter","permissions":[{"actions":["Microsoft.Compute/virtualMachines/start/action","Microsoft.Compute/*/read","Microsoft.Storage/*"],"notActions":["Microsoft.Storage/*"],"dataActions":[],"notDataActions":[]}]}]`), nil
	case strings.HasPrefix(a, "role definition list --name VM Cleaner"):
		return []byte(`[{"roleName":"VM Cleaner","permissions":[{"actions":["Microsoft.Compute/virtualMachines/read","Microsoft.Compute/virtualMachines/delete"],"notActions":[],"dataActions":[],"notDataActions":[]}]}]`), nil
	}
	t.Errorf("unexpected az call: %s", a)
	return nil, errors.New("unexpected")
}

func credsConfig() *config.Config {
	cfg := config.Default()
	cfg.PlanGate.Engines = map[string]string{"aws": "/bin/true", "kubectl": "/bin/true", "gcloud": "/fake/gcloud", "az": "/fake/az"}
	cfg.Environments = []config.Environment{
		{Name: "prod", Tier: config.Protected, Match: config.Match{AWSAccounts: []string{"111111111111"}, KubeContexts: []string{"eks-blue"},
			GCPProjects: []string{"acme-prod"}, AzureSubscriptions: []string{"Acme Prod", "sub-custom"}}},
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

func TestDoctorCredsGCloudAz(t *testing.T) {
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI, gcpTestPermissions = fakeCloud(t), fakeGCPPermissions(t)
	defer func() { runCLI, gcpTestPermissions = old, oldHTTP }()
	t.Setenv("CLOUDSDK_CORE_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CORE_PROJECT", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")
	cfg := credsConfig()
	found := append(auditGCloud(cfg), auditAz(cfg)...)
	find := func(prefix string) credsFinding {
		for _, f := range found {
			if strings.HasPrefix(f.text, prefix) {
				return f
			}
		}
		t.Errorf("no finding for %s; got %v", prefix, found)
		return credsFinding{}
	}
	for _, c := range []struct{ prefix, level, has string }{
		{"gcloud account admin@acme.com on project acme-prod (environment prod, tier protected)", "FAIL", "holds: compute.instances.delete, iam.serviceAccounts.actAs"},
		{"gcloud account viewer@acme.com on project acme-prod", "ok", "none of 17 destructive permissions"},
		{"gcloud account expired@acme.com on project acme-prod", "WARN", "not checked (gcloud auth print-access-token failed"},
		{"gcloud account ci@acme.com on project zeta-42 (matches no environment)", "WARN", "holds: storage.buckets.delete"},
		{"az subscription Acme Prod (sub-prod, default) as me@acme.com (environment prod, tier protected)", "FAIL", "Owner at /subscriptions/sub-prod"},
		{"az subscription Acme Readers (sub-read) as me@acme.com (matches no environment)", "ok", "no role with a destructive action"},
		{"az subscription Acme Custom (sub-custom) as 11111111-aaaa (environment prod", "FAIL", "VM Cleaner (Microsoft.Compute/virtualMachines/delete) at /subscriptions/sub-custom/resourceGroups/rg1"},
		{"az subscription Acme Broken (sub-err)", "WARN", "not checked, az role assignment list failed (AuthorizationFailed"},
	} {
		f := find(c.prefix)
		if f.level != c.level || !strings.Contains(f.text, c.has) {
			t.Errorf("%s: %s %q, want %s with %q", c.prefix, f.level, f.text, c.level, c.has)
		}
	}
	for _, f := range found {
		if strings.Contains(f.text, "SECRET") || strings.Contains(f.text, "nobody@") {
			t.Errorf("finding shows a token or an uncredentialed account: %s", f.text)
		}
	}
	if len(found) != 8 {
		t.Errorf("%d findings, want 8: %v", len(found), found)
	}
	// AZURE_SUBSCRIPTION_ID moves the default.
	t.Setenv("AZURE_SUBSCRIPTION_ID", "sub-read")
	if f := auditAz(cfg); len(f) == 0 || !strings.HasPrefix(f[0].text, "az subscription Acme Readers (sub-read, default)") {
		t.Errorf("AZURE_SUBSCRIPTION_ID not the default: %v", f)
	}
}

func TestGCloudTokenNotInHTTPError(t *testing.T) {
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI = fakeCloud(t)
	gcpTestPermissions = func(_ context.Context, token, _ string, _ []string) ([]string, error) {
		return nil, errors.New("Permission denied for " + token)
	}
	defer func() { runCLI, gcpTestPermissions = old, oldHTTP }()
	t.Setenv("CLOUDSDK_CORE_ACCOUNT", "")
	t.Setenv("CLOUDSDK_CORE_PROJECT", "")
	for _, f := range auditGCloud(credsConfig()) {
		if strings.Contains(f.text, "SECRET") {
			t.Errorf("token in finding: %s", f.text)
		}
		if strings.Contains(f.text, "admin@") && (f.level != "WARN" || !strings.Contains(f.text, "not checked (Permission denied for <token>)")) {
			t.Errorf("API error: %s %s", f.level, f.text)
		}
	}
}

func TestAzDestructiveEntries(t *testing.T) {
	for _, c := range []struct {
		actions, not []string
		want         int
	}{
		{[]string{"*"}, nil, 1},
		{[]string{"*"}, []string{"Microsoft.Authorization/*/Delete"}, 1}, // a narrower notAction does not cancel *
		{[]string{"*/read"}, nil, 0},
		{[]string{"Microsoft.Compute/virtualMachines/delete"}, []string{"Microsoft.Compute/*"}, 0},
		{[]string{"microsoft.compute/virtualmachines/DELETE"}, nil, 1},
		{[]string{"Microsoft.Authorization/roleAssignments/write"}, nil, 1},
		{[]string{"Microsoft.Compute/virtualMachines/write"}, nil, 0},
		{[]string{"*/delete"}, []string{"*/delete"}, 0},
		{[]string{"Microsoft.Sql/*"}, nil, 1},
	} {
		if got := azDestructiveEntries(c.actions, c.not); len(got) != c.want {
			t.Errorf("%v not %v: %v, want %d", c.actions, c.not, got, c.want)
		}
	}
}

func TestDoctorCredsExit(t *testing.T) {
	old, oldHTTP := runCLI, gcpTestPermissions
	runCLI, gcpTestPermissions = fakeCloud(t), fakeGCPPermissions(t)
	defer func() { runCLI, gcpTestPermissions = old, oldHTTP }()
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
	if strings.Contains(out.String(), "not audited") || strings.Contains(out.String(), "SECRET") {
		t.Errorf("output: %s", out.String())
	}
}
