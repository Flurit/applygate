package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTargets(t *testing.T) {
	home := t.TempDir()
	write := func(rel, s string) string {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	read := os.ReadFile
	env := map[string]string{"HOME": home}

	// kubeconfig: ~/.kube/config, then the first file in KUBECONFIG that
	// sets current-context.
	write(".kube/config", "apiVersion: v1\nkind: Config\ncurrent-context: kind-dev\n")
	if got := KubeContext(env, read); got != "kind-dev" {
		t.Errorf("default kubeconfig: %q", got)
	}
	a := write("a.yaml", "apiVersion: v1\nkind: Config\n")
	b := write("b.yaml", "current-context: arn:aws:eks:us-east-1:111111111111:cluster/prod\n")
	if got := KubeContext(map[string]string{"HOME": home, "KUBECONFIG": a + string(os.PathListSeparator) + b}, read); got != "arn:aws:eks:us-east-1:111111111111:cluster/prod" {
		t.Errorf("KUBECONFIG list: %q", got)
	}
	if got := KubeContext(map[string]string{}, read); got != "" {
		t.Errorf("no HOME: %q", got)
	}

	// gcloud: env, then the active configuration.
	write(".config/gcloud/active_config", "work\n")
	write(".config/gcloud/configurations/config_work", "[compute]\nzone = us-east1-b\n[core]\naccount = me@example.com\nproject = acme-payments-prod\n")
	if got := GCPProject(env, read); got != "acme-payments-prod" {
		t.Errorf("active config: %q", got)
	}
	if got := GCPProject(map[string]string{"HOME": home, "CLOUDSDK_CORE_PROJECT": "sandbox-1"}, read); got != "sandbox-1" {
		t.Errorf("env: %q", got)
	}

	// az: the default subscription; the file starts with a byte order mark.
	write(".azure/azureProfile.json", "\xef\xbb\xbf"+`{"subscriptions": [{"id": "1111", "name": "Dev", "isDefault": false}, {"id": "2222", "name": "Payments Production", "isDefault": true}]}`)
	if name, id := AzureSubscription(env, read); name != "Payments Production" || id != "2222" {
		t.Errorf("azure: %q %q", name, id)
	}
}
