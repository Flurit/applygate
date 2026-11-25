package shell

import (
	"slices"
	"testing"
)

func TestNamesInfra(t *testing.T) {
	names := []struct {
		text string
		want string
	}{
		{"MANPAGER='terraform destroy -auto-approve' man ls", "terraform"},
		{"for d in a b; do kubectl -n $d delete pods --all; done", "kubectl"},
		{"X=1 tofu apply", "tofu"},
		{"opentofu plan", "opentofu"},
		{"cd infra && terragrunt run-all destroy", "terragrunt"},
		{"aws s3 rb s3://bucket --force", "aws s3 rb"},
		{"P=prod aws --profile $P sts get-caller-identity", "aws"},
		{"aws-vault exec prod -- env", "aws"},
		{"helm uninstall api", "helm"},
		{"oc delete project payments", "oc"},
		{"gcloud projects delete acme", "gcloud"},
		{"gsutil rm -r gs://bucket", "gsutil"},
		{"az group delete -n rg", "az"},
		{"eksctl delete cluster --name c", "eksctl"},
		{"pulumi destroy --yes", "pulumi"},
		{"npx cdk destroy", "cdk"},
		{"flux uninstall", "flux"},
		{"argocd app delete api", "argocd"},
		{"ansible-playbook site.yml", "ansible"},
		{"vault kv metadata delete secret/x", "vault"},
		{"kustomize build . | cat", "kustomize"},
		{"sed -i s/a/b/ ~/.claude/settings.json", ".claude/settings"},
		{"cat x > .applygate.yaml", ".applygate.yaml"},
		{"applygate trust", "applygate trust"},
		{"cp a terraform.tfstate", ".tfstate"},
		{"KUBECTL=1; Terraform plan", "terraform"},
	}
	for _, c := range names {
		if got := NamesInfra(c.text); !slices.Contains(got, c.want) {
			t.Errorf("NamesInfra(%q) = %v, want it to hold %q", c.text, got, c.want)
		}
	}
	// A name counts as a whole word only, and ordinary development
	// commands name none.
	for _, text := range []string{
		`D=/tmp/x; ls "$D"`,
		"for f in *.go; do wc -l \"$f\"; done",
		"python3 tools/report.py",
		"go test ./... && go vet ./...",
		"npm run build && npm test",
		"grep -rn azure docs",          // not az
		"echo [A-Za-z]",                // not az
		"cat docs/oauth.md",            // not oc
		"ls helmet/ cdk8s/ vaulted",    // not helm, cdk, vault
		"bin/applygate selftest",       // applygate alone is not on the list
		"git -C /src/applygate status", // nor in a path
		"echo awsome",                  // not aws
	} {
		if got := NamesInfra(text); len(got) != 0 {
			t.Errorf("NamesInfra(%q) = %v, want none", text, got)
		}
	}
}
