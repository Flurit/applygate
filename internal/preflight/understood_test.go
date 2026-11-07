package preflight

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const awsLock = "provider \"registry.terraform.io/hashicorp/aws\" {\n  version = \"5.40.0\"\n  hashes = [\"h1:abc=\"]\n}\n"

func TestUnderstood(t *testing.T) {
	pad := strings.Repeat("# padding padding padding padding padding\n", 30000)
	cases := []struct {
		name  string
		files map[string]string
		want  string // "" = understood; otherwise a substring of the reason
	}{
		{"local only", map[string]string{"main.tf": "resource \"terraform_data\" \"x\" {}\n"}, ""},
		{"aws locked", map[string]string{"main.tf": "resource \"aws_instance\" \"x\" {}\n", ".terraform.lock.hcl": awsLock}, ""},
		{"aws not installed, not locked", map[string]string{"main.tf": "resource \"aws_instance\" \"x\" {}\n"}, ""},
		{"aws installed, not locked", map[string]string{"main.tf": "resource \"aws_instance\" \"x\" {}\n", ".terraform/providers/registry.terraform.io/hashicorp/aws/5.40.0/linux_amd64/terraform-provider-aws": "x"}, "installed but not in the lock file"},
		{"external provider", map[string]string{"main.tf": "data \"external\" \"x\" {\n  program = [\"sh\"]\n}\n"}, "not one applygate understands"},
		{"third party provider", map[string]string{"main.tf": "terraform {\n  required_providers {\n    evil = {\n      source = \"evilcorp/evil\"\n    }\n  }\n}\nprovider \"evil\" {}\n"}, "not one applygate understands"},
		{"unknown provider by prefix", map[string]string{"main.tf": "resource \"datadog_monitor\" \"x\" {}\n"}, "not one applygate understands"},
		{"remote module not installed", map[string]string{"main.tf": "module \"x\" {\n  source = \"hashicorp/consul/aws\"\n}\n"}, "not installed locally"},
		{"remote module installed", map[string]string{
			"main.tf":                         "module \"x\" {\n  source = \"hashicorp/consul/aws\"\n}\n",
			".terraform/modules/modules.json": `{"Modules":[{"Key":"x","Source":"hashicorp/consul/aws","Dir":".terraform/modules/x"}]}`,
			".terraform/modules/x/main.tf":    "resource \"terraform_data\" \"y\" {}\n"}, ""},
		{"installed module calls a remote one", map[string]string{
			"main.tf":                         "module \"x\" {\n  source = \"hashicorp/consul/aws\"\n}\n",
			".terraform/modules/modules.json": `{"Modules":[{"Key":"x","Source":"hashicorp/consul/aws","Dir":".terraform/modules/x"}]}`,
			".terraform/modules/x/main.tf":    "module \"y\" {\n  source = \"git::https://example.invalid/y.git\"\n}\n"}, "not installed locally"},
		{"local module calls a remote one", map[string]string{"main.tf": "module \"x\" {\n  source = \"./m\"\n}\n", "m/main.tf": "module \"y\" {\n  source = \"git::https://example.invalid/y.git\"\n}\n"}, "not installed locally"},
		{"module source from a variable", map[string]string{"main.tf": "module \"x\" {\n  source = var.s\n}\n"}, "not a literal"},
		{"file over the cap", map[string]string{"main.tf": "resource \"terraform_data\" \"x\" {}\n" + pad + pad + pad + pad}, "cannot be read"},
		{"tfquery file that does not parse", map[string]string{"q.tfquery.hcl": "provider \"x\" {{{\n"}, "does not parse"},
		{"tfquery file with an unknown provider", map[string]string{"q.tfquery.hcl": "provider \"datadog\" {}\n"}, "not one applygate understands"},
		{"child module provider", map[string]string{"main.tf": "module \"x\" {\n  source = \"./m\"\n}\n", "m/main.tf": "resource \"datadog_monitor\" \"x\" {}\n"}, "not one applygate understands"},
		{"tests directory", map[string]string{"tests/a.tftest.hcl": "provider \"datadog\" {}\n"}, "not one applygate understands"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, b := range c.files {
				put(t, dir, n, b)
			}
			got := Understood(context.Background(), dir, filepath.Join(dir, ".terraform"))
			if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestPinnedByUpstream(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, ".terraform")
	if err := PinnedByUpstream(context.Background(), dir, data); err != nil {
		t.Fatalf("no providers installed: %v", err)
	}
	put(t, dir, ".terraform/providers/registry.terraform.io/hashicorp/aws/5.40.0/linux_amd64/terraform-provider-aws", "x")
	if err := PinnedByUpstream(context.Background(), dir, data); err == nil {
		t.Fatal("a directory with an installed provider and no upstream must not be pinned")
	}
}
