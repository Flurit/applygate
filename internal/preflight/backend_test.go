package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

// The declared backend is read from .tf.json, unquoted labels and override
// files; a computed value makes it unknown (finding 2T1), and cloud and
// remote workspace names are read (2T7).
func TestDeclaredBackendForms(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		url        string
		unreadable bool
	}{
		{"json", map[string]string{"backend.tf.json": `{"terraform":{"backend":{"s3":{"bucket":"acme-prod","key":"a/tfstate"}}}}`}, "s3://acme-prod/a/tfstate", false},
		{"json list", map[string]string{"backend.tf.json": `{"terraform":[{"backend":{"s3":{"bucket":"b","key":"k"}}}]}`}, "s3://b/k", false},
		{"unquoted label", map[string]string{"main.tf": "terraform {\n  backend s3 {\n    bucket = \"b\"\n    key = \"k\"\n  }\n}\n"}, "s3://b/k", false},
		{"override wins", map[string]string{"main.tf": "terraform {\n  backend \"s3\" {\n    bucket = \"dev\"\n    key = \"k\"\n  }\n}\n",
			"override.tf": "terraform {\n  backend \"s3\" {\n    bucket = \"prod\"\n    key = \"k\"\n  }\n}\n"}, "s3://prod/k", false},
		{"variable", map[string]string{"main.tf": "terraform {\n  backend \"s3\" {\n    bucket = var.bucket\n    key = \"k\"\n  }\n}\n"}, "", true},
		{"template", map[string]string{"main.tf": "terraform {\n  backend \"s3\" {\n    bucket = \"${local.b}\"\n    key = \"k\"\n  }\n}\n"}, "", true},
		{"json template", map[string]string{"backend.tf.json": `{"terraform":{"backend":{"s3":{"bucket":"${var.b}","key":"k"}}}}`}, "", true},
		{"broken json", map[string]string{"backend.tf.json": `{"terraform":{"backend":`}, "", true},
		{"assume_role object", map[string]string{"main.tf": "terraform {\n  backend \"s3\" {\n    bucket = \"b\"\n    key = \"k\"\n    assume_role = {\n      role_arn = \"arn:aws:iam::1:role/x\"\n    }\n  }\n}\n"}, "s3://b/k", false},
		{"cloud workspace", map[string]string{"main.tf": "terraform {\n  cloud {\n    organization = \"acme\"\n    workspaces {\n      name = \"payments-prod\"\n    }\n  }\n}\n"}, "cloud://acme/payments-prod", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, b := range c.files {
				os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644)
			}
			be := DeclaredBackend(dir)
			if be == nil {
				t.Fatal("no backend")
			}
			if (be.Unreadable != "") != c.unreadable {
				t.Fatalf("unreadable %q, want %v", be.Unreadable, c.unreadable)
			}
			if !c.unreadable && be.URL() != c.url {
				t.Fatalf("url %s, want %s", be.URL(), c.url)
			}
		})
	}
}

func TestProviderAWS(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.tf"), []byte("provider \"aws\" {\n  profile = \"dev\"\n}\nprovider \"aws\" {\n  alias = \"prod\"\n  assume_role {\n    role_arn = \"arn:aws:iam::111122223333:role/admin\"\n  }\n}\n"), 0o644)
	p, r := ProviderAWS(dir)
	if len(p) != 1 || p[0] != "dev" || len(r) != 1 || r[0] != "arn:aws:iam::111122223333:role/admin" {
		t.Fatalf("profiles %v roles %v", p, r)
	}
}
