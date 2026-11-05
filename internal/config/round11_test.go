package config

import "testing"

func TestBackendMatchIgnoresSpelling(t *testing.T) {
	pat := "https://gitlab.com/api/v4/projects/123/terraform/state/main"
	for _, v := range []string{
		"https://gitlab.com/api/v4/projects/123/terraform/state/main", "https://GITLAB.COM/api/v4/projects/123/terraform/state/main",
		"https://gitlab.com:443/api/v4/projects/123/terraform/state/main", "https://gitlab.com/api/v4/projects/123/terraform/state/%6Dain",
		"https://gitlab.com//api/v4/projects/123/terraform/state/main", "https://gitlab.com/api/v4/./projects/123/terraform/state/main",
	} {
		if !backendMatch(pat, v) {
			t.Errorf("%s does not match %s", v, pat)
		}
	}
	for _, c := range []struct{ pat, v string }{
		{"gcs://acme-state/core", "gcs://acme-state/core/"}, {"gcs://acme-state/core", "gcs://acme-state//core"},
		{"s3://acme-tf-state-prod/*", "s3://acme-tf-state-prod//prod/network"}, {"s3://b/*", "s3://b/k"},
	} {
		if !backendMatch(c.pat, c.v) {
			t.Errorf("%s does not match %s", c.v, c.pat)
		}
	}
	if backendMatch("gcs://acme-state/core", "gcs://acme-state/other") {
		t.Errorf("different prefixes matched")
	}
}
