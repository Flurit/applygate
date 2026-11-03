package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTerragrunt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte(`
include "root" {
  path = find_in_parent_folders()
}
terraform {
  source = "../../prod//modules/app"
}
remote_state {
  backend = "s3"
  config = {
    bucket = "acme-prod-tfstate"
    key    = "${path_relative_to_include()}/terraform.tfstate"
  }
}
`), 0o644)
	tg := ReadTerragrunt(dir)
	if tg == nil || tg.Source != "../../prod//modules/app" || tg.Backend["bucket"] != "acme-prod-tfstate" || tg.Backend["key"] != "/terraform.tfstate" {
		t.Fatalf("%+v", tg)
	}
}
