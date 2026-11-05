package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

// data "archive_file" writes its archive during plan: over a state file when
// output_path names one.
func TestArchiveFileOutputPath(t *testing.T) {
	cases := map[string]bool{
		`"${path.module}/lambda.zip"`:           false,
		`"lambda.zip"`:                          false,
		`"${path.module}/../terraform.tfstate"`: true,
		`"/etc/cron.d/x"`:                       true,
		`var.out`:                               true,
		`"~/.claude/settings.json"`:             true,
	}
	for expr, want := range cases {
		dir := t.TempDir()
		src := "data \"archive_file\" \"x\" {\n  type = \"zip\"\n  source_dir = \"src\"\n  output_path = " + expr + "\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		got := RunsPrograms(dir, filepath.Join(dir, ".terraform")) != ""
		if got != want {
			t.Errorf("output_path = %s: runs a program %v, want %v", expr, got, want)
		}
	}
}
