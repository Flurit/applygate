package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegularFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	f, err := OpenAppend(p, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("x")
	f.Close()
	if b, err := ReadFile(p); err != nil || string(b) != "x" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}
