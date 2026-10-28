package shell

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"strings"
	"testing"
)

// TestDecoderChains covers F9: base32 and gzip decoders, and tee passthrough,
// are now followed so an encoded destructive command resolves to a block
// instead of falling back to the generic "text piped into a shell" ask.
func TestDecoderChains(t *testing.T) {
	fs := fakeFS(map[string]string{})
	const payload = "terraform destroy -auto-approve"

	b32 := base32.StdEncoding.EncodeToString([]byte(payload))

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(payload))
	zw.Close()
	gzB64 := base64.StdEncoding.EncodeToString(gz.Bytes())

	cases := []struct {
		name, cmd string
	}{
		{"base32", "echo " + b32 + " | base32 -d | sh"},
		{"gzip", "echo " + gzB64 + " | base64 -d | gunzip | sh"},
		{"gzip-d", "echo " + gzB64 + " | base64 -d | gzip -d | bash"},
		{"tee", "echo 'terraform destroy -auto-approve' | tee /tmp/x.sh | sh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Analyze(c.cmd, Options{Dir: "/repo", Env: map[string]string{"HOME": "/home/u"}, Aliases: map[string]string{}, ReadFile: fs})
			got := strings.Join(render(r), "\n")
			if !strings.Contains(got, "terraform destroy") {
				t.Fatalf("%s: expected the decoded destroy to resolve, got:\n%s", c.name, got)
			}
			if strings.Contains(got, "PROBLEM") {
				t.Fatalf("%s: should resolve to a command, not an unresolved problem:\n%s", c.name, got)
			}
		})
	}

	// A benign gzip payload must not be misread as a destroy.
	var gz2 bytes.Buffer
	zw2 := gzip.NewWriter(&gz2)
	zw2.Write([]byte("terraform plan"))
	zw2.Close()
	benign := "echo " + base64.StdEncoding.EncodeToString(gz2.Bytes()) + " | base64 -d | gunzip | sh"
	r := Analyze(benign, Options{Dir: "/repo", Env: map[string]string{"HOME": "/home/u"}, Aliases: map[string]string{}, ReadFile: fs})
	got := strings.Join(render(r), "\n")
	if strings.Contains(got, "destroy") {
		t.Fatalf("benign gzip payload misread: %s", got)
	}
	if !strings.Contains(got, "terraform plan") {
		t.Fatalf("benign gzip payload not resolved: %s", got)
	}
}
