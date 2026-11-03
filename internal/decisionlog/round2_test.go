package decisionlog

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Redaction gaps (finding 2D1).
func TestRedactRound2(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{`DB_PASSWORD="correct horse battery"`, "horse"},
		{`mysql -u root -p'S3cr3t pw' db`, "S3cr3t"},
		{`docker login -u me -p hunter2 registry.io`, "hunter2"},
		{`redis-cli -h r -a hunter2 ping`, "hunter2"},
		{`sshpass -p 'hunter2' ssh host`, "hunter2"},
		{"-----BEGIN PGP PRIVATE KEY BLOCK-----\nabcdef\n-----END PGP PRIVATE KEY BLOCK-----", "abcdef"},
		{`{"Authorization": "Bearer eyJhbGciOi"}`, "eyJhbGciOi"},
		{`DefaultEndpointsProtocol=https;AccountName=a;AccountKey=Zm9vYmFy==;EndpointSuffix=x`, "Zm9vYmFy"},
		{`https://a.blob.core.windows.net/c?sv=2022&sig=AbCdEf%2B&se=x`, "AbCdEf"},
		{`VAULT_TOKEN=hvs.CAESIJlU9xyzabcdefghijklmnop vault read x`, "hvs.CAES"},
		{`npm_abcdefghijklmnopqrstuvwxyz0123456789`, "npm_abc"},
		{`API_TOKEN=abc$def`, "$def"},
	} {
		if out := Redact(c.in); strings.Contains(out, c.secret) {
			t.Errorf("%q -> %q still holds %q", c.in, out, c.secret)
		}
	}
	if out := Redact("TOKEN=$TOKEN terraform plan"); !strings.Contains(out, "$TOKEN") {
		t.Errorf("a variable reference was redacted: %q", out)
	}
}

// Notes are redacted (2D2), and an oversized line does not hide the
// entries after it (2D3).
func TestLogRound2(t *testing.T) {
	e := Entry{Notes: []string{"MCP tool x judged as: curl -H 'Authorization: Bearer abc123' x"}}
	redactEntry(&e)
	if strings.Contains(e.Notes[0], "abc123") {
		t.Fatalf("note not redacted: %q", e.Notes[0])
	}
	var buf bytes.Buffer
	buf.WriteString(`{"verdict":"allow"}` + "\n")
	buf.WriteString(`{"command":"` + strings.Repeat("x", maxLine+10) + `"}` + "\n")
	buf.WriteString(`{"verdict":"block"}` + "\n")
	entries, bad := Read(&buf)
	if len(entries) != 2 || bad != 1 || entries[1].Verdict != "block" {
		t.Fatalf("entries %d bad %d", len(entries), bad)
	}
}

// A huge command is cut before it is redacted and logged, so writing the
// entry stays fast and small (finding 3D1).
func TestHugeCommandIsCut(t *testing.T) {
	e := Entry{Command: "terraform destroy -auto-approve; : " + strings.Repeat("mysql -pxyz ", 600000)}
	start := time.Now()
	redactEntry(&e)
	// The time bound is loose: CI runs with the race detector, which makes
	// the regular expressions many times slower. Without the cut this input
	// takes minutes.
	if len(e.Command) > 2*maxField || time.Since(start) > 20*time.Second {
		t.Fatalf("command %d bytes, %s", len(e.Command), time.Since(start))
	}
}

// More secret-bearing forms (finding 3D3).
func TestRedactRound3(t *testing.T) {
	for _, c := range []struct{ in, secret string }{
		{`aws ssm put-parameter --name /db/pw --type SecureString --value hunter2xyz`, "hunter2xyz"},
		{`kubectl create secret generic db --from-literal=password=hunter2xyz`, "hunter2xyz"},
		{`vault kv put secret/db user=admin password=hunter2xyz`, "hunter2xyz"},
		{`gh secret set DEPLOY_KEY --body "hunter2 xyz"`, "hunter2"},
		{`echo -n hunter2xyz | docker secret create db_pw -`, "hunter2xyz"},
		{`az login -u me@x.io -p hunter2xyz`, "hunter2xyz"},
		{`curl -H 'Cookie: session=abc123def' https://x`, "abc123def"},
		{`curl -d '{}' https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX`, "XXXXXXXXXXXX"},
	} {
		if out := Redact(c.in); strings.Contains(out, c.secret) {
			t.Errorf("%q -> %q still holds %q", c.in, out, c.secret)
		}
	}
}
