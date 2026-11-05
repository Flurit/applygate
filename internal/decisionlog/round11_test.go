package decisionlog

import (
	"strings"
	"testing"
)

func TestRedactJSONFindsEscapedSecrets(t *testing.T) {
	for _, in := range []string{
		`{"command":"export DB_PASSWORD=\"hunter2SHELLPW\" && ./deploy.sh"}`,
		`{"command":"mysql -u root -p\"hunter2MYSQL\" db"}`,
		`{"body":"{\"password\":\"hunter2NEST\",\"user\":\"x\"}"}`,
		`{"password":"hunter2KEY","user":"x"}`,
		`{"query":"ALTER USER bob PASSWORD 'hunter2SQL'"}`,
	} {
		out := RedactJSONCut(in, 4096)
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret left in %s -> %s", in, out)
		}
	}
	if out := RedactJSONCut(`{"target":"prod-db","verb":"delete"}`, 4096); !strings.Contains(out, "prod-db") {
		t.Errorf("an ordinary value was redacted: %s", out)
	}
	if out := RedactJSONCut(`not json password=hunter2`, 4096); strings.Contains(out, "hunter2") {
		t.Errorf("text fallback: %s", out)
	}
}

func TestBypassIsNotASecretName(t *testing.T) {
	for _, in := range []string{"somecli --bypass-approval prod-db", "somecli --compass north", "somecli --passthrough x"} {
		if out := Redact(in); out != in {
			t.Errorf("%q redacted to %q", in, out)
		}
	}
	for _, in := range []string{"somecli --pass hunter2", "somecli --db-pass hunter2", "somecli --password hunter2", "pass=hunter2"} {
		if out := Redact(in); strings.Contains(out, "hunter2") {
			t.Errorf("%q not redacted: %q", in, out)
		}
	}
}

func TestEntryPathsAndCwdAreRedacted(t *testing.T) {
	e := &Entry{Paths: []string{"notes.txt", "password=hunter2hunter2"}, Cwd: "/work/token=abcdef123456"}
	redactEntry(e)
	if strings.Contains(strings.Join(e.Paths, " "), "hunter2") || strings.Contains(e.Cwd, "abcdef123456") {
		t.Errorf("not redacted: %v %s", e.Paths, e.Cwd)
	}
}
