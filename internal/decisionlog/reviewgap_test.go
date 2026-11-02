package decisionlog

import (
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/reviewgap"
)

// Reproductions of v0.6.0 review findings; see internal/reviewgap.

func TestReviewG1RedactionForms(t *testing.T) {
	// Token-shaped values are assembled at run time so the source carries no
	// string a secret scanner would take for a real token.
	pat, stripe, gitlab := "github"+"_pat_"+"11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "sk"+"_live_"+"51PQxAexampleexampleexample", "gl"+"pat-"+"abcdefghij0123456789"
	cases := map[string]string{
		"terraform apply -var db_pass=Hunter1Secret":             "Hunter1Secret",
		"aws configure set aws_secret_access_key Hunter2Secret":  "Hunter2Secret",
		"vault login --token Hunter3Secret":                      "Hunter3Secret",
		"curl -u admin:Hunter4Secret https://api.example.com":    "Hunter4Secret",
		"mysql -pHunter5Secret -h db":                            "Hunter5Secret",
		"psql postgres://admin:Hunter6Secret@db.example.com/app": "Hunter6Secret",
		"mysql --password Hunter7Secret":                         "Hunter7Secret",
		"git clone https://" + pat + "@github.com/x/y":           pat[:30],
		"export STRIPE=" + stripe:                                stripe[:21],
		"export GL=" + gitlab:                                    gitlab[:16],
		`{"private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASSECRETBODY\n-----END PRIVATE KEY-----\n"}`: "SECRETBODY",
	}
	var leaked []string
	for in, secret := range cases {
		if strings.Contains(Redact(in), secret) {
			leaked = append(leaked, in)
		}
	}
	reviewgap.Check(t, "G1", len(leaked) == 0, "not redacted: %q", leaked)
}
