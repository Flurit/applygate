package plangate

import (
	"encoding/json"
	"testing"
)

func TestRestrictsValuesAreOred(t *testing.T) {
	cases := []struct {
		cond string
		want bool
	}{
		{`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}`, true},
		{`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","0.0.0.0/0"]}}`, false},
		{`{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-1"}}`, false},
		{`{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/*"}}`, false},
		{`{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::111111111111:role/*"}}`, true},
		{`{"ForAllValues:StringLike":{"aws:PrincipalOrgPaths":"o-1/*"}}`, false},
		{`{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}`, true},
	}
	for _, c := range cases {
		if got := restricts(json.RawMessage(c.cond)); got != c.want {
			t.Errorf("restricts(%s) = %v, want %v", c.cond, got, c.want)
		}
	}
}
