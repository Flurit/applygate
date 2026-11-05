package plangate

import (
	"encoding/json"
	"testing"
)

func TestProtectionRemovedByDeletingTheSetting(t *testing.T) {
	R := DefaultRules()
	flagged := func(changes ...rc) bool {
		r, err := Evaluate(Input{PlanJSON: planJSON(changes...), MaxDestroy: -1}, R)
		if err != nil {
			t.Fatal(err)
		}
		_, ok := rules(t, r)["protection-removed"]
		return ok
	}
	typ := "aws_instance"
	before := map[string]any{"disable_api_termination": true}
	if !flagged(rc{"aws_instance.a", typ, []string{"update"}, before, map[string]any{"disable_api_termination": nil}}) {
		t.Error("true to null is not flagged")
	}
	if !flagged(rc{"aws_instance.a", typ, []string{"update"}, before, map[string]any{}}) {
		t.Error("true to a missing key is not flagged")
	}
	// A removed block: the nested setting vanishes with it.
	if !flagged(rc{"aws_dynamodb_table.t", "aws_dynamodb_table", []string{"update"},
		map[string]any{"point_in_time_recovery": []any{map[string]any{"enabled": true}}}, map[string]any{"point_in_time_recovery": []any{}}}) {
		t.Error("a removed point_in_time_recovery block is not flagged")
	}
	// Nothing was set before: nothing is removed.
	if flagged(rc{"aws_instance.a", typ, []string{"update"}, map[string]any{}, map[string]any{}}) {
		t.Error("an attribute that was never set is flagged")
	}
	// Unchanged protection stays quiet.
	if flagged(rc{"aws_instance.a", typ, []string{"update"}, before, before}) {
		t.Error("an unchanged protection is flagged")
	}
}

func TestCidrUnionAndBroadWildcards(t *testing.T) {
	var all []string
	for i := 0; i < 32; i++ {
		all = append(all, itoa(i*8)+".0.0.0/5")
	}
	if !cidrsWide(all) {
		t.Error("32 prefixes of /5 are the whole IPv4 space")
	}
	if cidrsWide([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
		t.Error("the private ranges are not wide")
	}
	for _, c := range []struct {
		cond string
		want bool
	}{
		{`{"StringLike":{"aws:PrincipalOrgID":"o-*"}}`, false},
		{`{"StringLike":{"aws:SourceVpce":"vpce-*"}}`, false},
		{`{"StringLike":{"aws:SourceVpc":"vpc-*"}}`, false},
		{`{"StringLike":{"aws:userid":"AIDA*"}}`, false},
		{`{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::1*:role/x"}}`, false},
		{`{"StringLike":{"aws:SourceVpce":"vpce-0123456789abcdef*"}}`, true},
		{`{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, true},
	} {
		if got := restricts(json.RawMessage(c.cond)); got != c.want {
			t.Errorf("restricts(%s) = %v, want %v", c.cond, got, c.want)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
