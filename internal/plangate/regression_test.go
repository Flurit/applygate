package plangate

import (
	"encoding/json"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
)

// Regression tests for defects found in security reviews, by topic.

// Round 7: exposure rules that read the wrong attribute, or that a
// non-restricting condition or NotPrincipal got past.
func TestExposureReadsTheRightAttribute(t *testing.T) {
	pub := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`
	cases := []struct {
		name, typ string
		after     map[string]any
		want      bool
	}{
		{"opensearch domain policy", "aws_opensearch_domain_policy", map[string]any{"access_policies": pub}, true},
		{"elasticsearch domain", "aws_elasticsearch_domain", map[string]any{"access_policies": pub}, true},
		{"secure transport only", "aws_s3_bucket_policy", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`}, true},
		{"org id condition", "aws_s3_bucket_policy", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-123"}}}]}`}, false},
		{"source account condition", "aws_sns_topic_policy", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Condition":{"StringEquals":{"AWS:SourceAccount":"1"}}}]}`}, false},
		{"not principal", "aws_s3_bucket_policy", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::1:root"},"Action":"s3:GetObject"}]}`}, true},
		{"inline bucket policy", "aws_s3_bucket", map[string]any{"policy": pub}, true},
		{"efs policy", "aws_efs_file_system_policy", map[string]any{"policy": pub}, true},
		{"api gateway policy", "aws_api_gateway_rest_api_policy", map[string]any{"policy": pub}, true},
		{"public snapshot", "aws_db_snapshot", map[string]any{"shared_accounts": []any{"all"}}, true},
		{"private snapshot", "aws_db_snapshot", map[string]any{"shared_accounts": []any{"123456789012"}}, false},
		{"public image", "aws_ami_launch_permission", map[string]any{"group": "all"}, true},
		{"public layer", "aws_lambda_layer_version_permission", map[string]any{"principal": "*"}, true},
		{"admin by exclusive set", "aws_iam_role_policy_attachments_exclusive", map[string]any{"policy_arns": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}, true},
		{"admin by sso", "aws_ssoadmin_managed_policy_attachment", map[string]any{"managed_policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, true},
	}
	for _, c := range cases {
		rc := &tfjson.ResourceChange{Address: c.typ + ".x", Type: c.typ}
		got := exposed(rc, c.after, DefaultRules())
		if (len(got) > 0) != c.want {
			t.Errorf("%s: got %v, want exposed=%v", c.name, got, c.want)
		}
	}
}

// A condition that names a limiting key still leaves a statement public when
// its operator excludes instead of limiting, or its value matches everyone.
func TestExposureConditionOperators(t *testing.T) {
	cases := []struct {
		name, cond string
		want       bool
	}{
		{"source ip anywhere", `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`, true},
		{"not equals one account", `{"StringNotEquals":{"aws:PrincipalAccount":"111111111111"}}`, true},
		{"string like star", `{"StringLike":{"aws:PrincipalArn":"*"}}`, true},
		{"ip in a range", `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, false},
		{"org id", `{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}`, false},
		{"account list", `{"StringEquals":{"aws:PrincipalAccount":["111111111111","222222222222"]}}`, false},
	}
	for _, c := range cases {
		doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":` + c.cond + `}]}`
		if got := policyPublic(doc); got != c.want {
			t.Errorf("%s: public = %v, want %v", c.name, got, c.want)
		}
	}
}

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
