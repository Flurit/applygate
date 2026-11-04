package plangate

import (
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
)

// Round 7: exposure rules that read the wrong attribute, or that a
// non-restricting condition or NotPrincipal got past.
func TestExposureRound7(t *testing.T) {
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
