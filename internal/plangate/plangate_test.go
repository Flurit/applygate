package plangate

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Flurit/seatbelt/internal/preflight"
)

type rc struct {
	addr, typ string
	acts      []string
	before    map[string]any
	after     map[string]any
}

func planJSON(changes ...rc) []byte {
	var list []map[string]any
	for _, c := range changes {
		list = append(list, map[string]any{"address": c.addr, "mode": "managed", "type": c.typ, "name": "x",
			"change": map[string]any{"actions": c.acts, "before": c.before, "after": c.after}})
	}
	b, _ := json.Marshal(map[string]any{"format_version": "1.2", "resource_changes": list})
	return b
}

func rules(t *testing.T, r *Result) map[string]preflight.Severity {
	t.Helper()
	out := map[string]preflight.Severity{}
	for _, f := range r.Findings {
		out[f.Rule] = f.Severity
	}
	return out
}

func TestRules(t *testing.T) {
	R := DefaultRules()
	cases := []struct {
		name    string
		changes []rc
		in      Input
		want    []string
		not     []string
	}{
		{"create-only is clean", []rc{{"aws_s3_bucket.a", "aws_s3_bucket", []string{"create"}, nil, map[string]any{"bucket": "a", "force_destroy": false}}},
			Input{MaxDestroy: 0}, nil, []string{"destroy-count", "protection-removed", "stateful-destroyed"}},
		{"new bucket with force_destroy is not 'removed' protection", []rc{{"aws_s3_bucket.a", "aws_s3_bucket", []string{"create"}, nil, map[string]any{"force_destroy": true}}},
			Input{MaxDestroy: -1}, nil, []string{"protection-removed"}},
		{"stateless replace counts but is not stateful", []rc{{"aws_instance.a", "aws_instance", []string{"create", "delete"}, map[string]any{"disable_api_termination": false}, map[string]any{"disable_api_termination": false}}},
			Input{MaxDestroy: 0}, []string{"destroy-count"}, []string{"stateful-destroyed", "protection-removed"}},
		{"turning off termination protection on update", []rc{{"aws_instance.a", "aws_instance", []string{"update"}, map[string]any{"disable_api_termination": true}, map[string]any{"disable_api_termination": false}}},
			Input{MaxDestroy: -1}, []string{"protection-removed"}, nil},
		{"dynamodb delete", []rc{{"aws_dynamodb_table.t", "aws_dynamodb_table", []string{"delete"}, map[string]any{"name": "t"}, nil}},
			Input{MaxDestroy: -1}, []string{"stateful-destroyed"}, []string{"destroy-count"}},
		{"backup retention to zero", []rc{{"aws_db_instance.d", "aws_db_instance", []string{"update"}, map[string]any{"backup_retention_period": 7.0}, map[string]any{"backup_retention_period": 0.0}}},
			Input{MaxDestroy: -1}, []string{"protection-removed"}, nil},
		{"ssh open via vpc ingress rule", []rc{{"aws_vpc_security_group_ingress_rule.s", "aws_vpc_security_group_ingress_rule", []string{"create"}, nil, map[string]any{"cidr_ipv4": "0.0.0.0/0", "from_port": 22.0, "to_port": 22.0, "ip_protocol": "tcp"}}},
			Input{MaxDestroy: -1}, []string{"exposure"}, nil},
		{"https open is fine", []rc{{"aws_security_group_rule.s", "aws_security_group_rule", []string{"create"}, nil, map[string]any{"type": "ingress", "cidr_blocks": []any{"0.0.0.0/0"}, "from_port": 443.0, "to_port": 443.0, "protocol": "tcp"}}},
			Input{MaxDestroy: -1}, nil, []string{"exposure"}},
		{"admin policy attachment", []rc{{"aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment", []string{"create"}, nil, map[string]any{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}}},
			Input{MaxDestroy: -1}, []string{"exposure"}, nil},
		{"resource * alone is not flagged", []rc{{"aws_iam_policy.p", "aws_iam_policy", []string{"create"}, nil, map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Action":["logs:PutLogEvents"],"Resource":"*"}]}`}}},
			Input{MaxDestroy: -1}, nil, []string{"exposure"}},
		{"public bucket policy", []rc{{"aws_s3_bucket_policy.p", "aws_s3_bucket_policy", []string{"create"}, nil, map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`}}},
			Input{MaxDestroy: -1}, []string{"exposure"}, nil},
		{"lock table change", []rc{{"aws_dynamodb_table.lock", "aws_dynamodb_table", []string{"update"}, map[string]any{"name": "tf-locks"}, map[string]any{"name": "tf-locks"}}},
			Input{MaxDestroy: -1, Backend: &preflight.Backend{Type: "s3", Config: map[string]string{"bucket": "b", "dynamodb_table": "tf-locks"}}}, []string{"state-infrastructure"}, nil},
		{"out of scope", []rc{{"module.net.aws_vpc.v", "aws_vpc", []string{"update"}, map[string]any{}, map[string]any{}}},
			Input{MaxDestroy: -1, Scope: []string{"module.app.*"}}, []string{"out-of-scope"}, nil},
		{"in scope", []rc{{"module.app.aws_instance.a", "aws_instance", []string{"update"}, map[string]any{}, map[string]any{}}},
			Input{MaxDestroy: -1, Scope: []string{"module.app.*"}}, nil, []string{"out-of-scope"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			in.PlanJSON = planJSON(c.changes...)
			r, err := Evaluate(in, R)
			if err != nil {
				t.Fatal(err)
			}
			got := rules(t, r)
			for _, w := range c.want {
				if _, ok := got[w]; !ok {
					t.Errorf("missing %s; got %v", w, got)
				}
			}
			for _, n := range c.not {
				if _, ok := got[n]; ok {
					t.Errorf("unexpected %s; got %+v", n, r.Findings)
				}
			}
		})
	}
}

// TestLargePlanLatency measures evaluation of a 1,000-resource plan against
// the spec's 1 second target.
func TestLargePlanLatency(t *testing.T) {
	var changes []rc
	for i := 0; i < 1000; i++ {
		typ := []string{"aws_instance", "aws_s3_bucket", "aws_security_group", "aws_iam_policy", "aws_db_instance"}[i%5]
		changes = append(changes, rc{fmt.Sprintf("module.m%d.%s.r", i%20, typ), typ, []string{"update"},
			map[string]any{"tags": map[string]any{"n": i}, "deletion_protection": true},
			map[string]any{"tags": map[string]any{"n": i + 1}, "deletion_protection": true, "ingress": []any{map[string]any{"from_port": 443.0, "to_port": 443.0, "cidr_blocks": []any{"10.0.0.0/8"}}},
				"policy": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}})
	}
	js := planJSON(changes...)
	R := DefaultRules()
	start := time.Now()
	r, err := Evaluate(Input{PlanJSON: js, MaxDestroy: 0}, R)
	el := time.Since(start)
	if err != nil || r.Changes != 1000 {
		t.Fatalf("err %v changes %d", err, r.Changes)
	}
	t.Logf("1000-resource plan (%d KB JSON) evaluated in %s", len(js)/1024, el)
	if el > time.Second {
		t.Errorf("plan evaluation took %s, over the 1s target", el)
	}
}

// TestPlanTooLarge checks the F7 size cap: an oversized plan is a critical
// finding (so protected tiers block) instead of being parsed for seconds.
func TestPlanTooLarge(t *testing.T) {
	big := make([]byte, maxPlanBytes+1)
	res, err := Evaluate(Input{PlanJSON: big, MaxDestroy: 0}, DefaultRules())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Rule != "plan-too-large" || res.Findings[0].Severity != preflight.Critical {
		t.Fatalf("want one critical plan-too-large finding, got %+v", res.Findings)
	}
}

func TestUnprotectedStatefulCreate(t *testing.T) {
	R := DefaultRules()

	// Narrowed F11: ask (High) only when a DB is created with BOTH deletion
	// protection off AND the final snapshot skipped — no safety net at all.
	res, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(
		rc{"aws_db_instance.d", "aws_db_instance", []string{"create"}, nil,
			map[string]any{"deletion_protection": false, "skip_final_snapshot": true}},
	)}, R)
	sev := rules(t, res)
	if s, ok := sev["stateful-unprotected-create"]; !ok || s != preflight.High {
		t.Fatalf("want High stateful-unprotected-create, got findings %+v", res.Findings)
	}
	if _, ok := sev["stateful-destroyed"]; ok {
		t.Fatalf("create must not be a destroy: %+v", res.Findings)
	}

	// Protection off but a final snapshot kept: allowed, recorded as an Info
	// note (not the High ask).
	res2, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(
		rc{"aws_db_instance.d", "aws_db_instance", []string{"create"}, nil,
			map[string]any{"deletion_protection": false, "skip_final_snapshot": false}},
	)}, R)
	sev2 := rules(t, res2)
	if _, ok := sev2["stateful-unprotected-create"]; ok {
		t.Fatalf("partial-protection create must not ask: %+v", res2.Findings)
	}
	if s, ok := sev2["stateful-create-note"]; !ok || s != preflight.Info {
		t.Fatalf("want an Info stateful-create-note, got %+v", res2.Findings)
	}

	// Fully protected create: clean, no finding at all.
	res3, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(
		rc{"aws_db_instance.d", "aws_db_instance", []string{"create"}, nil,
			map[string]any{"deletion_protection": true, "skip_final_snapshot": false}},
	)}, R)
	sev3 := rules(t, res3)
	if _, ok := sev3["stateful-unprotected-create"]; ok {
		t.Fatalf("protected create should be clean: %+v", res3.Findings)
	}
	if _, ok := sev3["stateful-create-note"]; ok {
		t.Fatalf("protected create should not be noted: %+v", res3.Findings)
	}

	// A non-database stateful resource (e.g. S3 with force_destroy) is no longer
	// flagged on create under the narrowed rule.
	res4, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(
		rc{"aws_s3_bucket.b", "aws_s3_bucket", []string{"create"}, nil,
			map[string]any{"force_destroy": true}},
	)}, R)
	if _, ok := rules(t, res4)["stateful-unprotected-create"]; ok {
		t.Fatalf("non-DB create should not fire the narrowed rule: %+v", res4.Findings)
	}
}
