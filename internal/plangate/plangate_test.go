package plangate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/preflight"
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

// TestProtectedResources covers the protected_resources config: address
// globs whose destroy or replace is critical whatever the resource type.
func TestProtectedResources(t *testing.T) {
	R := DefaultRules()
	res, _ := Evaluate(Input{MaxDestroy: -1, Protected: []string{"aws_instance.bastion", "module.data.*"}, PlanJSON: planJSON(
		rc{"aws_instance.bastion", "aws_instance", []string{"create", "delete"}, map[string]any{}, map[string]any{}},
		rc{"module.data.aws_instance.x", "aws_instance", []string{"delete"}, map[string]any{}, nil},
		rc{"aws_instance.web", "aws_instance", []string{"delete"}, map[string]any{}, nil},
	)}, R)
	sev := rules(t, res)
	if s, ok := sev["protected-resource"]; !ok || s != preflight.Critical {
		t.Fatalf("want Critical protected-resource, got %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.Rule == "protected-resource" {
			if len(f.Evidence) != 2 {
				t.Fatalf("want the bastion and module.data resources only, got %v", f.Evidence)
			}
		}
	}
	// An update to a protected resource is not a destroy.
	res2, _ := Evaluate(Input{MaxDestroy: -1, Protected: []string{"aws_instance.bastion"}, PlanJSON: planJSON(
		rc{"aws_instance.bastion", "aws_instance", []string{"update"}, map[string]any{}, map[string]any{}},
	)}, R)
	if _, ok := rules(t, res2)["protected-resource"]; ok {
		t.Fatalf("update must not fire protected-resource: %+v", res2.Findings)
	}
}

// TestCodeExecution covers spec scenario S12: a provisioner on a resource the
// plan creates, replaces or destroys, and an external data source whose read
// the plan defers to apply, are a High finding. Configuration that the apply
// does not run is not.
func TestCodeExecution(t *testing.T) {
	R := DefaultRules()
	change := func(addr, module, mode, typ, name string, acts ...string) map[string]any {
		return map[string]any{"address": addr, "module_address": module, "mode": mode, "type": typ, "name": name,
			"change": map[string]any{"actions": acts, "before": nil, "after": map[string]any{}}}
	}
	withProv := func(addr, mode, typ, name, prov string) map[string]any {
		r := map[string]any{"address": addr, "mode": mode, "type": typ, "name": name}
		if prov != "" {
			r["provisioners"] = []any{map[string]any{"type": prov}}
		}
		return r
	}
	plan := map[string]any{
		"format_version": "1.2",
		"resource_changes": []any{
			change("aws_instance.a", "", "managed", "aws_instance", "a", "create"),
			change("data.external.secrets", "", "data", "external", "secrets", "read"),
			// A module instance with a string key holding brackets and a dot.
			change(`module.db["a.b]"].null_resource.bootstrap[0]`, `module.db["a.b]"]`, "managed", "null_resource", "bootstrap", "create"),
			change("aws_instance.tainted", "", "managed", "aws_instance", "tainted", "create", "delete"),
			change("null_resource.old", "", "managed", "null_resource", "old", "delete"),
			change("aws_instance.same", "", "managed", "aws_instance", "same", "no-op"),
			change(`aws_instance.tagged["x"]`, "", "managed", "aws_instance", "tagged", "update"),
		},
		"configuration": map[string]any{"root_module": map[string]any{
			"resources": []any{
				withProv("aws_instance.a", "managed", "aws_instance", "a", "local-exec"),
				withProv("data.external.secrets", "data", "external", "secrets", ""),
				withProv("aws_instance.tainted", "managed", "aws_instance", "tainted", "local-exec"),
				withProv("null_resource.old", "managed", "null_resource", "old", "local-exec"),
				withProv("aws_instance.same", "managed", "aws_instance", "same", "local-exec"),
				withProv("aws_instance.tagged", "managed", "aws_instance", "tagged", "remote-exec"),
				// count = 0: in the configuration, no instance in the plan.
				withProv("null_resource.never", "managed", "null_resource", "never", "local-exec"),
				// Read during the plan, so not in resource_changes.
				withProv("data.external.at_plan", "data", "external", "at_plan", ""),
			},
			"module_calls": map[string]any{"db": map[string]any{"source": "./db", "module": map[string]any{
				"resources": []any{withProv("null_resource.bootstrap", "managed", "null_resource", "bootstrap", "remote-exec")},
			}}},
		}},
	}
	js, _ := json.Marshal(plan)
	res, err := Evaluate(Input{MaxDestroy: -1, PlanJSON: js}, R)
	if err != nil {
		t.Fatal(err)
	}
	f := finding(res, "code-execution")
	if f == nil || f.Severity != preflight.High {
		t.Fatalf("want High code-execution, got %+v", res.Findings)
	}
	want := []string{
		"aws_instance.a: provisioner local-exec",
		"aws_instance.tainted: provisioner local-exec",
		"data.external.secrets: external data source runs a program",
		`module.db["a.b]"].null_resource.bootstrap[0]: provisioner remote-exec`,
		"null_resource.old: provisioner local-exec",
	}
	if fmt.Sprint(f.Evidence) != fmt.Sprint(want) {
		t.Fatalf("evidence\n %q\nwant\n %q", f.Evidence, want)
	}
	// A plain plan has no code-execution finding.
	res2, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(rc{"aws_instance.a", "aws_instance", []string{"create"}, nil, map[string]any{}})}, R)
	if _, ok := rules(t, res2)["code-execution"]; ok {
		t.Fatalf("unexpected code-execution: %+v", res2.Findings)
	}
}

func TestStripKeys(t *testing.T) {
	for in, want := range map[string]string{
		"module.a":                      "module.a",
		"module.a[0].module.b":          "module.a.module.b",
		`module.a["x"].module.b["y"]`:   "module.a.module.b",
		`module.a["a.b]c"].module.b[2]`: "module.a.module.b",
		`module.a["q\"]"].module.b`:     "module.a.module.b",
		`module.a["[nested]"]`:          "module.a",
	} {
		if got := stripKeys(in); got != want {
			t.Errorf("stripKeys(%s) = %s, want %s", in, got, want)
		}
	}
}

// TestExposureOnUpdate: an update is flagged only for exposure it adds; a
// create or replace is flagged for everything its planned value exposes.
func TestExposureOnUpdate(t *testing.T) {
	R := DefaultRules()
	ssh := map[string]any{"from_port": 22.0, "to_port": 22.0, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}}
	rdp := map[string]any{"from_port": 3389.0, "to_port": 3389.0, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}}
	sg := func(tag string, rules ...any) map[string]any {
		return map[string]any{"ingress": rules, "tags": map[string]any{"env": tag}}
	}
	cases := []struct {
		name   string
		acts   []string
		before map[string]any
		after  map[string]any
		want   []string
	}{
		{"tag-only update over an open group", []string{"update"}, sg("a", ssh), sg("b", ssh), nil},
		{"update opens a new port", []string{"update"}, sg("a", ssh), sg("a", ssh, rdp), []string{"aws_security_group.s: ingress from the internet on port 3389"}},
		{"update closes a port", []string{"update"}, sg("a", ssh, rdp), sg("a", ssh), nil},
		{"replace keeps an open port", []string{"delete", "create"}, sg("a", ssh), sg("b", ssh), []string{"aws_security_group.s: ingress from the internet on port 22"}},
		{"create", []string{"create"}, nil, sg("a", ssh), []string{"aws_security_group.s: ingress from the internet on port 22"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(rc{"aws_security_group.s", "aws_security_group", c.acts, c.before, c.after})}, R)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			if f := finding(res, "exposure"); f != nil {
				got = f.Evidence
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("exposure %q, want %q", got, c.want)
			}
		})
	}
	// A policy that already granted a wildcard is not re-flagged on update,
	// and a new wildcard is.
	pol := func(actions string) map[string]any {
		return map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Action":` + actions + `,"Resource":"*"}]}`}
	}
	res, _ := Evaluate(Input{MaxDestroy: -1, PlanJSON: planJSON(rc{"aws_iam_policy.p", "aws_iam_policy", []string{"update"}, pol(`"s3:*"`), pol(`["s3:*","ec2:*"]`)})}, R)
	f := finding(res, "exposure")
	if f == nil || fmt.Sprint(f.Evidence) != "[aws_iam_policy.p: IAM policy allows wildcard action ec2:*]" {
		t.Fatalf("want only the new ec2:* wildcard, got %+v", res.Findings)
	}
}

// TestFPStudyPlans replays trimmed plans from the plan-gate false-positive
// study (review/fp-study): real terraform show -json output from public
// examples applied to LocalStack. Day-2 plans (a no-op re-plan, a default-tag
// change) must not raise code-execution or exposure for configuration the
// apply does not run or exposure that was already there; the create plans
// still must.
func TestFPStudyPlans(t *testing.T) {
	R := DefaultRules()
	cases := []struct {
		file string
		rule string
		want []string
	}{
		{"lambda-simple-create.json", "code-execution", []string{"module.lambda_function.null_resource.archive[0]: provisioner local-exec"}},
		{"lambda-simple-noop.json", "code-execution", nil},
		{"lambda-simple-tags.json", "code-execution", nil},
		{"ec2-complete-create.json", "exposure", []string{
			`module.ec2_complete.aws_iam_role_policy_attachment.this["AdministratorAccess"]: attaches AdministratorAccess`,
			"module.security_group.aws_security_group_rule.ingress_rules[1]: ingress from the internet on all ports",
		}},
		{"ec2-complete-tags.json", "exposure", nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			js, err := os.ReadFile(filepath.Join("testdata", "fpstudy", c.file))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Evaluate(Input{MaxDestroy: -1, PlanJSON: js}, R)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			if f := finding(res, c.rule); f != nil {
				if f.Severity != preflight.High {
					t.Errorf("%s severity %s, want high", c.rule, f.Severity)
				}
				got = f.Evidence
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("%s evidence %q, want %q", c.rule, got, c.want)
			}
		})
	}
}

func finding(r *Result, rule string) *preflight.Finding {
	for i := range r.Findings {
		if r.Findings[i].Rule == rule {
			return &r.Findings[i]
		}
	}
	return nil
}
