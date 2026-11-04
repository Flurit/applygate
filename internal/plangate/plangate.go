// Package plangate evaluates the JSON form of a saved Terraform or OpenTofu
// plan ("terraform show -json tfplan") against AWS-first rules.
package plangate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/Flurit/applygate/internal/preflight"
)

//go:embed rules/aws.json
var awsRules []byte

// Rules are the data-driven resource lists.
type Rules struct {
	StatefulTypes []string     `json:"stateful_types"`
	Protection    []Protection `json:"protection"`
	AdminPorts    []int        `json:"admin_ports"`
	AdminPolicies []string     `json:"admin_policies"`
	stateful      map[string]bool
}

// Protection is an attribute whose value disables a safeguard.
type Protection struct {
	Types  []string `json:"types"`
	Attr   string   `json:"attr"`
	Unsafe any      `json:"unsafe"`
	What   string   `json:"what"`
	// When is "change" (flag an update or replace that sets the unsafe
	// value), "delete" (flag a delete or replace while the prior value is
	// unsafe, because the provider acts on it at deletion) or "both".
	When string `json:"when"`
}

// dbWithFinalSnapshot is the set of resource types that have both
// deletion_protection and skip_final_snapshot, so the narrowed F11 create rule
// (both safeguards off at once) applies to them.
var dbWithFinalSnapshot = map[string]bool{
	"aws_db_instance":     true,
	"aws_rds_cluster":     true,
	"aws_docdb_cluster":   true,
	"aws_neptune_cluster": true,
}

// isBool reports whether m[k] is present and equals want.
func isBool(m map[string]any, k string, want bool) bool {
	if m == nil {
		return false
	}
	b, ok := m[k].(bool)
	return ok && b == want
}

// DefaultRules returns the embedded AWS rules.
func DefaultRules() *Rules {
	var r Rules
	if err := json.Unmarshal(awsRules, &r); err != nil {
		panic("plangate: embedded rules: " + err.Error())
	}
	r.stateful = map[string]bool{}
	for _, t := range r.StatefulTypes {
		r.stateful[t] = true
	}
	return &r
}

// Input is everything the gate needs.
type Input struct {
	PlanJSON   []byte
	MaxDestroy int      // -1 unlimited
	Scope      []string // address globs the agent declared; empty = no scope rule
	// Protected are resource address globs from config whose destroy or
	// replace is critical regardless of type (protected_resources).
	Protected []string
	Backend   *preflight.Backend
}

// Result of evaluating a plan.
type Result struct {
	Findings []preflight.Finding
	Deletes  []string // pure deletes
	Replaces []string
	Changes  int
}

// Evaluate parses and checks the plan.
// maxPlanBytes caps the plan JSON we will parse. Beyond this, parsing costs
// seconds and could approach the decision deadline, so an oversized plan is
// treated as a critical finding (protected tiers block) rather than parsed.
const maxPlanBytes = 16 << 20

func Evaluate(in Input, rules *Rules) (*Result, error) {
	if len(in.PlanJSON) > maxPlanBytes {
		return &Result{Findings: []preflight.Finding{{
			Rule:     "plan-too-large",
			Severity: preflight.Critical,
			Message:  fmt.Sprintf("plan JSON is %d MB, over the %d MB limit; too large to evaluate", len(in.PlanJSON)>>20, maxPlanBytes>>20),
		}}}, nil
	}
	var p tfjson.Plan
	if err := json.Unmarshal(in.PlanJSON, &p); err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(in.PlanJSON, &top); err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	if _, ok := top["planned_values"]; !ok {
		if _, ok := top["resource_changes"]; !ok {
			// State JSON (terraform show -json without a plan) or other
			// JSON: judging it as an empty plan would allow anything.
			return nil, fmt.Errorf("plan JSON: not a plan (no planned_values or resource_changes); pass terraform show -json <planfile>")
		}
	}
	res := &Result{}
	// Actions (Terraform 1.14) run provider operations the resource
	// changes do not describe.
	var actions []json.RawMessage
	if raw, ok := top["action_invocations"]; ok && json.Unmarshal(raw, &actions) == nil && len(actions) > 0 {
		res.Findings = append(res.Findings, preflight.Finding{Rule: "plan-actions", Severity: preflight.High,
			Message: fmt.Sprintf("the plan invokes %d action(s), which run provider operations applygate cannot check", len(actions))})
	}
	var stateful, protection, exposure, stateInfra, outOfScope, unprotectedCreate, reducedCreate, protectedAddr, unknownAttrs []string
	var crit = func(list *[]string, s string) { *list = append(*list, s) }

	for _, rc := range p.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode == tfjson.DataResourceMode {
			continue
		}
		acts := normalActions(rc.Change.Actions)
		if acts.NoOp() || acts.Read() || len(acts) == 0 {
			continue
		}
		res.Changes++
		del := acts.Delete()
		repl := acts.Replace()
		if del {
			res.Deletes = append(res.Deletes, rc.Address)
		}
		if repl {
			res.Replaces = append(res.Replaces, rc.Address)
		}
		before, _ := rc.Change.Before.(map[string]any)
		after, _ := rc.Change.After.(map[string]any)

		if del || repl {
			verb := "destroyed"
			if repl {
				verb = "replaced"
			}
			if rules.stateful[rc.Type] {
				crit(&stateful, rc.Address+" ("+rc.Type+") is "+verb)
			}
			if len(in.Protected) > 0 && isProtected(rc.Address, in.Protected) {
				crit(&protectedAddr, rc.Address+" is "+verb+" (listed in protected_resources)")
			}
		}
		for _, pr := range rules.Protection {
			if !contains(pr.Types, rc.Type) {
				continue
			}
			bv, bok := lookup(before, pr.Attr)
			av, aok := lookup(after, pr.Attr)
			beforeUnsafe := bok && equal(bv, pr.Unsafe)
			afterUnsafe := aok && equal(av, pr.Unsafe)
			onChange := pr.When == "change" || pr.When == "both"
			onDelete := pr.When == "delete" || pr.When == "both"
			switch {
			case onDelete && del && beforeUnsafe:
				crit(&protection, rc.Address+": "+pr.What+" while it is being deleted")
			case onDelete && repl && beforeUnsafe:
				crit(&protection, rc.Address+": "+pr.What+" while it is being replaced")
			case onChange && (acts.Update() || repl) && afterUnsafe && !beforeUnsafe:
				crit(&protection, rc.Address+": "+pr.What)
			}
		}
		// F11 (narrowed): a database created with no safety net at all —
		// deletion protection off AND the final snapshot skipped — is High, so
		// a protected tier asks. A create with only one safeguard off (e.g.
		// protection off but a final snapshot kept) is allowed and recorded as
		// an Info note. A create removes nothing, and the replace/destroy rules
		// already gate the actual loss, so this stays off the critical path.
		if acts.Create() && dbWithFinalSnapshot[rc.Type] {
			dpOff := isBool(after, "deletion_protection", false)
			skip := isBool(after, "skip_final_snapshot", true)
			switch {
			case dpOff && skip:
				crit(&unprotectedCreate, rc.Address+": created with deletion protection off and the final snapshot skipped")
			case dpOff:
				reducedCreate = append(reducedCreate, rc.Address+": created with deletion protection off (a final snapshot is still taken)")
			case skip:
				reducedCreate = append(reducedCreate, rc.Address+": created with the final snapshot skipped (deletion protection is on)")
			}
		}
		if !del {
			unknownAttrs = append(unknownAttrs, unknownWatched(rc, rules)...)
			ev := exposed(rc, after, rules)
			if acts.Update() {
				// An update reports only the exposure it introduces; what
				// was already open before this change is not this plan's doing.
				ev = without(ev, exposed(rc, before, rules))
			}
			exposure = append(exposure, ev...)
		}
		if in.Backend != nil && in.Backend.Type == "s3" {
			bucket, table := in.Backend.Config["bucket"], in.Backend.Config["dynamodb_table"]
			name := firstString(after, before, "bucket", "name")
			if strings.HasPrefix(rc.Type, "aws_s3_bucket") && bucket != "" && name == bucket ||
				rc.Type == "aws_dynamodb_table" && table != "" && name == table {
				crit(&stateInfra, rc.Address+" changes the state backend resource "+name)
			}
		}
		if len(in.Scope) > 0 && !inScope(rc.Address, in.Scope) {
			outOfScope = append(outOfScope, rc.Address)
		}
	}

	add := func(rule string, sev preflight.Severity, msg string, ev []string) {
		if len(ev) == 0 {
			return
		}
		sort.Strings(ev)
		res.Findings = append(res.Findings, preflight.Finding{Rule: rule, Severity: sev, Message: msg, Evidence: ev})
	}
	n := len(res.Deletes) + len(res.Replaces)
	if in.MaxDestroy >= 0 && n > in.MaxDestroy {
		add("destroy-count", preflight.High, fmt.Sprintf("plan destroys or replaces %d resources; the limit for this tier is %d", n, in.MaxDestroy),
			append(append([]string(nil), res.Deletes...), res.Replaces...))
	}
	add("stateful-unprotected-create", preflight.High, "plan creates a database with no safety net (deletion protection off and final snapshot skipped)", unprotectedCreate)
	add("stateful-create-note", preflight.Info, "database created with reduced protection (allowed; recorded)", reducedCreate)
	add("stateful-destroyed", preflight.Critical, "plan destroys or replaces stateful resources", stateful)
	add("protected-resource", preflight.Critical, "plan destroys or replaces resources listed in protected_resources", protectedAddr)
	add("code-execution", preflight.High, "applying this plan runs code outside Terraform's own providers (provisioners or external data sources)", codeExecution(&p))
	add("protection-removed", preflight.Critical, "plan removes data protection", protection)
	add("exposure", preflight.High, "plan exposes resources", exposure)
	add("unknown-watched", preflight.High, "values the exposure and protection rules check are known only at apply time, so the plan cannot show they are safe", unknownAttrs)
	add("state-infrastructure", preflight.Critical, "plan changes the Terraform state backend itself", stateInfra)
	add("out-of-scope", preflight.High, "plan changes resources outside the declared scope", outOfScope)
	var meta struct {
		Errored bool `json:"errored"`
	}
	_ = json.Unmarshal(in.PlanJSON, &meta)
	if meta.Errored {
		add("plan-errored", preflight.Critical, "the saved plan is marked as errored", []string{"errored: true"})
	}
	return res, nil
}

// codeExecution lists the places where applying the plan would run
// arbitrary code with the user's credentials. Spec scenario S12.
//
// A provisioner (local-exec, remote-exec) runs when its resource instance is
// created, which includes the create half of a replace. A destroy-time
// provisioner runs when the instance is destroyed, and the plan JSON does not
// say which kind a provisioner is, so a delete counts too. A resource the
// plan leaves alone, or one with no instances (count 0, an empty for_each),
// runs nothing.
//
// An "external" data source runs its program during the plan. It runs again
// on apply only when the plan deferred the read: then it appears in
// resource_changes with a "read" action.
func codeExecution(p *tfjson.Plan) []string {
	// Instances that are created, replaced or destroyed, keyed by their
	// configuration address (no instance keys, so module.m["a"].x.y[0] is
	// module.m.x.y).
	changing := map[string][]string{}
	seen := map[string]bool{}
	var out []string
	note := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, rc := range p.ResourceChanges {
		if rc == nil || rc.Change == nil {
			continue
		}
		acts := normalActions(rc.Change.Actions)
		if rc.Mode == tfjson.DataResourceMode {
			if rc.Type == "external" && acts.Read() {
				note(rc.Address + ": external data source runs a program")
			}
			continue
		}
		if acts.Create() || acts.Replace() || acts.Delete() {
			ca := configAddress(rc)
			changing[ca] = append(changing[ca], rc.Address)
		}
	}
	if len(changing) == 0 || p.Config == nil {
		return out
	}
	var walk func(prefix string, m *tfjson.ConfigModule)
	walk = func(prefix string, m *tfjson.ConfigModule) {
		if m == nil {
			return
		}
		for _, r := range m.Resources {
			if r == nil {
				continue
			}
			for _, addr := range changing[prefix+r.Address] {
				for _, pv := range r.Provisioners {
					if pv != nil && pv.Type != "" {
						note(addr + ": provisioner " + pv.Type)
					}
				}
			}
		}
		for n, mc := range m.ModuleCalls {
			if mc != nil {
				walk(prefix+"module."+n+".", mc.Module)
			}
		}
	}
	walk("", p.Config.RootModule)
	return out
}

// configAddress is the configuration address of a resource instance: its
// module path without instance keys, then [data.]type.name.
func configAddress(rc *tfjson.ResourceChange) string {
	var b strings.Builder
	if rc.ModuleAddress != "" {
		b.WriteString(stripKeys(rc.ModuleAddress))
		b.WriteByte('.')
	}
	if rc.Mode == tfjson.DataResourceMode {
		b.WriteString("data.")
	}
	b.WriteString(rc.Type + "." + rc.Name)
	return b.String()
}

// stripKeys removes instance keys ([0], ["a.b]"]) from a module address. A
// string key is quoted and may contain brackets, dots and escaped quotes.
func stripKeys(addr string) string {
	var b strings.Builder
	depth, quoted, escaped := 0, false, false
	for _, c := range addr {
		switch {
		case quoted:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				quoted = false
			}
		case depth > 0:
			switch c {
			case '"':
				quoted = true
			case '[':
				depth++
			case ']':
				depth--
			}
		case c == '[':
			depth++
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// exposed returns exposure findings for a resource's planned values.
// exposureAttrs are the attributes exposed reads, by resource type.
var exposureAttrs = map[string][]string{
	"aws_security_group":                  {"ingress"},
	"aws_security_group_rule":             {"cidr_blocks", "ipv6_cidr_blocks", "from_port", "to_port", "protocol"},
	"aws_vpc_security_group_ingress_rule": {"cidr_ipv4", "cidr_ipv6", "from_port", "to_port", "ip_protocol"},
	"aws_s3_bucket_public_access_block":   {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"},
	"aws_s3_account_public_access_block":  {"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"},
	"aws_s3_bucket_acl":                   {"acl", "access_control_policy"},
	"aws_s3_bucket_policy":                {"policy"},
	"aws_iam_policy":                      {"policy"},
	"aws_iam_role_policy":                 {"policy"},
	"aws_iam_user_policy":                 {"policy"},
	"aws_iam_group_policy":                {"policy"},
	"aws_sqs_queue_policy":                {"policy"},
	"aws_sns_topic_policy":                {"policy"},
	"aws_kms_key_policy":                  {"policy"},
	"aws_ecr_repository_policy":           {"policy"},
	"aws_secretsmanager_secret_policy":    {"policy"},
	"aws_lambda_permission":               {"principal"},
	"aws_lambda_function_url":             {"authorization_type"},
	// 4H14: every type exposed reads.
	"aws_default_security_group":      {"ingress"},
	"aws_db_instance":                 {"publicly_accessible"},
	"aws_rds_cluster_instance":        {"publicly_accessible"},
	"aws_redshift_cluster":            {"publicly_accessible"},
	"aws_dms_replication_instance":    {"publicly_accessible"},
	"aws_iam_role":                    {"assume_role_policy", "managed_policy_arns", "inline_policy"},
	"aws_iam_role_policy_attachment":  {"policy_arn"},
	"aws_iam_user_policy_attachment":  {"policy_arn"},
	"aws_iam_group_policy_attachment": {"policy_arn"},
	"aws_iam_policy_attachment":       {"policy_arn"},
	// Round 7: the policy attribute of the OpenSearch and Elasticsearch
	// domains is access_policies; attachment sets, SSO and sharing.
	"aws_opensearch_domain":                      {"access_policies"},
	"aws_elasticsearch_domain":                   {"access_policies"},
	"aws_opensearch_domain_policy":               {"access_policies"},
	"aws_elasticsearch_domain_policy":            {"access_policies"},
	"aws_s3_bucket":                              {"policy"},
	"aws_efs_file_system_policy":                 {"policy"},
	"aws_api_gateway_rest_api_policy":            {"policy"},
	"aws_iam_role_policy_attachments_exclusive":  {"policy_arns"},
	"aws_iam_user_policy_attachments_exclusive":  {"policy_arns"},
	"aws_iam_group_policy_attachments_exclusive": {"policy_arns"},
	"aws_ssoadmin_managed_policy_attachment":     {"managed_policy_arn"},
	"aws_db_snapshot":                            {"shared_accounts"},
	"aws_db_cluster_snapshot":                    {"shared_accounts"},
	"aws_ami_launch_permission":                  {"group"},
	"aws_lambda_layer_version_permission":        {"principal"},
}

// unknownWatched lists the attributes of a created, updated or replaced
// resource that the exposure rules (and, for an update or replace, the
// protection rules) check but whose value is known only at apply time
// (after_unknown): an open CIDR or a removed deletion protection would not
// show in the plan.
func unknownWatched(rc *tfjson.ResourceChange, rules *Rules) []string {
	unk, _ := rc.Change.AfterUnknown.(map[string]any)
	if len(unk) == 0 {
		return nil
	}
	if rc.Type == "aws_security_group_rule" {
		if after, _ := rc.Change.After.(map[string]any); after != nil && after["type"] == "egress" {
			return nil
		}
	}
	attrs := append([]string(nil), exposureAttrs[rc.Type]...)
	// Protection can only be removed from a resource that exists.
	if acts := normalActions(rc.Change.Actions); acts.Update() || acts.Replace() {
		for _, pr := range rules.Protection {
			if contains(pr.Types, rc.Type) && (pr.When == "change" || pr.When == "both") {
				attrs = append(attrs, pr.Attr)
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range attrs {
		if v, ok := lookup(unk, a); ok && anyTrue(v) && !seen[a] {
			seen[a] = true
			out = append(out, rc.Address+": "+a+" is known only after apply")
		}
	}
	return out
}

// anyTrue reports whether an after_unknown value marks anything unknown.
func anyTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case []any:
		for _, e := range x {
			if anyTrue(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if anyTrue(e) {
				return true
			}
		}
	}
	return false
}

// normalActions reads an action list as Terraform means it, whatever its
// form: show -json writes lower-case lists of known shapes, but a plan
// handed to plan-check may not come from show. A list holding delete (in
// any case) deletes, and replaces when it also creates; an action
// applygate does not know counts as a delete.
func normalActions(in tfjson.Actions) tfjson.Actions {
	var create, del, update, read, noop, unknown bool
	for _, a := range in {
		switch tfjson.Action(strings.ToLower(string(a))) {
		case tfjson.ActionCreate:
			create = true
		case tfjson.ActionDelete:
			del = true
		case tfjson.ActionUpdate:
			update = true
		case tfjson.ActionRead:
			read = true
		case tfjson.ActionNoop:
			noop = true
		default:
			unknown = true
		}
	}
	switch {
	case (del || unknown) && create:
		return tfjson.Actions{tfjson.ActionDelete, tfjson.ActionCreate}
	case del || unknown:
		return tfjson.Actions{tfjson.ActionDelete}
	case create:
		return tfjson.Actions{tfjson.ActionCreate}
	case update:
		return tfjson.Actions{tfjson.ActionUpdate}
	case read:
		return tfjson.Actions{tfjson.ActionRead}
	case noop:
		return tfjson.Actions{tfjson.ActionNoop}
	}
	return nil
}

func exposed(rc *tfjson.ResourceChange, after map[string]any, rules *Rules) []string {
	if after == nil {
		return nil
	}
	var out []string
	var open func(cidrs ...any) bool
	open = func(cidrs ...any) bool {
		for _, c := range cidrs {
			switch v := c.(type) {
			case string:
				if wideCIDR(v) {
					return true
				}
			case []any:
				if open(v...) {
					return true
				}
			}
		}
		return false
	}
	portHit := func(from, to any, proto any) (string, bool) {
		f, fok := num(from)
		t, tok := num(to)
		if p, _ := proto.(string); p == "-1" || p == "all" {
			return "all ports", true
		}
		if !fok || !tok {
			return "", false
		}
		if f <= 0 && t >= 65535 || f == -1 {
			return "all ports", true
		}
		// Every admin port in the range is named: an update that widens a
		// range already open on one of them adds the others, which the
		// update's before/after comparison must see.
		var hit []string
		for _, port := range rules.AdminPorts {
			if float64(port) >= f && float64(port) <= t {
				hit = append(hit, strconv.Itoa(port))
			}
		}
		switch len(hit) {
		case 0:
			return "", false
		case 1:
			return "port " + hit[0], true
		}
		return "ports " + strings.Join(hit, ", "), true
	}
	switch rc.Type {
	case "aws_security_group", "aws_default_security_group":
		ingress, _ := after["ingress"].([]any)
		for _, r := range ingress {
			m, _ := r.(map[string]any)
			if m != nil && open(m["cidr_blocks"], m["ipv6_cidr_blocks"]) {
				if what, ok := portHit(m["from_port"], m["to_port"], m["protocol"]); ok {
					out = append(out, rc.Address+": ingress from the internet on "+what)
				}
			}
		}
	case "aws_security_group_rule":
		if after["type"] == "ingress" && open(after["cidr_blocks"], after["ipv6_cidr_blocks"]) {
			if what, ok := portHit(after["from_port"], after["to_port"], after["protocol"]); ok {
				out = append(out, rc.Address+": ingress from the internet on "+what)
			}
		}
	case "aws_vpc_security_group_ingress_rule":
		if open(after["cidr_ipv4"], after["cidr_ipv6"]) {
			if what, ok := portHit(after["from_port"], after["to_port"], after["ip_protocol"]); ok {
				out = append(out, rc.Address+": ingress from the internet on "+what)
			}
		}
	case "aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block":
		for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
			if v, ok := after[k].(bool); ok && !v {
				out = append(out, rc.Address+": "+k+" is false")
			}
		}
	case "aws_s3_bucket_acl":
		if acl, _ := after["acl"].(string); acl == "public-read" || acl == "public-read-write" || acl == "authenticated-read" {
			out = append(out, rc.Address+": bucket ACL "+acl)
		}
		if b, err := json.Marshal(after["access_control_policy"]); err == nil &&
			(strings.Contains(string(b), "acs.amazonaws.com/groups/global/AllUsers") || strings.Contains(string(b), "acs.amazonaws.com/groups/global/AuthenticatedUsers")) {
			out = append(out, rc.Address+": bucket ACL grants access to all users")
		}
	case "aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance":
		if v, ok := after["publicly_accessible"].(bool); ok && v {
			out = append(out, rc.Address+": publicly_accessible is true")
		}
	case "aws_iam_role":
		if s, _ := after["assume_role_policy"].(string); policyPublic(s) {
			out = append(out, rc.Address+": trust policy lets any principal assume the role")
		}
		arns, _ := after["managed_policy_arns"].([]any)
		for _, a := range arns {
			arn, _ := a.(string)
			for _, p := range rules.AdminPolicies {
				if strings.HasSuffix(arn, ":policy/"+p) {
					out = append(out, rc.Address+": attaches "+p)
				}
			}
		}
		inline, _ := after["inline_policy"].([]any)
		for _, ip := range inline {
			m, _ := ip.(map[string]any)
			if s, _ := m["policy"].(string); s != "" {
				for _, w := range policyWildcards(s) {
					out = append(out, rc.Address+": "+w)
				}
			}
		}
	case "aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key_policy", "aws_ecr_repository_policy",
		"aws_secretsmanager_secret_policy", "aws_glacier_vault_lock", "aws_efs_file_system_policy", "aws_api_gateway_rest_api_policy":
		if s, _ := after["policy"].(string); policyPublic(s) {
			out = append(out, rc.Address+": resource policy allows any principal")
		}
	case "aws_elasticsearch_domain_policy", "aws_opensearch_domain_policy", "aws_elasticsearch_domain", "aws_opensearch_domain":
		if s, _ := after["access_policies"].(string); policyPublic(s) {
			out = append(out, rc.Address+": the domain's access policy allows any principal")
		}
	case "aws_kms_key", "aws_sqs_queue", "aws_sns_topic", "aws_ecr_repository", "aws_secretsmanager_secret", "aws_s3_bucket":
		if s, _ := after["policy"].(string); policyPublic(s) {
			out = append(out, rc.Address+": resource policy allows any principal")
		}
	case "aws_lambda_layer_version_permission":
		if p, _ := after["principal"].(string); p == "*" {
			out = append(out, rc.Address+": lets any account use the layer")
		}
	case "aws_ami_launch_permission":
		if g, _ := after["group"].(string); g == "all" {
			out = append(out, rc.Address+": makes the image public")
		}
	case "aws_db_snapshot", "aws_db_cluster_snapshot":
		accts, _ := after["shared_accounts"].([]any)
		for _, a := range accts {
			if v, _ := a.(string); v == "all" {
				out = append(out, rc.Address+": makes the snapshot public")
			}
		}
	case "aws_iam_role_policy_attachments_exclusive", "aws_iam_user_policy_attachments_exclusive", "aws_iam_group_policy_attachments_exclusive":
		arns, _ := after["policy_arns"].([]any)
		for _, a := range arns {
			arn, _ := a.(string)
			for _, p := range rules.AdminPolicies {
				if strings.HasSuffix(arn, ":policy/"+p) {
					out = append(out, rc.Address+": attaches "+p)
				}
			}
		}
	case "aws_ssoadmin_managed_policy_attachment":
		if arn, _ := after["managed_policy_arn"].(string); arn != "" {
			for _, p := range rules.AdminPolicies {
				if strings.HasSuffix(arn, ":policy/"+p) {
					out = append(out, rc.Address+": attaches "+p)
				}
			}
		}
	case "aws_lambda_permission":
		if p, _ := after["principal"].(string); p == "*" {
			out = append(out, rc.Address+": lets any principal invoke the function")
		}
	case "aws_lambda_function_url":
		if t, _ := after["authorization_type"].(string); strings.EqualFold(t, "NONE") {
			out = append(out, rc.Address+": a function URL without authorization")
		}
	case "aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy":
		if s, _ := after["policy"].(string); s != "" {
			for _, w := range policyWildcards(s) {
				out = append(out, rc.Address+": "+w)
			}
		}
	case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment":
		if arn, _ := after["policy_arn"].(string); arn != "" {
			for _, p := range rules.AdminPolicies {
				if strings.HasSuffix(arn, ":policy/"+p) {
					out = append(out, rc.Address+": attaches "+p)
				}
			}
		}
	}
	return out
}

type policyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

type statement struct {
	Effect       string          `json:"Effect"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Condition    json.RawMessage `json:"Condition"`
}

// restrictingKeys are the condition keys that limit who a statement
// reaches: the caller's account, organization, ARN or network, or the
// source of a service's request. A condition with none of them (a transport
// requirement, a tag, a time) leaves a "*" principal public.
var restrictingKeys = map[string]bool{"aws:principalorgid": true, "aws:principalorgpaths": true, "aws:principalarn": true,
	"aws:principalaccount": true, "aws:sourcearn": true, "aws:sourceaccount": true, "aws:sourceowner": true, "aws:sourceorgid": true,
	"aws:sourceorgpaths": true, "aws:sourcevpc": true, "aws:sourcevpce": true, "aws:sourceip": true, "aws:userid": true,
	"aws:username": true, "aws:resourceaccount": true, "aws:resourceorgid": true, "aws:principalservicename": true,
	"aws:principalservicenamelist": true, "kms:calleraccount": true, "kms:viaservice": true, "sts:externalid": true,
	"aws:federatedprovider": true, "cognito-identity.amazonaws.com:aud": true, "aws:vpcsourceip": true, "elasticfilesystem:accesspointarn": true,
	"lambda:eventsourcetoken": true, "s3:resourceaccount": true}

// restricts reports whether a Condition limits who the statement reaches: a
// positive operator on a limiting key with a value that is not a wildcard.
// A negative operator (StringNotEquals, NotIpAddress, ArnNotLike) names who
// is left out, everyone else being let in; a value of "*", a CIDR of the
// whole internet or an ARN pattern that matches every ARN limits nobody.
func restricts(raw json.RawMessage) bool {
	var cond map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &cond) != nil {
		var any1 map[string]any
		return json.Unmarshal(raw, &any1) == nil && len(any1) > 0 // an unreadable form: assume it restricts
	}
	for op, keys := range cond {
		lop := strings.ToLower(op)
		if strings.HasPrefix(lop, "null") || strings.Contains(lop, "not") {
			continue // Null tests whether a key is present; a negative operator excludes, it does not limit
		}
		if strings.HasSuffix(lop, "ifexists") || strings.HasPrefix(lop, "forallvalues") {
			continue // a request without the key passes IfExists, and an empty set passes ForAllValues
		}
		for k, vraw := range keys {
			if !restrictingKeys[strings.ToLower(k)] {
				continue
			}
			vals := stringsOf(vraw)
			if len(vals) == 0 {
				var b bool
				var n float64
				if json.Unmarshal(vraw, &b) == nil || json.Unmarshal(vraw, &n) == nil {
					return true
				}
				continue
			}
			// The values of one key are ORed: the key limits who is let in
			// only when every one of them does.
			limits := true
			for _, v := range vals {
				if v == "*" || v == "" || strings.Trim(v, "*?:/") == "" || wideCIDR(v) || strings.HasPrefix(v, "arn:aws:*") || v == "arn:aws:iam::*:*" || arnAnyAccount(v) {
					limits = false
					break
				}
			}
			if limits {
				return true
			}
		}
	}
	return false
}

// arnAnyAccount reports an ARN pattern whose account field is a wildcard: it
// matches the resources of every AWS account.
func arnAnyAccount(v string) bool {
	parts := strings.SplitN(v, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && strings.Trim(parts[4], "*?") == "" && parts[4] != ""
}

func statements(doc string) []statement {
	var d policyDoc
	if json.Unmarshal([]byte(doc), &d) != nil {
		return nil
	}
	var list []statement
	if json.Unmarshal(d.Statement, &list) != nil {
		var one statement
		if json.Unmarshal(d.Statement, &one) == nil {
			list = []statement{one}
		}
	}
	return list
}

func stringsOf(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// policyWildcards flags Allow statements with "*" or "service:*" actions.
// Resource "*" alone is common and is not flagged.
func policyWildcards(doc string) []string {
	var out []string
	for _, s := range statements(doc) {
		if s.Effect != "Allow" {
			continue
		}
		for _, a := range stringsOf(s.Action) {
			// Any action pattern whose part after the service is only
			// wildcards (*, ?*, **, *?) matches every action of it.
			_, act, _ := strings.Cut(a, ":")
			if a == "*" || act != "" && strings.Trim(act, "*?") == "" && strings.Contains(act, "*") || strings.Trim(a, "*?") == "" && a != "" {
				out = append(out, "IAM policy allows wildcard action "+a)
			}
		}
		if len(s.NotAction) > 0 {
			// Allow with NotAction allows every action but the listed ones.
			out = append(out, "IAM policy allows every action except "+strings.Join(stringsOf(s.NotAction), ", "))
		}
	}
	return out
}

func policyPublic(doc string) bool {
	for _, s := range statements(doc) {
		if s.Effect != "Allow" {
			continue
		}
		// A Condition that names no key limiting who is reached (an empty
		// one, SecureTransport, a tag) leaves the statement public.
		if len(s.Condition) > 0 && restricts(s.Condition) {
			continue
		}
		// Allow with NotPrincipal reaches everyone but the listed ones.
		if anyPrincipal(s.Principal) || len(s.NotPrincipal) > 0 && string(s.NotPrincipal) != "null" {
			return true
		}
	}
	return false
}

// anyPrincipal reports whether a Principal is "*", or names "*" for any
// kind (AWS, Service, Federated), alone or in a list.
func anyPrincipal(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == "*"
	}
	var byKind map[string]json.RawMessage
	if json.Unmarshal(raw, &byKind) != nil {
		return false
	}
	for _, v := range byKind {
		for _, p := range stringsOf(v) {
			if p == "*" {
				return true
			}
		}
	}
	return false
}

// wideCIDR reports whether a CIDR covers the whole internet or a large
// part of it: 0.0.0.0/0, or a split such as 0.0.0.0/1 and 128.0.0.0/1.
func wideCIDR(c string) bool {
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		return false
	}
	ones, bits := n.Mask.Size()
	if bits == 32 {
		return ones <= 4
	}
	return ones <= 16
}

// lookup reads a dotted path ("a.0.b") from planned values.
func lookup(m map[string]any, p string) (any, bool) {
	if m == nil {
		return nil, false
	}
	var cur any = m
	for _, part := range strings.Split(p, ".") {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[part]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, cur != nil
}

func equal(v, want any) bool {
	if a, ok := num(v); ok {
		if b, ok := num(want); ok {
			return a == b
		}
	}
	return fmt.Sprint(v) == fmt.Sprint(want)
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// without returns the items of list that are not in drop.
func without(list, drop []string) []string {
	if len(drop) == 0 {
		return list
	}
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	var out []string
	for _, s := range list {
		if !skip[s] {
			out = append(out, s)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func firstString(after, before map[string]any, keys ...string) string {
	for _, m := range []map[string]any{after, before} {
		for _, k := range keys {
			if s, ok := m[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// isProtected matches an address against protected_resources with the
// instance keys of count and for_each left out on both sides, so
// aws_instance.bastion covers aws_instance.bastion[0] and module.data covers
// module.data["eu"].aws_s3_bucket.b.
func isProtected(addr string, patterns []string) bool {
	bare := stripKeys(addr)
	for _, p := range patterns {
		bp := stripKeys(p)
		if inScope(addr, []string{p}) || inScope(bare, []string{bp}) || bare == bp || strings.HasPrefix(bare, bp+".") {
			return true
		}
	}
	return false
}

func inScope(addr string, scope []string) bool {
	for _, s := range scope {
		if ok, _ := path.Match(s, addr); ok || strings.HasPrefix(addr, strings.TrimSuffix(s, "*")) && strings.HasSuffix(s, "*") {
			return true
		}
	}
	return false
}
