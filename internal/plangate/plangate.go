// Package plangate evaluates the JSON form of a saved Terraform or OpenTofu
// plan ("terraform show -json tfplan") against AWS-first rules.
package plangate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"

	"github.com/Flurit/seatbelt/internal/preflight"
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
	Backend    *preflight.Backend
}

// Result of evaluating a plan.
type Result struct {
	Findings []preflight.Finding
	Deletes  []string // pure deletes
	Replaces []string
	Changes  int
}

// Evaluate parses and checks the plan.
func Evaluate(in Input, rules *Rules) (*Result, error) {
	var p tfjson.Plan
	if err := json.Unmarshal(in.PlanJSON, &p); err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	res := &Result{}
	var stateful, protection, exposure, stateInfra, outOfScope []string
	var crit = func(list *[]string, s string) { *list = append(*list, s) }

	for _, rc := range p.ResourceChanges {
		if rc == nil || rc.Change == nil || rc.Mode == tfjson.DataResourceMode {
			continue
		}
		acts := rc.Change.Actions
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

		if (del || repl) && rules.stateful[rc.Type] {
			verb := "destroyed"
			if repl {
				verb = "replaced"
			}
			crit(&stateful, rc.Address+" ("+rc.Type+") is "+verb)
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
		if !del {
			exposure = append(exposure, exposed(rc, after, rules)...)
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
	add("stateful-destroyed", preflight.Critical, "plan destroys or replaces stateful resources", stateful)
	add("protection-removed", preflight.Critical, "plan removes data protection", protection)
	add("exposure", preflight.High, "plan exposes resources", exposure)
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

// exposed returns exposure findings for a resource's planned values.
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
				if v == "0.0.0.0/0" || v == "::/0" {
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
		for _, port := range rules.AdminPorts {
			if float64(port) >= f && float64(port) <= t {
				return "port " + strconv.Itoa(port), true
			}
		}
		return "", false
	}
	switch rc.Type {
	case "aws_security_group":
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
		if acl, _ := after["acl"].(string); acl == "public-read" || acl == "public-read-write" {
			out = append(out, rc.Address+": bucket ACL "+acl)
		}
	case "aws_s3_bucket_policy":
		if s, _ := after["policy"].(string); policyPublic(s) {
			out = append(out, rc.Address+": bucket policy allows any principal")
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
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
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
			if a == "*" || strings.HasSuffix(a, ":*") {
				out = append(out, "IAM policy allows wildcard action "+a)
			}
		}
	}
	return out
}

func policyPublic(doc string) bool {
	for _, s := range statements(doc) {
		if s.Effect != "Allow" || len(s.Condition) > 0 {
			continue
		}
		p := strings.ReplaceAll(string(s.Principal), " ", "")
		if p == `"*"` || strings.Contains(p, `"AWS":"*"`) || strings.Contains(p, `"AWS":["*"]`) {
			return true
		}
	}
	return false
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

func inScope(addr string, scope []string) bool {
	for _, s := range scope {
		if ok, _ := path.Match(s, addr); ok || strings.HasPrefix(addr, strings.TrimSuffix(s, "*")) && strings.HasSuffix(s, "*") {
			return true
		}
	}
	return false
}
