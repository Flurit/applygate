package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/plangate"
)

type planChange struct {
	addr, typ     string
	actions       []string
	before, after map[string]any
}

func showJSON(changes ...planChange) func(string, string, string) ([]byte, error) {
	return func(string, string, string) ([]byte, error) {
		var list []map[string]any
		for _, c := range changes {
			list = append(list, map[string]any{"address": c.addr, "mode": "managed", "type": c.typ, "name": "x",
				"change": map[string]any{"actions": c.actions, "before": c.before, "after": c.after}})
		}
		return json.Marshal(map[string]any{"format_version": "1.2", "resource_changes": list})
	}
}

// applyIn decides `terraform apply tfplan` with the workspace selected, in a
// directory whose config makes prod protected, staging standard and dev
// disposable. extra lines go to the repository config and user lines to a
// user config, which alone may loosen a setting.
func applyIn(t *testing.T, workspace string, extra, user []string, plan func(string, string, string) ([]byte, error)) ActionResult {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".terraform"), 0o755)
	os.WriteFile(filepath.Join(dir, ".terraform", "environment"), []byte(workspace), 0o644)
	lines := append([]string{
		"mode: enforce",
		"strict: false",
		"name_hints: false",
		"default_tier: disposable",
		"environments:",
		"  - name: prod",
		"    tier: protected",
		"    match: {workspaces: [prod]}",
		"  - name: staging",
		"    tier: standard",
		"    match: {workspaces: [staging]}",
		"  - name: dev",
		"    tier: disposable",
		"    match: {workspaces: [dev]}",
	}, extra...)
	os.WriteFile(filepath.Join(dir, config.FileName), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	writePlanfile(t, filepath.Join(dir, "tfplan"), workspace)
	userPath := ""
	if len(user) > 0 {
		userPath = filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(userPath, []byte(strings.Join(user, "\n")+"\n"), 0o600)
	}
	cfg, err := config.Load(userPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	d := Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: "terraform apply tfplan", Cwd: dir, CanAsk: true, DirKnown: true},
		cfg, Deps{Env: map[string]string{"PATH": "/nonexistent"}, PlanJSON: plan})
	if len(d.Actions) != 1 {
		t.Fatalf("got %d actions, want 1: %+v", len(d.Actions), d.Actions)
	}
	return d.Actions[0]
}

func hasFinding(a ActionResult, rule string) bool {
	for _, f := range a.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// A plan whose only deletes and replaces are routine replaces is allowed in
// a standard tier and still blocked in a protected one; anything else in the
// plan that destroys keeps the plan a destroy.
func TestRoutineReplaceByTier(t *testing.T) {
	replace := []string{"delete", "create"}
	lt := planChange{"aws_launch_template.app", "aws_launch_template", replace, map[string]any{}, map[string]any{}}
	td := planChange{"module.svc.aws_ecs_task_definition.app", "aws_ecs_task_definition", []string{"create", "delete"}, map[string]any{}, map[string]any{}}
	instance := planChange{"aws_instance.web", "aws_instance", replace, map[string]any{}, map[string]any{}}
	ltDelete := planChange{"aws_launch_template.old", "aws_launch_template", []string{"delete"}, map[string]any{}, nil}
	dbUnprotected := planChange{"aws_db_instance.db", "aws_db_instance", []string{"update"}, map[string]any{"deletion_protection": true}, map[string]any{"deletion_protection": false}}

	cases := []struct {
		name      string
		workspace string
		extra     []string
		user      []string
		plan      []planChange
		verdict   Verdict
		class     classify.Class
		finding   string // a rule that must be among the findings, "" for none required
	}{
		{"standard allows", "staging", nil, nil, []planChange{lt, td}, Allow, classify.RoutineReplace, ""},
		{"disposable allows", "dev", nil, nil, []planChange{lt, td}, Allow, classify.RoutineReplace, ""},
		{"protected blocks", "prod", nil, nil, []planChange{lt, td}, Block, classify.RoutineReplace, "destroy-count"},
		{"protected blocks with the destroy limit raised", "prod", nil, []string{"plan_gate:", "  max_destroy: {protected: 5}"}, []planChange{lt, td}, Block, classify.RoutineReplace, ""},
		{"beside an unlisted replace it is a destroy", "staging", nil, nil, []planChange{lt, instance}, Ask, classify.Destroy, ""},
		{"beside a delete it is a destroy", "staging", nil, nil, []planChange{lt, ltDelete}, Ask, classify.Destroy, ""},
		{"protected_resources brings the ask back", "staging", []string{`protected_resources: ["aws_launch_template.app"]`}, nil, []planChange{lt}, Ask, classify.Destroy, "protected-resource"},
		{"protected_resources matches inside a module with a leading star", "staging", []string{`protected_resources: ["*aws_ecs_task_definition.app"]`}, nil, []planChange{td}, Ask, classify.Destroy, "protected-resource"},
		{"an unrelated critical finding still asks", "staging", nil, nil, []planChange{lt, dbUnprotected}, Ask, classify.RoutineReplace, "protection-removed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := applyIn(t, c.workspace, c.extra, c.user, showJSON(c.plan...))
			if a.Verdict != c.verdict || a.Class != c.class {
				t.Fatalf("verdict %s class %s, want %s %s; why %q; findings %+v", a.Verdict, a.Class, c.verdict, c.class, a.Why, a.Findings)
			}
			if c.finding != "" && !hasFinding(a, c.finding) {
				t.Errorf("no %s finding: %+v", c.finding, a.Findings)
			}
			if c.name == "protected blocks with the destroy limit raised" && hasFinding(a, "destroy-count") {
				t.Errorf("destroy-count with the limit at 5: %+v", a.Findings)
			}
			if c.class == classify.RoutineReplace && !strings.Contains(a.Why, "replaced on routine change") {
				t.Errorf("why %q does not say the replaces are routine", a.Why)
			}
		})
	}

	// When a finding, not the class, is what asks, the next step is about the
	// findings; when the class blocks, it is about the replace.
	asked := applyIn(t, "staging", nil, nil, showJSON(lt, dbUnprotected))
	if !strings.Contains(asked.NextStep, "Show the findings") {
		t.Errorf("next step for a finding: %q", asked.NextStep)
	}
	blocked := applyIn(t, "prod", nil, nil, showJSON(lt))
	if !strings.Contains(blocked.NextStep, "Replacing resources in a protected environment needs a human") {
		t.Errorf("next step for the protected block: %q", blocked.NextStep)
	}
}

func TestSavedPlanClass(t *testing.T) {
	cases := []struct {
		name string
		res  plangate.Result
		want classify.Class
	}{
		{"no deletes or replaces", plangate.Result{Changes: 3}, classify.ApplySavedPlan},
		{"a delete", plangate.Result{Deletes: []string{"a"}}, classify.Destroy},
		{"a replace that is not routine", plangate.Result{Replaces: []string{"a"}}, classify.Destroy},
		{"only routine replaces", plangate.Result{Replaces: []string{"a", "b"}, RoutineReplaces: []string{"a", "b"}}, classify.RoutineReplace},
		{"one of two replaces is routine", plangate.Result{Replaces: []string{"a", "b"}, RoutineReplaces: []string{"a"}}, classify.Destroy},
		{"a routine replace and a delete", plangate.Result{Deletes: []string{"c"}, Replaces: []string{"a"}, RoutineReplaces: []string{"a"}}, classify.Destroy},
	}
	for _, c := range cases {
		if got := SavedPlanClass(&c.res); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// plan-check and the hook agree: the verdict of a routine-only plan.
	routine := &plangate.Result{Replaces: []string{"a"}, RoutineReplaces: []string{"a"}}
	for tier, want := range map[config.Tier]Verdict{config.Protected: Block, config.Standard: Allow, config.Disposable: Allow} {
		if got := SavedPlanVerdict(routine, tier); got != want {
			t.Errorf("SavedPlanVerdict in %s: %s, want %s", tier, got, want)
		}
	}
}

// Every class in the table has a verdict for every tier: a missing cell is
// the zero value, which is allow.
func TestTableRowsAreComplete(t *testing.T) {
	if _, ok := Table[classify.RoutineReplace]; !ok {
		t.Fatal("routine-replace has no row")
	}
	for class, row := range Table {
		for _, tier := range []config.Tier{config.Protected, config.Standard, config.Disposable} {
			if _, ok := row[tier]; !ok {
				t.Errorf("%s has no verdict for %s", class, tier)
			}
		}
	}
}
