package suggest

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/policy"
)

// The agent-driven trial log: five public repositories under /work, Claude
// Code and Codex in observe mode, 169 decisions.
const trialLog = "../../review/agent-trial/results/2026-10-29-both/decisions.jsonl"

func loadTrial(t *testing.T) []decisionlog.Entry {
	t.Helper()
	f, err := os.Open(trialLog)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, bad := decisionlog.Read(f)
	if bad != 0 || len(entries) != 169 {
		t.Fatalf("read %d entries, %d malformed", len(entries), bad)
	}
	return entries
}

func env(p *Proposal, name string) *Env {
	for i := range p.Envs {
		if p.Envs[i].Name == name {
			return &p.Envs[i]
		}
	}
	return nil
}

func TestHints(t *testing.T) {
	cases := []struct {
		v    string
		tier config.Tier
		ok   bool
	}{
		{"prod", config.Protected, true},
		{"envs/production/eu-west-1", config.Protected, true},
		{"non-prod", config.Standard, true},
		{"pre-prod", config.Standard, true},
		{"staging", config.Standard, true},
		{"qa", config.Standard, true},
		{"examples", config.Disposable, true},
		{"dev-sandbox", config.Disposable, true},
		{"prod-test", config.Disposable, true}, // the production word is cancelled; test remains
		{"vpc", "", false},
		{"terraform/deployments/ecr", "", false},
		{"products", "", false},
	}
	for _, c := range cases {
		tier, ok := hint(c.v)
		if ok != c.ok || tier != c.tier {
			t.Errorf("hint(%q) = %s,%v; want %s,%v", c.v, tier, ok, c.tier, c.ok)
		}
	}
}

func TestDirHintPicksTheMostProtectedComponent(t *testing.T) {
	glob, name, tier, ok := dirHint("non-prod/us-east-1/stage/webserver-cluster")
	if !ok || glob != "non-prod/**" || name != "non-prod" || tier != config.Standard {
		t.Fatalf("got %q %q %s %v", glob, name, tier, ok)
	}
	glob, name, tier, _ = dirHint("envs/staging/prod-replica/db")
	if glob != "envs/staging/prod-replica/**" || name != "prod-replica" || tier != config.Protected {
		t.Fatalf("a deeper production word must win: got %q %q %s", glob, name, tier)
	}
	if _, _, _, ok := dirHint("terraform/aws-accounts/cloud-platform-aws/vpc"); ok {
		t.Fatal("a path with no hint word must not be classified")
	}
}

func TestBuildTerragruntLiveExample(t *testing.T) {
	p := Build(loadTrial(t), Options{Root: "/work/terragrunt-infrastructure-live-example", Now: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)})
	if p.InScope != 39 || p.WouldFlag != 2 {
		t.Fatalf("in scope %d, would flag %d", p.InScope, p.WouldFlag)
	}
	if strings.Join(p.Agents, ",") != "claude,codex" {
		t.Fatalf("agents %v", p.Agents)
	}
	prod := env(p, "prod")
	if prod == nil || prod.Tier != config.Protected || strings.Join(prod.Paths, ",") != "prod/**" {
		t.Fatalf("prod environment: %+v", prod)
	}
	nonprod := env(p, "non-prod")
	if nonprod == nil || nonprod.Tier != config.Standard || strings.Join(nonprod.Paths, ",") != "non-prod/**" {
		t.Fatalf("non-prod environment: %+v", nonprod)
	}
	if p.Envs[0].Name != "prod" {
		t.Fatalf("most protected first, got %s", p.Envs[0].Name)
	}
	if len(p.Unclassified) != 0 || p.RootRuns != 2 {
		t.Fatalf("unclassified %v, root runs %d", p.Unclassified, p.RootRuns)
	}
	if len(p.Flags) != 1 || p.Flags[0].Class != "dynamic" || !strings.Contains(p.Flags[0].Advice, "interpreter") {
		t.Fatalf("flags %+v", p.Flags)
	}
	y := p.YAML()
	for _, want := range []string{"39 of them in /work/terragrunt-infrastructure-live-example", "mode: observe", "paths: [\"prod/**\"]", "2 in non-prod/us-east-1/stage/webserver-cluster", "ran 2 times at the repository root", "1x ask   dynamic"} {
		if !strings.Contains(y, want) {
			t.Errorf("YAML lacks %q:\n%s", want, y)
		}
	}
	if err := p.Check(); err != nil {
		t.Fatalf("proposal does not parse: %v\n%s", err, y)
	}
}

func TestBuildLeavesUnhintedDirectoriesToThePerson(t *testing.T) {
	p := Build(loadTrial(t), Options{Root: "/work/cloud-platform-infrastructure"})
	if len(p.Envs) != 0 {
		t.Fatalf("no name says anything here, yet %d environments were proposed: %+v", len(p.Envs), p.Envs)
	}
	// vpc/eks sits under vpc, so one commented entry covers both: 10 + 5.
	if len(p.Unclassified) != 1 || p.Unclassified[0].Rel != "terraform/aws-accounts/cloud-platform-aws/vpc" || p.Unclassified[0].Runs != 15 {
		t.Fatalf("unclassified %+v", p.Unclassified)
	}
	if len(p.Loose) != 2 || !strings.HasPrefix(p.Loose[0], "backend s3://cloud-platform-terraform-state/") || !strings.HasPrefix(p.Loose[1], "profile moj-cp") {
		t.Fatalf("loose signals %v", p.Loose)
	}
	y := p.YAML()
	if !strings.Contains(y, "environments:   # none proposed") || !strings.Contains(y, "#    match: {paths: [\"terraform/aws-accounts/cloud-platform-aws/vpc/**\"]}   # 15 engine commands") {
		t.Fatalf("YAML:\n%s", y)
	}
	if strings.Contains(y, "\n  - name:") {
		t.Fatal("an unhinted directory must stay commented out")
	}
	if err := p.Check(); err != nil {
		t.Fatalf("proposal does not parse: %v\n%s", err, y)
	}
	cfg, err := loadYAML(t, y)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsStrict() || len(cfg.Environments) != 0 {
		t.Fatalf("the written file must keep every directory protected: strict %v, %d environments", cfg.IsStrict(), len(cfg.Environments))
	}
}

func TestBuildKeepsTheExistingConfig(t *testing.T) {
	root := "/work/terraform-aws-vpc"
	entries := loadTrial(t)
	fresh := Build(entries, Options{Root: root})
	ex := env(fresh, "examples")
	if ex == nil || ex.Tier != config.Disposable || ex.Paths[0] != "examples/**" || ex.Existing {
		t.Fatalf("without a config, examples is proposed: %+v", ex)
	}

	existing := &config.Config{Root: root, Mode: "enforce", OnError: "auto",
		Environments:       []config.Environment{{Name: "examples", Tier: config.Disposable, Match: config.Match{Paths: []string{root + "/examples/**"}, Workspaces: []string{"ex-*"}}}},
		PlanGate:           config.PlanGate{MaxDestroy: map[config.Tier]int{config.Protected: 0, config.Standard: 3}},
		ProtectedResources: []string{"module.data.*"},
		Wrappers:           []config.Wrapper{{Name: "runit", Skip: 1}},
	}
	p := Build(entries, Options{Root: root, Existing: existing})
	if len(p.Envs) != 1 || !p.Envs[0].Existing || p.Envs[0].Paths[0] != "examples/**" || p.Envs[0].Workspaces[0] != "ex-*" {
		t.Fatalf("the existing environment must be carried over, relative to the root, and not proposed again: %+v", p.Envs)
	}
	if len(p.Unclassified) != 0 || p.RootRuns != 12 {
		t.Fatalf("unclassified %v, root runs %d", p.Unclassified, p.RootRuns)
	}
	y := p.YAML()
	for _, want := range []string{"mode: enforce", "# from the existing config", "max_destroy: {protected: 0, standard: 3}", "protected_resources: [\"module.data.*\"]", "- {name: runit, skip: 1, profile_arg: 0}"} {
		if !strings.Contains(y, want) {
			t.Errorf("YAML lacks %q:\n%s", want, y)
		}
	}
	if err := p.Check(); err != nil {
		t.Fatalf("proposal does not parse: %v\n%s", err, y)
	}
}

func TestBuildIgnoresOtherRepositoriesAndScratchDirectories(t *testing.T) {
	p := Build(loadTrial(t), Options{Root: "/work/govuk-infrastructure"})
	if p.InScope != 41 {
		t.Fatalf("in scope %d", p.InScope)
	}
	for _, d := range p.Unclassified {
		if strings.Contains(d.Rel, "..") || strings.HasPrefix(d.Rel, "/") {
			t.Fatalf("directory outside the root leaked in: %q", d.Rel)
		}
	}
	if len(p.Loose) != 0 {
		t.Fatalf("a cloud:// backend is not a signal to list: %v", p.Loose)
	}
	if len(p.Flags) != 2 || p.Flags[0].Class != "state-surgery" || !strings.Contains(p.Flags[0].Advice, "judged as protected because no environment matched") {
		t.Fatalf("flags %+v", p.Flags)
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestBuildWithNothingInScope(t *testing.T) {
	p := Build(loadTrial(t), Options{Root: "/elsewhere"})
	if p.InScope != 0 || len(p.Envs) != 0 || len(p.Flags) != 0 {
		t.Fatalf("%+v", p)
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestWrapperHint(t *testing.T) {
	entries := []decisionlog.Entry{{Time: time.Now(), Agent: "claude", Cwd: "/repo", Verdict: policy.Ask, Enforced: policy.Allow, Mode: "observe",
		Actions: []policy.ActionResult{{Class: classify.UnknownWrapper, Engine: "terraform", Command: "company-run prod terraform apply", Dir: "/repo/envs/prod", Tier: config.Protected, Env: "prod", Verdict: policy.Ask}}}}
	p := Build(entries, Options{Root: "/repo"})
	if len(p.Wrappers) != 1 || p.Wrappers[0] != "company-run" {
		t.Fatalf("wrappers %v", p.Wrappers)
	}
	if e := env(p, "prod"); e == nil || e.Paths[0] != "envs/prod/**" {
		t.Fatalf("envs %+v", p.Envs)
	}
	y := p.YAML()
	if !strings.Contains(y, "#   - {name: company-run, skip: 1}") || !strings.Contains(y, "add it under wrappers") {
		t.Fatalf("YAML:\n%s", y)
	}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
}

func loadYAML(t *testing.T, y string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/" + config.FileName
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		return nil, err
	}
	return config.LoadFile(path)
}

func TestBuildProposesClusterAndCloudTargets(t *testing.T) {
	act := func(engine, ctx, project, sub string) policy.ActionResult {
		return policy.ActionResult{Class: classify.CloudDestructive, Engine: engine, Dir: "/r/k8s", Tier: config.Protected, Env: "unknown",
			KubeContext: ctx, GCPProject: project, AzureSubscription: sub, Verdict: policy.Block, Command: engine + " delete x"}
	}
	entries := []decisionlog.Entry{
		{Cwd: "/r", Actions: []policy.ActionResult{act("kubectl", "prod-eks", "", "")}},
		{Cwd: "/r", Actions: []policy.ActionResult{act("kubectl", "kind-dev", "", "")}},
		{Cwd: "/r", Actions: []policy.ActionResult{act("gcloud", "", "acme-payments-prod", "")}},
		{Cwd: "/r", Actions: []policy.ActionResult{act("az", "", "", "Payments")}},
	}
	p := Build(entries, Options{Root: "/r"})
	y := p.YAML()
	if !strings.Contains(y, `kube_contexts: ["prod-eks"]`) || !strings.Contains(y, `gcp_projects: ["acme-payments-prod"]`) || !strings.Contains(y, `kube_contexts: ["kind-dev"]`) {
		t.Fatalf("YAML:\n%s", y)
	}
	// A subscription whose name says nothing is left for the person.
	if !strings.Contains(strings.Join(p.Loose, "\n"), "Azure subscription Payments") {
		t.Fatalf("loose %v", p.Loose)
	}
	if err := p.Check(); err != nil {
		t.Fatalf("proposal does not parse: %v\n%s", err, y)
	}
}
