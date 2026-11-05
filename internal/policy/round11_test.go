package policy

import (
	"path/filepath"
	"testing"
)

const stateBucketRepo = `version: 1
mode: enforce
strict: false
default_tier: disposable
name_hints: false
environments:
  - name: prod
    tier: protected
    match:
      paths: ["envs/prod/**"]
      backends: ["s3://acme-tf-state-prod/*"]
`

func TestS3WriteToAStateBucketIsStateSurgery(t *testing.T) {
	root := writeRepo(t, stateBucketRepo, "envs/dev", "envs/prod")
	cfg := loadCfg(t, "", root)
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent"}}
	dev := filepath.Join(root, "envs/dev")
	claude := func(cmd string) Decision {
		return Decide(Event{Agent: "claude", Tool: "Bash", Kind: KindShell, Command: cmd, Cwd: dev, CanAsk: true, DirKnown: true}, cfg, deps)
	}
	for _, cmd := range []string{
		"aws s3 mv s3://acme-tf-state-prod/prod/network s3://elsewhere/x",
		"aws s3 cp /dev/null s3://acme-tf-state-prod/prod/network",
		"aws s3api put-object --bucket acme-tf-state-prod --key prod/network --body /dev/null",
		"aws s3 rm s3://acme-tf-state-prod/prod/network",
	} {
		d := claude(cmd)
		if d.Verdict == Allow || d.Actions[0].Class != "state-surgery" {
			t.Errorf("%s: %s %s (%v)", cmd, d.Verdict, d.Actions[0].Class, d.Actions[0].Matched)
		}
	}
	// Another bucket is ordinary work in a disposable directory.
	if d := claude("aws s3 cp x s3://scratch/x"); d.Verdict != Allow {
		t.Errorf("scratch bucket: %s", d.Verdict)
	}
}

func TestRelativeCdFromAnUnreportedDirectoryIsUnknown(t *testing.T) {
	root := writeRepo(t, mixedRepo, "examples/simple", "envs/prod")
	cfg := loadCfg(t, "", root)
	deps := Deps{Env: map[string]string{"PATH": "/nonexistent"}}
	for _, cmd := range []string{"cd examples/simple && terraform destroy -auto-approve", "terraform -chdir=examples/simple destroy -auto-approve",
		"cd examples; cd simple && terraform destroy -auto-approve", "env -C examples/simple terraform destroy -auto-approve", "make -C examples/simple destroy"} {
		d := Decide(codexEvent(cmd, root), cfg, deps)
		if d.Verdict == Allow {
			t.Errorf("%s: allowed from an unreported directory", cmd)
		}
	}
}
