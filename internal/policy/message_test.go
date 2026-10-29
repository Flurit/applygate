package policy

import (
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/classify"
)

func TestMessageAudienceSplit(t *testing.T) {
	action := ActionResult{
		Class:    classify.StateSurgery,
		Command:  "terraform state rm aws_s3_bucket.x",
		Why:      "state surgery",
		Verdict:  Ask,
		Tier:     "standard",
		Env:      "staging",
		NextStep: nextStep(classify.StateSurgery, "terraform"),
	}

	// Enforced ask -> human prompt: human-facing line, no agent "Next step".
	ask := message(Decision{Verdict: Ask, Enforced: Ask, Actions: []ActionResult{action}})
	if !strings.Contains(ask, "needs your approval") {
		t.Fatalf("ask prompt should be human-facing: %q", ask)
	}
	if strings.Contains(ask, "Next step") {
		t.Fatalf("ask prompt must not carry agent-facing Next step text: %q", ask)
	}

	// Enforced block -> agent: keeps "Next step", no human approval line.
	block := action
	block.Verdict = Block
	blk := message(Decision{Verdict: Block, Enforced: Block, Actions: []ActionResult{block}})
	if !strings.Contains(blk, "Next step") {
		t.Fatalf("block should keep agent-facing Next step: %q", blk)
	}
	if strings.Contains(blk, "needs your approval") {
		t.Fatalf("block must not carry the human approval line: %q", blk)
	}

	// ask converted to block (agent cannot prompt) -> agent-facing.
	conv := message(Decision{Verdict: Ask, Enforced: Block, Actions: []ActionResult{block}})
	if !strings.Contains(conv, "Next step") || strings.Contains(conv, "needs your approval") {
		t.Fatalf("converted ask->block should be agent-facing: %q", conv)
	}
}
