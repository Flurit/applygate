package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const trialLog = "../../review/agent-trial/results/2026-10-29-both/decisions.jsonl"

func TestSuggestPrintsAProposalForTheRoot(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cmdSuggest([]string{"--log", trialLog, "--root", "/work/terraform-aws-vpc"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	y := out.String()
	for _, want := range []string{"version: 1", "mode: observe", "- name: examples", "paths: [\"examples/**\"]", "max_destroy: {protected: 0}"} {
		if !strings.Contains(y, want) {
			t.Errorf("missing %q in:\n%s", want, y)
		}
	}
	if !strings.Contains(errb.String(), "169 decisions read") || !strings.Contains(errb.String(), "34 in /work/terraform-aws-vpc") {
		t.Errorf("summary: %s", errb.String())
	}
}

func TestSuggestWritesOnceAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".applygate.yaml")
	var out, errb bytes.Buffer
	if code := cmdSuggest([]string{"--log", trialLog, "--root", "/work/govuk-infrastructure", "--out", target}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "terraform/deployments/ecr/**") || !strings.Contains(out.String(), "wrote "+target) {
		t.Fatalf("file:\n%s\nstdout: %s", b, out.String())
	}
	out.Reset()
	errb.Reset()
	if code := cmdSuggest([]string{"--log", trialLog, "--root", "/work/govuk-infrastructure", "--out", target}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "not overwriting") {
		t.Fatalf("second write: exit %d, stderr %s", code, errb.String())
	}
	if b2, _ := os.ReadFile(target); !bytes.Equal(b, b2) {
		t.Fatal("the existing file changed")
	}
}

func TestSuggestWithNoDecisionsForTheRoot(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cmdSuggest([]string{"--log", trialLog, "--root", t.TempDir()}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "none under") || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %s", code, out.String(), errb.String())
	}
}
