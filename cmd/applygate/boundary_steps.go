package main

import (
	"fmt"
	"slices"

	"github.com/Flurit/applygate/internal/scan"
)

// The steps of the boundary report (docs/boundary.md, "Steps between
// levels"). A step is closed by a person, never by applygate: it changes
// nothing. A check that is not ok carries the id of the step that closes it,
// set where the check is made, so no step is chosen by matching the words of
// an error from a cloud. Several checks may name one step; the report prints
// it once and lists the credentials it is about.
const (
	stepManagedInstall    = "managed-install"
	stepManagedFix        = "managed-fix"
	stepAgentCLI          = "agent-cli-root-owned"
	stepAWSReadOnly       = "aws-read-only"
	stepAWSSimulatorGrant = "aws-simulator-grant"
	stepKubeView          = "kube-view"
	stepGCPViewer         = "gcp-viewer"
	stepAzReader          = "az-reader"
	stepAWSCLI            = "aws-cli"
	stepNotChecked        = "not-checked"
	stepNameEnvs          = "name-environments"
	stepCredentialFile    = "credential-file"
	stepNothingAudited    = "nothing-audited"
	stepRunAudit          = "run-audit"
	stepWhoApplies        = "who-applies"
	stepSandbox           = "sandbox"
	stepAttest            = "attest"
	stepAttestName        = "attest-name"
	stepL3Pointers        = "l3-pointers"
)

type stepDef struct {
	level int
	title string
	lines []string
}

// stepOrder is the order the report prints steps in: by level, then as listed.
var stepOrder = []string{
	stepManagedInstall, stepManagedFix, stepAgentCLI,
	stepRunAudit, stepAWSReadOnly, stepAWSSimulatorGrant, stepKubeView, stepGCPViewer, stepAzReader,
	stepAWSCLI, stepNotChecked, stepNameEnvs, stepNothingAudited, stepCredentialFile, stepWhoApplies,
	stepSandbox, stepAttest, stepAttestName,
}

var stepTable = map[string]stepDef{
	stepManagedInstall: {1, "Install a managed, exclusive copy of applygate (there is no managed install)", []string{
		"/usr/bin/sudo /path/to/verified/applygate install --managed --exclusive",
		"Use a release you verified (docs/install.md), by its full path. Repository configs must be trusted again afterwards,",
		"and your user config may only tighten. The agent's user must not be able to run sudo without a password (docs/managed.md).",
	}},
	stepManagedFix: {1, "Repair the managed install (the lines above say what failed)", []string{
		"Run the install again from a verified release, by its full path: it replaces the managed binary and keeps the system",
		"config and the trust store. Then run applygate doctor from the managed binary (docs/managed.md).",
	}},
	stepAgentCLI: {1, "Install the agent CLI root-owned", []string{
		"Claude Code and Codex read the managed settings, so a copy your user can replace can be swapped for one that ignores them.",
		"Install it from a system package, or from an npm prefix that root owns (docs/managed.md, \"What it does not cover\").",
	}},
	stepRunAudit: {2, "Ask the cloud what the credentials here can do", []string{
		"applygate scan --boundary, or applygate doctor --boundary, asks AWS, Google Cloud, Azure and the clusters, read-only,",
		"with the credentials it audits (docs/credentials.md).",
	}},
	stepAWSReadOnly: {2, "Give the agent a read-only AWS role in place of these identities", []string{
		"Point the agent's production profile at a role that can read and plan, and read the state, and change nothing",
		"(docs/credentials.md, \"Setting it up on AWS\", step 1; examples/boundary/aws-agent-readonly.json). An identity that can",
		"change production without MFA is what a wrong verdict would reach.",
	}},
	stepAWSSimulatorGrant: {2, "Let the audit see these AWS identities", []string{
		"AWS refused a call the audit makes as the identity it audits. Allow iam:SimulatePrincipalPolicy on the identity's own ARN",
		"(for a role, also iam:GetRole), or check it by hand (docs/credentials.md, \"When AWS refuses the simulator call\").",
		"A refusal says nothing about what the identity can delete.",
	}},
	stepKubeView: {2, "Bind the agent's Kubernetes identity to the view role", []string{
		"In production clusters, bind the identity the agent uses to the built-in view ClusterRole, and put writes behind a",
		"context whose credentials need a person (docs/credentials.md, \"Kubernetes\"; examples/boundary/k8s-agent-view.yaml).",
	}},
	stepGCPViewer: {2, "Narrow the agent's Google Cloud access", []string{
		"Give the agent's account roles/viewer, and roles/storage.objectViewer on the state bucket. Apply through service-account",
		"impersonation that only a person may use, and do not grant the agent roles/iam.serviceAccountTokenCreator or",
		"roles/iam.serviceAccountUser on the apply account (docs/credentials.md, \"Google Cloud and Azure\";",
		"examples/boundary/gcp-agent-viewer.sh).",
	}},
	stepAzReader: {2, "Narrow the agent's Azure access", []string{
		"Give the agent Reader on production subscriptions. Contributor or Owner comes only through Privileged Identity Management",
		"activation by a person, with MFA. Roles that are eligible and not active are not seen by the audit (docs/credentials.md;",
		"examples/boundary/azure-agent-reader.sh).",
	}},
	stepAWSCLI: {2, "Make the aws CLI available to this command", []string{
		"applygate could not run aws, so it audited no AWS profile. A missing aws is reported as not checked, not as no AWS credentials:",
		"L2 is not reached on a machine without it, even if the agent holds none. If the agent uses AWS, put aws on PATH; under a managed",
		"install it must be root-owned, or named in plan_gate.engines.aws in the system config (docs/managed.md).",
	}},
	stepNotChecked: {2, "Make the credentials the lines above name checkable", []string{
		"Sign in again, grant what the line names, or install the missing CLI, then run this again. Until then the audit does not",
		"show that production is out of reach from them.",
	}},
	stepNameEnvs: {2, "Name your environments, so the audit can place these credentials", []string{
		"These can make destructive changes in an environment no config names, so applygate cannot tell whether it is production.",
		"Run applygate init, or list the profiles, accounts, contexts, projects or subscriptions under environments in your config,",
		"then run this again (docs/config.md).",
	}},
	stepNothingAudited: {2, "applygate cannot show that the agent holds no credential", []string{
		"No AWS profile, kube context, gcloud account or Azure subscription was audited, and an absence cannot be shown. If the agent",
		"uses a cloud, make its CLI available to this command and sign in. Otherwise L1 is as far as this machine's evidence goes.",
	}},
	stepCredentialFile: {2, "Keep your own sessions out of the agent's reach", []string{
		"Files like these are readable by this user, so by any agent that runs as you. The audit says what the credentials can do,",
		"not who can read them. Run applies as a different OS user, or from a machine or CI job the agent does not run on, or keep",
		"sessions short and sign out when done (docs/credentials.md, step 3).",
		"This check stays \"not verified\" while the agent's user can read them, so L2 is not reached.",
	}},
	stepWhoApplies: {2, "Decide who applies production changes", []string{
		"A person, with a role that needs MFA from a device the agent cannot answer (docs/credentials.md, step 2), or a pipeline",
		"whose apply role the agent cannot assume (docs/ci.md). applygate does not see which you use; for L3 you attest it",
		"(boundary.attest: ci_apply).",
	}},
	stepSandbox: {3, "Turn on the host sandbox in managed settings", []string{
		"Claude Code: sandbox.enabled true and allowUnsandboxedCommands false, in a root-owned managed settings file. These keys have",
		"not been tested live. Codex sandbox modes are not checked (docs/boundary.md).",
	}},
	stepAttest: {3, "Attest what only you can vouch for", []string{
		"Set boundary.attest in the user config once each is true. ci_apply: applies to protected environments run only in a reviewed",
		"pipeline, with a role the agent cannot assume. state_guards: the state bucket is versioned and object-locked, with a deny",
		"policy for deleting versions or changing the policy. Attested is vouched for, not checked (docs/boundary.md).",
	}},
	stepAttestName: {3, "Correct boundary.attest in the user config", []string{
		"It names something that is not one of the controls applygate knows (docs/boundary.md).",
	}},
	stepL3Pointers: {3, "L3 adds a host sandbox and two things only you can vouch for", []string{
		"Claude Code: sandbox.enabled true and allowUnsandboxedCommands false in managed settings (keys not tested live; Codex sandbox",
		"modes are not checked). Then set boundary.attest to ci_apply and state_guards once they are true: attested is vouched for,",
		"not checked (docs/boundary.md).",
	}},
}

// stepTarget is the level the steps lead to: the one required, by the user
// config or --require, and L2 when none is.
func stepTarget(require string) int {
	if require == "" {
		return 2
	}
	return max(levelNum(require), 0)
}

// nextSteps is what a person does to reach target, from the checks that are
// not ok or attested up to that level. It is a pure function of the result,
// and nil when there is nothing to say.
func nextSteps(r *boundaryResult, target int) *scan.Steps {
	if target <= 0 {
		return nil
	}
	if r.reached >= target {
		switch {
		case r.reached >= 3:
			return &scan.Steps{Header: "Reached L3, the top level. Attested controls are vouched for, not checked; what no level covers is in docs/boundary.md."}
		case r.reached == 2:
			return pointers()
		}
		return nil
	}
	subjects := map[string][]string{}
	for _, c := range r.checks {
		if c.level < 1 || c.level > target || c.status == "ok" || c.status == "attested" || c.step == "" {
			continue
		}
		list := subjects[c.step]
		if c.subject != "" && !slices.Contains(list, c.subject) {
			list = append(list, c.subject)
		}
		subjects[c.step] = list
	}
	has := func(id string) bool { _, ok := subjects[id]; return ok }
	// Saying nothing was audited adds nothing where the credentials that
	// were found already have steps.
	if has(stepNothingAudited) {
		for _, id := range []string{stepAWSReadOnly, stepAWSSimulatorGrant, stepKubeView, stepGCPViewer, stepAzReader, stepAWSCLI, stepNotChecked, stepNameEnvs} {
			if has(id) {
				delete(subjects, stepNothingAudited)
				break
			}
		}
	}
	// Who applies is a question once the credentials have been audited and
	// L2 is still out of reach.
	if r.audited && target >= 2 {
		for id := range subjects {
			if stepTable[id].level == 2 {
				subjects[stepWhoApplies] = nil
				break
			}
		}
	}
	out := &scan.Steps{Header: fmt.Sprintf("Steps to L%d", target)}
	l1, l2 := false, false
	for _, id := range stepOrder {
		subj, ok := subjects[id]
		if !ok {
			continue
		}
		d := stepTable[id]
		out.Items = append(out.Items, scan.Step{Level: d.level, Title: d.title, Subjects: subj, Lines: d.lines})
		l1, l2 = l1 || d.level == 1, l2 || d.level == 2
	}
	if len(out.Items) == 0 {
		return nil
	}
	if l1 && l2 {
		out.Note = "The credential steps do not depend on L1 and can be done first."
	}
	return out
}

// pointers is what follows once L2 is reached and L3 is not asked for: where
// the next level starts, and nothing more.
func pointers() *scan.Steps {
	d := stepTable[stepL3Pointers]
	return &scan.Steps{Header: "L2 is reached. What the next level adds:", Items: []scan.Step{{Level: d.level, Title: d.title, Lines: d.lines}}}
}
