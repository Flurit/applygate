package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Flurit/applygate/internal/config"
)

// applygate doctor --creds audits the credentials the agent's environment
// can use. The hook judges a call before it runs; it cannot stop a call it
// misjudged. What does stop one is credentials that cannot change
// production without a person (docs/credentials.md): an agent profile that
// can only read production, and a write role that requires MFA. The audit
// asks the cloud, for every AWS profile and kube context this environment
// has, who it is and whether it can make destructive changes without MFA,
// and reports the production ones that can.
//
// It contacts AWS (sts get-caller-identity, iam simulate-principal-policy,
// iam get-role) and the Kubernetes API servers (auth can-i), with the
// credentials it audits; it changes nothing. A person runs it, not the
// hook.

// runCLI runs a cloud CLI; tests replace it.
var runCLI = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), errors.New(msg)
	}
	return out.Bytes(), nil
}

// credsTimeout bounds each CLI call; an SSO profile may be slow to answer.
var credsTimeout = 20 * time.Second

// destructiveActions are the AWS actions the audit asks the policy
// simulator about: deleting data and infrastructure, and changing who may
// do so. One allowed without MFA makes a profile able to damage production.
var destructiveActions = []string{"ec2:TerminateInstances", "ec2:DeleteVpc", "rds:DeleteDBInstance", "rds:DeleteDBCluster",
	"s3:DeleteBucket", "s3:PutBucketPolicy", "dynamodb:DeleteTable", "eks:DeleteCluster", "lambda:DeleteFunction",
	"cloudformation:DeleteStack", "kms:ScheduleKeyDeletion", "iam:CreateUser", "iam:AttachRolePolicy", "iam:PutRolePolicy",
	"iam:CreateAccessKey", "sts:AssumeRole"}

// kubeVerbs are what the audit asks each kube context about.
var kubeVerbs = [][]string{{"delete", "namespaces"}, {"delete", "deployments"}, {"create", "clusterrolebindings"}, {"delete", "persistentvolumeclaims"}}

type credsFinding struct {
	level string // "ok", "WARN", "FAIL"
	text  string
}

func cmdDoctorCreds(stdout, stderr io.Writer) int {
	wd, _ := os.Getwd()
	cfg, err := config.Load(config.UserPath(), wd)
	if err != nil {
		fmt.Fprintln(stderr, "applygate: config:", err)
		return 2
	}
	fmt.Fprintln(stdout, "Credentials this environment can use (it contacts AWS and the clusters, read-only):")
	var all []credsFinding
	all = append(all, auditAWS(cfg)...)
	all = append(all, auditKube(cfg)...)
	all = append(all, credsFinding{"ok", "gcloud and az are not audited yet: see docs/credentials.md for the IAM setup to check by hand"})
	fails := 0
	for _, f := range all {
		if f.level == "FAIL" {
			fails++
		}
		fmt.Fprintf(stdout, "%-4s %s\n", f.level, f.text)
	}
	if fails > 0 {
		fmt.Fprintf(stdout, "\n%d credential(s) can change production without a person. The hook judges calls before they run and can be wrong; these credentials are what a wrong judgment would reach. docs/credentials.md shows how to give the agent read-only access and keep writes behind MFA.\n", fails)
		return 1
	}
	return 0
}

// tierOf is the tier the config gives a profile, account or kube context,
// and whether any environment or name hint matched it.
func tierOf(cfg *config.Config, sig config.Signals) (config.Tier, string, bool) {
	r := cfg.Resolve(sig)
	if r.Unknown {
		return r.Tier, "", false
	}
	return r.Tier, r.Env, true
}

func auditAWS(cfg *config.Config) []credsFinding {
	bin, err := cfg.EngineBinary("aws")
	if err != nil {
		return []credsFinding{{"WARN", "aws: not audited (" + err.Error() + ")"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
	out, err := runCLI(ctx, bin, "configure", "list-profiles")
	cancel()
	var profiles []string
	if err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				profiles = append(profiles, l)
			}
		}
	}
	sort.Strings(profiles)
	if len(profiles) > 50 {
		profiles = profiles[:50]
	}
	var res []credsFinding
	// The environment's own credentials (AWS_ACCESS_KEY_ID, AWS_PROFILE)
	// are what a call with no --profile uses.
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != "" || len(profiles) == 0 {
		res = append(res, auditProfile(cfg, bin, ""))
	}
	for _, p := range profiles {
		res = append(res, auditProfile(cfg, bin, p))
	}
	return res
}

func awsArgs(profile string, args ...string) []string {
	args = append(args, "--output", "json")
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args
}

func auditProfile(cfg *config.Config, bin, profile string) credsFinding {
	name := "aws profile " + profile
	if profile == "" {
		name = "aws default credentials"
		if p := os.Getenv("AWS_PROFILE"); p != "" {
			name += " (AWS_PROFILE=" + p + ")"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
	defer cancel()
	out, err := runCLI(ctx, bin, awsArgs(profile, "sts", "get-caller-identity")...)
	if err != nil {
		return credsFinding{"WARN", name + ": not checked, sts get-caller-identity failed (" + err.Error() + ")"}
	}
	var id struct{ Account, Arn string }
	if json.Unmarshal(out, &id) != nil || id.Arn == "" {
		return credsFinding{"WARN", name + ": not checked, sts get-caller-identity gave no identity"}
	}
	tier, env, matched := tierOf(cfg, config.Signals{AWSProfile: profile, AWSAccount: id.Account})
	where := "matches no environment"
	if matched {
		where = "environment " + env + ", tier " + string(tier)
	}
	prod := matched && tier == config.Protected
	who := fmt.Sprintf("%s: %s (account %s, %s)", name, id.Arn, id.Account, where)
	if strings.HasSuffix(id.Arn, ":root") {
		return credsFinding{levelFor(prod, matched), who + ": the account's root user can do anything"}
	}
	src, err := principalARN(ctx, bin, profile, id.Arn)
	if err != nil {
		return credsFinding{"WARN", who + ": not checked, " + err.Error()}
	}
	args := awsArgs(profile, "iam", "simulate-principal-policy", "--policy-source-arn", src, "--action-names")
	args = append(args, destructiveActions...)
	args = append(args, "--context-entries", "ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=false,ContextKeyType=boolean")
	out, err = runCLI(ctx, bin, args...)
	if err != nil {
		return credsFinding{"WARN", who + ": not checked, iam simulate-principal-policy failed (" + err.Error() + "); grant the profile iam:SimulatePrincipalPolicy on itself, or check it by hand (docs/credentials.md)"}
	}
	var sim struct {
		EvaluationResults []struct {
			EvalActionName string
			EvalDecision   string
		}
	}
	if json.Unmarshal(out, &sim) != nil {
		return credsFinding{"WARN", who + ": not checked, the simulator's answer could not be read"}
	}
	var allowed []string
	for _, r := range sim.EvaluationResults {
		if r.EvalDecision == "allowed" {
			allowed = append(allowed, r.EvalActionName)
		}
	}
	if len(sim.EvaluationResults) == 0 {
		return credsFinding{"WARN", who + ": not checked, the simulator returned no results"}
	}
	if len(allowed) == 0 {
		return credsFinding{"ok", who + ": none of " + fmt.Sprint(len(destructiveActions)) + " destructive actions allowed without MFA"}
	}
	return credsFinding{levelFor(prod, matched), who + ": allowed without MFA: " + strings.Join(allowed, ", ")}
}

// levelFor is how a credential that can make destructive changes is
// reported: a failure in production, a warning where the config does not
// say which environment it belongs to, fine elsewhere.
func levelFor(prod, matched bool) string {
	switch {
	case prod:
		return "FAIL"
	case !matched:
		return "WARN"
	}
	return "ok"
}

// principalARN is the ARN the policy simulator takes for a caller: a user's
// ARN as it is, and for an assumed role the role's own ARN (with its path,
// which only iam get-role gives).
func principalARN(ctx context.Context, bin, profile, arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "", fmt.Errorf("an identity ARN applygate cannot read (%s)", arn)
	}
	res := parts[5]
	switch {
	case strings.HasPrefix(res, "user/"):
		return arn, nil
	case strings.HasPrefix(res, "assumed-role/"):
		role := strings.Split(strings.TrimPrefix(res, "assumed-role/"), "/")[0]
		out, err := runCLI(ctx, bin, awsArgs(profile, "iam", "get-role", "--role-name", role)...)
		if err != nil {
			return "", fmt.Errorf("iam get-role %s failed (%v)", role, err)
		}
		var r struct{ Role struct{ Arn string } }
		if json.Unmarshal(out, &r) != nil || r.Role.Arn == "" {
			return "", fmt.Errorf("iam get-role %s gave no ARN", role)
		}
		return r.Role.Arn, nil
	}
	return "", fmt.Errorf("an identity of a kind the simulator does not take (%s)", arn)
}

func auditKube(cfg *config.Config) []credsFinding {
	bin, err := cfg.EngineBinary("kubectl")
	if err != nil {
		return nil // no kubectl: nothing to audit
	}
	ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
	out, err := runCLI(ctx, bin, "config", "get-contexts", "-o", "name")
	cancel()
	if err != nil {
		return []credsFinding{{"WARN", "kubectl: contexts not listed (" + err.Error() + ")"}}
	}
	var res []credsFinding
	n := 0
	for _, c := range strings.Split(string(out), "\n") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if n++; n > 50 {
			break
		}
		tier, env, matched := tierOf(cfg, config.Signals{KubeContext: c})
		where := "matches no environment"
		if matched {
			where = "environment " + env + ", tier " + string(tier)
		}
		prod := matched && tier == config.Protected
		var can []string
		checked := true
		for _, v := range kubeVerbs {
			ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
			ans, err := runCLI(ctx, bin, "auth", "can-i", v[0], v[1], "--all-namespaces", "--context", c, "--request-timeout=10s")
			cancel()
			a := strings.TrimSpace(string(ans))
			switch {
			case a == "yes":
				can = append(can, v[0]+" "+v[1])
			case a == "no":
			case err != nil:
				res = append(res, credsFinding{"WARN", fmt.Sprintf("kube context %s (%s): not checked (%v)", c, where, err)})
				checked = false
			}
			if !checked {
				break
			}
		}
		if !checked {
			continue
		}
		if len(can) == 0 {
			res = append(res, credsFinding{"ok", fmt.Sprintf("kube context %s (%s): none of %d destructive verbs allowed", c, where, len(kubeVerbs))})
		} else {
			res = append(res, credsFinding{levelFor(prod, matched), fmt.Sprintf("kube context %s (%s): allowed: %s", c, where, strings.Join(can, ", "))})
		}
	}
	return res
}
