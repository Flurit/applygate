package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
// asks the cloud, for every AWS profile, kube context, gcloud account and
// Azure subscription this environment has, who it is and whether it can
// make destructive changes without a person, and reports the production
// ones that can.
//
// It contacts AWS (sts get-caller-identity, iam simulate-principal-policy,
// iam get-role), the Kubernetes API servers (auth can-i), Google Cloud
// (gcloud auth print-access-token, and Resource Manager's
// projects.testIamPermissions over HTTPS) and Azure (az role assignment
// list, az role definition list), with the credentials it audits; it
// changes nothing. A person runs it, not the hook.

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

// maxAudited bounds how many profiles and contexts one run audits; more are reported, not skipped silently.
const maxAudited = 500

// credsTimeout bounds each CLI call; an SSO profile may be slow to answer.
var credsTimeout = 20 * time.Second

// destructiveActions are the AWS actions the audit asks the policy
// simulator about: deleting data and infrastructure, and changing who may
// do so. One allowed without MFA makes a profile able to damage production.
var destructiveActions = []string{"ec2:TerminateInstances", "ec2:DeleteVpc", "rds:DeleteDBInstance", "rds:DeleteDBCluster",
	"s3:DeleteBucket", "s3:PutBucketPolicy", "dynamodb:DeleteTable", "eks:DeleteCluster", "lambda:DeleteFunction",
	"cloudformation:DeleteStack", "kms:ScheduleKeyDeletion", "iam:CreateUser", "iam:AttachRolePolicy", "iam:PutRolePolicy",
	"iam:CreateAccessKey", "sts:AssumeRole",
	// The remote state: deleting a version, turning versioning off or
	// rewriting the bucket policy is how state is lost or opened.
	"s3:DeleteObjectVersion", "s3:PutBucketVersioning", "s3:DeleteBucketPolicy"}

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
	fmt.Fprintln(stdout, "Credentials this environment can use (it contacts AWS, Google Cloud, Azure and the clusters, read-only):")
	all := auditAll(cfg)
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

// auditAll is every credential audit doctor --creds and --boundary run.
func auditAll(cfg *config.Config) []credsFinding {
	var all []credsFinding
	all = append(all, auditAWS(cfg)...)
	all = append(all, auditKube(cfg)...)
	all = append(all, auditGCloud(cfg)...)
	all = append(all, auditAz(cfg)...)
	return all
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
	var res []credsFinding
	if len(profiles) > maxAudited {
		res = append(res, credsFinding{"WARN", fmt.Sprintf("aws: %d profiles listed, only the first %d are audited; the rest are not checked", len(profiles), maxAudited)})
		profiles = profiles[:maxAudited]
	}
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
		if n++; n > maxAudited {
			res = append(res, credsFinding{"WARN", fmt.Sprintf("kube: more than %d contexts, the rest are not audited", maxAudited)})
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

// where is how a finding names the environment a credential belongs to.
func where(tier config.Tier, env string, matched bool) string {
	if !matched {
		return "matches no environment"
	}
	return "environment " + env + ", tier " + string(tier)
}

// gcpDestructivePermissions are the Google Cloud permissions the audit asks
// Resource Manager about, in the spirit of destructiveActions: deleting data
// and infrastructure, changing who may do so, and acting as a service
// account, which reaches that account's rights too.
var gcpDestructivePermissions = []string{"compute.instances.delete", "compute.networks.delete", "cloudsql.instances.delete",
	"storage.buckets.delete", "storage.buckets.setIamPolicy", "storage.objects.delete", "container.clusters.delete",
	"resourcemanager.projects.setIamPolicy", "resourcemanager.projects.delete", "iam.serviceAccountKeys.create",
	"iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "cloudfunctions.functions.delete",
	"run.services.delete", "spanner.instances.delete", "bigquery.datasets.delete", "cloudkms.cryptoKeyVersions.destroy"}

// redact takes a token out of a message that might echo it.
func redact(msg, token string) string {
	if token == "" {
		return msg
	}
	return strings.ReplaceAll(msg, token, "<token>")
}

// gcpTestPermissions asks Resource Manager which of perms the token's
// account holds on the project (projects.testIamPermissions); tests replace
// it. The token goes only into the Authorization header and never into an
// error.
var gcpTestPermissions = func(ctx context.Context, token, project string, perms []string) ([]string, error) {
	body, err := json.Marshal(map[string][]string{"permissions": perms})
	if err != nil {
		return nil, err
	}
	u := "https://cloudresourcemanager.googleapis.com/v1/projects/" + url.PathEscape(project) + ":testIamPermissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New(redact(err.Error(), token))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error struct{ Message string } }
		_ = json.Unmarshal(b, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("testIamPermissions: HTTP %d: %s", resp.StatusCode, redact(msg, token))
	}
	var r struct{ Permissions []string }
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, errors.New("testIamPermissions: the answer could not be read")
	}
	return r.Permissions, nil
}

// auditGCloud checks, for every (account, project) pair the gcloud
// configurations name, which destructive permissions the account itself
// holds on the project. gcloud has nothing like the MFA-absent simulation:
// any such permission held by a credential the agent can use counts.
func auditGCloud(cfg *config.Config) []credsFinding {
	bin, err := cfg.EngineBinary("gcloud")
	if err != nil {
		return nil // no gcloud: nothing to audit
	}
	call := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
		defer cancel()
		return runCLI(ctx, bin, args...)
	}
	out, err := call("auth", "list", "--format=json")
	if err != nil {
		return []credsFinding{{"WARN", "gcloud: accounts not listed (" + err.Error() + ")"}}
	}
	var accts []struct{ Account, Status string }
	if json.Unmarshal(out, &accts) != nil {
		return []credsFinding{{"WARN", "gcloud: the account list could not be read"}}
	}
	if len(accts) == 0 {
		return nil // no credentialed account: nothing the agent can use
	}
	credentialed := map[string]bool{}
	for _, a := range accts {
		credentialed[a.Account] = true
	}
	type pair struct{ account, project string }
	seen := map[pair]bool{}
	var pairs []pair
	add := func(a, p string) {
		if a == "" || p == "" || !credentialed[a] || seen[pair{a, p}] {
			return
		}
		seen[pair{a, p}] = true
		pairs = append(pairs, pair{a, p})
	}
	type core struct {
		Core struct{ Account, Project string }
	}
	// The active pair, as a call with no --account or --project uses it.
	var active core
	if out, err := call("config", "list", "--format=json"); err == nil {
		_ = json.Unmarshal(out, &active)
	}
	for _, a := range accts {
		if strings.EqualFold(a.Status, "ACTIVE") && active.Core.Account == "" {
			active.Core.Account = a.Account
		}
	}
	if v := os.Getenv("CLOUDSDK_CORE_ACCOUNT"); v != "" {
		active.Core.Account = v
	}
	if v := os.Getenv("CLOUDSDK_CORE_PROJECT"); v != "" {
		active.Core.Project = v
	}
	add(active.Core.Account, active.Core.Project)
	if out, err := call("config", "configurations", "list", "--format=json"); err == nil {
		var confs []struct{ Properties core }
		_ = json.Unmarshal(out, &confs)
		for _, c := range confs {
			add(c.Properties.Core.Account, c.Properties.Core.Project)
		}
	}
	var res []credsFinding
	// A credentialed account no configuration pairs with a project is
	// still usable with --account, against the active project.
	for _, a := range accts {
		covered := false
		for _, p := range pairs {
			covered = covered || p.account == a.Account
		}
		switch {
		case covered:
		case active.Core.Project != "":
			add(a.Account, active.Core.Project)
		default:
			res = append(res, credsFinding{"WARN", "gcloud account " + a.Account + ": not checked (no configuration names a project for it)"})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].account != pairs[j].account {
			return pairs[i].account < pairs[j].account
		}
		return pairs[i].project < pairs[j].project
	})
	if len(pairs) > maxAudited {
		res = append(res, credsFinding{"WARN", fmt.Sprintf("gcloud: %d account and project pairs, only the first %d are audited; the rest are not checked", len(pairs), maxAudited)})
		pairs = pairs[:maxAudited]
	}
	tokens := map[string]string{}
	tokenErr := map[string]error{}
	for _, p := range pairs {
		tier, env, matched := tierOf(cfg, config.Signals{GCPProject: p.project})
		prod := matched && tier == config.Protected
		who := fmt.Sprintf("gcloud account %s on project %s (%s)", p.account, p.project, where(tier, env, matched))
		tok, ok := tokens[p.account]
		if !ok && tokenErr[p.account] == nil {
			out, err := call("auth", "print-access-token", "--account="+p.account)
			tok = strings.TrimSpace(string(out))
			if err == nil && tok == "" {
				err = errors.New("no token printed")
			}
			if err != nil {
				tokenErr[p.account] = errors.New(redact(err.Error(), tok))
			} else {
				tokens[p.account] = tok
			}
		}
		if err := tokenErr[p.account]; err != nil {
			res = append(res, credsFinding{"WARN", who + ": not checked (gcloud auth print-access-token failed: " + err.Error() + ")"})
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
		held, err := gcpTestPermissions(ctx, tok, p.project, gcpDestructivePermissions)
		cancel()
		if err != nil {
			res = append(res, credsFinding{"WARN", who + ": not checked (" + redact(err.Error(), tok) + ")"})
			continue
		}
		if len(held) == 0 {
			res = append(res, credsFinding{"ok", fmt.Sprintf("%s: none of %d destructive permissions", who, len(gcpDestructivePermissions))})
			continue
		}
		sort.Strings(held)
		res = append(res, credsFinding{levelFor(prod, matched), who + ": holds: " + strings.Join(held, ", ")})
	}
	return res
}

// azDestructiveRoles are built-in Azure roles that allow deleting resources
// or granting access; azReadOnlyRoles allow neither. Any other role's
// definition is read and its actions checked.
var azDestructiveRoles = map[string]bool{"owner": true, "contributor": true, "user access administrator": true,
	"role based access control administrator": true, "virtual machine contributor": true, "storage account contributor": true,
	"sql server contributor": true, "azure kubernetes service contributor role": true, "key vault contributor": true,
	"network contributor": true}

var azReadOnlyRoles = map[string]bool{"reader": true, "monitoring reader": true, "billing reader": true,
	"security reader": true, "log analytics reader": true, "cost management reader": true}

// azActionCovers says whether pattern (an Azure action, possibly with *)
// covers action. Matching is case-insensitive; a * matches any run of
// characters.
func azActionCovers(pattern, action string) bool {
	pattern, action = strings.ToLower(pattern), strings.ToLower(action)
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == action
	}
	if !strings.HasPrefix(action, parts[0]) {
		return false
	}
	rest := action[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(rest, p)
		}
		j := strings.Index(rest, p)
		if j < 0 {
			return false
		}
		rest = rest[j+len(p):]
	}
	return true
}

// azDestructiveAction says whether an action entry of a role definition
// allows a destructive change: everything, a delete, a write on
// Microsoft.Authorization (granting access) or a provider-wide wildcard,
// which includes that provider's deletes.
func azDestructiveAction(a string) bool {
	l := strings.ToLower(a)
	return l == "*" || strings.HasSuffix(l, "/delete") || strings.HasSuffix(l, "/*") ||
		(strings.HasPrefix(l, "microsoft.authorization/") && strings.HasSuffix(l, "/write"))
}

// azDestructiveEntries are the entries of actions not cancelled by an
// exact or wildcard entry of not that covers them.
func azDestructiveEntries(actions, not []string) []string {
	var out []string
	for _, a := range actions {
		if !azDestructiveAction(a) {
			continue
		}
		cancelled := false
		for _, n := range not {
			cancelled = cancelled || azActionCovers(n, a)
		}
		if !cancelled {
			out = append(out, a)
		}
	}
	return out
}

// auditAz checks, for every Azure subscription the CLI is signed in to,
// the roles the signed-in principal holds there (inherited and through
// groups included) and reports those that allow destructive changes.
func auditAz(cfg *config.Config) []credsFinding {
	bin, err := cfg.EngineBinary("az")
	if err != nil {
		return nil // no az: nothing to audit
	}
	call := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), credsTimeout)
		defer cancel()
		return runCLI(ctx, bin, args...)
	}
	out, err := call("account", "list", "--all", "--output", "json")
	if err != nil {
		return []credsFinding{{"WARN", "az: subscriptions not listed (" + err.Error() + ")"}}
	}
	var subs []struct {
		ID, Name  string
		IsDefault bool
		User      struct{ Name, Type string }
	}
	if json.Unmarshal(out, &subs) != nil {
		return []credsFinding{{"WARN", "az: the subscription list could not be read"}}
	}
	// AZURE_SUBSCRIPTION_ID is the subscription a call with no
	// --subscription uses.
	if v := os.Getenv("AZURE_SUBSCRIPTION_ID"); v != "" {
		for i := range subs {
			subs[i].IsDefault = strings.EqualFold(subs[i].ID, v)
		}
	}
	sort.SliceStable(subs, func(i, j int) bool {
		if subs[i].IsDefault != subs[j].IsDefault {
			return subs[i].IsDefault
		}
		return subs[i].Name < subs[j].Name
	})
	var res []credsFinding
	if len(subs) > maxAudited {
		res = append(res, credsFinding{"WARN", fmt.Sprintf("az: %d subscriptions listed, only the first %d are audited; the rest are not checked", len(subs), maxAudited)})
		subs = subs[:maxAudited]
	}
	for _, s := range subs {
		tier, env, matched := tierOf(cfg, config.Signals{AzureSubscription: s.Name, AzureSubscriptionID: s.ID})
		prod := matched && tier == config.Protected
		id := s.ID
		if s.IsDefault {
			id += ", default"
		}
		who := fmt.Sprintf("az subscription %s (%s) as %s (%s)", s.Name, id, s.User.Name, where(tier, env, matched))
		if s.User.Name == "" {
			res = append(res, credsFinding{"WARN", who + ": not checked (the subscription names no signed-in principal)"})
			continue
		}
		out, err := call("role", "assignment", "list", "--assignee", s.User.Name, "--all", "--include-inherited", "--include-groups", "--subscription", s.ID, "--output", "json")
		if err != nil {
			res = append(res, credsFinding{"WARN", who + ": not checked, az role assignment list failed (" + err.Error() + ")"})
			continue
		}
		var assigns []struct{ RoleDefinitionName, Scope string }
		if json.Unmarshal(out, &assigns) != nil {
			res = append(res, credsFinding{"WARN", who + ": not checked, the role assignments could not be read"})
			continue
		}
		var bad, unread []string
		defs := map[string][]string{} // role name -> its destructive entries
		defErr := map[string]error{}
		for _, a := range assigns {
			role := a.RoleDefinitionName
			lr := strings.ToLower(role)
			switch {
			case azReadOnlyRoles[lr]:
				continue
			case azDestructiveRoles[lr]:
				bad = append(bad, role+" at "+a.Scope)
				continue
			}
			if _, ok := defs[lr]; !ok && defErr[lr] == nil {
				defs[lr], defErr[lr] = azRoleDestructive(call, role, s.ID)
				if defErr[lr] != nil {
					unread = append(unread, role+" ("+defErr[lr].Error()+")")
				}
			}
			if d := defs[lr]; len(d) > 0 {
				bad = append(bad, role+" ("+strings.Join(d, ", ")+") at "+a.Scope)
			}
		}
		switch {
		case len(bad) > 0:
			text := who + ": roles allowing destructive changes: " + strings.Join(bad, "; ")
			if len(unread) > 0 {
				text += "; definitions not read: " + strings.Join(unread, "; ")
			}
			res = append(res, credsFinding{levelFor(prod, matched), text})
		case len(unread) > 0:
			res = append(res, credsFinding{"WARN", who + ": not checked, role definitions not read: " + strings.Join(unread, "; ")})
		default:
			res = append(res, credsFinding{"ok", who + ": no role with a destructive action"})
		}
	}
	return res
}

// azRoleDestructive reads a role's definition in the subscription and
// returns its action and data-action entries that allow destructive
// changes.
func azRoleDestructive(call func(...string) ([]byte, error), role, sub string) ([]string, error) {
	out, err := call("role", "definition", "list", "--name", role, "--subscription", sub, "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("az role definition list failed: %v", err)
	}
	var defs []struct {
		Permissions []struct {
			Actions, NotActions, DataActions, NotDataActions []string
		}
	}
	if json.Unmarshal(out, &defs) != nil {
		return nil, errors.New("the definition could not be read")
	}
	if len(defs) == 0 {
		return nil, errors.New("no definition found")
	}
	var d []string
	for _, def := range defs {
		for _, p := range def.Permissions {
			d = append(d, azDestructiveEntries(p.Actions, p.NotActions)...)
			d = append(d, azDestructiveEntries(p.DataActions, p.NotDataActions)...)
		}
	}
	return d, nil
}
