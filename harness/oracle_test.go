package harness

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The effects oracle. The AI reviewers found the family "the guard allows a
// spelling it did not understand" one spelling at a time; this test finds it
// without them. It builds commands from destructive atoms (a terraform destroy
// in the prod directory, a write to its state file, to a hook settings file)
// and spellings of how a shell can reach them (cd forms, quoting, expansion,
// nested shells, redirect forms), asks the guard, and for every command the
// guard allows runs it for real under every shell on the machine against fake
// terraform, aws and kubectl programs that log their argument vector and
// directory. An allowed command whose run reached prod, changed a state or a
// guard file, or wrote outside the sandbox is a failure: the guard allowed what
// the shell turned into the atom.
//
// A shell runs a command differently from the shell the guard modelled, which
// is the point: the verdict has to hold under all of them.

type oracleAtom struct {
	name  string
	cmd   string // run from the prod directory unless a spelling moves it
	kind  string // "tool" (a fake terraform subcommand runs in prod), "file" (a protected file changes), "cloud" (a fake cloud CLI runs a destructive verb against prod), "plan" (terraform apply of a plan file), "control" (harmless: it counts allowed runs and has no effect)
	prog  string // the program word a spelling may rewrite; "terraform" when empty
	needs string // a shell the atom acts under only ("zsh"); skipped where it is missing
}

func (a oracleAtom) pg() string {
	if a.prog == "" {
		return "terraform"
	}
	return a.prog
}

// with rewrites the first occurrence of the atom's program word.
func (a oracleAtom) with(repl string) string { return strings.Replace(a.cmd, a.pg(), repl, 1) }

// quoted splits the program word with an empty quote pair: 'terra”form'.
func (a oracleAtom) quoted() string {
	p := a.pg()
	k := (len(p) + 1) / 2
	return "'" + p[:k] + "''" + p[k:] + "'"
}

var oracleAtoms = []oracleAtom{
	{name: "destroy", cmd: "terraform destroy -auto-approve", kind: "tool"},
	{name: "apply", cmd: "terraform apply -auto-approve", kind: "tool"},
	{name: "state rm", cmd: "terraform state rm aws_s3_bucket.a", kind: "tool"},
	{name: "taint", cmd: "terraform taint aws_s3_bucket.a", kind: "tool"},
	{name: "state write", cmd: "echo corrupt > terraform.tfstate", kind: "file"},
	{name: "state rm file", cmd: "rm -f terraform.tfstate", kind: "file"},
	{name: "state move", cmd: "mv terraform.tfstate /tmp/oracle-moved", kind: "file"},
	{name: "state truncate", cmd: ": > terraform.tfstate", kind: "file"},
	{name: "state sed", cmd: "sed -i.bak 's/a/b/' terraform.tfstate", kind: "file"},
	{name: "state tee", cmd: "echo x | tee terraform.tfstate", kind: "file"},
	{name: "state cp", cmd: "cp /dev/null terraform.tfstate", kind: "file"},
	{name: "state brace", cmd: "echo x > terraform.tfst{ate,}", kind: "file", needs: "zsh"},
	{name: "guard write", cmd: "echo '{}' > .claude/settings.json", kind: "file"},
	{name: "state clobber", cmd: "echo x >| terraform.tfstate", kind: "file"},
	{name: "state zsh clobber", cmd: "echo x >! terraform.tfstate", kind: "file", needs: "zsh"},
	{name: "state dd", cmd: "dd if=/dev/null of=terraform.tfstate 2>/dev/null", kind: "file"},
	{name: "state ln", cmd: "ln -sf /dev/null terraform.tfstate", kind: "file"},
	{name: "state truncate", cmd: "truncate -s 0 terraform.tfstate", kind: "file"},
	{name: "guard cp", cmd: "cp /dev/null .claude/settings.json", kind: "file"},
	{name: "tofu destroy", cmd: "tofu destroy -auto-approve", kind: "tool", prog: "tofu"},

	// Cloud effects: the fake CLIs log argv and the cloud environment variables,
	// and a destructive verb that names a protected target (or, with no target
	// named, runs in the prod directory) is an effect.
	{name: "aws rb", cmd: "aws s3 rb s3://acme-logs --force", kind: "cloud", prog: "aws"},
	{name: "aws prod profile", cmd: "aws --profile prod-admin ec2 terminate-instances --instance-ids i-0abc", kind: "cloud", prog: "aws"},
	{name: "aws env profile", cmd: "AWS_PROFILE=prod-admin aws rds delete-db-instance --db-instance-identifier db --skip-final-snapshot", kind: "cloud", prog: "aws"},
	{name: "aws export profile", cmd: "export AWS_PROFILE=prod-admin; aws s3 rm s3://acme --recursive", kind: "cloud", prog: "aws"},
	{name: "aws wildcard profile", cmd: "aws --profile=prod-ops cloudformation delete-stack --stack-name core", kind: "cloud", prog: "aws"},
	{name: "kubectl delete", cmd: "kubectl delete ns payments", kind: "cloud", prog: "kubectl"},
	{name: "kubectl context", cmd: "kubectl --context eks-blue delete deploy api", kind: "cloud", prog: "kubectl"},
	{name: "kubectl context eq", cmd: "kubectl --context=eks-blue delete pvc data", kind: "cloud", prog: "kubectl"},
	{name: "kubectl mixed", cmd: "kubectl --context kind-dev delete ns a; kubectl --context eks-blue delete ns b", kind: "cloud", prog: "kubectl"},
	{name: "helm uninstall", cmd: "helm --kube-context eks-blue uninstall api", kind: "cloud", prog: "helm"},
	{name: "az delete", cmd: "az group delete --subscription Payments --name rg --yes", kind: "cloud", prog: "az"},
	{name: "gcloud delete", cmd: "gcloud compute instances delete vm1 --project acme-payments-9f2 --quiet", kind: "cloud", prog: "gcloud"},
	{name: "gcloud env", cmd: "CLOUDSDK_CORE_PROJECT=acme-payments-9f2 gcloud sql instances delete db --quiet", kind: "cloud", prog: "gcloud"},

	// terraform apply of a saved plan. tfplan is a create-only plan of the
	// directory's own workspace; tfplan-bad deletes the prod database;
	// tfplan-devws and tfplan-prodws were made in another workspace.
	{name: "plan benign", cmd: "terraform apply tfplan", kind: "control"},
	{name: "plan destructive", cmd: "terraform apply tfplan-bad", kind: "plan"},
	{name: "plan destructive auto", cmd: "terraform apply -auto-approve tfplan-bad", kind: "plan"},
	{name: "plan from dev dir", cmd: "terraform apply ../dev/tfplan-bad", kind: "plan"},
	{name: "plan other workspace", cmd: "terraform apply tfplan-devws", kind: "plan"},
	{name: "plan other workspace in dev", cmd: "cd ../dev && terraform apply tfplan-prodws", kind: "plan"},
	{name: "plan chdir other workspace", cmd: "terraform -chdir=../dev apply tfplan-prodws", kind: "plan"},
	{name: "plan prod state flag", cmd: "terraform -chdir=../dev apply -state=../prod/terraform.tfstate tfplan", kind: "plan"},

	// Controls: harmless commands the guard is expected to allow, so that the
	// matrix exercises allowed runs and cannot pass because it stopped everything.
	{name: "control plan", cmd: "terraform plan", kind: "control"},
	{name: "control aws dev", cmd: "aws --profile dev s3 ls", kind: "control", prog: "aws"},
	{name: "control kubectl dev", cmd: "kubectl --context kind-dev get pods", kind: "control", prog: "kubectl"},
	{name: "control file", cmd: "echo hi > scratch.txt", kind: "control"},
}

// A spelling turns an atom into a command run from a given directory.
type oracleSpelling struct {
	name string
	from string                    // "prod" or "dev": where the command starts
	f    func(a oracleAtom) string // the command, with the atom reached by the spelling
}

// spellingNeeds names the shell a spelling runs under; the spelling is skipped
// where that shell is missing.
var spellingNeeds = map[string]string{"zsh -c": "zsh", "dash -c": "dash"}

func oracleSpellings() []oracleSpelling {
	id := func(a oracleAtom) string { return a.cmd }
	return []oracleSpelling{
		{"direct", "prod", id},
		{"quoted program", "prod", func(a oracleAtom) string { return a.with(a.quoted()) }},
		{"command prefix", "prod", func(a oracleAtom) string { return "command " + a.cmd }},
		{"env prefix", "prod", func(a oracleAtom) string { return "env " + a.cmd }},
		{"backslash", "prod", func(a oracleAtom) string { return "\\" + a.cmd }},
		{"bash -c", "prod", func(a oracleAtom) string { return "bash -c " + shq(a.cmd) }},
		{"sh -c", "prod", func(a oracleAtom) string { return "sh -c " + shq(a.cmd) }},
		{"eval", "prod", func(a oracleAtom) string { return "eval " + shq(a.cmd) }},
		{"echo pipe sh", "prod", func(a oracleAtom) string { return "echo " + shq(a.cmd) + " | sh" }},
		{"printf pipe bash", "prod", func(a oracleAtom) string { return "printf '%s' " + shq(a.cmd) + " | bash" }},
		{"variable program", "prod", func(a oracleAtom) string { return "t=" + a.pg() + "; " + a.with("$t") }},
		{"default expansion", "prod", func(a oracleAtom) string { return a.with("${x:-" + a.pg() + "}") }},
		{"subshell", "prod", func(a oracleAtom) string { return "(" + a.cmd + ")" }},
		{"brace group", "prod", func(a oracleAtom) string { return "{ " + a.cmd + "; }" }},
		{"and list", "prod", func(a oracleAtom) string { return "true && " + a.cmd }},
		{"for loop", "prod", func(a oracleAtom) string { return "for i in 1; do " + a.cmd + "; done" }},
		{"function", "prod", func(a oracleAtom) string { return "f() { " + a.cmd + "; }; f" }},
		{"xargs", "prod", func(a oracleAtom) string { return "echo x | xargs -I{} sh -c " + shq(a.cmd) }},
		{"time", "prod", func(a oracleAtom) string { return "time " + a.cmd }},
		{"exec", "prod", func(a oracleAtom) string { return "exec " + a.cmd }},
		{"timeout", "prod", func(a oracleAtom) string { return "timeout 5 " + a.cmd }},
		{"nice", "prod", func(a oracleAtom) string { return "nice " + a.cmd }},
		{"zsh -c", "prod", func(a oracleAtom) string { return "zsh -c " + shq(a.cmd) }},
		{"dash -c", "prod", func(a oracleAtom) string { return "dash -c " + shq(a.cmd) }},
		{"here-string", "prod", func(a oracleAtom) string { return "bash <<< " + shq(a.cmd) }},
		{"here-doc", "prod", func(a oracleAtom) string { return "sh <<'EOF'\n" + a.cmd + "\nEOF" }},
		{"substitution program", "prod", func(a oracleAtom) string { return a.with("$(echo " + a.pg() + ")") }},
		{"ansi-c quote", "prod", func(a oracleAtom) string { return a.with("$'" + a.pg() + "'") }},
		{"background", "prod", func(a oracleAtom) string { return a.cmd + " & wait" }},
		{"or list", "prod", func(a oracleAtom) string { return "false || " + a.cmd }},
		{"semicolon", "prod", func(a oracleAtom) string { return "true; " + a.cmd }},
		{"if", "prod", func(a oracleAtom) string { return "if true; then " + a.cmd + "; fi" }},
		{"while read", "prod", func(a oracleAtom) string { return "echo x | while read l; do " + a.cmd + "; done" }},
		{"cd dotdot", "dev", func(a oracleAtom) string { return "cd .. && cd prod && " + a.cmd }},
		{"cd absolute var", "dev", func(a oracleAtom) string { return "cd \"$PWD/../prod\" && " + a.cmd }},
		{"cd tilde dash", "dev", func(a oracleAtom) string { return "cd ../prod; cd - >/dev/null; cd - >/dev/null && " + a.cmd }},
		{"git -C", "dev", func(a oracleAtom) string { return "env -C ../prod sh -c " + shq(a.cmd) }},
		{"nohup", "prod", func(a oracleAtom) string { return "nohup " + a.cmd }},
		{"cd sibling", "dev", func(a oracleAtom) string { return "cd ../prod && " + a.cmd }},
		{"cd sibling dot", "dev", func(a oracleAtom) string { return "cd ../prod/. && " + a.cmd }},
		{"cd subshell", "dev", func(a oracleAtom) string { return "(cd ../prod; " + a.cmd + ")" }},
		{"cd quoted", "dev", func(a oracleAtom) string { return "cd '../pr''od' && " + a.cmd }},
		{"cd glob", "dev", func(a oracleAtom) string { return "cd ../pro* && " + a.cmd }},
		{"cd tilde plus", "dev", func(a oracleAtom) string { return "cd ~+/../prod && " + a.cmd }},
		{"cd substitution", "dev", func(a oracleAtom) string { return "cd $(echo ../prod) && " + a.cmd }},
		{"cd variable", "dev", func(a oracleAtom) string { return "d=../prod; cd $d && " + a.cmd }},
		{"cd two operands", "dev", func(a oracleAtom) string { return "cd dev prod && " + a.cmd }},
		{"pushd", "dev", func(a oracleAtom) string { return "pushd ../prod && " + a.cmd }},
		{"cdpath", "dev", func(a oracleAtom) string { return "CDPATH=.. cd prod && " + a.cmd }},
		{"env -C", "dev", func(a oracleAtom) string { return "env -C ../prod " + a.cmd }},
		{"chdir", "dev", func(a oracleAtom) string {
			if a.kind != "tool" || a.pg() != "terraform" {
				return "cd ../prod && " + a.cmd
			}
			return strings.Replace(a.cmd, "terraform ", "terraform -chdir=../prod ", 1)
		}},
		{"chdir variable", "dev", func(a oracleAtom) string {
			if a.kind != "tool" || a.pg() != "terraform" {
				return "d=../prod; cd $d && " + a.cmd
			}
			return "d=../prod; " + strings.Replace(a.cmd, "terraform ", "terraform -chdir=$d ", 1)
		}},
	}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type oracleBox struct {
	t      *testing.T
	root   string
	repo   string
	home   string
	bin    string // the fake tools
	log    string
	guard  string // the applygate binary
	shells map[string]string
}

// The fake programs log "tool<TAB>directory<TAB>argv<TAB>context" for every
// call. The context is the selected workspace and the cloud environment.
const fakeLogScript = `#!/bin/sh
if [ "${1#-chdir=}" != "$1" ]; then cd "${1#-chdir=}" || exit 1; shift; fi
printf '%s\t%s\t%s\tws=%s %s\n' "$(basename "$0")" "$PWD" "$*" "$(cat .terraform/environment 2>/dev/null)" "$(env | grep -E '^(AWS_|KUBE|CLOUDSDK|AZURE|ARM_)' | tr '\n' ' ')" >> LOG
`

// The fake terraform also answers "show -json PLAN" from PLAN.json, which is
// how the guard reads a saved plan.
const fakeTerraformTail = `if [ "$1" = show ]; then
  for last; do :; done
  [ -f "$last.json" ] && cat "$last.json"
fi
exit 0
`

// The fake sudo runs what it is given, as the real one would.
const fakeSudo = `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -n|-E|-S|-H) shift ;;
    -u) shift 2 ;;
    *=*) export "$1"; shift ;;
    *) break ;;
  esac
done
exec "$@"
`

func newOracleBox(t *testing.T) *oracleBox {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	repo, _, home, err := Materialize(filepath.Join(root, "m"))
	if err != nil {
		t.Fatal(err)
	}
	b := &oracleBox{t: t, root: root, repo: repo, home: home, bin: filepath.Join(root, "fakebin"), log: filepath.Join(root, "effects.log")}
	if err := os.MkdirAll(b.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(fakeLogScript, "LOG", b.log, 1)
	for _, tool := range []string{"terraform", "tofu", "aws", "kubectl", "helm", "az", "gcloud"} {
		body := script + "exit 0\n"
		if tool == "terraform" || tool == "tofu" {
			body = script + fakeTerraformTail
		}
		if err := os.WriteFile(filepath.Join(b.bin, tool), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(b.bin, "sudo"), []byte(fakeSudo), 0o755); err != nil {
		t.Fatal(err)
	}
	b.writePlans()
	// The guard, built once from this tree.
	b.guard = filepath.Join(root, "applygate")
	out, err := exec.Command("go", "build", "-o", b.guard, "../cmd/applygate").CombinedOutput()
	if err != nil {
		t.Fatalf("building the guard: %v\n%s", err, out)
	}
	// The person trusted the fixture's configuration.
	cfg := filepath.Join(repo, ".applygate.yaml")
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(cfg)
	sum := sha256.Sum256(data)
	trust, _ := json.Marshal(map[string]string{strings.ToLower(real): hex.EncodeToString(sum[:])})
	if err := os.MkdirAll(filepath.Join(home, ".config", "applygate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "applygate", "trusted.json"), trust, 0o644); err != nil {
		t.Fatal(err)
	}
	b.shells = map[string]string{}
	for _, s := range []string{"bash", "zsh", "dash", "sh"} {
		if p, err := exec.LookPath(s); err == nil {
			b.shells[s] = p
		}
	}
	return b
}

// writePlans puts saved plans in the prod and dev directories. A plan is a
// zip whose tfplan entry is a protobuf message holding the workspace (field 13,
// then field 3), stored uncompressed, with its "terraform show -json" output
// in PLAN.json beside it.
func (b *oracleBox) writePlans() {
	write := func(dir, name, ws string, destructive bool) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "tfplan", Method: zip.Store})
		if err != nil {
			b.t.Fatal(err)
		}
		inner := append([]byte{0x1a, byte(len(ws))}, ws...)
		_, _ = w.Write(append([]byte{0x6a, byte(len(inner))}, inner...))
		_ = zw.Close()
		actions := []string{"create"}
		if destructive {
			actions = []string{"delete", "create"}
		}
		js, _ := json.Marshal(map[string]any{"format_version": "1.2", "applyable": true, "complete": true, "errored": false,
			"resource_changes": []map[string]any{{"address": "aws_db_instance.main", "mode": "managed", "type": "aws_db_instance", "name": "main",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": map[string]any{"actions": actions,
					"before": map[string]any{"identifier": "prod-db", "deletion_protection": true},
					"after":  map[string]any{"identifier": "prod-db", "deletion_protection": !destructive}}}}})
		must := func(err error) {
			if err != nil {
				b.t.Fatal(err)
			}
		}
		must(os.WriteFile(filepath.Join(b.repo, "envs", dir, name), buf.Bytes(), 0o644))
		must(os.WriteFile(filepath.Join(b.repo, "envs", dir, name+".json"), js, 0o644))
	}
	for _, dir := range []string{"prod", "dev"} {
		must := func(err error) {
			if err != nil {
				b.t.Fatal(err)
			}
		}
		must(os.MkdirAll(filepath.Join(b.repo, "envs", dir, ".terraform"), 0o755))
		must(os.WriteFile(filepath.Join(b.repo, "envs", dir, ".terraform", "environment"), []byte(dir), 0o644))
		write(dir, "tfplan", dir, false)
		write(dir, "tfplan-bad", "prod", true)
		write(dir, "tfplan-devws", "dev", false)
		write(dir, "tfplan-prodws", "prod", false)
	}
}

const oracleState = `{"version":4,"terraform_version":"1.9.0","serial":3,"lineage":"abc","outputs":{},"resources":[]}`

// reset puts the protected files back and empties the effects log.
func (b *oracleBox) reset() {
	for _, f := range []string{"envs/prod/terraform.tfstate", "envs/dev/terraform.tfstate"} {
		// Remove first: an atom may have left a symlink, and writing through it
		// would not restore the file.
		_ = os.Remove(filepath.Join(b.repo, f))
		_ = os.WriteFile(filepath.Join(b.repo, f), []byte(oracleState), 0o644)
	}
	_ = os.MkdirAll(filepath.Join(b.repo, "envs/prod/.claude"), 0o755)
	_ = os.Remove(filepath.Join(b.repo, "envs/prod/.claude/settings.json"))
	_ = os.WriteFile(filepath.Join(b.repo, "envs/prod/.claude/settings.json"), []byte(`{"hooks":{}}`), 0o644)
	_ = os.Remove(filepath.Join(b.repo, "envs/prod/terraform.tfstate.bak"))
	_ = os.Remove(filepath.Join(b.repo, "envs/prod/scratch.txt"))
	_ = os.Remove(filepath.Join(b.repo, "envs/dev/scratch.txt"))
	_ = os.Remove("/tmp/oracle-moved")
	_ = os.Remove(b.log)
}

func (b *oracleBox) env() []string {
	return []string{"PATH=" + b.bin + ":/usr/bin:/bin", "FAKEBIN=" + b.bin, "HOME=" + b.home, "XDG_CONFIG_HOME=" + filepath.Join(b.home, ".config"),
		"XDG_STATE_HOME=" + filepath.Join(b.home, ".state"), "USER=agent", "LANG=C"}
}

// verdict is the guard's decision for cmd run from dir.
func (b *oracleBox) verdict(dir, cmd string) string {
	c := exec.Command(b.guard, "check", "--no-judge", "--cwd", dir, "--", cmd)
	c.Env = b.env()
	err := c.Run()
	if err == nil {
		return "allow"
	}
	if ee, ok := err.(*exec.ExitError); ok {
		switch ee.ExitCode() {
		case 4:
			return "ask"
		case 3:
			return "block"
		}
	}
	return "error"
}

// verdicts asks the guard about every case, several at a time.
func (b *oracleBox) verdicts(cases []oracleCase) []string {
	out := make([]string, len(cases))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = b.verdict(cases[i].dir, cases[i].cmd)
			}
		}()
	}
	for i := range cases {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

var destructiveWords = map[string]bool{
	// terraform
	"destroy": true, "apply": true, "taint": true, "rm": true, "import": true, "untaint": true, "force-unlock": true, "push": true,
	// cloud CLIs
	"rb": true, "uninstall": true, "drain": true, "purge": true,
}

func destructive(w string) bool {
	return destructiveWords[w] || strings.HasPrefix(w, "delete") || strings.HasPrefix(w, "terminate") || strings.HasPrefix(w, "remove")
}

// prodTargets name the protected environment's cloud targets in the fixture.
var prodTargets = []string{"prod-admin", "prod-", "eks-blue", "acme-payments-9f2", "payments"}

// explicitTarget reports whether a cloud call names its own profile, context,
// project or subscription (so the directory does not decide where it lands).
func explicitTarget(line string) bool {
	l := strings.ToLower(line)
	for _, m := range []string{"--profile", "--context", "--kube-context", "--project", "--subscription", "aws_profile=", "aws_default_profile=",
		"kubeconfig=", "cloudsdk_core_project=", "azure_subscription_id=", "arm_subscription_id="} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

func reachesProd(line string) bool {
	l := strings.ToLower(line)
	for _, m := range prodTargets {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// planEffect judges "terraform apply PLAN": it is an effect when the plan
// deletes something, or was made in a workspace other than the selected one,
// or the state flag points at the prod state from elsewhere.
func (b *oracleBox) planEffect(prod, pwd string, words []string, ctx string) (string, bool) {
	var plan, state string
	for i, w := range words {
		if w == "apply" {
			for _, a := range words[i+1:] {
				switch {
				case strings.HasPrefix(a, "-state="):
					state = strings.TrimPrefix(a, "-state=")
				case !strings.HasPrefix(a, "-"):
					plan = a
				}
			}
			break
		}
	}
	if plan == "" {
		return "", false
	}
	path := plan
	if !filepath.IsAbs(path) {
		path = filepath.Join(pwd, plan)
	}
	zdata, err := os.ReadFile(path)
	if err != nil {
		return "", false // not a plan file: the generic rule decides
	}
	ws := ""
	for _, name := range []string{"prod", "dev"} {
		if bytes.Contains(zdata, []byte("\x1a"+string(rune(len(name)))+name)) {
			ws = name
		}
	}
	selected := ""
	if i := strings.Index(ctx, "ws="); i >= 0 {
		selected = strings.Fields(ctx[i+3:] + " ")[0]
		if strings.Contains(selected, "=") {
			selected = ""
		}
	}
	js, _ := os.ReadFile(path + ".json")
	switch {
	case strings.Contains(string(js), `"delete"`):
		return fmt.Sprintf("applied a plan that deletes the prod database (plan workspace %s, selected %s, in %s)", ws, selected, pwd), true
	case ws != "" && selected != "" && ws != selected:
		return fmt.Sprintf("applied a plan made in workspace %s while workspace %s was selected", ws, selected), true
	}
	if state != "" {
		sp := state
		if !filepath.IsAbs(sp) {
			sp = filepath.Join(pwd, sp)
		}
		if filepath.Clean(sp) == filepath.Join(prod, "terraform.tfstate") && pwd != prod {
			return "applied against the prod state file from " + pwd, true
		}
	}
	return "", true
}

// effects runs cmd under a shell from dir and reports what it reached in prod.
func (b *oracleBox) effects(shell, dir, cmd string) []string {
	b.reset()
	c := exec.Command(shell, "-c", cmd)
	c.Dir = dir
	c.Env = b.env()
	done := make(chan struct{})
	go func() { _ = c.Run(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = c.Process.Kill()
		<-done
	}
	var out []string
	prod := filepath.Join(b.repo, "envs", "prod")
	if data, err := os.ReadFile(b.log); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			f := strings.SplitN(l, "\t", 4)
			if len(f) < 4 || f[0] == "" {
				continue
			}
			tool, pwd, argv, ctx := f[0], f[1], f[2], f[3]
			inProd := pwd == prod || strings.HasPrefix(pwd, prod+"/")
			words := strings.Fields(argv)
			switch tool {
			case "terraform", "tofu":
				if msg, ok := b.planEffect(prod, pwd, words, ctx); ok {
					if msg != "" {
						out = append(out, msg)
					}
					continue
				}
				// A read of the prod directory is not an effect; a destructive
				// subcommand is.
				if inProd {
					for _, w := range words {
						if destructiveWords[w] {
							out = append(out, "ran "+tool+" "+argv+" in prod")
						}
					}
				}
			default:
				bad := false
				for _, w := range words {
					if destructive(w) {
						bad = true
					}
				}
				if !bad {
					continue
				}
				switch {
				case reachesProd(argv + " " + ctx):
					out = append(out, "ran "+tool+" "+argv+" against a prod target ("+strings.TrimSpace(ctx)+")")
				case !explicitTarget(argv+" "+ctx) && inProd:
					out = append(out, "ran "+tool+" "+argv+" in the prod directory with no target named")
				}
			}
		}
	}
	if got, err := os.ReadFile(filepath.Join(prod, "terraform.tfstate")); err != nil || string(got) != oracleState {
		out = append(out, "changed the prod state file")
	}
	if got, err := os.ReadFile(filepath.Join(prod, ".claude", "settings.json")); err != nil || string(got) != `{"hooks":{}}` {
		out = append(out, "changed the prod hook settings")
	}
	if _, err := os.Stat("/tmp/oracle-moved"); err == nil {
		out = append(out, "moved the state file to /tmp")
	}
	return out
}

// oracleCase is one generated command and where it starts.
type oracleCase struct {
	spelling string
	atom     oracleAtom
	from     string
	dir      string
	cmd      string
}

func TestEffectsOracle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells")
	}
	if testing.Short() {
		t.Skip("builds the guard and runs shells")
	}
	if os.Getenv("APPLYGATE_ORACLE") == "separate" {
		t.Skip("CI runs the oracle in its own step")
	}
	b := newOracleBox(t)
	if len(b.shells) == 0 {
		if os.Getenv("APPLYGATE_ORACLE") == "required" {
			t.Fatal("the oracle is required here and no POSIX shell exists")
		}
		t.Skip("no POSIX shell")
	}
	prod := filepath.Join(b.repo, "envs", "prod")
	dirs := map[string]string{"prod": prod, "dev": filepath.Join(b.repo, "envs", "dev")}

	// The detector works: every atom, run directly with no guard, shows its
	// effect under some shell here. (An atom that acts under zsh only is not
	// checked where zsh is missing.)
	for _, a := range oracleAtoms {
		if a.kind == "control" {
			continue
		}
		if a.needs != "" && b.shells[a.needs] == "" {
			t.Logf("no %s here: %q acts only under %s, so it is not checked", a.needs, a.cmd, a.needs)
			continue
		}
		seen := false
		for _, sh := range b.shells {
			if len(b.effects(sh, prod, a.cmd)) > 0 {
				seen = true
			}
		}
		if !seen {
			t.Errorf("the oracle does not see the effect of %q (%s) under any shell here: the checks below prove nothing for it", a.cmd, a.name)
		}
	}

	var cases []oracleCase
	skipped := map[string]bool{}
	for _, sp := range oracleSpellings() {
		if n := spellingNeeds[sp.name]; n != "" && b.shells[n] == "" {
			skipped[sp.name] = true
			continue
		}
		for _, a := range oracleAtoms {
			if a.needs != "" && b.shells[a.needs] == "" {
				continue
			}
			cases = append(cases, oracleCase{sp.name, a, sp.from, dirs[sp.from], sp.f(a)})
		}
	}
	for n := range skipped {
		t.Logf("no shell for the spelling %q here: skipped", n)
	}
	fixed := len(cases)
	seed := oracleSeed()
	t.Logf("oracle seed %d (set APPLYGATE_ORACLE_SEED to repeat a run, APPLYGATE_ORACLE_GEN for the number of generated commands)", seed)
	for _, g := range generateCases(seed, oracleGenCount(), b.shells, prod) {
		g.dir = dirs[g.from]
		cases = append(cases, g)
	}

	shellNames := make([]string, 0, len(b.shells))
	for n := range b.shells {
		shellNames = append(shellNames, n)
	}
	sort.Strings(shellNames)

	t0 := time.Now()
	verdicts := b.verdicts(cases)
	t.Logf("oracle: %d verdicts in %s", len(cases), time.Since(t0).Round(time.Second))
	var stopped, allowed, ranSafe, controls int
	var failures []string
	for i, c := range cases {
		if verdicts[i] != "allow" {
			stopped++
			continue
		}
		allowed++
		if c.atom.kind == "control" {
			controls++
		}
		for _, sh := range shellNames {
			if eff := b.effects(b.shells[sh], c.dir, c.cmd); len(eff) > 0 {
				failures = append(failures, fmt.Sprintf("allowed from %s, under %s it %s: %s  [%s]", c.from, sh, strings.Join(eff, "; "), c.cmd, c.spelling))
			} else {
				ranSafe++
			}
		}
	}
	t.Logf("oracle: %d atoms, %d fixed spellings (%d commands) and %d generated commands (seed %d); %d stopped by the guard, %d allowed (%d of them controls), %d allowed runs under %d shells had no effect in prod",
		len(oracleAtoms), len(oracleSpellings()), fixed, len(cases)-fixed, seed, stopped, allowed, controls, ranSafe, len(b.shells))
	if controls == 0 {
		t.Errorf("the guard allowed none of the control commands: the matrix ran nothing allowed, so it proves nothing")
	}
	for _, f := range failures {
		t.Errorf("%s (seed %d)", f, seed)
	}
}
