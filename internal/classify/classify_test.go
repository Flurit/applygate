package classify

import (
	"testing"

	"github.com/Flurit/applygate/internal/shell"
)

func classify(t *testing.T, cmd, dir string, env map[string]string) []Action {
	t.Helper()
	res := shell.Analyze(cmd, shell.Options{Dir: dir, Env: env, ReadFile: func(string) ([]byte, error) { return nil, errNotFound }})
	return Invocations(res, Options{Home: "/home/u"})
}

type notFound struct{}

func (notFound) Error() string { return "not found" }

var errNotFound error = notFound{}

// first returns the first action that is not read-only, or the first one.
func first(acts []Action) Action {
	for _, a := range acts {
		if a.Class != ReadOnly {
			return a
		}
	}
	if len(acts) > 0 {
		return acts[0]
	}
	return Action{}
}

func TestClassifyCommands(t *testing.T) {
	cases := []struct {
		name, cmd string
		env       map[string]string
		class     Class
		dir       string // expected Dir; "-" for not checked
		anyDir    bool
		target    string
	}{
		// C1: program names are compared without case.
		{name: "upper-case terraform", cmd: "TERRAFORM destroy", class: Destroy, dir: "/r/envs/dev"},
		{name: "windows exe suffix", cmd: "terraform.exe destroy", class: Destroy, dir: "-"},
		{name: "mixed-case aws", cmd: "AWS s3 rb s3://b --force", class: CloudDestructive, dir: "-"},
		// C9: Terragrunt's working directory, and a -chdir that cannot be resolved.
		{name: "terragrunt --working-dir", cmd: "terragrunt --working-dir ../prod destroy", class: Destroy, dir: "/r/envs/prod"},
		{name: "terragrunt --terragrunt-working-dir after the command", cmd: "terragrunt destroy --terragrunt-working-dir=../prod", class: Destroy, dir: "/r/envs/prod"},
		{name: "TG_WORKING_DIR", cmd: "TG_WORKING_DIR=../prod terragrunt destroy", class: Destroy, dir: "/r/envs/prod"},
		{name: "unresolved -chdir", cmd: "terraform -chdir=$(ls -d ../pro*) destroy", class: Destroy, dir: "", anyDir: true},
		// C14: TF_CLI_ARGS and TF_CLI_ARGS_<sub> are arguments.
		{name: "TF_CLI_ARGS_init", cmd: "TF_CLI_ARGS_init='-migrate-state -force-copy' terraform init", class: StateSurgery, dir: "-"},
		{name: "TF_CLI_ARGS on apply", cmd: "TF_CLI_ARGS=-destroy terraform apply", class: Destroy, dir: "-"},
		// C14: cloud CLI verbs and flag values.
		{name: "gcloud storage rm with a flag value that is a read word", cmd: "gcloud storage rm -r gs://b --verbosity info", class: CloudDestructive, dir: "-"},
		{name: "az delete-batch with --auth-mode login", cmd: "az storage blob delete-batch --source c --account-name a --auth-mode login", class: CloudDestructive, dir: "-"},
		{name: "gsutil rm", cmd: "gsutil -m rm -r gs://b", class: CloudDestructive, dir: "-"},
		{name: "gsutil ls", cmd: "gsutil ls gs://b", class: ReadOnly, dir: "-"},
		{name: "gcloud list stays read-only", cmd: "gcloud compute instances list --format json", class: ReadOnly, dir: "-"},
		{name: "gcloud create is a write", cmd: "gcloud compute instances create vm-info --zone z", class: CloudWrite, dir: "-"},
		{name: "kubectl --cluster target", cmd: "kubectl --cluster prod delete ns payments", class: CloudDestructive, dir: "-", target: "prod"},
		{name: "kubectl --server target", cmd: "kubectl --server https://prod.example:6443 get pods", class: ReadOnly, dir: "-", target: "https://prod.example:6443"},
		{name: "helm --kube-apiserver target", cmd: "helm --kube-apiserver https://k uninstall web", class: CloudDestructive, dir: "-", target: "https://k"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := first(classify(t, c.cmd, "/r/envs/dev", c.env))
			if a.Class != c.class {
				t.Fatalf("class %q (%s), want %q", a.Class, a.Why, c.class)
			}
			if c.dir != "-" && a.Dir != c.dir {
				t.Errorf("dir %q, want %q", a.Dir, c.dir)
			}
			if a.AnyDir != c.anyDir {
				t.Errorf("AnyDir %v, want %v", a.AnyDir, c.anyDir)
			}
			if c.target != "" && a.Target != c.target {
				t.Errorf("target %q, want %q", a.Target, c.target)
			}
		})
	}
}

// Problems after which the analysis stopped are judged anywhere under the
// root (C12); an unknown directory from the analysis is too (C3, C11).
func TestAnyDir(t *testing.T) {
	for cmd, want := range map[string]bool{
		"cd ../prod && terraform destroy\n)": true,
		"cd $(cat d) && terraform destroy":   true,
		"terraform destroy":                  false,
		"cd ../prod && terraform destroy":    false,
	} {
		anyDir := false
		for _, a := range classify(t, cmd, "/r/envs/dev", nil) {
			anyDir = anyDir || a.AnyDir
		}
		if anyDir != want {
			t.Errorf("%q: AnyDir %v, want %v", cmd, anyDir, want)
		}
	}
}
