package classify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Flurit/applygate/internal/shell"
)

// state writes the layout the round-11 reproductions use: a protected
// directory with a local state file next to a dev one.
func round11Dirs(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	for _, d := range []string{"envs/prod", "envs/dev"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "terraform.tfstate"), []byte(`{"version":4}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func stateSurgeryAt(acts []Action, dir string) bool {
	for _, a := range acts {
		if a.Class == StateSurgery && a.Dir == dir {
			return true
		}
	}
	return false
}

func TestStateFileNamedByAnyWriter(t *testing.T) {
	root := round11Dirs(t)
	prod := filepath.Join(root, "envs/prod")
	for _, cmd := range []string{
		"find -P . -name terraform.tfstate -delete", "find -L . -type f -delete", "find -H ../prod -delete",
		"rm -rf ~+", "cp ../dev/terraform.tfstate ~+", "cp --target-directory=. ../dev/terraform.tfstate",
		"cp -t. ../dev/terraform.tfstate", "mv --target=. ../dev/terraform.tfstate",
		"zip -mj x.zip terraform.tfstate", "zip -qm x.zip terraform.tfstate",
		"git archive -o terraform.tfstate HEAD", "git archive -oterraform.tfstate HEAD", "git bundle create terraform.tfstate HEAD",
		"opa build -o terraform.tfstate .", "kustomize build . -o terraform.tfstate", "kustomize build . --output=terraform.tfstate",
		"az rest --method get --url https://x --output-file terraform.tfstate", "gh release download v1 -O terraform.tfstate",
		"curl --hsts terraform.tfstate http://x", "curl --alt-svc terraform.tfstate http://x", "curl -w '%output{terraform.tfstate}x' http://x",
		"wget --save-cookies terraform.tfstate http://x", "wget --hsts-file=terraform.tfstate http://x",
		"tar -rf terraform.tfstate x", "tar --append -f terraform.tfstate x",
		"aws apigateway get-export --rest-api-id a --stage-name s --export-type swagger terraform.tfstate",
		"aws eks update-kubeconfig --name x --kubeconfig terraform.tfstate",
		"echo x >! terraform.tfstate", "echo x > terraform.tfstate{,.bak}",
	} {
		if !stateSurgeryAt(classify(t, cmd, prod, nil), prod) {
			t.Errorf("%s: not state surgery in %s: %+v", cmd, prod, classify(t, cmd, prod, nil))
		}
	}
}

func TestStateFileReadersStayAllowed(t *testing.T) {
	root := round11Dirs(t)
	prod := filepath.Join(root, "envs/prod")
	for _, cmd := range []string{
		"cut -d, -f1 terraform.tfstate", "jq . terraform.tfstate", "grep x terraform.tfstate", "zip b.zip terraform.tfstate",
		"tar cf b.tar terraform.tfstate", "cp terraform.tfstate terraform.tfstate.bak", "sed -n 1p terraform.tfstate",
		"awk '{print}' terraform.tfstate", "wc -l terraform.tfstate", "ls ~+",
	} {
		for _, a := range classify(t, cmd, prod, nil) {
			if a.Class == StateSurgery {
				t.Errorf("%s: read treated as state surgery: %s", cmd, a.Why)
			}
		}
	}
	// A script that writes the file inside its text is a write.
	if !stateSurgeryAt(classify(t, `awk '{print > "terraform.tfstate"}' x`, prod, nil), prod) {
		t.Errorf("awk writing the state file in its script is not state surgery")
	}
}

func TestCopyWithGlobAndUnresolvedDestinationDoesNotPanic(t *testing.T) {
	root := round11Dirs(t)
	dev := filepath.Join(root, "envs/dev")
	for _, cmd := range []string{`cp *.txt "$DEST"`, `cp -r build/* "$OUT"`, `mv *.log "$d"`, `rsync -a build/* "$OUT"`, `ln -s *.so "$LIB"`, `cp "$A" "$B"`} {
		acts := classify(t, cmd, dev, nil) // a panic fails the test
		if len(acts) == 0 {
			t.Errorf("%s: no action: an unresolved destination may be a state file", cmd)
		}
	}
}

func TestTargetDirectoryForms(t *testing.T) {
	w := func(s ...string) []shell.Word {
		var out []shell.Word
		for _, x := range s {
			out = append(out, shell.Word{Text: x, Resolved: true, Prefix: x})
		}
		return out
	}
	for _, args := range [][]string{
		{"-t", "d", "a"}, {"-td", "a"}, {"--target-directory", "d", "a"}, {"--target-directory=d", "a"}, {"--target=d", "a"}, {"a", "-t", "d"},
	} {
		td, rest, ok := targetDirectory(w(args...))
		if !ok || td.Text != "d" || len(rest) != 1 || rest[0].Text != "a" {
			t.Errorf("%v: got %q %v %v", args, td.Text, rest, ok)
		}
	}
	if _, _, ok := targetDirectory(w("a", "b")); ok {
		t.Errorf("no option, yet found one")
	}
}

func TestCurlAndGhMutations(t *testing.T) {
	for cmd, want := range map[string]Class{
		"curl -X DELETE https://management.azure.com/x":                                       CloudDestructive,
		"curl -XDELETE https://api.github.com/repos/o/r":                                      CloudDestructive,
		"wget --method=DELETE https://x":                                                      CloudDestructive,
		"curl --aws-sigv4 aws:amz:us-east-1:ec2 -X POST https://ec2.us-east-1.amazonaws.com/": CloudWrite,
		"gh api -X DELETE repos/o/r":                                                          CloudDestructive,
		"gh repo delete o/r --yes":                                                            CloudDestructive,
		"gh workflow run destroy.yml":                                                         CloudWrite,
	} {
		if a := first(classify(t, cmd, "/r/envs/prod", nil)); a.Class != want {
			t.Errorf("%s: got %s, want %s", cmd, a.Class, want)
		}
	}
	for _, cmd := range []string{"curl https://example.com", "curl -X DELETE http://localhost:9200/i", "curl -X POST https://example.com -d x", "gh pr list"} {
		for _, a := range classify(t, cmd, "/r/envs/prod", nil) {
			if a.Class == CloudDestructive || a.Class == CloudWrite {
				t.Errorf("%s: ordinary call classified %s", cmd, a.Class)
			}
		}
	}
}

func TestSecretPrintingReadsAreCredentialAccess(t *testing.T) {
	for _, cmd := range []string{
		"aws secretsmanager get-secret-value --secret-id x", "aws ssm get-parameter --name /x --with-decryption",
		"aws sts get-session-token", "aws ecr get-login-password", "kubectl get secret db -o yaml", "kubectl get secrets -o json",
		"kubectl config view --raw", "az keyvault secret show --name n --vault-name v",
	} {
		if a := first(classify(t, cmd, "/r/envs/dev", nil)); a.Class != CredentialAccess {
			t.Errorf("%s: got %s", cmd, a.Class)
		}
	}
	for _, cmd := range []string{"kubectl get pods -o yaml", "kubectl get secret db", "aws ssm get-parameter --name /x", "aws sts get-caller-identity"} {
		if a := first(classify(t, cmd, "/r/envs/dev", nil)); a.Class == CredentialAccess {
			t.Errorf("%s: ordinary read treated as credential access", cmd)
		}
	}
}

func TestS3WrittenObject(t *testing.T) {
	for cmd, want := range map[string]string{
		"aws s3 cp x s3://b/k":                             "s3://b/k",
		"aws s3 mv s3://b/k s3://c/k":                      "s3://b/k",
		"aws s3 rm s3://b/k":                               "s3://b/k",
		"aws s3 sync . s3://b/p/":                          "s3://b/p/",
		"aws s3api put-object --bucket b --key k --body f": "s3://b/k",
		"aws s3 ls s3://b/k":                               "",
		"aws s3api get-object --bucket b --key k out":      "",
	} {
		if a := first(classify(t, cmd, "/r/envs/dev", nil)); a.S3Object != want {
			t.Errorf("%s: S3Object %q, want %q", cmd, a.S3Object, want)
		}
	}
}

func TestTerragruntSingleDashOptions(t *testing.T) {
	for _, cmd := range []string{"terragrunt -working-dir ../prod destroy", "terragrunt -terragrunt-working-dir=../prod destroy", "terragrunt --working-dir=../prod destroy"} {
		if a := first(classify(t, cmd, "/r/envs/dev", nil)); a.Dir != "/r/envs/prod" {
			t.Errorf("%s: Dir %q", cmd, a.Dir)
		}
	}
	if a := first(classify(t, "gcloud projects delete acme-9f2", "/r/envs/dev", nil)); a.Target != "acme-9f2" {
		t.Errorf("gcloud projects delete: target %q", a.Target)
	}
}

func TestModelledProgramRefusesWrapperNames(t *testing.T) {
	for _, n := range []string{"busybox", "gtar", "gmv", "bsdtar", "rename", "python3.11", "tar", "expect", "claude"} {
		if !ModelledProgram(n) {
			t.Errorf("%s is modelled", n)
		}
	}
	for _, n := range []string{"company-run", "mytool", "make-it-so"} {
		if ModelledProgram(n) {
			t.Errorf("%s is not modelled", n)
		}
	}
}
