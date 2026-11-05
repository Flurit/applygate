package shell

import (
	"sort"
	"testing"
)

// The programs that keep "any arguments" are the audited ones in inert, plus
// the programs whose shapes are written elsewhere; adding a name to the nil set
// means auditing it.
func TestNilShapesAreTheAuditedOnes(t *testing.T) {
	elsewhere := toSet("applygate", "env")
	var extra []string
	for n, s := range shapes {
		if s == nil && !inert[n] && !elsewhere[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("programs with a nil shape that are not in the audited list: %v", extra)
	}
	for n := range inert {
		if s, ok := shapes[n]; !ok || s != nil {
			t.Errorf("%s is listed as inert but has a shape", n)
		}
	}
}

func plainCall(t *testing.T, cmd string) bool {
	t.Helper()
	ok, _ := PlainShape(cmd, analyze(cmd, "/r"))
	return ok
}

func TestAllowListedProgramsOnlyTakeListedOptions(t *testing.T) {
	plain := []string{
		"rm -rf build", "rm -f a b", "mkdir -p out/x", "touch a", "chmod -R go-w dir", "chmod -x run.sh", "chmod 644 a",
		"ln -s a b", "cp -r a b", "cp -t dir a b", "mv -f a b", "tee -a log", "echo x | tee out.txt",
		"sort -u a", "sort -k2,2 -t, a", "sort -n a", "uniq -c a", "tree -L 2", "diff -u a b", "diff -r a b",
		"xxd a", "xxd -r -p a", "base64 -d a", "gzip -dc a.gz", "gzip -c a", "gzip -l a.gz", "gunzip -c a.gz", "unzip -l a.zip", "unzip -p a.zip f", "unzip -o a.zip", "unzip -d out a.zip",
		"date +%Y", "date -u +%s", "hostname", "file -b a", "gofmt -l .", "gofmt -d a.go", "tfsec . --format json",
		"gsutil ls gs://b", "find . -name '*.tf' -type f", "find . -maxdepth 2 -not -path './.git/*' -print", "find . \\( -name a -o -name b \\) -print0",
		"find . -newer a -size +1M", "find dir -mtime -7",
	}
	for _, c := range plain {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q should be plain: %v %s", c, ok, why)
		}
	}
	notPlain := []string{
		// options that write a file or run a program, and spellings of them
		"sort -o out a", "sort -oout a", "sort --output=out a", "sort --compress-program=sh a", "sort --compress a", "sort -T /tmp a",
		"uniq a out", "tree -o out", "tree --output=out", "tree -H x", "diff -l a b", "diff --paginate a b",
		"xxd -r a out", "base64 -o out a", "base64 -i a -o out",
		"gzip a", "gunzip a.gz", "gzip -k a", "unzip -O cp866 a.zip", "unzip --foo a.zip",
		"date -s 2020-01-01", "date --set=x", "date 110512302026", "hostname newname", "file -C", "gofmt -w a.go", "gofmt -cpuprofile p a.go",
		"tfsec --out r.json .", "gsutil rm gs://b/x", "gsutil -o x:y ls", "gsutil cp a gs://b",
		"find . -exec sh -c x ;", "find . -execdir sh ;", "find . -delete", "find . -fprint out", "find . -fprint0 out", "find . -fprintf out x",
		"find . -fls out", "find -P . -delete", "find . -name a -exec sh -c x ;", "find . -newerXY x", "find . -foo",
		"rm --no-preserve-root -rf /", "rm --recur a", "cp --rec a b", "cp -b a b", "cp --backup a b", "cp -S x a b", "mv -S x a b", "ln --sym a b",
		"mkdir --mod=0 a", "chmod --silly a", "tee --append x -z",
		// an unresolved word may be an option
		"sort $X a", "tree $X", "find $X -name a", "find . $X", "uniq $X", "xxd $X",
	}
	for _, c := range notPlain {
		if plainCall(t, c) {
			t.Errorf("%q should not be plain", c)
		}
	}
}

func TestAllowListLooseProgramsTakeVariableOperands(t *testing.T) {
	for _, c := range []string{`rm -rf "$DIR"`, `mkdir -p "$d/x"`, `cp "$a" "$b"`, `mv "$a" "$b"`, `touch "$f"`, `chmod +x "$f"`, `ln -s "$a" "$b"`} {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q: %v %s", c, ok, why)
		}
	}
}

func TestAllowListStage2(t *testing.T) {
	plain := []string{
		"curl -sSL https://example.com/x", "curl -fsSL -o out.sh https://example.com/x", "curl -s -H 'Accept: application/json' https://example.com",
		"curl -X POST -d @body.json https://example.com", "curl -sS -w '%{http_code}' https://example.com", "curl -I https://example.com",
		"curl --retry 3 --max-time 10 --compressed https://example.com", "curl -O https://example.com/a.tgz", "curl -u user:pw https://example.com",
		"wget -q https://example.com/x", "wget -qO- https://example.com/x", "wget -O out.tgz https://example.com/x", "wget --post-data=a=b https://example.com",
		"zip -r out.zip dir", "zip -qr out.zip dir -x '*.git*'", "zip -j out.zip a b",
		"yq '.a.b' file.yaml", "yq -r '.a' f.yaml", "yq -i '.a = 1' f.yaml", "yq eval '.a' f.yaml", "yq -o json f.yaml",
		"rg foo", "rg -n --hidden -g '*.tf' foo dir", "rg -C 2 -i 'a b' .", "rg --files -t tf", "rg -e foo -e bar",
		"printf '%s\\n' hello", "printf -- '-x\\n'",
		"tflint --recursive", "actionlint -oneline",
	}
	for _, c := range plain {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q should be plain: %v %s", c, ok, why)
		}
	}
	notPlain := []string{
		// options that read options, write files the analysis does not follow, or run programs
		"curl -K cfg https://example.com", "curl --config cfg https://example.com", "curl -c jar https://example.com", "curl --cookie-jar jar https://example.com",
		"curl -D hdr https://example.com", "curl --dump-header hdr https://example.com", "curl --stderr err https://example.com", "curl --trace t https://example.com",
		"curl --libcurl x.c https://example.com", "curl --hsts h https://example.com", "curl --etag-save e https://example.com", "curl --create-dirs -o a/b https://example.com",
		"curl --output-dir /x -O https://example.com/a", "curl -o a https://x/1 -o b https://x/2", "curl -O https://x/1 -O https://x/2", "curl --next https://x",
		"curl -w '%output{f}x' https://example.com", "curl -w @fmt https://example.com", "curl -o 'out_#1' 'https://x/[a-c]'", "curl --engine e https://x",
		"curl --silen https://x", "curl $X https://x",
		"wget -o log https://x", "wget -a log https://x", "wget -i urls https://x", "wget -b https://x", "wget -r https://x", "wget -m https://x", "wget -e robots=off https://x",
		"wget --execute x https://x", "wget --content-disposition https://x", "wget --save-cookies c https://x", "wget -O a -O b https://x", "wget --config c https://x",
		"zip -T a.zip", "zip -TT sh a.zip b", "zip --unzip-command sh a.zip b", "zip -O out.zip a", "zip -b /tmp a.zip b", "zip -z a.zip",
		"yq -s '.a' f.yaml", "yq --split-exp x f.yaml", "yq --security-enable-system-operator '.a' f", "yq --nosuch f",
		"rg --pre cmd foo", "rg --pre-glob '*.x' foo", "rg -z foo", "rg --search-zip foo", "rg --hostname-bin x foo", "rg --nosuch foo", "rg $X",
		"printf -v x %s a", "printf '%s' $x", "tflint --init", "tflint --config c", "tflint --plugin-dir d", "tflint -c c",
		"actionlint -shellcheck sh", "actionlint -pyflakes x", "actionlint -init-config",
	}
	for _, c := range notPlain {
		if plainCall(t, c) {
			t.Errorf("%q should not be plain", c)
		}
	}
}

func TestStage3Grammars(t *testing.T) {
	plain := []string{"cd dir && ls", "cd -P dir", "cd", "cd ..", "echo x > out.txt", "echo x >> out.txt", "cat < in.txt", "ls 2>&1", "ls >/dev/null 2>&1", "cat <<EOF\nhi\nEOF", `cd "$HOME"`}
	for _, c := range plain {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q should be plain: %v %s", c, ok, why)
		}
	}
	notPlain := []string{"cd a b", "cd -", "cd -x a", "echo x >| out", "echo x >! out", "echo x <> out", "echo x > out{1,2}", "echo x > *.txt", "echo x > ~/out", "echo x > $OUT", `echo x > "$OUT"`,
		"echo x > =cmd", "echo x &> out", "echo x {fd}> out", "echo x >& out", "echo x > ''"}
	for _, c := range notPlain {
		if plainCall(t, c) {
			t.Errorf("%q should not be plain", c)
		}
	}
}

func TestStage4Verbs(t *testing.T) {
	plain := []string{
		"terraform plan -input=false -out=tfplan", "terraform import a.b id", "kubectl port-forward p 80:80", "aws eks update-kubeconfig --name c", "terraform plan -var-file=prod.tfvars -var 'a=b' -target=module.x", "terraform validate -json", "terraform fmt -check -recursive",
		"terraform -chdir=envs/dev plan -no-color", "terraform show -json tfplan", "terraform output -raw x", "terraform state list", "terraform state show aws_s3_bucket.a",
		"terraform workspace show", "terraform workspace select dev", "terraform init -backend=false -input=false", "terraform version", "terraform providers schema -json",
		"terraform providers lock -platform=linux_amd64", "terraform plan -state=terraform.tfstate.backup", "tofu plan -detailed-exitcode", "terraform apply tfplan", "terraform apply -auto-approve",
		"aws sts get-caller-identity", "aws ec2 describe-instances --region us-east-1", "aws s3 ls s3://b", "aws iam list-roles --query 'x'", "aws logs tail /x", "aws configure get region",
		"aws dynamodb scan --table-name t", "aws --version", "aws ec2 wait instance-running --instance-ids i-1",
		"az group list", "az vm show -g r -n n", "az account show", "gcloud compute instances list", "gcloud config get-value project", "gcloud projects describe p",
		"kubectl get pods -n x", "kubectl describe pod p", "kubectl logs p -f", "kubectl rollout status deploy/x", "kubectl auth can-i get pods", "kubectl config current-context", "kubectl version",
		"helm list -A", "helm status r", "helm template r ./chart", "helm get values r", "helm repo list", "vault status", "vault kv get secret/x", "vault read secret/x",
	}
	for _, c := range plain {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q should be plain: %v %s", c, ok, why)
		}
	}
	notPlain := []string{
		"terraform plan -state-out=x", "terraform plan -backup=x", "terraform plan -generate-config-out=x.tf", "terraform init -plugin-dir=/x", "terraform apply -state=x tfplan",
		"terraform taint a.b", "terraform state rm a.b", "terraform state mv a b", "terraform state push x", "terraform workspace new x", "terraform workspace delete x",
		"terraform console", "terraform test", "terraform refresh", "terraform force-unlock id", "terraform providers mirror dir", "terraform graph -type=plan", "terraform plan -nosuch", "terraform plan $X",
		"aws ssm start-session --target i-1", "aws ecs execute-command --cluster c --command sh", "aws emr ssh --cluster-id j", "aws s3 cp a s3://b/c", "aws s3 sync . s3://b", "aws ec2 run-instances", "aws configure set x y",
		"aws ec2-instance-connect ssh --instance-id i", "az vm run-command invoke", "az ssh vm", "az group create -n x", "az rest --method get --url u", "gcloud compute ssh vm", "gcloud compute instances delete v",
		"kubectl exec p -- sh", "kubectl edit deploy x", "kubectl diff -f x", "kubectl apply -f x", "kubectl delete pod p", "kubectl cp a p:/b", "kubectl foo", "kubectl --kubeconfig k get pods",
		"helm install r c", "helm upgrade r c", "helm uninstall r", "helm plugin install x", "helm template r c --post-renderer p", "vault write secret/x a=b", "vault server -dev", "vault kv put secret/x a=b",
	}
	for _, c := range notPlain {
		if plainCall(t, c) {
			t.Errorf("%q should not be plain", c)
		}
	}
}
