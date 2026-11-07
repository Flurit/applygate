package shell

import (
	"strings"
	"testing"
)

func TestStage6Programs(t *testing.T) {
	plain := []string{
		"docker ps", "docker ps -a --format '{{.Names}}'", "docker images -q", "docker image ls --digests", "docker image inspect x", "docker inspect -f '{{.State}}' c", "docker logs -f --tail 20 c",
		"docker version", "docker info", "docker context ls", "docker context show", "docker compose ps", "docker compose -f x.yml config -q", "docker compose logs --tail 5 web", "docker -H unix:///var/run/docker.sock ps",
		"docker --context prod ps", "podman ps -a", "podman images", "podman logs c", "podman --log-level debug ps",
		"gh pr list --state open --json number,title", "gh pr view 12 --json state -q .state", "gh pr diff 12 --name-only", "gh pr checks 12", "gh pr create --title t --body b --base main", "gh pr comment 12 -b ok",
		"gh pr merge 12 --squash", "gh issue list -L 5 -l bug", "gh issue view 3", "gh issue create -t t -b b", "gh repo view -R a/b --json name", "gh run list -L 3 --json status", "gh run view 123 --log-failed",
		"gh api repos/a/b/pulls --paginate", "gh api repos/a/b -q .name", "gh api -X GET repos/a/b", "gh auth status", "gh config get editor", "gh search prs --owner a --state=open foo", "gh release list", "gh workflow list", "gh status",
		"glab mr list", "glab ci status", "glab issue view 3", "glab api projects", "glab auth status",
		"trivy fs .", "trivy image --severity HIGH,CRITICAL alpine", "trivy config --format json dir", "trivy fs --scanners vuln,secret --skip-dirs vendor .", "trivy repo https://github.com/a/b", "trivy version", "trivy k8s --report summary cluster",
		"kustomize build overlays/dev", "kustomize build --load-restrictor LoadRestrictionsNone .", "kustomize version",
		"opa eval -d policy.rego -i in.json 'data.x'", "opa test ./policy -v", "opa fmt -d policy.rego", "opa fmt -l .", "opa check policy.rego", "opa parse x.rego", "opa inspect bundle", "opa version",
		"conftest test plan.json -p policy", "conftest test --no-color -o json x.yaml", "conftest verify -p policy", "conftest parse x.yaml", "conftest version",
		"infracost --version", "infracost version", "infracost output --path out.json --format table", "infracost configure get api_key",
		"terragrunt --version", "terragrunt hclfmt", "terragrunt hclfmt --terragrunt-check", "terragrunt hcl fmt --check", "terragrunt help",
		"terraform-docs markdown table .", "terraform-docs json modules/x", "terraform-docs markdown table --sort-by required .", "terraform-docs version",
		"checkov -d . --quiet --compact", "checkov -f main.tf --framework terraform --skip-check CKV_AWS_1", "checkov -d . -o json --soft-fail",
	}
	for _, c := range plain {
		if ok, why := PlainShape(c, analyze(c, "/r")); !ok {
			t.Errorf("%q should be plain: %s", c, why)
		}
	}
	notPlain := []string{
		"docker -H ssh://h ps", "docker --host=ssh://h ps", "docker --config d ps", "docker ps -H ssh://h", "docker run alpine", "docker exec c sh", "docker rm c", "docker compose up", "docker compose run x", "docker compose -f x.yml config -o out.yml",
		"docker build .", "docker foo", "docker ps $X", "docker logs --follow=x --bogus c", "podman --runtime /x ps", "podman --conmon x ps", "podman --connection c ps", "podman --url ssh://h ps", "podman --identity k ps", "podman -c x ps", "podman machine ssh",
		"podman compose ps", "podman run x",
		"gh pr view 1 --web", "gh pr view 1 -w", "gh pr create --editor", "gh pr create -e", "gh pr create --web", "gh pr diff 1 --web", "gh pr list -w", "gh alias set x y", "gh extension install x", "gh myext", "gh api repos/a/b --input f -X POST --web",
		"gh repo delete a/b", "gh repo create x", "gh repo clone a/b -- --upload-pack=sh", "gh release create v1", "gh release download v1", "gh run download 1", "gh workflow run x", "gh pr review 1 --approve", "gh auth login", "gh auth status --show-token",
		"gh config set editor sh", "gh codespace ssh", "gh secret set x", "gh pr list $X", "gh browse", "gh gist create f", "gh run rerun 1", "gh pr merge 1 --edit",
		"glab mr create", "glab mr merge 1", "glab alias set a b", "glab ci run", "glab api x --web", "glab auth login",
		"trivy fs -o out.json .", "trivy fs --output out.json .", "trivy fs -c cfg.yaml .", "trivy fs --config cfg.yaml .", "trivy k8s --kubeconfig k cluster", "trivy plugin install x", "trivy image --generate-default-config", "trivy module install x", "trivy fs $X",
		"kustomize build --enable-alpha-plugins .", "kustomize build --enable-exec .", "kustomize build --enable-helm .", "kustomize build --helm-command sh .", "kustomize build -o out .", "kustomize edit set image a=b", "kustomize create", "kustomize cfg cat x", "kustomize localize x",
		"opa build ./policy", "opa fmt -w x.rego", "opa fmt --write x.rego", "opa run -s", "opa eval --watch x", "opa test -w ./policy", "opa sign x", "opa exec x",
		"conftest fmt x", "conftest test --update https://x p.json", "conftest push x", "conftest pull x", "conftest plugin install x",
		"infracost breakdown --path .", "infracost diff --path .", "infracost configure set api_key x", "infracost auth login", "infracost output --path out.json --out-file r.txt",
		"terragrunt plan", "terragrunt run-all apply", "terragrunt init", "terragrunt hclfmt --terragrunt-config x", "terragrunt render-json", "terragrunt validate",
		"terraform-docs markdown table --output-file README.md .", "terraform-docs markdown -c cfg.yml .", "terraform-docs markdown --config cfg.yml .", "terraform-docs markdown --output-mode inject .", "terraform-docs markdown --output-template t .", "terraform-docs markdown --output-check .", "terraform-docs foo .",
		"checkov -d . --external-checks-dir ext", "checkov -d . --external-checks-git url", "checkov --config-file c.yaml -d .", "checkov -d . --output-file-path out", "checkov -d . --bc-api-key k", "checkov -d . --create-baseline", "checkov -d . $X",
	}
	for _, c := range notPlain {
		if ok, _ := PlainShape(c, analyze(c, "/r")); ok {
			t.Errorf("%q should not be plain", c)
		}
	}
}

// The options that run a program or write a file by name are absent from the
// tables: a key is a program (and subcommand words) and the options that no leaf
// under it may list. A new entry for one fails this test.
func TestDangerousOptionsAreAbsentFromTheTables(t *testing.T) {
	danger := map[string][]string{
		"git": {"--ext-diff", "--textconv", "--filters", "--exec", "--upload-pack", "--receive-pack", "--open-files-in-pager", "--output", "--work-tree",
			"--exec-path", "--config-env", "--template", "--tool", "--help", "--edit", "--gpg-sign", "--lost-found", "--separate-git-dir", "--interactive", "--remote", "--show-signature",
		},
		"git rebase":       {"-x", "-i"},
		"git grep":         {"-O"},
		"git commit":       {"-S", "-e", "-c", "-t", "--template"},
		"git tag":          {"-s", "-u", "-v", "--verify"},
		"git add":          {"-e", "-i", "-p"},
		"git clone":        {"-u", "-c", "--config", "--template"},
		"git ls-remote":    {"-u"},
		"git archive":      {"-o"},
		"git format-patch": {"-o"},
		"git merge":        {"-e", "-S"},
		"git pull":         {"-e", "-S"},
		"git cherry-pick":  {"-e", "-S"},
		"git revert":       {"-e", "-S"},
		"docker":           {"--config", "-H", "--host", "--runtime"},
		"podman":           {"--runtime", "--conmon", "--hooks-dir", "--network-cmd-path", "--helper-binaries-dir", "--url", "--identity", "--connection", "-c", "--remote", "--cdi-spec-dir", "--root", "--runroot", "--storage-opt"},
		"gh":               {"--web", "--editor", "--output", "--dir", "--clobber"},
		"gh pr":            {"-w", "-e"}, "gh issue": {"-w", "-e"}, "gh repo": {"-w", "-e"}, "gh release": {"-w", "-e"}, "gh gist": {"-w", "-e"}, "gh label": {"-w", "-e"},
		"trivy":          {"-o", "--output", "-c", "--config", "--kubeconfig", "--generate-default-config"},
		"kustomize":      {"--enable-alpha-plugins", "--enable-exec", "--enable-helm", "--helm-command"},
		"opa":            {"-w", "--write", "--watch", "--output"},
		"conftest":       {"--update"},
		"checkov":        {"--external-checks-dir", "--external-checks-git", "--config-file", "--output-file-path"},
		"terraform-docs": {"-c", "--config", "--output-file", "--output-mode", "--output-template", "--output-check", "--output-format"},
	}
	for _, c := range allowCmds {
		if c.name == "git" && c.words[0] != "rev-parse" && (c.p.flags["--git-dir"] || c.p.vals["--git-dir"]) {
			t.Errorf("git %s lists --git-dir", c.words[0])
		}
		key := c.name + " " + strings.Join(c.words, " ")
		for k, bad := range danger {
			if key != k && !strings.HasPrefix(key, k+" ") {
				continue
			}
			for _, o := range bad {
				if c.p.flags[o] || c.p.vals[o] || c.p.optVal[o] {
					t.Errorf("%s lists %s, which runs a program or writes a file by name", key, o)
				}
			}
		}
	}
	for _, o := range []string{"--config", "--output-file"} {
		if allowProgs["checkov"].flags[o] || allowProgs["checkov"].vals[o] {
			t.Errorf("checkov lists %s", o)
		}
	}
}

// Every program with an allow-list entry that has a write kind in OutputOpts
// still reports it: the classifier names the path from it.
func TestOutputOptionsStayNextToTheEntries(t *testing.T) {
	want := map[string]string{
		"curl": "-o", "wget": "-O", "tree": "-o", "tfsec": "--out", "terraform-docs": "--output-file", "trivy": "-o", "checkov": "--output-file-path", "tflint": "--out",
		"infracost": "--out-file", "go": "-o", "git": "--output", "find": "-fprint", "terraform": "-out", "tofu": "-state-out", "terragrunt": "-backup", "kustomize": "-o", "opa": "-o",
	}
	for n, o := range want {
		found := false
		for _, x := range OutputOpts(n) {
			found = found || x == o
		}
		if !found {
			t.Errorf("%s has no output option %s", n, o)
		}
	}
}

func TestStage6Readers(t *testing.T) {
	plain := []string{"ls -la", "ls -lah dir", "ls -1 a b", "ls --color=auto", "ls -ltr", "ls -R .", "cat a.txt", "cat -n a b", "head -n 5 f", "head -5 f", "head -c 100 f", "tail -n +3 f", "tail -f log", "tail -n 20 f",
		"wc -l f", "wc -lw a b", "cut -d, -f1 f", "cut -c1-5 f", "basename -s .txt a.txt", "basename a/b", "dirname a/b", "realpath .", "realpath -m x", "readlink -f a", "seq 1 10", "seq -5 5", "seq -s, 1 3",
		`cat "$f"`, `ls "$d"`, "cat a | head -3 | wc -l"}
	for _, c := range plain {
		if ok, why := PlainShape(c, analyze(c, "/r")); !ok {
			t.Errorf("%q should be plain: %s", c, why)
		}
	}
	for _, c := range []string{"cat --nosuch f", "ls --bogus", "ls -j", "head --nosuch f", "tail --nosuch f", "wc --nosuch f", "cut --nosuch f", "seq --nosuch 3", "realpath --nosuch a", "readlink --nosuch a"} {
		if ok, _ := PlainShape(c, analyze(c, "/r")); ok {
			t.Errorf("%q should not be plain", c)
		}
	}
}
