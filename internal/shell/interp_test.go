package shell

import (
	"strings"
	"testing"
)

// The four Python bodies Claude Code ran in the agent-driven trial of
// 2026-10-29 (abbreviated): each edits a .tf or .hcl file and mentions
// terraform or terragrunt only as text.
var trialEdits = []string{
	// cloud-platform-infrastructure: pin launch template names in cluster.tf.
	"python3 -I - <<'EOF'\nimport re\np='cluster.tf'\ns=open(p).read()\npins={'def':'default_ng_19_06_26','mon':'monitoring_ng_19_06_26'}\nfor short,key in pins.items():\n    pat=re.compile(r'(    name       = \"\\$\\{terraform\\.workspace\\}-%s-ng\"\\n)'%short)\n    assert len(pat.findall(s))==1,short\n    s=pat.sub(r'\\1    launch_template_name = \"%s\"\\n'%key,s)\nopen(p,'w').write(s)\nEOF\nterraform fmt -no-color cluster.tf moved.tf; git diff cluster.tf",
	// cloud-platform-infrastructure: rename node group map keys.
	"python3 -I - <<'EOF'\nimport re\np='cluster.tf'\ns=open(p).read()\nassert s.count('${terraform.workspace}-def-ng')==1\nhead,tail=s.split('  eks_managed_node_groups = merge(',1)\nblock,rest=tail.split('\\n  )\\n',1)\nfor k in ['default_ng_19_06_26']:\n    block=re.sub(r'\\b%s( *)= local\\.'%k, lambda m:k.replace('_','-')+m.group(1)+'= local.', block)\nopen(p,'w').write(head+'  eks_managed_node_groups = merge('+block+'\\n  )\\n'+rest)\nEOF",
	// terragrunt-infrastructure-live-example: switch root.hcl to a local backend.
	"python3 -I - <<'EOF'\nimport re\np='root.hcl'\ns=open(p).read()\nstart=s.index('remote_state {')\nend=s.index('# Configure what repos')\ns=s[:start]+'''remote_state {\n  backend = \"local\"\n  config = {\n    path = \"${get_terragrunt_dir()}/terraform.tfstate\"\n  }\n}\n\n'''+s[end:]\nopen(p,'w').write(s)\nEOF",
	// terragrunt-infrastructure-live-example: add inputs to a copied terragrunt.hcl.
	"python3 -I - <<'EOF'\np='mysql-replica/terragrunt.hcl'\ns=open(p).read()\ni=s.index('# ----', s.index('terraform {'))\ns=s[:i]+'''inputs = {\n  name = \"mysql_replica_${include.envcommon.locals.env}\"\n}\n'''\nopen(p,'w').write(s)\nEOF\ntail -12 mysql-replica/terragrunt.hcl",
}

func TestFileOnlyInterpreterBodies(t *testing.T) {
	fs := fakeFS(map[string]string{
		"/repo/fix.py":  "import re\np='main.tf'\ns=open(p).read()\nopen(p,'w').write(re.sub('terraform','tofu',s))\n",
		"/repo/fix.js":  "const fs=require('node:fs');let s=fs.readFileSync('main.tf','utf8');fs.writeFileSync('main.tf',s.replace(/terraform/g,'tofu'));\n",
		"/repo/body.py": "s=open('main.tf').read()\nopen('main.tf','w').write(s.replace('terraform','tofu'))\n",
	})
	type tc struct {
		name, cmd string
		note      bool   // a file-edit note is expected and no problem
		reason    string // substring of the problem reason otherwise
	}
	cases := []tc{
		{"trial edit 1", trialEdits[0], true, ""},
		{"trial edit 2", trialEdits[1], true, ""},
		{"trial edit 3 mentions .tfstate as text", trialEdits[2], true, ""},
		{"trial edit 4", trialEdits[3], true, ""},
		{"script file", "python3 fix.py", true, ""},
		{"script file with plain arguments", "python3 fix.py cluster.tf", true, ""},
		{"stdin from a file", "python3 - < body.py", true, ""},
		{"-c literal", `python3 -c "s=open('main.tf').read(); open('main.tf','w').write(s.replace('terraform','tofu'))"`, true, ""},
		{"node -e", `node -e "const fs=require('fs');let s=fs.readFileSync('main.tf','utf8');s=s.replace(/terraform\.workspace/g,'x');fs.writeFileSync('main.tf',s)"`, true, ""},
		{"node script with regex exec", "node fix.js", true, ""},
		{"python regex compile is not the builtin", "python3 -c \"import re; p=re.compile('terraform'); open('a.tf','w').write(p.sub('tofu', open('a.tf').read()))\"", true, ""},

		// The same edit plus a way to run something: still asked.
		{"subprocess", "python3 -I - <<'EOF'\nimport re, subprocess\np='cluster.tf'\ns=open(p).read()\nopen(p,'w').write(s)\nsubprocess.run(['terraform','destroy','-auto-approve'])\nEOF", false, "uses subprocess"},
		{"os.system built from pieces", "python3 -I - <<'EOF'\nimport os\ngetattr(os,'sys'+'tem')('terra'+'form destroy -auto-approve')\nEOF", false, "uses getattr()"},
		{"aliased os module", "python3 -I - <<'EOF'\nimport os as o\no.system('terraform destroy')\nEOF", false, "uses system()"},
		{"from os import", "python3 -I - <<'EOF'\nfrom os import system\nsystem('terraform destroy')\nEOF", false, "uses system()"},
		{"__import__", "python3 -c \"__import__('os').system('terraform destroy')\"", false, "uses __import__"},
		{"importlib", "python3 -c \"import importlib; importlib.import_module('os').system('terraform destroy')\"", false, "uses importlib"},
		{"eval", "python3 -c \"eval('print(1)'); open('a.tf','w').write('terraform')\"", false, "uses eval()"},
		{"exec", "python3 -c \"exec(open('x').read()); open('a.tf','w').write('terraform')\"", false, "uses exec()"},
		{"sys.modules", "python3 -c \"import sys; sys.modules['os'].system('terraform destroy')\"", false, "uses sys.modules"},
		{"shutil", "python3 -c \"import shutil; shutil.rmtree('.terraform'); open('a.tf','w').write('terraform')\"", false, "uses shutil"},
		{"local module import", "python3 -c \"import helper; helper.fix('terraform')\"", false, "imports helper"},
		{"ctypes", "python3 -c \"import ctypes; open('a.tf','w').write('terraform')\"", false, "uses ctypes"},
		{"asyncio import", "python3 -c \"import asyncio; open('a.tf','w').write('terraform')\"", false, "imports asyncio"},
		{"boto3", "python3 -I - <<'EOF'\nimport boto3\ns=open('main.tf').read()\nopen('main.tf','w').write(s.replace('terraform','tofu'))\nEOF", false, "uses an AWS SDK"},
		{"requests", "python3 -c \"import requests; open('a.tf','w').write('terraform')\"", false, "imports requests"},
		{"urllib", "python3 -c \"from urllib.request import urlopen; open('a.tf','w').write('terraform')\"", false, "imports urllib.request"},
		{"pickle", "python3 -c \"import pickle; open('a.tf','w').write('terraform')\"", false, "uses pickle"},
		{"base64 in the body", "python3 -c \"import base64; open(base64.b64decode('Lg==').decode(),'w').write('terraform')\"", false, "uses base64"},
		{"escaped characters", `python3 -c "open('\x61.tf','w').write('terraform')"`, false, "builds text at run time"},
		{"chr()", `python3 -c "open(chr(97)+'.tf','w').write('terraform')"`, false, "builds text at run time"},
		{"reversed slice", `python3 -c "open('ft.a'[::-1],'w').write('terraform')"`, false, "builds text at run time"},
		{"guard name under an escaped character", `python3 -c "open('\x2eseatbelt.yaml','w').write('terraform')"`, false, "names seatbelt"},
		{"yaml.load", "python3 -c \"import yaml; yaml.load(open('x')); open('a.tf','w').write('terraform')\"", false, "uses yaml.load"},

		// Guard, credential and state files keep today's verdicts.
		{"guard file target", "python3 -I - <<'EOF'\ns=open('.seatbelt.yaml').read()\nopen('.seatbelt.yaml','w').write(s.replace('enforce','observe'))\nEOF", false, "names .seatbelt.yaml"},
		{"guard file split across literals", `python3 -c "open('.seat'+'belt.yaml','w').write('mode: observe # terraform')"`, false, "names .seatbelt.yaml"},
		{"hook config", `python3 -c "open('.claude/settings.json','w').write('{} # terraform')"`, false, "names .claude/settings"},
		{"credential file", `python3 -c "print(open('/h/.aws/credentials').read()); open('a.tf','w').write('terraform')"`, false, "names .aws/credentials"},
		{"state file as a target", "python3 -I - <<'EOF'\np='terraform.tfstate'\ns=open(p).read()\nopen(p,'w').write(s.replace('\"serial\": 5','\"serial\": 6'))\nEOF", false, "touches the state file terraform.tfstate"},
		{"state file as a literal target", `python3 -c "open('envs/prod/terraform.tfstate','w').write('{}')"`, false, "touches the state file envs/prod/terraform.tfstate"},
		{"provider cache", `python3 -c "open('.terraform/terraform.tfstate','w').write('{} # terraform')"`, false, "touches the state file .terraform/terraform.tfstate"},
		{"pathlib is not followed", `python3 -c "from pathlib import Path; Path('.terraform/terraform.tfstate').write_text('{}')"`, false, "imports pathlib"},
		{"fileinput rewrites in place", `python3 -c "import fileinput; [print(l.replace('terraform','tofu'), end='') for l in fileinput.input(['a.tf'], inplace=True)]"`, false, "imports fileinput"},

		// Write targets assembled at run time fail closed (adversarial review).
		{"guard name assembled from pieces", "python3 -I - <<'EOF'\nimport os\na='seat'\nb='belt'\np='.'+a+b+'.yaml'\n# edit terraform.workspace\nopen(p,'w').write('mode: observe\\n')\nEOF", false, "open() writes to a path it builds at run time"},
		{"state file split across literals", `python3 -c "open('x.'+'tfstate','w').write('{}') # terraform"`, false, "open() writes to a path it builds at run time"},
		{"os.replace onto an assembled name", "python3 -I - <<'EOF'\nimport os\na='seat'\np='.'+a+'belt.yaml'\nopen('tmp','w').write('mode: observe # terraform')\nos.replace('tmp',p)\nEOF", false, "replace() writes to a path it builds at run time"},
		{"os.symlink onto an assembled name", "python3 -I - <<'EOF'\nimport os\na='seat'\np='.'+a+'belt.yaml'\nos.symlink('/etc/evil', p) # terraform\nEOF", false, "symlink() writes to a path it builds at run time"},
		{"os.link to a literal guard name", `python3 -c "import os; os.link('a.tf', '.seat'+'belt.yaml') # terraform"`, false, "names .seatbelt.yaml"},
		{"f-string target", `python3 -c "a='seatbelt'; open(f'.{a}.yaml','w').write('terraform')"`, false, "names seatbelt"},
		{"f-string target without the name", `python3 -c "a='.tf'; open(f'main{a}','w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"percent-formatted target", `python3 -c "p='%s.tf' % 'main'; open(p,'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"os.path.join target", `python3 -c "import os; open(os.path.join('envs','main.tf'),'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"reassigned name", `python3 -c "p='a.tf'; p=p+'x'; open(p,'w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"augmented assignment", "python3 -I - <<'EOF'\np='a'\np+='.tf'\nopen(p,'w').write('terraform')\nEOF", false, "open() writes to a path it builds at run time"},
		{"keyword argument target", `python3 -c "p='a.tf'; open(file=p, mode='w').write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"unknown mode", `python3 -c "m='w'; open(os_path,m).write('terraform')"`, false, "open() writes to a path it builds at run time"},
		{"read of an unresolved path is fine", `python3 -c "import sys; s=open(sys.argv[0]).read(); open('a.tf','w').write(s.replace('terraform','tofu'))"`, true, ""},
		{"os.environ", `python3 -c "import os; os.environ['BASH_ENV']='/tmp/x'; open('a.tf','w').write('terraform')"`, false, "uses environ"},
		{"import os as alias", `python3 -c "import os as o; o.rename('a.tf','b.tf') # terraform"`, false, "imports os under another name"},
		{"os through another module", `python3 -c "import glob; glob.os.rename('a.tf','b.tf') # terraform"`, false, "uses .os"},
		{"help() opens a pager", `python3 -c "help(str); open('a.tf','w').write('terraform')"`, false, "uses help()"},
		{"fexecve", `python3 -c "import os; os.fexecve(3, ['terraform','destroy'], {})"`, false, "uses fexecve()"},
		{"full-width identifiers", "python3 -c \"\uff45\uff56\uff41\uff4c('1'); open('a.tf','w').write('terraform')\"", false, "uses eval()"},
		{"writes a shell start-up file", `python3 -c "open('/h/.bashrc','a').write('alias terraform=rm')"`, false, "touches /h/.bashrc"},
		{"writes a program file", `python3 -c "open('run.sh','w').write('terraform destroy')"`, false, "touches run.sh"},
		{"writes into .git", `python3 -c "open('.git/hooks/pre-commit','w').write('terraform destroy')"`, false, "names .git/hooks"},
		{"relative target resolved against the directory", `cd .claude && python3 -c "open('settings.json','w').write('{} # terraform')"`, false, "touches the guard file settings.json"},
		{"relative target in an ordinary directory", `cd envs/prod && python3 -c "open('settings.json','w').write('{} # terraform')"`, true, ""},
		{"node assembled guard name", `node -e "const fs=require('fs');const a='seat';const b='belt';const p='.'+a+b+'.yaml';/* terraform */fs.writeFileSync(p,'mode: observe');"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node state file split across literals", `node -e "require('fs').writeFileSync('x.'+'tfstate','{}') // terraform"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node template literal target", "node -e 'const a=\"main\";require(\"fs\").writeFileSync(`${a}.tf`,\"terraform\")'", false, "writeFileSync() writes to a path it builds at run time"},
		{"node plain template literal target", "node -e 'require(\"fs\").writeFileSync(`main.tf`,\"terraform\")'", true, ""},
		{"node path.join target", `node -e "const p=require('path');require('fs').writeFileSync(p.join('envs','main.tf'),'terraform')"`, false, "writeFileSync() writes to a path it builds at run time"},
		{"node symlink destination", `node -e "const fs=require('fs');const d='.seat'+'belt.yaml';fs.symlinkSync('/etc/evil', d) // terraform"`, false, "names .seatbelt.yaml"},
		{"node copyFileSync destination assembled", `node -e "const fs=require('fs');const d=['.seat','belt.yaml'].join('');fs.copyFileSync('a.tf', d) // terraform"`, false, "copyFileSync() writes to a path it builds at run time"},
		{"node process.env write", `node -e "process.env.BASH_ENV='/tmp/x';require('fs').writeFileSync('a.tf','terraform')"`, false, "uses process.env"},
		{"node process.chdir", `node -e "process.chdir('.claude');require('fs').writeFileSync('settings.json','terraform')"`, false, "names .claude"},
		{"guard file as a script argument", "python3 fix.py ../.seatbelt.yaml", false, "an argument names"},
		{"state file as a script argument", "python3 fix.py terraform.tfstate", false, "an argument names"},
		{"configured guard file", "python3 -c \"open('audit.jsonl','a').write('terraform')\"", false, "names the guard file audit.jsonl"},
		{"node writes a guard file", `node -e "const fs=require('fs');fs.writeFileSync('.seatbelt.yaml','mode: observe # terraform')"`, false, "names .seatbelt.yaml"},

		// Node ways to run something.
		{"node child_process", `node -e "require('child_process').execSync('terra'+'form destroy')"`, false, "uses child_process"},
		{"node destructured execSync", `node -e "const {execSync}=require('fs');execSync('terraform destroy')"`, false, "uses execSync()"},
		{"node split module name", `node -e "const cp=require('child_'+'process');cp.exec('terraform destroy')"`, false, "uses child_process"},
		{"node computed require without a call", `node -e "const m=['child','process'].join('_');const cp=require(m);cp.exec('terraform destroy')"`, false, "requires a module whose name is computed"},
		{"node Function constructor", `node -e "new Function('return process')().mainModule.require('child_process').exec('terraform destroy')"`, false, "uses Function"},
		{"node fetch", `node -e "fetch('https://x').then(()=>require('fs').writeFileSync('a.tf','terraform'))"`, false, "uses fetch"},
		{"node https import", `node -e "import https from 'https'; require('fs').writeFileSync('a.tf','terraform')"`, false, "imports https"},
		{"node dynamic import", `node -e "const n=process.argv[1];import(n).then(cp=>cp.exec('terraform destroy'))"`, false, "requires a module whose name is computed"},
		{"node process index", `node -e "process['binding']('spawn_sync'); require('fs').writeFileSync('a.tf','terraform')"`, false, "uses process["},

		// Bodies that are not fully known, or not Python or Node.
		{"unquoted heredoc with a variable", "python3 - <<EOF\nimport re\np='cluster.tf'\ns=open(p).read().replace('terraform', '$NAME')\nopen(p,'w').write(s)\nEOF", false, "cannot be analyzed"},
		{"decoded body", "echo cz1vcGVuKCdtYWluLnRmJykucmVhZCgpOyBvcGVuKCdtYWluLnRmJywndycpLndyaXRlKHMucmVwbGFjZSgndGVycmFmb3JtJywndG9mdScpKQo= | base64 -d | python3", false, "cannot be analyzed"},
		{"unresolved script argument", "python3 fix.py $TARGET", false, "an argument cannot be resolved"},
		{"perl", `perl -e 'open(F,">x.tf"); print F "terraform {}"'`, false, "cannot be analyzed"},
		{"ruby", `ruby -e 'File.write("x.tf", "terraform {}")'`, false, "cannot be analyzed"},
	}
	for _, c := range cases {
		r := Analyze(c.cmd, Options{Dir: "/repo", Env: map[string]string{"HOME": "/h"}, ReadFile: fs, MaxDepth: 8,
			ProtectedPaths: []string{"**/.seatbelt.yaml", "/var/log/agent/audit.jsonl"},
			ProtectedPath: func(p string) bool {
				return strings.HasSuffix(p, "/.claude/settings.json") || strings.HasSuffix(p, "/.seatbelt.yaml") || p == "/var/log/agent/audit.jsonl"
			}})
		got := strings.Join(render(r), "\n")
		if c.note {
			if len(r.Problems) != 0 {
				t.Errorf("%s: want no problem, got:\n%s", c.name, got)
			}
			if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "treated as a file edit") {
				t.Errorf("%s: want one file-edit note, got %v", c.name, r.Notes)
			}
			continue
		}
		if len(r.Notes) != 0 {
			t.Errorf("%s: want no note, got %v", c.name, r.Notes)
		}
		if len(r.Problems) == 0 {
			t.Errorf("%s: want a problem, got none:\n%s", c.name, got)
			continue
		}
		if !strings.Contains(r.Problems[0].Reason, "code mentions infrastructure") || !strings.Contains(r.Problems[0].Reason, c.reason) {
			t.Errorf("%s: want reason containing %q, got %q", c.name, c.reason, r.Problems[0].Reason)
		}
	}
}

// A repository that lives under a directory named like a guard file (this
// project's own worktrees sit in .claude/worktrees/) is not a guard file.
func TestFileOnlyIgnoresGuardWordsInTheRepositoryPath(t *testing.T) {
	for _, dir := range []string{"/home/u/.claude/worktrees/seatbelt/envs/prod", "/home/u/.config/work/repo", "/var/lib/ci/workspace/.aws-infra"} {
		r := Analyze(trialEdits[3], Options{Dir: dir, ReadFile: fakeFS(nil), ProtectedPaths: []string{"**/.seatbelt.yaml", "**/.local/state/seatbelt/**"},
			ProtectedPath: func(p string) bool { return strings.HasSuffix(p, "/.seatbelt.yaml") }})
		if len(r.Problems) != 0 || len(r.Notes) != 1 {
			t.Errorf("%s: problems %+v notes %v", dir, r.Problems, r.Notes)
		}
	}
}

func TestFileOnlyPerlAndUnknownLanguagesKeepThePlainReason(t *testing.T) {
	r := Analyze(`perl -e 'system("terra"."form destroy")'`, Options{Dir: "/repo", ReadFile: fakeFS(nil)})
	if len(r.Problems) != 1 || strings.Contains(r.Problems[0].Reason, "(") {
		t.Fatalf("perl should keep the plain reason: %+v", r.Problems)
	}
}

func TestGuardNeedles(t *testing.T) {
	cases := map[string]string{
		"**/.seatbelt.yaml":               ".seatbelt.yaml",
		"**/managed-settings.d/**":        "managed-settings.d",
		"**/.local/state/seatbelt/**":     ".local/state/seatbelt seatbelt",
		"/var/log/agent/audit.jsonl":      "/var/log/agent/audit.jsonl audit.jsonl",
		"infra/*/hooks.json":              "hooks.json",
		"**/*.log":                        "",
		"":                                "",
		"**/.config/seatbelt/config.yaml": ".config/seatbelt/config.yaml config.yaml",
	}
	for in, want := range cases {
		if got := strings.Join(guardNeedles(in), " "); got != want {
			t.Errorf("guardNeedles(%q) = %q, want %q", in, got, want)
		}
	}
}
